package contexts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/getcleanup"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/recent"
	serverapi "github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/rendezvousproto"
	"github.com/scotthaleen/px/internal/transfer"
)

func TestRendezvousHTTPClientAddsExplicitCAAndRejectsInvalidBundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()

	t.Setenv(EnvCAFile, "")
	client, err := rendezvousHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("disposable certificate trusted without explicit CA")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvCAFile, caFile)
	client, err = rendezvousHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("trusted response = %s", response.Status)
	}

	badFile := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvCAFile, badFile)
	if _, err := rendezvousHTTPClient(); err == nil || !strings.Contains(err.Error(), EnvCAFile) {
		t.Fatalf("malformed CA error = %v", err)
	}
	t.Setenv(EnvCAFile, filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := rendezvousHTTPClient(); err == nil || !strings.Contains(err.Error(), EnvCAFile) {
		t.Fatalf("missing CA error = %v", err)
	}
}

func TestControlRejectsImpostorClaimingPinnedServerID(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverID := identity.ID(publicKey)
	authReceived := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		challenge := rendezvousproto.Challenge{
			Version: rendezvousproto.AuthenticationVersion, Type: "challenge", ServerID: serverID,
			Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
			AuthoritySignature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		}
		data, _ := json.Marshal(challenge)
		if err := conn.Write(r.Context(), websocket.MessageText, data); err != nil {
			authReceived <- false
			return
		}
		readContext, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		_, _, err = conn.Read(readContext)
		authReceived <- err == nil
	}))
	defer server.Close()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "device.key")
	if err := identity.WriteFiles(privatePath, filepath.Join(dir, "device.pub")); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(apphome.Paths{}, nil, nil)
	result := manager.connectControl(context.Background(), State{
		ServerURL: server.URL, ServerID: serverID, privatePath: privatePath, Credential: &membership.Credential{},
	})
	if result.healthy || <-authReceived {
		t.Fatal("client authenticated to an impostor claiming the pinned server ID")
	}
}

func TestControlRejectsForgedCompletionOfGenuineChallenge(t *testing.T) {
	for _, unsigned := range []bool{true, false} {
		name := "forged final proof"
		if unsigned {
			name = "unsigned final response"
		}
		t.Run(name, func(t *testing.T) {
			realServer, _ := newEnrollmentServer(t)
			challengeConnection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(realServer.URL, "http")+"/v1/connect", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, challengeData, err := challengeConnection.Read(context.Background())
			challengeConnection.CloseNow()
			if err != nil {
				t.Fatal(err)
			}
			var challenge rendezvousproto.Challenge
			if err := json.Unmarshal(challengeData, &challenge); err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			privatePath := filepath.Join(dir, "device.key")
			publicPath := filepath.Join(dir, "device.pub")
			if err := identity.WriteFiles(privatePath, publicPath); err != nil {
				t.Fatal(err)
			}
			deviceKey, err := identity.LoadPublic(publicPath)
			if err != nil {
				t.Fatal(err)
			}
			deviceID := identity.ID(deviceKey)
			credential := membership.Credential{Claims: membership.CredentialClaims{
				ServerID: challenge.ServerID, DeviceKey: deviceID, Revision: 1,
			}}
			authReceived := make(chan bool, 1)
			impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				if err := conn.Write(r.Context(), websocket.MessageText, challengeData); err != nil {
					authReceived <- false
					return
				}
				_, authenticationData, err := conn.Read(r.Context())
				if err != nil {
					authReceived <- false
					return
				}
				var authentication rendezvousproto.Authentication
				if err := json.Unmarshal(authenticationData, &authentication); err != nil {
					authReceived <- false
					return
				}
				message := controlMessage{Version: rendezvousproto.Version, Type: "authenticated"}
				if !unsigned {
					message.AuthenticationProof = forgedAuthenticatedProof(challenge, deviceID, credential.Claims.Revision, authentication.Signature)
				}
				data, _ := json.Marshal(message)
				err = conn.Write(r.Context(), websocket.MessageText, data)
				authReceived <- err == nil
			}))
			defer impostor.Close()

			manager := NewManager(apphome.Paths{}, nil, nil)
			result := manager.connectControl(context.Background(), State{
				ServerURL: impostor.URL, ServerID: challenge.ServerID, DeviceID: deviceID,
				privatePath: privatePath, Credential: &credential,
			})
			if result.healthy || !<-authReceived {
				t.Fatal("client accepted or did not exercise impostor final response")
			}
		})
	}
}

func forgedAuthenticatedProof(challenge rendezvousproto.Challenge, deviceID string, revision int64, deviceSignature string) *rendezvousproto.AuthenticatedProof {
	canonical, _ := rendezvousproto.ServerChallengeBytes(challenge)
	digest := sha256.Sum256(canonical)
	return &rendezvousproto.AuthenticatedProof{
		Version: rendezvousproto.AuthenticationVersion, ChallengeDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
		DeviceID: deviceID, DeviceKey: deviceID, MembershipRevision: revision, DeviceSignature: deviceSignature,
		AuthoritySignature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
}

func TestTwoContextsRemainIsolatedAndIdempotent(t *testing.T) {
	manager, databaseStore, paths := newTestManager(t)
	serverA, membersA := newEnrollmentServer(t)
	serverB, membersB := newEnrollmentServer(t)
	sharedOffered := filepath.Join(t.TempDir(), "offered")
	sharedInbox := filepath.Join(t.TempDir(), "inbox")

	home, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: serverA.URL, Label: "laptop", OfferedRoot: sharedOffered, InboxRoot: sharedInbox, STUNURLs: []string{"stun:127.0.0.1:3478"}})
	if err != nil {
		t.Fatal(err)
	}
	work, err := manager.Join(context.Background(), JoinRequest{Name: "work", ServerURL: serverB.URL, Label: "workstation", OfferedRoot: sharedOffered, InboxRoot: sharedInbox})
	if err != nil {
		t.Fatal(err)
	}
	if home.State != "pending" || work.State != "pending" || home.DeviceID == work.DeviceID || home.ServerID == work.ServerID {
		t.Fatalf("home = %+v, work = %+v", home, work)
	}
	if home.OfferedRoot != work.OfferedRoot || home.InboxRoot != work.InboxRoot {
		t.Fatal("shared roots were not preserved")
	}
	if _, err := membersA.Approve(context.Background(), home.PendingCode, "local", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := membersB.Approve(context.Background(), work.PendingCode, "local", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	homeEnrolled, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: serverA.URL, Label: "laptop", OfferedRoot: sharedOffered, InboxRoot: sharedInbox})
	if err != nil {
		t.Fatal(err)
	}
	workEnrolled, err := manager.Join(context.Background(), JoinRequest{Name: "work", ServerURL: serverB.URL, Label: "workstation", OfferedRoot: sharedOffered, InboxRoot: sharedInbox})
	if err != nil {
		t.Fatal(err)
	}
	if homeEnrolled.State != "enrolled" || workEnrolled.State != "enrolled" || homeEnrolled.Credential == nil || workEnrolled.Credential == nil {
		t.Fatalf("home = %+v, work = %+v", homeEnrolled, workEnrolled)
	}
	if len(homeEnrolled.STUNURLs) != 1 || homeEnrolled.STUNURLs[0] != "stun:127.0.0.1:3478" || len(workEnrolled.STUNURLs) != 0 {
		t.Fatalf("home STUN = %v, work STUN = %v", homeEnrolled.STUNURLs, workEnrolled.STUNURLs)
	}
	if homeEnrolled.Credential.Claims.ServerID == workEnrolled.Credential.Claims.ServerID || homeEnrolled.Credential.Claims.Label == workEnrolled.Credential.Claims.Label {
		t.Fatal("credential state crossed contexts")
	}
	encodedState, err := json.Marshal(homeEnrolled)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedState), "credential") || strings.Contains(string(encodedState), homeEnrolled.Credential.Signature) {
		t.Fatalf("public context state exposed credential: %s", encodedState)
	}
	if err := manager.SetAlias(context.Background(), "home", "vm", "home-peer"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "work", "vm", "work-peer"); err != nil {
		t.Fatal(err)
	}
	homeEnrolled, _ = manager.Get(context.Background(), "home")
	workEnrolled, _ = manager.Get(context.Background(), "work")
	if homeEnrolled.Aliases["vm"] != "home-peer" || workEnrolled.Aliases["vm"] != "work-peer" {
		t.Fatalf("home aliases = %+v, work aliases = %+v", homeEnrolled.Aliases, workEnrolled.Aliases)
	}
	if name, err := manager.Default(context.Background()); err != nil || name != "home" {
		t.Fatalf("default = %q, %v", name, err)
	}
	if err := manager.SetDefault(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if name, err := manager.Default(context.Background()); err != nil || name != "work" {
		t.Fatalf("default = %q, %v", name, err)
	}

	var contextCount int
	if err := databaseStore.DB().QueryRow(`select count(*) from contexts`).Scan(&contextCount); err != nil || contextCount != 2 {
		t.Fatalf("context count = %d, %v", contextCount, err)
	}
	if home.privatePath == work.privatePath || filepath.Dir(home.privatePath) != paths.AgentKeys {
		t.Fatal("context key paths are not isolated")
	}
	manager.policy.keepaliveInterval = time.Millisecond
	manager.policy.keepaliveJitter = 0
	manager.policy.pongTimeout = 100 * time.Millisecond
	connectionContext, cancelConnections := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelConnections()
	results := make(chan controlResult, 2)
	go func() { results <- manager.connectControl(connectionContext, homeEnrolled) }()
	go func() { results <- manager.connectControl(connectionContext, workEnrolled) }()
	for range 2 {
		if result := <-results; !result.healthy || result.revoked {
			t.Fatalf("context keepalive result = %+v", result)
		}
	}
}

func TestJoinPersistsContextDefaultAndSTUNAtomically(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	if _, err := databaseStore.DB().Exec(`create trigger fail_context_stun before insert on context_stun_servers begin select raise(abort, 'injected STUN failure'); end`); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Join(context.Background(), JoinRequest{
		Name: "home", ServerURL: server.URL, Label: "laptop", STUNURLs: []string{"stun:127.0.0.1:3478"},
	})
	if err == nil || !strings.Contains(err.Error(), "persist context STUN server") {
		t.Fatalf("join error = %v", err)
	}
	var contexts, stunServers int
	var defaultContext sql.NullString
	if err := databaseStore.DB().QueryRow(`select count(*) from contexts`).Scan(&contexts); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.DB().QueryRow(`select count(*) from context_stun_servers`).Scan(&stunServers); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.DB().QueryRow(`select default_context from context_settings where singleton = 1`).Scan(&defaultContext); err != nil {
		t.Fatal(err)
	}
	if contexts != 0 || stunServers != 0 || defaultContext.Valid {
		t.Fatalf("partial join persisted: contexts=%d stun=%d default=%q", contexts, stunServers, defaultContext.String)
	}
}

func TestJoinSTUNCreationIntentPreservesExistingContexts(t *testing.T) {
	manager, _, _ := newTestManager(t)
	for _, test := range []struct {
		name    string
		request JoinRequest
		want    []string
	}{
		{name: "default", request: JoinRequest{DefaultSTUN: true}, want: []string{DefaultSTUNURL}},
		{name: "none", request: JoinRequest{NoSTUN: true}, want: []string{}},
		{name: "custom", request: JoinRequest{STUNURLs: []string{"stun:127.0.0.1:3478"}}, want: []string{"stun:127.0.0.1:3478"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := newEnrollmentServer(t)
			request := test.request
			request.Name, request.Label, request.ServerURL = test.name, test.name, server.URL
			state, err := manager.Join(t.Context(), request)
			if err != nil || !slices.Equal(state.STUNURLs, test.want) {
				t.Fatalf("join = %v, %v; want STUN %v", state.STUNURLs, err, test.want)
			}
			request.DefaultSTUN, request.NoSTUN, request.STUNURLs = true, false, nil
			request.RequireUnchanged = true
			resumed, err := manager.Join(t.Context(), request)
			if err != nil || !slices.Equal(resumed.STUNURLs, test.want) {
				t.Fatalf("resumed join = %v, %v; want STUN %v", resumed.STUNURLs, err, test.want)
			}
		})
	}
	server, _ := newEnrollmentServer(t)
	if _, err := manager.Join(t.Context(), JoinRequest{Name: "invalid", Label: "invalid", ServerURL: server.URL, DefaultSTUN: true, NoSTUN: true}); err == nil {
		t.Fatal("contradictory STUN intent succeeded")
	}
}

func TestJoinRejectsInvalidBuildDefaultSTUN(t *testing.T) {
	original := DefaultSTUNURL
	DefaultSTUNURL = "turn:relay.example:3478"
	t.Cleanup(func() { DefaultSTUNURL = original })

	manager, _, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	_, err := manager.Join(t.Context(), JoinRequest{Name: "invalid", Label: "invalid", ServerURL: server.URL, DefaultSTUN: true})
	if err == nil || !strings.Contains(err.Error(), "default STUN URL") {
		t.Fatalf("invalid build default error = %v", err)
	}
}

func TestServerInfoReportsProtocolMismatchBeforeEnrollment(t *testing.T) {
	manager, _, _ := newTestManager(t)
	for _, test := range []struct {
		name string
		info rendezvousproto.ServerInfo
		want string
	}{
		{name: "legacy compatible", info: rendezvousproto.ServerInfo{Version: rendezvousproto.Version, ServerID: "server", Authority: "server"}},
		{name: "newer control", info: rendezvousproto.ServerInfo{Version: 3, ControlVersion: 3, AuthenticationVersion: rendezvousproto.AuthenticationVersion, ServerID: "server"}, want: "control protocol mismatch"},
		{name: "older authentication", info: rendezvousproto.ServerInfo{Version: rendezvousproto.Version, ControlVersion: rendezvousproto.Version, AuthenticationVersion: 1, ServerID: "server"}, want: "authentication protocol mismatch"},
		{name: "contradictory control", info: rendezvousproto.ServerInfo{Version: 2, ControlVersion: 1, AuthenticationVersion: rendezvousproto.AuthenticationVersion, ServerID: "server"}, want: "inconsistent control protocol versions"},
		{name: "reverse contradictory control", info: rendezvousproto.ServerInfo{Version: 1, ControlVersion: 2, AuthenticationVersion: rendezvousproto.AuthenticationVersion, ServerID: "server"}, want: "inconsistent control protocol versions"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(test.info)
			}))
			defer server.Close()
			_, err := manager.serverInfo(t.Context(), server.URL)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("serverInfo error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestJoinRedeemsInviteWithoutPersistingToken(t *testing.T) {
	manager, _, paths := newTestManager(t)
	server, members := newEnrollmentServer(t)
	created, err := members.CreateInvite(t.Context(), "Invited", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.Join(t.Context(), JoinRequest{Name: "invited", Label: "Invited", ServerURL: server.URL, Invite: created.Token})
	if err != nil || state.State != "enrolled" || state.Credential == nil || state.PendingCode != "" {
		t.Fatalf("invite join = %+v, %v", state, err)
	}
	if err := verifyEnrollment(*state.Credential, state.ServerID, state.DeviceID, state.Label); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), created.Token) {
		t.Fatal("agent database retained invite token")
	}
	if _, err := members.RedeemInvite(t.Context(), created.Token, make(ed25519.PublicKey, ed25519.PublicKeySize), "Invited", time.Now()); !membership.HasCode(err, membership.CodeInviteUnavailable) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestJoinInvitePreflightRejectsUnsupportedAndWrongServerWithoutTransmission(t *testing.T) {
	manager, _, _ := newTestManager(t)
	invitingServer, invitingStore := newEnrollmentServer(t)
	created, err := invitingStore.CreateInvite(t.Context(), "Invited", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var invitingInfo rendezvousproto.ServerInfo
	if err := manager.getJSON(t.Context(), invitingServer.URL+"/v1/server", &invitingInfo); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		info rendezvousproto.ServerInfo
		want string
	}{
		{name: "unsupported", info: rendezvousproto.ServerInfo{Version: 2, ControlVersion: 2, AuthenticationVersion: 2, ServerID: invitingInfo.ServerID, Authority: invitingInfo.ServerID}, want: "does not support"},
		{name: "wrong server", info: func() rendezvousproto.ServerInfo {
			_, _, otherAuthority := newTestAuthority(t)
			return rendezvousproto.ServerInfo{Version: 2, ControlVersion: 2, AuthenticationVersion: 2, InviteVersion: 1, ServerID: otherAuthority.ServerID(), Authority: otherAuthority.ServerID()}
		}(), want: "different rendezvous server"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var redemptions atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/server" {
					_ = json.NewEncoder(w).Encode(test.info)
					return
				}
				redemptions.Add(1)
				http.NotFound(w, r)
			}))
			defer server.Close()
			_, err := manager.Join(t.Context(), JoinRequest{Name: strings.ReplaceAll(test.name, " ", "-"), Label: "Invited", ServerURL: server.URL, Invite: created.Token})
			if err == nil || !strings.Contains(err.Error(), test.want) || redemptions.Load() != 0 {
				t.Fatalf("join error = %v, redemptions = %d", err, redemptions.Load())
			}
		})
	}
}

func TestJoinInviteReconcilesCommittedResponseLoss(t *testing.T) {
	manager, _, _ := newTestManager(t)
	backend, members := newEnrollmentServer(t)
	created, err := members.CreateInvite(t.Context(), "Reconciled", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var redemptions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/invites/redeem" && redemptions.Add(1) == 1 {
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, r)
			if recorder.Code != http.StatusOK {
				t.Errorf("backend redemption = %d: %s", recorder.Code, recorder.Body.String())
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	state, err := manager.Join(t.Context(), JoinRequest{Name: "reconciled", Label: "Reconciled", ServerURL: server.URL, Invite: created.Token})
	if err != nil || state.State != "enrolled" || redemptions.Load() != 1 {
		t.Fatalf("reconciled join = %+v, %v, redemptions = %d", state, err, redemptions.Load())
	}
}

func TestInviteTransportRequiresHTTPSOrLoopback(t *testing.T) {
	for _, test := range []struct {
		origin string
		valid  bool
	}{
		{origin: "https://px.example", valid: true},
		{origin: "http://localhost:8080", valid: true},
		{origin: "http://127.0.0.1:8080", valid: true},
		{origin: "http://[::1]:8080", valid: true},
		{origin: "http://px.example", valid: false},
		{origin: "http://192.0.2.1", valid: false},
	} {
		if err := validateInviteTransport(test.origin); (err == nil) != test.valid {
			t.Fatalf("validateInviteTransport(%q) = %v, valid=%v", test.origin, err, test.valid)
		}
	}
	manager, _, _ := newTestManager(t)
	_, err := manager.Join(t.Context(), JoinRequest{Name: "insecure", ServerURL: "http://192.0.2.1", Label: "device", Invite: testInviteToken("server")})
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("nonloopback HTTP join error = %v", err)
	}
}

func TestRendezvousClientRefusesDiscoveryAndRedemptionRedirects(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		data, _ := io.ReadAll(r.Body)
		if bytes.Contains(data, []byte(token)) {
			t.Error("redirect target received invite token")
		}
		http.Error(w, "unexpected redirect", http.StatusInternalServerError)
	}))
	defer target.Close()

	discoveryRedirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer discoveryRedirect.Close()
	if _, err := manager.serverInfo(t.Context(), discoveryRedirect.URL); err == nil || targetRequests.Load() != 0 {
		t.Fatalf("discovery redirect error = %v, target requests = %d", err, targetRequests.Load())
	}
	enrollmentRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer enrollmentRedirect.Close()
	if _, err := manager.enroll(t.Context(), enrollmentRedirect.URL, publicKey, "device"); err == nil || targetRequests.Load() != 0 {
		t.Fatalf("enrollment redirect error = %v, target requests = %d", err, targetRequests.Load())
	}

	redemptionRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/invites/redeem" {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		http.NotFound(w, r)
	}))
	defer redemptionRedirect.Close()
	info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
	_, err := manager.redeemInvite(t.Context(), redemptionRedirect.URL, info, token, publicKey, "device")
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") || targetRequests.Load() != 0 {
		t.Fatalf("redemption redirect error = %v, target requests = %d", err, targetRequests.Load())
	}
}

func TestInviteRedemptionErrorsAreLocalAndRedacted(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusTooManyRequests} {
		var redemptions, statuses atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/invites/redeem":
				redemptions.Add(1)
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"code":"malicious","error":%q}`, "proxy echoed "+token)
			case "/v1/enrollments/status":
				statuses.Add(1)
				http.Error(w, "unexpected status", http.StatusInternalServerError)
			}
		}))
		info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
		_, err := manager.redeemInvite(t.Context(), server.URL, info, token, publicKey, "device")
		server.Close()
		if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "proxy echoed") || redemptions.Load() != 1 || statuses.Load() != 0 {
			t.Fatalf("status %d error = %v, redemptions=%d statuses=%d", status, err, redemptions.Load(), statuses.Load())
		}
	}
}

func TestInviteRedemptionAmbiguityUsesBoundedReconciliation(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	credential, err := authority.Issue(publicKey, "device", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	validResponse, _ := json.Marshal(rendezvousproto.InviteRedemption{Version: 1, State: "enrolled", Credential: credential})
	for _, test := range []struct {
		name          string
		firstResponse func(http.ResponseWriter)
		retryResponse func(http.ResponseWriter)
		wantRedeems   int32
		statusEnroll  int32
	}{
		{name: "internal", firstResponse: func(w http.ResponseWriter) { http.Error(w, "internal "+token, http.StatusInternalServerError) }, wantRedeems: 2},
		{name: "gateway", firstResponse: func(w http.ResponseWriter) { http.Error(w, "gateway "+token, http.StatusBadGateway) }, wantRedeems: 2},
		{name: "service unavailable", firstResponse: func(w http.ResponseWriter) { http.Error(w, "unavailable "+token, http.StatusServiceUnavailable) }, wantRedeems: 2},
		{name: "gateway timeout", firstResponse: func(w http.ResponseWriter) { http.Error(w, "timeout "+token, http.StatusGatewayTimeout) }, wantRedeems: 2},
		{name: "request timeout", firstResponse: func(w http.ResponseWriter) { http.Error(w, "timeout "+token, http.StatusRequestTimeout) }, wantRedeems: 2},
		{name: "odd status", firstResponse: func(w http.ResponseWriter) { http.Error(w, "odd "+token, http.StatusTeapot) }, wantRedeems: 2},
		{name: "unknown success field", firstResponse: func(w http.ResponseWriter) {
			_, _ = w.Write(append(validResponse[:len(validResponse)-1], []byte(`,"extra":true}`)...))
		}, wantRedeems: 2},
		{name: "trailing success", firstResponse: func(w http.ResponseWriter) { _, _ = w.Write(append(validResponse, []byte(` {}`)...)) }, wantRedeems: 2},
		{name: "invalid credential", firstResponse: func(w http.ResponseWriter) {
			invalid := credential
			invalid.Signature = "invalid"
			_ = json.NewEncoder(w).Encode(rendezvousproto.InviteRedemption{Version: 1, State: "enrolled", Credential: invalid})
		}, wantRedeems: 2},
		{name: "committed gateway", firstResponse: func(w http.ResponseWriter) { http.Error(w, "lost", http.StatusServiceUnavailable) }, wantRedeems: 1, statusEnroll: 1},
		{name: "retry remains ambiguous", firstResponse: func(w http.ResponseWriter) { http.Error(w, "lost", http.StatusBadGateway) }, retryResponse: func(w http.ResponseWriter) { http.Error(w, "still lost", http.StatusGatewayTimeout) }, wantRedeems: 2, statusEnroll: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var redemptions, statuses atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/invites/redeem":
					attempt := redemptions.Add(1)
					if attempt == 1 {
						test.firstResponse(w)
						return
					}
					if test.retryResponse != nil {
						test.retryResponse(w)
						return
					}
					_, _ = w.Write(validResponse)
				case "/v1/enrollments/status":
					attempt := statuses.Add(1)
					if test.statusEnroll != 0 && attempt >= test.statusEnroll {
						_ = json.NewEncoder(w).Encode(rendezvousproto.Enrollment{State: "enrolled", Credential: &credential})
						return
					}
					_ = json.NewEncoder(w).Encode(rendezvousproto.Enrollment{State: "expired"})
				}
			}))
			defer server.Close()
			info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
			enrolled, err := manager.redeemInvite(t.Context(), server.URL, info, token, publicKey, "device")
			if err != nil || enrolled.State != "enrolled" || redemptions.Load() != test.wantRedeems || statuses.Load() < 1 {
				t.Fatalf("result=%+v err=%v redemptions=%d statuses=%d", enrolled, err, redemptions.Load(), statuses.Load())
			}
		})
	}
}

func TestInviteRedemptionUnknownOutcomeIsBoundedAndRedacted(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	var redemptions, statuses atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/invites/redeem":
			redemptions.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `{"code":"echo","error":%q}`, token)
		case "/v1/enrollments/status":
			statuses.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, token)
		}
	}))
	defer server.Close()
	info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
	_, err := manager.redeemInvite(t.Context(), server.URL, info, token, publicKey, "device")
	if err == nil || err.Error() != "invite redemption outcome is unknown; retry onboarding with the same invite, context, label, and device key" || strings.Contains(err.Error(), token) || redemptions.Load() != 2 || statuses.Load() != 2 {
		t.Fatalf("error=%v redemptions=%d statuses=%d", err, redemptions.Load(), statuses.Load())
	}
}

func TestConsumedInviteWithUnavailableStatusIsUnknownWithoutRetry(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	var redemptions, statuses atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/invites/redeem":
			redemptions.Add(1)
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"code":"invite_unavailable","error":%q}`, token)
		case "/v1/enrollments/status":
			statuses.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, token)
		}
	}))
	defer server.Close()
	info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
	_, err := manager.redeemInvite(t.Context(), server.URL, info, token, publicKey, "device")
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") || strings.Contains(err.Error(), token) || redemptions.Load() != 1 || statuses.Load() != 1 {
		t.Fatalf("error=%v redemptions=%d statuses=%d", err, redemptions.Load(), statuses.Load())
	}
}

func TestConsumedInviteMalformedStatusResponsesRemainAmbiguous(t *testing.T) {
	manager, _, _ := newTestManager(t)
	_, _, authority := newTestAuthority(t)
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	token := testInviteToken(authority.ServerID())
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "empty object", body: `{}`},
		{name: "unknown state", body: `{"state":"unknown"}`},
		{name: "malformed pending", body: `{"state":"pending"}`},
		{name: "malformed expired", body: `{"state":"expired","code":"AAAA-AAAA"}`},
		{name: "unknown field", body: `{"state":"expired","extra":true}`},
		{name: "trailing data", body: `{"state":"expired"} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var redemptions, statuses atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/invites/redeem":
					redemptions.Add(1)
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"code":"invite_unavailable"}`))
				case "/v1/enrollments/status":
					statuses.Add(1)
					_, _ = w.Write([]byte(test.body))
				}
			}))
			defer server.Close()
			info := rendezvousproto.ServerInfo{InviteVersion: 1, ServerID: authority.ServerID(), Authority: authority.ServerID()}
			_, err := manager.redeemInvite(t.Context(), server.URL, info, token, publicKey, "device")
			if err == nil || !strings.Contains(err.Error(), "outcome is unknown") || redemptions.Load() != 1 || statuses.Load() != 1 {
				t.Fatalf("error=%v redemptions=%d statuses=%d", err, redemptions.Load(), statuses.Load())
			}
		})
	}
}

func testInviteToken(serverID string) string {
	tag := membership.InviteServerTag(serverID)
	inviteID := make([]byte, 16)
	secret := make([]byte, 32)
	for index := range inviteID {
		inviteID[index] = byte(index)
	}
	for index := range secret {
		secret[index] = byte(index + 16)
	}
	return "PXI1." + base64.RawURLEncoding.EncodeToString(tag[:]) + "." + hex.EncodeToString(inviteID) + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func TestVerifyEnrollmentRequiresRevisionOne(t *testing.T) {
	_, _, authority := newTestAuthority(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := authority.Issue(publicKey, "device", 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEnrollment(credential, authority.ServerID(), identity.ID(publicKey), "device"); err == nil {
		t.Fatal("revision-2 enrollment credential accepted")
	}
}

func newTestAuthority(t *testing.T) (string, string, *membership.Authority) {
	t.Helper()
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "authority.key"), filepath.Join(dir, "authority.pub")
	if err := membership.Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	authority, err := membership.Load(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath, authority
}

func TestControlProtocolVersionIgnoresFutureFields(t *testing.T) {
	if got := controlProtocolVersion([]byte(`{"version":3,"future_field":{"value":true}}`)); got != 3 {
		t.Fatalf("protocol version = %d, want 3", got)
	}
}

func TestJoinPreservesConcurrentTerminalState(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, enrollmentStarted, releaseEnrollment := newBlockingEnrollmentServer(t, 2)
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop"})
		result <- err
	}()
	<-enrollmentStarted
	if _, err := databaseStore.DB().Exec(`update contexts set state = 'revoked' where name = 'home'`); err != nil {
		t.Fatal(err)
	}
	close(releaseEnrollment)
	if err := <-result; !errors.Is(err, ErrInvalidContextState) {
		t.Fatalf("join after revocation = %v", err)
	}
	state, err := manager.Get(context.Background(), "home")
	if err != nil || state.State != "revoked" {
		t.Fatalf("terminal state = %q, %v", state.State, err)
	}
}

func TestStopPreventsBlockedJoinFromCommittingOrStartingWorker(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, enrollmentStarted, releaseEnrollment := newBlockingEnrollmentServer(t, 1)
	manager.runtime = context.Background()
	manager.cancel = func() {}
	manager.activated = true
	result := make(chan error, 1)
	go func() {
		_, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop"})
		result <- err
	}()
	<-enrollmentStarted
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(releaseEnrollment)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("join after stop = %v", err)
	}
	var contexts int
	if err := databaseStore.DB().QueryRow(`select count(*) from contexts`).Scan(&contexts); err != nil || contexts != 0 {
		t.Fatalf("contexts after stop = %d, %v", contexts, err)
	}
	if len(manager.workers) != 0 {
		t.Fatalf("workers started after stop: %v", manager.workers)
	}
}

func TestContextAndAliasAdmissionAreBounded(t *testing.T) {
	t.Run("contexts", func(t *testing.T) {
		manager, databaseStore, _ := newTestManager(t)
		for index := range MaxContexts {
			insertTestContext(t, databaseStore.DB(), fmt.Sprintf("context-%02d", index), "/offered", "/inbox")
		}
		states, err := manager.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if size, err := encodedContextProjectionSize(states); err != nil || size > contextProjectionSize {
			t.Fatalf("minimum maximum-count projection = %d, %v", size, err)
		}
		_, err = manager.Join(context.Background(), JoinRequest{Name: "overflow", ServerURL: "https://px.example", Label: "device"})
		if !errors.Is(err, ErrContextCapacity) {
			t.Fatalf("context capacity error = %v", err)
		}
	})

	t.Run("aliases", func(t *testing.T) {
		manager, databaseStore, _ := newTestManager(t)
		insertTestContext(t, databaseStore.DB(), "home", "/offered", "/inbox")
		for index := range MaxAliasesPerContext {
			if _, err := databaseStore.DB().Exec(`insert into context_aliases (context_name, alias, target_label) values ('home', ?, 'peer')`, fmt.Sprintf("alias-%02d", index)); err != nil {
				t.Fatal(err)
			}
		}
		if err := manager.SetAlias(context.Background(), "home", "overflow", "peer"); !errors.Is(err, ErrAliasCapacity) {
			t.Fatalf("alias capacity error = %v", err)
		}
		if err := manager.SetAlias(context.Background(), "home", "alias-00", "updated"); err != nil {
			t.Fatalf("update at alias capacity: %v", err)
		}
	})

	t.Run("encoded projection", func(t *testing.T) {
		manager, databaseStore, _ := newTestManager(t)
		largeRoot := "/" + strings.Repeat("x", contextProjectionSize/2)
		insertTestContext(t, databaseStore.DB(), "home", largeRoot, largeRoot)
		if _, err := databaseStore.DB().Exec(`insert into context_aliases (context_name, alias, target_label) values ('home', 'existing', 'target')`); err != nil {
			t.Fatal(err)
		}
		if err := manager.SetAlias(context.Background(), "home", "peer", "target"); !errors.Is(err, ErrContextProjection) {
			t.Fatalf("projection capacity error = %v", err)
		}
		if removed, err := manager.RemoveAlias(context.Background(), "home", "existing"); err != nil || removed.Name != "existing" {
			t.Fatalf("remove alias from over-limit state = %+v, %v", removed, err)
		}
		if _, err := manager.Disable(context.Background(), "home"); !errors.Is(err, ErrContextProjection) {
			t.Fatalf("oversized disable error = %v", err)
		}
		var enabled int
		var state string
		if err := databaseStore.DB().QueryRow(`select enabled, state from contexts where name = 'home'`).Scan(&enabled, &state); err != nil || enabled != 1 || state != "pending" {
			t.Fatalf("context changed after rejected disable: enabled=%d state=%q err=%v", enabled, state, err)
		}
	})
}

func TestStopCancelsWithoutManagerStateLock(t *testing.T) {
	manager := &Manager{}
	canceled := make(chan struct{})
	manager.cancel = func() { close(canceled) }
	manager.mu.Lock()
	defer manager.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- manager.Stop(context.Background()) }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stop waited for the manager state lock before cancellation")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStopBoundsWaitForAdmittedMutation(t *testing.T) {
	manager := &Manager{}
	canceled := make(chan struct{})
	manager.cancel = func() { close(canceled) }
	mutationDone, err := manager.beginMutationCommit()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = manager.Stop(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stop error = %v", err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("stop did not cancel before waiting for an admitted mutation")
	}
	mutationDone()
}

func TestPeerSnapshotIsDeterministicAndContextLocal(t *testing.T) {
	manager, _, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "local"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "zeta", "Beta"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "alpha-alias", "beta"); err != nil {
		t.Fatal(err)
	}
	controlContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.controls["home"] = &controlConnection{
		ctx: controlContext,
		peers: map[string]membership.Member{
			"beta":  {Label: "Beta", DeviceID: "device-b"},
			"alpha": {Label: "alpha", DeviceID: "device-a"},
		},
	}
	peers, err := manager.Peers(context.Background(), "home")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].Label != "alpha" || peers[1].Label != "Beta" || len(peers[0].Aliases) != 0 || strings.Join(peers[1].Aliases, ",") != "alpha-alias,zeta" {
		t.Fatalf("peers = %+v", peers)
	}
	encoded, err := json.Marshal(peers[0].Aliases)
	if err != nil || string(encoded) != "[]" {
		t.Fatalf("empty aliases = %s, %v", encoded, err)
	}
}

func TestControlRequestCapacityAndDisconnectCleanup(t *testing.T) {
	controlContext, cancel := context.WithCancel(context.Background())
	control := &controlConnection{ctx: controlContext, waiters: make(map[string]controlWaiter)}
	for index := range 4 {
		requestID := strings.Repeat(string(rune('a'+index)), 32)
		control.waiters[requestID] = controlWaiter{operation: "members.list", response: make(chan controlResponse, 1)}
	}
	if _, err := control.request(context.Background(), "members.list", ""); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("capacity error = %v", err)
	}
	waiters := control.waiters
	cancel()
	control.closeWaiters()
	if len(control.waiters) != 0 {
		t.Fatalf("waiters remain after disconnect: %d", len(control.waiters))
	}
	for requestID, waiter := range waiters {
		select {
		case response := <-waiter.response:
			if response.err == nil {
				t.Fatalf("waiter %s was not failed", requestID)
			}
		default:
			t.Fatalf("waiter %s was not notified", requestID)
		}
	}
}

func TestControlRequestWriteCancellationAndApprovalUncertainty(t *testing.T) {
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	control := &controlConnection{ctx: controlContext, waiters: make(map[string]controlWaiter)}
	started := make(chan struct{})
	release := make(chan struct{})
	gateDone := make(chan struct{})
	go func() {
		defer close(gateDone)
		_, _ = control.writes.run(context.Background(), func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	requestContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	if _, err := control.request(requestContext, "pending.approve", "ABCD-2345"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-write cancellation = %v", err)
	}
	if len(control.waiters) != 0 {
		t.Fatalf("canceled request left %d waiter(s)", len(control.waiters))
	}
	close(release)
	<-gateDone

	client, stop := websocketTestPair(t, true)
	defer stop()
	control.conn = client
	requestContext, cancelRequest = context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := control.request(requestContext, "pending.approve", "ABCD-2345")
		result <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelRequest()
	if err := <-result; !errors.Is(err, ErrApprovalOutcomeUnknown) {
		t.Fatalf("post-write cancellation = %v", err)
	}

	disconnectClient, disconnectStop := websocketTestPair(t, true)
	defer disconnectStop()
	disconnectContext, disconnect := context.WithCancel(context.Background())
	disconnected := &controlConnection{ctx: disconnectContext, conn: disconnectClient, waiters: make(map[string]controlWaiter)}
	result = make(chan error, 1)
	go func() {
		_, err := disconnected.request(context.Background(), "pending.approve", "ABCD-2345")
		result <- err
	}()
	time.Sleep(20 * time.Millisecond)
	disconnect()
	disconnected.closeWaiters()
	if err := <-result; !errors.Is(err, ErrApprovalOutcomeUnknown) {
		t.Fatalf("post-write disconnect = %v", err)
	}

	for _, test := range []struct {
		operation string
		want      error
	}{
		{operation: "invite.create", want: ErrInviteCreateOutcomeUnknown},
		{operation: "invite.revoke", want: ErrInviteRevokeOutcomeUnknown},
	} {
		client, stop := websocketTestPair(t, true)
		operationContext, cancelOperation := context.WithCancel(context.Background())
		inviteControl := &controlConnection{ctx: operationContext, conn: client, waiters: make(map[string]controlWaiter)}
		requestID := strings.Repeat("c", 32)
		result := make(chan error, 1)
		go func() {
			_, err := inviteControl.requestControl(context.Background(), requestID, test.operation, inviteapi.ControlListRequest{Type: test.operation, RequestID: requestID, Version: inviteapi.Version}, true)
			result <- err
		}()
		time.Sleep(20 * time.Millisecond)
		cancelOperation()
		inviteControl.closeWaiters()
		if err := <-result; !errors.Is(err, test.want) {
			t.Fatalf("%s disconnect = %v", test.operation, err)
		}
		stop()
	}
}

func TestControlResponseCorrelationAndBufferedResponsePreference(t *testing.T) {
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	first := controlWaiter{operation: "members.list", response: make(chan controlResponse, 1)}
	second := controlWaiter{operation: "pending.list", response: make(chan controlResponse, 1)}
	control := &controlConnection{
		ctx: controlContext,
		waiters: map[string]controlWaiter{
			strings.Repeat("a", 32): first,
			strings.Repeat("b", 32): second,
		},
	}
	control.handle(controlMessage{Version: rendezvousproto.Version, Type: "pending.list", RequestID: strings.Repeat("a", 32)})
	if len(control.waiters) != 2 {
		t.Fatalf("wrong operation consumed waiter: %d", len(control.waiters))
	}
	control.handle(controlMessage{Version: rendezvousproto.Version, Type: "members.list", RequestID: strings.Repeat("a", 32)})
	control.handle(controlMessage{Version: rendezvousproto.Version, Type: "pending.list", RequestID: strings.Repeat("b", 32)})
	for index, waiter := range []controlWaiter{first, second} {
		select {
		case result := <-waiter.response:
			if result.err != nil || result.message.RequestID == "" {
				t.Fatalf("response %d = %+v", index, result)
			}
		default:
			t.Fatalf("response %d was not correlated", index)
		}
	}
	buffered := controlWaiter{response: make(chan controlResponse, 1)}
	buffered.response <- controlResponse{message: controlMessage{Type: "members.list"}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	response, err := control.waitResponse(canceled, buffered)
	if err != nil || response.Type != "members.list" {
		t.Fatalf("buffered response lost to cancellation: %+v, %v", response, err)
	}
	inviteID := strings.Repeat("c", 32)
	inviteWaiter := controlWaiter{operation: "invite.create", response: make(chan controlResponse, 1)}
	control.waiters[inviteID] = inviteWaiter
	encoded := []byte(`{"type":"invite.error","request_id":"` + inviteID + `","version":1,"code":"invite_capacity","message":"invite capacity reached"}`)
	control.handleData(encoded, controlMessage{Version: rendezvousproto.Version, Type: "invite.error", RequestID: inviteID})
	select {
	case result := <-inviteWaiter.response:
		if !bytes.Equal(result.data, encoded) {
			t.Fatalf("invite response was not preserved for strict decoding: %q", result.data)
		}
	default:
		t.Fatal("invite error was not correlated")
	}
}

func TestConcurrentControlRequestsCorrelateOutOfOrderResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		requests := make([]controlMessage, 0, 2)
		for range 2 {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var request controlMessage
			if json.Unmarshal(data, &request) != nil {
				return
			}
			requests = append(requests, request)
		}
		for index := len(requests) - 1; index >= 0; index-- {
			response := controlMessage{Version: rendezvousproto.Version, Type: requests[index].Type, RequestID: requests[index].RequestID}
			data, err := json.Marshal(response)
			if err != nil || conn.Write(r.Context(), websocket.MessageText, data) != nil {
				return
			}
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	conn, _, err := websocket.Dial(controlContext, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	control := &controlConnection{ctx: controlContext, conn: conn, waiters: make(map[string]controlWaiter)}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for range 2 {
			_, data, err := conn.Read(controlContext)
			if err != nil {
				return
			}
			var response controlMessage
			if json.Unmarshal(data, &response) == nil {
				control.handle(response)
			}
		}
	}()
	type result struct {
		operation string
		response  controlMessage
		err       error
	}
	results := make(chan result, 2)
	for _, operation := range []string{"members.list", "pending.list"} {
		operation := operation
		go func() {
			response, err := control.request(controlContext, operation, "")
			results <- result{operation: operation, response: response, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil || result.response.Type != result.operation || result.response.RequestID == "" {
			t.Fatalf("request %s response = %+v, %v", result.operation, result.response, result.err)
		}
	}
	<-readerDone
}

func TestMemberStatusAndActiveMemberLookup(t *testing.T) {
	members := []membership.Member{{DeviceID: "local-id", Label: "Laptop"}, {DeviceID: "peer-id", Label: "VM"}}
	if member, ok := activeMemberByLabel(members, "vm"); !ok || member.DeviceID != "peer-id" {
		t.Fatalf("active member = %+v, %v", member, ok)
	}
	if _, ok := activeMemberByLabel(members, "missing"); ok {
		t.Fatal("unknown member was found")
	}
	online := map[string]bool{"peer-id": true}
	for _, test := range []struct {
		memberID string
		coherent bool
		want     string
	}{
		{memberID: "local-id", coherent: true, want: "local"},
		{memberID: "peer-id", coherent: true, want: "online"},
		{memberID: "offline-id", coherent: true, want: "offline"},
		{memberID: "peer-id", coherent: false, want: "unknown"},
	} {
		if got := memberStatus("local-id", test.memberID, online, test.coherent); got != test.want {
			t.Fatalf("memberStatus(%q, %v) = %q, want %q", test.memberID, test.coherent, got, test.want)
		}
	}
}

func TestPendingContextExpiresWithoutResubmission(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	state, err := manager.Join(context.Background(), JoinRequest{Name: "expiring", ServerURL: server.URL, Label: "device"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`update contexts set pending_expires_at = ? where name = ?`, time.Now().Add(-time.Second).Unix(), state.Name); err != nil {
		t.Fatal(err)
	}
	manager.runContext(context.Background(), state.Name)
	state, err = manager.Get(context.Background(), state.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != "expired" {
		t.Fatalf("state = %q, want expired", state.State)
	}
}

func TestContextJoinedBeforeActivationIsQueued(t *testing.T) {
	manager, _, _ := newTestManager(t)
	runtimeContext, cancel := context.WithCancel(context.Background())
	manager.runtime, manager.cancel = runtimeContext, cancel
	t.Cleanup(func() {
		cancel()
		manager.wg.Wait()
	})
	server, _ := newEnrollmentServer(t)
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if len(manager.pending) != 1 || manager.pending[0] != "home" || len(manager.workers) != 0 {
		t.Fatalf("pending = %v, workers = %v", manager.pending, manager.workers)
	}
	manager.Activate()
	manager.mu.Lock()
	_, active := manager.workers["home"]
	manager.mu.Unlock()
	if !active {
		t.Fatal("queued context worker was not activated")
	}
}

func TestJoinCanRequireExistingSettingsToRemainUnchanged(t *testing.T) {
	manager, _, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	offered := filepath.Join(t.TempDir(), "offered")
	inbox := filepath.Join(t.TempDir(), "inbox")
	state, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: offered, InboxRoot: inbox})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: offered, InboxRoot: filepath.Join(t.TempDir(), "other"), RequireUnchanged: true})
	if err == nil || !strings.Contains(err.Error(), "different settings") {
		t.Fatalf("changed join error = %v", err)
	}
	unchanged, err := manager.Get(context.Background(), "home")
	if err != nil || unchanged.InboxRoot != state.InboxRoot || unchanged.DeviceID != state.DeviceID {
		t.Fatalf("context changed = %+v, %v", unchanged, err)
	}
	if _, err := manager.Disable(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: offered, InboxRoot: inbox, RequireUnchanged: true, RequireExisting: true})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled join error = %v", err)
	}
	if _, err := manager.Enable(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: offered, InboxRoot: inbox, RequireUnchanged: true, RequireExisting: true})
	if err == nil || !strings.Contains(err.Error(), "removed during onboarding") {
		t.Fatalf("removed join error = %v", err)
	}
}

func TestContextDisableEnableAndRemovalLifecycle(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	runtimeContext, cancelRuntime := context.WithCancel(context.Background())
	manager.runtime, manager.cancel = runtimeContext, cancelRuntime
	manager.activated = true
	t.Cleanup(func() {
		cancelRuntime()
		manager.wg.Wait()
	})
	server, _ := newEnrollmentServer(t)
	offeredRoot := filepath.Join(t.TempDir(), "offered")
	inboxRoot := filepath.Join(t.TempDir(), "inbox")
	if err := os.MkdirAll(offeredRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(inboxRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	offeredFile := filepath.Join(offeredRoot, "keep.txt")
	inboxFile := filepath.Join(inboxRoot, "keep.txt")
	if err := os.WriteFile(offeredFile, []byte("offered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inboxFile, []byte("inbox"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: offeredRoot, InboxRoot: inboxRoot, STUNURLs: []string{"stun:127.0.0.1:3478"}})
	if err != nil {
		t.Fatal(err)
	}
	work, err := manager.Join(context.Background(), JoinRequest{Name: "work", ServerURL: server.URL, Label: "desktop"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "peer", "other"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	stdinSpool := filepath.Join(manager.paths.AgentTransfers, ".stdin-context-removal.spool")
	receiverID := strings.Repeat("a", 64)
	receiverPartial := filepath.Join(manager.paths.AgentTransfers, receiverID+".part")
	for _, path := range []string{stdinSpool, receiverPartial} {
		if err := os.WriteFile(path, []byte("private transfer state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at) values ('send', ?, 'home', 'peer-id', 'peer', 'file', 1, 'sha', 1, 1, 'token', 0, ?, 1, 'transferring', ?, ?, ?)`, strings.Repeat("b", 64), stdinSpool, now, now, now+60); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at) values ('receive', ?, 'home', 'peer-id', 'peer', 'file', 1, 'sha', 1, 1, 'token', 0, 'transferring', ?, ?, ?)`, receiverID, now, now, now+60); err != nil {
		t.Fatal(err)
	}

	disabled, err := manager.Disable(context.Background(), "home")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("disabled context remains enabled")
	}
	if _, ok := manager.workers["home"]; ok {
		t.Fatal("disabled context worker remains active")
	}
	if _, err := os.Stat(home.privatePath); err != nil {
		t.Fatalf("disabled context identity was not preserved: %v", err)
	}

	restarted := NewManager(manager.paths, databaseStore.DB, nil)
	restarted.runtime, restarted.cancel = context.WithCancel(context.Background())
	restarted.activated = true
	t.Cleanup(func() {
		restarted.cancel()
		restarted.wg.Wait()
	})
	persisted, err := restarted.Get(context.Background(), "home")
	if err != nil || persisted.Enabled {
		t.Fatalf("persisted context = %+v, %v", persisted, err)
	}
	enabled, err := restarted.Enable(context.Background(), "home")
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || enabled.DeviceID != home.DeviceID || enabled.privatePath != home.privatePath {
		t.Fatalf("enabled context changed identity: %+v", enabled)
	}

	restarted.active["home"] = activeOperations{total: 1}
	if err := restarted.Remove(context.Background(), "home"); !errors.Is(err, ErrContextActive) {
		t.Fatalf("active removal error = %v", err)
	}
	delete(restarted.active, "home")
	if _, err := databaseStore.DB().Exec(`create trigger fail_context_remove before delete on contexts when old.name = 'home' begin select raise(abort, 'blocked'); end`); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Remove(context.Background(), "home"); err == nil {
		t.Fatal("context removal succeeded despite database failure")
	}
	for _, path := range []string{home.privatePath, home.publicPath, stdinSpool, receiverPartial} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("failed context removal did not restore %q: %v", path, err)
		}
	}
	if _, err := databaseStore.DB().Exec(`drop trigger fail_context_remove`); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Remove(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Get(context.Background(), "home"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("removed context lookup error = %v", err)
	}
	if _, err := restarted.Get(context.Background(), "work"); err != nil {
		t.Fatalf("other context was removed: %v", err)
	}
	if _, err := os.Stat(work.privatePath); err != nil {
		t.Fatalf("other context identity was removed: %v", err)
	}
	for _, path := range []string{home.privatePath, home.publicPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed key %q still exists: %v", path, err)
		}
	}
	for _, path := range []string{stdinSpool, receiverPartial} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("private transfer artifact %q remains: %v", path, err)
		}
	}
	for _, path := range []string{offeredFile, inboxFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("user file %q was removed: %v", path, err)
		}
	}
	for table := range map[string]bool{"context_aliases": true, "context_stun_servers": true, "transfer_resumes": true} {
		var count int
		if err := databaseStore.DB().QueryRow(`select count(*) from ` + table + ` where context_name = 'home'`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows = %d, %v", table, count, err)
		}
	}
	if _, err := restarted.Default(context.Background()); err == nil {
		t.Fatal("removed default context remains selected")
	}
}

func TestRuntimeTransferCancellationHasStableInventoryID(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	now := time.Now().Unix()
	if _, err := databaseStore.DB().Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values ('home', 'http://server', 'server', 'device', 'private', 'public', 'device', 'connected', 1, 'offered', 'inbox', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	operationContext, id, release, err := manager.beginRuntimeTransfer(context.Background(), transfer.InventoryItem{Kind: "get", Context: "home", Peer: "peer", Name: "artifact", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if !strings.HasPrefix(id, "get-") {
		t.Fatalf("runtime transfer ID = %q", id)
	}
	manager.updateRuntimeTransfer(id, "transferring", 10, 100)
	manager.mu.Lock()
	progressed := manager.transferOps[id].item
	manager.mu.Unlock()
	if progressed.Bytes != 10 || progressed.Total != 100 || progressed.State != "active" {
		t.Fatalf("runtime progress = %+v", progressed)
	}
	manager.updateRuntimeTransfer(id, "transferring", 10, 100)
	manager.mu.Lock()
	stable := manager.transferOps[id].item
	manager.mu.Unlock()
	if stable.UpdatedAt != progressed.UpdatedAt {
		t.Fatalf("unchanged progress moved timestamp: %s -> %s", progressed.UpdatedAt, stable.UpdatedAt)
	}
	if err := manager.CancelTransfer(context.Background(), "home", id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-operationContext.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime cancellation did not reach operation context")
	}
}

func TestRetryPeerRequiresPersistedLabelAndDevice(t *testing.T) {
	retry := transfer.RetryMetadata{PeerLabel: "build-vm", PeerDeviceID: "device-a"}
	if err := retryPeerError(retry, membership.Member{Label: "BUILD-VM", DeviceID: "device-a"}); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []membership.Member{{Label: "other", DeviceID: "device-a"}, {Label: "build-vm", DeviceID: "device-b"}} {
		if err := retryPeerError(retry, peer); !errors.Is(err, transfer.ErrTransferPeerMismatch) {
			t.Fatalf("peer %+v error = %v", peer, err)
		}
	}
}

func TestContextConfigurationUpdateIsAtomicAndPreservesIdentity(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	initialOffered := filepath.Join(t.TempDir(), "offered")
	initialInbox := filepath.Join(t.TempDir(), "inbox")
	state, err := manager.Join(context.Background(), JoinRequest{
		Name: "home", ServerURL: server.URL, Label: "laptop", OfferedRoot: initialOffered,
		InboxRoot: initialInbox, STUNURLs: []string{"stun:first.example:3478"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "Zed", "server-z"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "alpha", "server-a"); err != nil {
		t.Fatal(err)
	}
	newOffered := filepath.Join(t.TempDir(), "nested", "..", "offered-new")
	newInbox := filepath.Join(t.TempDir(), "inbox-new")
	for _, root := range []string{newOffered, newInbox} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stun := []string{"stun:second.example:3478", "stun:first.example:3478"}
	configuration, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &newOffered, InboxRoot: &newInbox, STUNURLs: &stun})
	if err != nil {
		t.Fatal(err)
	}
	wantOffered, _ := filepath.EvalSymlinks(newOffered)
	wantInbox, _ := filepath.EvalSymlinks(newInbox)
	if configuration.OfferedRoot != filepath.Clean(wantOffered) || configuration.InboxRoot != filepath.Clean(wantInbox) || !slices.Equal(configuration.STUNURLs, stun) {
		t.Fatalf("configuration = %+v", configuration)
	}
	if !configuration.IsDefault || len(configuration.Aliases) != 2 || configuration.Aliases[0].Name != "alpha" || configuration.Aliases[1].Name != "Zed" {
		t.Fatalf("configuration metadata = %+v", configuration)
	}
	updated, err := manager.Get(context.Background(), "home")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ServerURL != state.ServerURL || updated.ServerID != state.ServerID || updated.DeviceID != state.DeviceID || updated.Label != state.Label || updated.privatePath != state.privatePath || updated.publicPath != state.publicPath || updated.PendingCode != state.PendingCode || updated.State != state.State || updated.Enabled != state.Enabled || updated.Aliases["Zed"] != "server-z" {
		t.Fatalf("non-configuration state changed: before=%+v after=%+v", state, updated)
	}

	badSTUN := []string{"turn:relay.example:3478"}
	badRoot := filepath.Join(t.TempDir(), "must-not-persist")
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &badRoot, STUNURLs: &badSTUN}); err == nil {
		t.Fatal("invalid STUN update succeeded")
	}
	unchanged, err := manager.Get(context.Background(), "home")
	if err != nil || unchanged.OfferedRoot != configuration.OfferedRoot || !slices.Equal(unchanged.STUNURLs, stun) {
		t.Fatalf("invalid update persisted: %+v, %v", unchanged, err)
	}

	duplicate := []string{"stun:duplicate.example:3478", "stun:duplicate.example:3478"}
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{InboxRoot: &initialInbox, STUNURLs: &duplicate}); err == nil {
		t.Fatal("duplicate STUN update succeeded")
	}
	unchanged, _ = manager.Get(context.Background(), "home")
	if unchanged.InboxRoot != configuration.InboxRoot || !slices.Equal(unchanged.STUNURLs, stun) {
		t.Fatalf("transaction rollback failed: %+v", unchanged)
	}
	var contextCount int
	if err := databaseStore.DB().QueryRow(`select count(*) from contexts where name = 'home'`).Scan(&contextCount); err != nil || contextCount != 1 {
		t.Fatalf("context count = %d, %v", contextCount, err)
	}

	clear := []string{}
	configuration, err = manager.Update(context.Background(), "home", UpdateRequest{STUNURLs: &clear})
	if err != nil || configuration.STUNURLs == nil || len(configuration.STUNURLs) != 0 {
		t.Fatalf("clear STUN = %+v, %v", configuration, err)
	}
	restarted := NewManager(manager.paths, databaseStore.DB, nil)
	persisted, err := restarted.Configuration(context.Background(), "home")
	if err != nil || persisted.OfferedRoot != configuration.OfferedRoot || persisted.InboxRoot != configuration.InboxRoot || len(persisted.STUNURLs) != 0 || len(persisted.Aliases) != 2 {
		t.Fatalf("restarted configuration = %+v, %v", persisted, err)
	}
}

func TestContextRootUpdateRejectsActiveOperationsAndSharedRootsWarn(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "home", OfferedRoot: shared, InboxRoot: filepath.Join(t.TempDir(), "home-inbox")}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "work", ServerURL: server.URL, Label: "work", OfferedRoot: filepath.Join(t.TempDir(), "work-offered"), InboxRoot: shared}); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.Symlink(filepath.Dir(shared), parentLink); err == nil {
		equivalent := filepath.Join(parentLink, filepath.Base(shared))
		if _, err := databaseStore.DB().Exec(`update contexts set inbox_root = ? where name = 'work'`, equivalent); err != nil {
			t.Fatal(err)
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	configuration, err := manager.Configuration(context.Background(), "home")
	if err != nil || len(configuration.Warnings) != 1 || !strings.Contains(configuration.Warnings[0], "work") {
		t.Fatalf("shared-root warnings = %+v, %v", configuration.Warnings, err)
	}
	allowPut := true
	putRoot, err := filepath.EvalSymlinks(shared)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err = manager.Update(context.Background(), "home", UpdateRequest{PutRoot: &putRoot, AllowPut: &allowPut})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(configuration.Warnings, func(warning string) bool {
		return strings.Contains(warning, "remote creation or supported replacement")
	}) {
		t.Fatalf("put overlap warnings = %v", configuration.Warnings)
	}
	if _, err := manager.beginContextOperation(context.Background(), "home", operationOffered); err != nil {
		t.Fatal(err)
	}
	changed := filepath.Join(t.TempDir(), "changed")
	if err := os.Mkdir(changed, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &changed}); !errors.Is(err, ErrContextActive) {
		t.Fatalf("active root update error = %v", err)
	}
	manager.endContextOperation("home", operationOffered)
	configuration, err = manager.Configuration(context.Background(), "home")
	wantShared, _ := filepath.EvalSymlinks(shared)
	if err != nil || configuration.OfferedRoot != wantShared {
		t.Fatalf("active update changed root: %+v, %v", configuration, err)
	}
}

func TestIncomingRootAdmissionLoadsCurrentSnapshotAtomically(t *testing.T) {
	for _, operation := range []struct {
		name    string
		session string
	}{
		{name: "incoming send", session: "px-send-session"},
		{name: "incoming offered", session: "px-offered-session"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			manager, _, _ := newTestManager(t)
			server, _ := newEnrollmentServer(t)
			stale, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "local"})
			if err != nil {
				t.Fatal(err)
			}
			updatedOffered, updatedInbox := filepath.Join(t.TempDir(), "offered"), filepath.Join(t.TempDir(), "inbox")
			for _, root := range []string{updatedOffered, updatedInbox} {
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &updatedOffered, InboxRoot: &updatedInbox}); err != nil {
				t.Fatal(err)
			}
			admitted, scope, err := manager.incomingState(context.Background(), stale.Name, operation.session)
			if err != nil {
				t.Fatal(err)
			}
			if scope == 0 {
				t.Fatal("incoming root operation was not admitted")
			}
			wantOffered, _ := filepath.EvalSymlinks(updatedOffered)
			wantInbox, _ := filepath.EvalSymlinks(updatedInbox)
			if admitted.OfferedRoot == stale.OfferedRoot || admitted.InboxRoot == stale.InboxRoot || admitted.OfferedRoot != wantOffered || admitted.InboxRoot != wantInbox {
				t.Fatalf("admitted stale state: stale=%+v admitted=%+v", stale, admitted)
			}
			next := filepath.Join(t.TempDir(), "next")
			if err := os.Mkdir(next, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &next}); !errors.Is(err, ErrContextActive) {
				t.Fatalf("configuration while admitted = %v", err)
			}
			manager.endContextOperation("home", scope)
		})
	}
}

func TestConfiguredRootValidationAndCanonicalization(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	wantDirectory, _ := filepath.EvalSymlinks(directory)
	manager := &Manager{writeProbe: probeRootWrite}
	canonical, err := manager.configuredRoot(directory, false)
	if err != nil || canonical != wantDirectory {
		t.Fatalf("valid root = %q, %v", canonical, err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.configuredRoot(file, false); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("file root error = %v", err)
	}
	if _, err := manager.configuredRoot(filepath.Join(base, "missing"), false); err == nil || !strings.Contains(err.Error(), "inspect root") {
		t.Fatalf("missing root error = %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(directory, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := manager.configuredRoot(link, false); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink root error = %v", err)
	}
	parentLink := filepath.Join(base, "parent-link")
	parent := filepath.Join(base, "parent")
	nested := filepath.Join(parent, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	equivalent := filepath.Join(parentLink, "nested")
	wantNested, _ := filepath.EvalSymlinks(nested)
	canonical, err = manager.configuredRoot(equivalent, false)
	if err != nil || canonical != wantNested || !sameRoot(nested, equivalent) {
		t.Fatalf("equivalent root = %q, same=%v, %v", canonical, sameRoot(nested, equivalent), err)
	}
	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.configuredRoot(writable, true); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(writable)
	if err != nil || len(entries) != 0 {
		t.Fatalf("write probe artifacts = %v, %v", entries, err)
	}
	t.Run("unwritable inbox", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("portable mode-bit write denial is unavailable on Windows")
		}
		unwritable := filepath.Join(base, "unwritable")
		if err := os.Mkdir(unwritable, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unwritable, 0o700) })
		if _, err := manager.configuredRoot(unwritable, true); err == nil {
			t.Skip("current user can write despite directory mode")
		}
		entries, err := os.ReadDir(unwritable)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed write probe artifacts = %v, %v", entries, err)
		}
	})
}

func TestInboxCapabilityFailureLeavesConfigurationUnchanged(t *testing.T) {
	manager, _, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	state, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "local"})
	if err != nil {
		t.Fatal(err)
	}
	newInbox := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(newInbox, 0o700); err != nil {
		t.Fatal(err)
	}
	manager.writeProbe = func(string) error { return errors.New("injected write denial") }
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{InboxRoot: &newInbox}); !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "injected write denial") {
		t.Fatalf("inbox capability error = %v", err)
	}
	unchanged, err := manager.Get(context.Background(), "home")
	if err != nil || unchanged.InboxRoot != state.InboxRoot {
		t.Fatalf("failed capability check changed context = %+v, %v", unchanged, err)
	}
	entries, err := os.ReadDir(newInbox)
	if err != nil || len(entries) != 0 {
		t.Fatalf("inbox validation artifacts = %v, %v", entries, err)
	}
}

func TestContextAliasesUseExactIdentityAndPersist(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "local"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "Build", "vm-one"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetAlias(context.Background(), "home", "build", "vm-two"); err != nil {
		t.Fatal(err)
	}
	values, err := manager.ListAliases(context.Background(), "home")
	if err != nil || len(values) != 2 || values[0] != (Alias{Name: "Build", Target: "vm-one"}) || values[1] != (Alias{Name: "build", Target: "vm-two"}) {
		t.Fatalf("aliases = %+v, %v", values, err)
	}
	for _, value := range values {
		shown, err := manager.GetAlias(context.Background(), "home", value.Name)
		if err != nil || shown != value {
			t.Fatalf("shown alias = %+v, %v", shown, err)
		}
	}
	if _, err := manager.GetAlias(context.Background(), "home", "BUILD"); !errors.Is(err, ErrAliasNotFound) {
		t.Fatalf("case-mismatched alias error = %v", err)
	}
	restarted := NewManager(manager.paths, databaseStore.DB, nil)
	removed, err := restarted.RemoveAlias(context.Background(), "home", "build")
	if err != nil || removed != values[1] {
		t.Fatalf("removed alias = %+v, %v", removed, err)
	}
	remaining, err := restarted.GetAlias(context.Background(), "home", "Build")
	if err != nil || remaining != values[0] {
		t.Fatalf("remaining alias = %+v, %v", remaining, err)
	}
	if _, err := restarted.RemoveAlias(context.Background(), "home", "Build"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RemoveAlias(context.Background(), "home", "Build"); !errors.Is(err, ErrAliasNotFound) || err.Error() != "context alias not found" {
		t.Fatalf("absent alias error = %v", err)
	}
}

func TestSTUNUpdateRestartsOnlyAffectedEnabledContext(t *testing.T) {
	manager, _, _ := newTestManager(t)
	manager.runtime, manager.cancel = context.WithCancel(context.Background())
	manager.activated = true
	t.Cleanup(func() {
		manager.cancel()
		manager.wg.Wait()
	})
	server, _ := newEnrollmentServer(t)
	for _, name := range []string{"home", "work"} {
		if _, err := manager.Join(context.Background(), JoinRequest{Name: name, ServerURL: server.URL, Label: name}); err != nil {
			t.Fatal(err)
		}
	}
	manager.mu.Lock()
	homeWorker, workWorker := manager.workers["home"], manager.workers["work"]
	manager.mu.Unlock()
	stun := []string{"stun:new.example:3478"}
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{STUNURLs: &stun}); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	newHomeWorker, newWorkWorker := manager.workers["home"], manager.workers["work"]
	manager.mu.Unlock()
	if newHomeWorker == nil || newHomeWorker == homeWorker {
		t.Fatal("affected context worker was not restarted")
	}
	if newWorkWorker != workWorker {
		t.Fatal("unaffected context worker was restarted")
	}
}

func TestEnableTerminalContextReturnsTypedStateError(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	server, _ := newEnrollmentServer(t)
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: server.URL, Label: "local"}); err != nil {
		t.Fatal(err)
	}
	for _, terminalState := range []string{"revoked", "expired"} {
		if _, err := databaseStore.DB().Exec(`update contexts set state = ?, enabled = 0 where name = 'home'`, terminalState); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Enable(context.Background(), "home"); !errors.Is(err, ErrInvalidContextState) || !strings.Contains(err.Error(), terminalState) {
			t.Fatalf("enable %s error = %v", terminalState, err)
		}
	}
}

func TestStatusSnapshotIsBoundedAndReadOnly(t *testing.T) {
	manager, databaseStore, _ := newTestManager(t)
	snapshot, err := manager.StatusSnapshot(context.Background(), "")
	if err != nil || snapshot.Context != nil || snapshot.Transfers != nil {
		t.Fatalf("empty snapshot = %+v, %v", snapshot, err)
	}
	now := time.Now().UTC().Unix()
	if _, err := databaseStore.DB().Exec(`insert into contexts (name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values ('home','https://px.example','server','local','private','public','local','connected',1,'offered','inbox',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`update context_settings set default_context='home' where singleton=1`); err != nil {
		t.Fatal(err)
	}
	retryID := strings.Repeat("d", 64)
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('send',?,'home','peer-id','private-peer','private-name',1,'sha',1,1,'secret-token',0,'transferring',?,?,?)`, retryID, now, now, now+3600); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.controls["home"] = &controlConnection{ctx: context.Background(), peers: map[string]membership.Member{
		"one": {DeviceID: "one", Label: "private-one"},
		"two": {DeviceID: "two", Label: "private-two"},
	}}
	manager.transferOps["get-active"] = &runtimeTransfer{item: transfer.InventoryItem{ID: "get-active", Context: "home", Active: true}}
	manager.mu.Unlock()
	snapshot, err = manager.StatusSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Context == nil || snapshot.Context.Name != "home" || snapshot.Context.OnlinePeers == nil || *snapshot.Context.OnlinePeers != 2 {
		t.Fatalf("context snapshot = %+v", snapshot.Context)
	}
	if snapshot.Transfers == nil || snapshot.Transfers.Active != 1 || snapshot.Transfers.Retryable != 1 {
		t.Fatalf("transfer snapshot = %+v", snapshot.Transfers)
	}
	if _, err := databaseStore.DB().Exec(`insert into context_aliases(context_name,alias,target_label) values ('home','builder','private-one'),('home','offline','missing'),('home','private-one','private-two')`); err != nil {
		t.Fatal(err)
	}
	peers, err := manager.CompletionPeers(context.Background(), "home", "b", true, 64)
	if err != nil || !slices.Equal(peers, []string{"builder"}) {
		t.Fatalf("peer completion = %v, %v", peers, err)
	}
	aliases, err := manager.CompletionAliases(context.Background(), "home", "", 1)
	if err != nil || len(aliases) != 1 {
		t.Fatalf("bounded alias completion = %v, %v", aliases, err)
	}
	target, err := manager.CompletionPeerTarget(context.Background(), "home", "private-one")
	if err != nil || target != "private-two" {
		t.Fatalf("alias-first peer target = %q, %v", target, err)
	}
}

func TestLegacyFilesystemRootFailsClosedAndCanBeRepaired(t *testing.T) {
	manager, store, _ := newTestManager(t)
	inbox := t.TempDir()
	insertTestContext(t, store.DB(), "home", string(os.PathSeparator), inbox)

	state, err := manager.Get(context.Background(), "home")
	if err != nil || state.OfferedRootScope != OfferedRootScopeNarrow || state.OfferedRootRevision != 1 || state.FilesystemRootAcknowledged || state.OfferedRootAuthorityValid {
		t.Fatalf("legacy state = %+v, %v", state, err)
	}
	if _, err := manager.beginRootOperation(context.Background(), "home"); err != nil {
		t.Fatalf("unrelated root operation error = %v", err)
	}
	manager.endTransfer("home")
	if _, err := manager.Inbox(context.Background(), "home", "sender"); err != nil {
		t.Fatalf("local inbox inspection error = %v", err)
	}
	if _, scope, err := manager.incomingState(context.Background(), "home", "px-send-test"); !errors.Is(err, ErrInvalidContextState) || scope != 0 || manager.active["home"].total != 0 {
		t.Fatalf("incoming authority admission = scope %v, active %+v, error %v", scope, manager.active["home"], err)
	}
	configuration, err := manager.Configuration(context.Background(), "home")
	if err != nil || len(configuration.Warnings) == 0 {
		t.Fatalf("legacy configuration = %+v, %v", configuration, err)
	}
	if _, err := manager.Join(context.Background(), JoinRequest{Name: "home", ServerURL: "https://px.example", Label: "device", OfferedRoot: string(os.PathSeparator), InboxRoot: inbox, AllowFilesystemRoot: true}); err == nil || !strings.Contains(err.Error(), "repair it with context configure") {
		t.Fatalf("legacy join repair error = %v", err)
	}

	root := string(os.PathSeparator)
	configuration, err = manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &root, AllowFilesystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.OfferedRootScope != OfferedRootScopeFilesystemRoot || configuration.OfferedRootRevision != 2 || !configuration.FilesystemRootAcknowledged {
		t.Fatalf("repaired configuration = %+v", configuration)
	}
	repaired, err := manager.Get(context.Background(), "home")
	if err != nil || !repaired.OfferedRootAuthorityValid {
		t.Fatalf("repaired state authority = %+v, %v", repaired, err)
	}
	if _, err := manager.beginRootOperation(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	manager.endTransfer("home")
}

func TestInboxPathAndMovePublishExclusively(t *testing.T) {
	manager, store, _ := newTestManager(t)
	offered, inboxRoot, destinationRoot := t.TempDir(), t.TempDir(), t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inboxRoot)
	senderDir := filepath.Join(inboxRoot, "home", "alice")
	if err := os.MkdirAll(senderDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(senderDir, "report.txt")
	if err := os.WriteFile(sourcePath, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	pathResult, err := manager.InboxPath(context.Background(), "home", "alice/report.txt")
	if err != nil || pathResult.Path != sourcePath {
		t.Fatalf("path result = %+v, %v", pathResult, err)
	}
	destination := filepath.Join(destinationRoot, "moved.txt")
	moveResult, err := manager.MoveInbox(context.Background(), "home", "alice/report.txt", destination)
	if err != nil || moveResult.State != inbox.MoveStateMoved || !moveResult.DestinationCommitted || !moveResult.SourceRemovalConfirmed {
		t.Fatalf("move result = %+v, %v", moveResult, err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "report" {
		t.Fatalf("destination = %q, %v", content, err)
	}
	if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists: %v", err)
	}

	if err := os.WriteFile(sourcePath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	collision, err := manager.MoveInbox(context.Background(), "home", "alice/report.txt", destination)
	if !errors.Is(err, getcleanup.ErrDestinationExists) || collision != (inbox.MoveResult{}) {
		t.Fatalf("collision = %+v, %v", collision, err)
	}
	content, err = os.ReadFile(sourcePath)
	if err != nil || string(content) != "second" {
		t.Fatalf("collision source = %q, %v", content, err)
	}
	if _, err := manager.MoveInbox(context.Background(), "home", "alice/report.txt", "relative.txt"); !errors.Is(err, inbox.ErrInvalidDestination) {
		t.Fatalf("relative destination error = %v", err)
	}
	root := filepath.VolumeName(destinationRoot) + string(filepath.Separator)
	if _, err := manager.MoveInbox(context.Background(), "home", "alice/report.txt", root); !errors.Is(err, inbox.ErrInvalidDestination) {
		t.Fatalf("root destination error = %v", err)
	}
}

func TestConcurrentInboxMovesPublishOnlyOnce(t *testing.T) {
	manager, store, _ := newTestManager(t)
	offered, inboxRoot, destinationRoot := t.TempDir(), t.TempDir(), t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inboxRoot)
	senderDir := filepath.Join(inboxRoot, "home", "alice")
	if err := os.MkdirAll(senderDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(senderDir, "report.txt"), bytes.Repeat([]byte("x"), 8<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result inbox.MoveResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	for _, destination := range []string{filepath.Join(destinationRoot, "first.txt"), filepath.Join(destinationRoot, "second.txt")} {
		go func() {
			<-start
			result, err := manager.MoveInbox(context.Background(), "home", "alice/report.txt", destination)
			outcomes <- outcome{result: result, err: err}
		}()
	}
	close(start)
	moved, unavailable := 0, 0
	for range 2 {
		result := <-outcomes
		switch {
		case result.err == nil && result.result.State == inbox.MoveStateMoved:
			moved++
		case errors.Is(result.err, inbox.ErrUnavailable):
			unavailable++
		default:
			t.Fatalf("concurrent move outcome = %+v, %v", result.result, result.err)
		}
	}
	if moved != 1 || unavailable != 1 {
		t.Fatalf("concurrent moves: moved=%d unavailable=%d", moved, unavailable)
	}
}

func TestInboxMoveLockIsKeyedAndCancelable(t *testing.T) {
	manager := &Manager{}
	key := inboxMoveKey("home", "alice/report.txt")
	if key != inboxMoveKey("HOME", "ALICE/REPORT.TXT") {
		t.Fatalf("case aliases have different keys")
	}
	if inboxMoveKey("home", "alice/Σ.txt") != inboxMoveKey("home", "alice/ς.txt") {
		t.Fatalf("Unicode case aliases have different keys")
	}
	unlock, err := manager.lockInboxMove(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	otherUnlock, err := manager.lockInboxMove(context.Background(), "home\x00alice/other.txt")
	if err != nil {
		t.Fatal(err)
	}
	otherUnlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.lockInboxMove(ctx, inboxMoveKey("HOME", "ALICE/REPORT.TXT")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock error = %v", err)
	}
	unlock()
	if len(manager.inboxMoves) != 0 {
		t.Fatalf("retained inbox move locks = %d", len(manager.inboxMoves))
	}
}

func TestConfigureRepairsMigratedFilesystemRootAndRebindsUnresolvedPublicReceives(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows filesystem-root validation remains issue #138")
	}
	manager, store, _ := newTestManager(t)
	insertTestContext(t, store.DB(), "home", "/", t.TempDir())
	now := time.Now().Unix()
	for index, state := range []string{"committing", "committed_pending_confirmation"} {
		id := fmt.Sprintf("%064x", index+1)
		if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility, offered_root_revision) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 1, ?, ?, ?, ?, 3, 'public', 1)`, id, strings.Repeat("a", 64), state, now, now, now+3600); err != nil {
			t.Fatal(err)
		}
	}
	root := "/"
	configuration, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &root, AllowFilesystemRoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.OfferedRootRevision != 2 || configuration.OfferedRootScope != OfferedRootScopeFilesystemRoot || !configuration.FilesystemRootAcknowledged || !configuration.OfferedRootAuthorityValid {
		t.Fatalf("repaired configuration = %+v", configuration)
	}
	var rebound int
	if err := store.DB().QueryRow(`select count(*) from transfer_resumes where context_name = 'home' and state != 'committed' and offered_root_revision = 2`).Scan(&rebound); err != nil || rebound != 2 {
		t.Fatalf("rebound public receives = %d, %v", rebound, err)
	}
}

func TestJoinRequiresFilesystemRootAcknowledgementAndRejectsItForNarrowRoot(t *testing.T) {
	manager, _, _ := newTestManager(t)
	request := JoinRequest{Name: "home", ServerURL: "https://px.example", Label: "device", OfferedRoot: string(os.PathSeparator), InboxRoot: t.TempDir()}
	if _, err := manager.Join(context.Background(), request); err == nil || !strings.Contains(err.Error(), "--allow-filesystem-root is required") {
		t.Fatalf("filesystem-root join error = %v", err)
	}
	request.OfferedRoot = t.TempDir()
	request.AllowFilesystemRoot = true
	if _, err := manager.Join(context.Background(), request); err == nil || !strings.Contains(err.Error(), "only valid for a filesystem root") {
		t.Fatalf("narrow-root join error = %v", err)
	}
}

func TestOfferedRootAuthorityChangeIsBlockedByActiveAndDurablePublicSendState(t *testing.T) {
	manager, store, _ := newTestManager(t)
	offered, inbox := t.TempDir(), t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inbox)
	if _, err := manager.beginContextOperation(context.Background(), "home", operationOffered); err != nil {
		t.Fatal(err)
	}
	next := t.TempDir()
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &next}); !errors.Is(err, ErrContextActive) {
		t.Fatalf("active update error = %v", err)
	}
	manager.endContextOperation("home", operationOffered)

	now := time.Now().Unix()
	_, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 0, 'transferring', ?, ?, ?, 3, 'public')`, strings.Repeat("a", 64), strings.Repeat("b", 64), now-3600, now-3600, now-1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.transfers.GC(context.Background(), time.Unix(now, 0)); err != nil {
		t.Fatal(err)
	}
	var prepublication int
	if err := store.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id = ?`, strings.Repeat("a", 64)).Scan(&prepublication); err != nil || prepublication != 0 {
		t.Fatalf("expired public prepublication rows = %d, %v", prepublication, err)
	}
	if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 1, 'committed_pending_confirmation', ?, ?, ?, 3, 'public')`, strings.Repeat("c", 64), strings.Repeat("d", 64), now-3600, now-3600, now-1); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &next}); !errors.Is(err, ErrContextAuthorityBlocked) {
		t.Fatalf("durable public-send update error = %v", err)
	}
	if _, err := store.DB().Exec(`update transfer_resumes set state = 'committed' where context_name = 'home'`); err != nil {
		t.Fatal(err)
	}
	if configuration, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &next}); err != nil || configuration.OfferedRootRevision != 2 {
		t.Fatalf("settled public-send update = %+v, %v", configuration, err)
	}
}

func TestRootChangesOnlyBlockOperationsThatDependOnTheChangedLocalRoot(t *testing.T) {
	manager, store, _ := newTestManager(t)
	offered, inbox := t.TempDir(), t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inbox)

	if _, err := manager.beginRootOperation(context.Background(), "home"); err != nil {
		t.Fatal(err)
	}
	nextOffered := t.TempDir()
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &nextOffered}); err != nil {
		t.Fatalf("outgoing operation blocked offered-root update: %v", err)
	}
	manager.endTransfer("home")

	if _, err := manager.beginContextOperation(context.Background(), "home", operationInbox); err != nil {
		t.Fatal(err)
	}
	thirdOffered := t.TempDir()
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &thirdOffered}); err != nil {
		t.Fatalf("inbox operation blocked offered-root update: %v", err)
	}
	nextInbox := t.TempDir()
	if _, err := manager.Update(context.Background(), "home", UpdateRequest{InboxRoot: &nextInbox}); !errors.Is(err, ErrContextActive) {
		t.Fatalf("inbox-root update during inbox operation = %v", err)
	}
	manager.endContextOperation("home", operationInbox)

	for _, session := range []string{"px-offered-test", "px-send-test"} {
		_, scope, err := manager.incomingState(context.Background(), "home", session)
		if err != nil || scope&operationOffered == 0 {
			t.Fatalf("incoming %s scope = %v, %v", session, scope, err)
		}
		candidate := t.TempDir()
		if _, err := manager.Update(context.Background(), "home", UpdateRequest{OfferedRoot: &candidate}); !errors.Is(err, ErrContextActive) {
			t.Fatalf("offered-root update during %s = %v", session, err)
		}
		if strings.HasPrefix(session, "px-send-") {
			candidateInbox := t.TempDir()
			if _, err := manager.Update(context.Background(), "home", UpdateRequest{InboxRoot: &candidateInbox}); !errors.Is(err, ErrContextActive) {
				t.Fatalf("inbox-root update during incoming send = %v", err)
			}
		}
		manager.endContextOperation("home", scope)
	}
}

func TestRemoveBlocksBeforeDestructiveWorkForUnresolvedPublicReceive(t *testing.T) {
	manager, store, paths := newTestManager(t)
	offered, inbox := t.TempDir(), t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inbox)
	privatePath := filepath.Join(paths.AgentKeys, "home.key")
	publicPath := filepath.Join(paths.AgentKeys, "home.pub")
	for _, path := range []string{privatePath, publicPath} {
		if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB().Exec(`update contexts set private_key_path = ?, public_key_path = ? where name = 'home'`, privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 1, 'committed_pending_confirmation', ?, ?, ?, 3, 'public')`, strings.Repeat("c", 64), strings.Repeat("d", 64), now, now, now-1); err != nil {
		t.Fatal(err)
	}
	if err := manager.transfers.GC(context.Background(), time.Unix(now, 0)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove(context.Background(), "home"); !errors.Is(err, ErrContextAuthorityBlocked) {
		t.Fatalf("remove error = %v", err)
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("blocked removal changed key %q: %v", path, err)
		}
	}
	if _, err := manager.Get(context.Background(), "home"); err != nil {
		t.Fatalf("blocked removal deleted context: %v", err)
	}
	var rows int
	if err := store.DB().QueryRow(`select count(*) from transfer_resumes where context_name = 'home'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("blocked removal transfer rows = %d, %v", rows, err)
	}
}

func TestDurablePublicReceiveBlockerCoversEveryUnresolvedStateAndRevision(t *testing.T) {
	_, store, _ := newTestManager(t)
	insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
	now := time.Now().Unix()
	for index, state := range []string{"transferring", "committing", "committed_pending_confirmation", "corrupt", "committed"} {
		id := fmt.Sprintf("%064x", index+1)
		var revision any
		if state == "committing" {
			revision = 999
		}
		if _, err := store.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility, offered_root_revision) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, 32768, 8, 'token', 0, ?, ?, ?, ?, 3, 'public', ?)`, id, strings.Repeat("e", 64), state, now, now, now+3600, revision); err != nil {
			t.Fatal(err)
		}
		err := blockDurablePublicSendAuthorityChange(context.Background(), store.DB(), "home")
		if state == "committed" {
			if err != nil {
				t.Fatalf("committed row blocked authority: %v", err)
			}
		} else if !errors.Is(err, ErrContextAuthorityBlocked) {
			t.Fatalf("state %s blocker error = %v", state, err)
		}
		if _, err := store.DB().Exec(`delete from transfer_resumes where transfer_id = ?`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := blockDurablePublicSendAuthorityChange(context.Background(), store.DB(), "home"); err != nil {
		t.Fatalf("settled public receive blocked authority: %v", err)
	}
}

func newTestManager(t *testing.T) (*Manager, *sqlite.Store, apphome.Paths) {
	t.Helper()
	paths, err := apphome.Resolve(filepath.Join(t.TempDir(), "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindAgent, paths.AgentDatabase)
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.New(cfg)
	if err := store.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Stop(context.Background()) })
	return NewManager(paths, store.DB, nil), store, paths
}

func TestRecentListAndClearLeaseContextAgainstRemoval(t *testing.T) {
	for _, operation := range []string{"list", "clear"} {
		t.Run(operation, func(t *testing.T) {
			manager, store, _ := newTestManager(t)
			insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
			if _, err := store.DB().Exec(`update contexts set enabled=0 where name='home'`); err != nil {
				t.Fatal(err)
			}
			leased := make(chan struct{})
			release := make(chan struct{})
			manager.recentLease = func() {
				close(leased)
				<-release
			}
			done := make(chan error, 1)
			go func() {
				if operation == "list" {
					_, err := manager.Recent(context.Background(), "home", 1)
					done <- err
					return
				}
				_, err := manager.ClearRecent(context.Background(), "home")
				done <- err
			}()
			<-leased
			if err := manager.Remove(context.Background(), "home"); !errors.Is(err, ErrContextActive) {
				t.Fatalf("remove during recent %s = %v", operation, err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("recent %s = %v", operation, err)
			}
			if _, err := manager.Get(context.Background(), "home"); err != nil {
				t.Fatalf("context after recent %s = %v", operation, err)
			}
		})
	}
}

func TestRecentListAndClearWorkForDisabledContext(t *testing.T) {
	manager, store, _ := newTestManager(t)
	insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
	if _, err := store.DB().Exec(`update contexts set enabled=0,device_id=?,label='device' where name='home'`, strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	observation := recent.Observation{Context: "home", Direction: "send", TransferID: strings.Repeat("a", 64), Kind: "sender_observed_commit", PeerDeviceID: strings.Repeat("B", 43), PeerLabel: "peer", Destination: "file", Visibility: "private", Bytes: 1, ObservedAt: time.Now().UTC()}
	if err := manager.recent.Insert(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Recent(context.Background(), "home", 1)
	if err != nil || len(snapshot.Observations) != 1 || snapshot.Reporter.Context != "home" {
		t.Fatalf("disabled recent = %+v, %v", snapshot, err)
	}
	cleared, err := manager.ClearRecent(context.Background(), "home")
	if err != nil || cleared.Cleared != 1 || cleared.Reporter.Context != "home" {
		t.Fatalf("disabled clear = %+v, %v", cleared, err)
	}
}

func TestPresenceLeaveAfterRecentQueryPreventsSnapshotSend(t *testing.T) {
	manager, store, _ := newTestManager(t)
	insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
	peer := membership.Member{DeviceID: strings.Repeat("B", 43), Label: "peer"}
	if err := manager.recent.Insert(context.Background(), recent.Observation{Context: "home", Direction: "receive", TransferID: strings.Repeat("a", 64), Kind: "receiver_published", PeerDeviceID: peer.DeviceID, PeerLabel: peer.Label, Destination: "file", Visibility: "private", Bytes: 1, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	control := &controlConnection{manager: manager, context: State{Name: "home"}, ctx: controlContext, peers: map[string]membership.Member{"peer": peer}, sessions: make(map[string]*contextSignaler)}
	signaler := control.newSignalerLocked(recent.SessionPrefix+strings.Repeat("1", 32), peer.DeviceID)
	queried := make(chan struct{})
	release := make(chan struct{})
	manager.recentQuery = func() {
		close(queried)
		<-release
	}
	channel := &cancelAwareRecentChannel{ctx: signaler.ctx, receive: recent.Message{Text: true, Data: []byte(`{"version":1,"limit":1}`)}}
	done := make(chan error, 1)
	go func() {
		done <- recent.Serve(signaler.ctx, channel, recent.Reporter{DeviceID: strings.Repeat("A", 43), Label: "device"}, peer.DeviceID, func(ctx context.Context, peerID string, limit int) ([]recent.Observation, error) {
			return manager.recentForPeer(ctx, control, "home", peer, peerID, limit)
		})
	}()
	<-queried
	control.mu.Lock()
	registered := control.sessions[signaler.session] == signaler
	control.mu.Unlock()
	if !registered {
		t.Fatal("established recent session was unregistered before serve completed")
	}
	control.handle(controlMessage{Type: "presence.left", DeviceID: peer.DeviceID})
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) || channel.sent.Load() {
		t.Fatalf("serve after leave = %v, sent=%t", err, channel.sent.Load())
	}
}

func TestStalledRecentRequestsReleaseAllSessionCapacity(t *testing.T) {
	manager := &Manager{recentDeadline: 5 * time.Millisecond}
	controlContext, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	peer := membership.Member{DeviceID: strings.Repeat("B", 43), Label: "peer"}
	control := &controlConnection{manager: manager, context: State{Name: "home"}, ctx: controlContext, peers: map[string]membership.Member{"peer": peer}, sessions: make(map[string]*contextSignaler)}
	signalers := make([]*contextSignaler, 0, 16)
	for index := range 16 {
		signaler, err := control.openSignaler(fmt.Sprintf("%s%032x", recent.SessionPrefix, index), peer.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		signalers = append(signalers, signaler)
	}
	if _, err := control.openSignaler(recent.SessionPrefix+strings.Repeat("f", 32), peer.DeviceID); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("seventeenth session = %v", err)
	}
	errs := make(chan error, len(signalers))
	for _, signaler := range signalers {
		go func() {
			errs <- manager.serveRecentChannel(signaler.ctx, signaler, stalledRecentChannel{}, State{Name: "home", DeviceID: strings.Repeat("A", 43), Label: "device"}, peer)
		}()
	}
	for range signalers {
		if err := <-errs; !errors.Is(err, recent.ErrProtocolTimeout) || err.Error() != "recent request timed out" {
			t.Fatalf("stalled recent session = %v", err)
		}
	}
	if len(control.sessions) != 0 {
		t.Fatalf("expired sessions retained = %d", len(control.sessions))
	}
	available, err := control.openSignaler(recent.SessionPrefix+strings.Repeat("e", 32), peer.DeviceID)
	if err != nil {
		t.Fatalf("capacity after expiry = %v", err)
	}
	_ = available.Close()
}

type stalledRecentChannel struct{}

func (stalledRecentChannel) Send(context.Context, recent.Message) error {
	return errors.New("unexpected recent response")
}

func (stalledRecentChannel) Receive(ctx context.Context) (recent.Message, error) {
	<-ctx.Done()
	return recent.Message{}, ctx.Err()
}

type cancelAwareRecentChannel struct {
	ctx     context.Context
	receive recent.Message
	sent    atomic.Bool
}

func (c *cancelAwareRecentChannel) Send(ctx context.Context, _ recent.Message) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
		c.sent.Store(true)
		return nil
	}
}

func (c *cancelAwareRecentChannel) Receive(context.Context) (recent.Message, error) {
	return c.receive, nil
}

func TestPutRootAuthorityIsIndependentAndMonotonic(t *testing.T) {
	manager, store, _ := newTestManager(t)
	offered := t.TempDir()
	inbox := t.TempDir()
	insertTestContext(t, store.DB(), "home", offered, inbox)
	putRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := manager.Update(t.Context(), "home", UpdateRequest{PutRoot: &putRoot})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.AllowPut || configuration.PutRoot == nil || *configuration.PutRoot != putRoot || configuration.PutRootRevision != 2 || !configuration.PutRootAuthorityValid {
		t.Fatalf("configured=%+v", configuration)
	}
	allow := true
	configuration, err = manager.Update(t.Context(), "home", UpdateRequest{AllowPut: &allow})
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.AllowPut || configuration.PutRootRevision != 3 {
		t.Fatalf("enabled=%+v", configuration)
	}
	configuration, err = manager.Update(t.Context(), "home", UpdateRequest{AllowPut: &allow})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.PutRootRevision != 3 {
		t.Fatalf("no-op revision=%d", configuration.PutRootRevision)
	}
	nextOffered := t.TempDir()
	configuration, err = manager.Update(t.Context(), "home", UpdateRequest{OfferedRoot: &nextOffered})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.PutRootRevision != 3 || configuration.OfferedRootRevision != 2 {
		t.Fatalf("independent revisions=%+v", configuration)
	}
	disable := false
	if _, err := manager.Update(t.Context(), "home", UpdateRequest{ClearPutRoot: true, AllowPut: &disable}); err != nil {
		t.Fatal(err)
	}
}

func TestPutBlockersPurgeSafeDatabaseOnlyStates(t *testing.T) {
	for _, blocker := range []struct {
		name string
		fn   func(context.Context, putBlockerQuery, string) error
	}{
		{name: "authority change", fn: blockDurablePutAuthorityChange},
		{name: "context removal", fn: blockDurablePutRemoval},
	} {
		for _, state := range []string{"finalized cleanup", "finalized committed cleanup", "finalized Windows committed cleanup", "resolved accept current", "expired sender"} {
			t.Run(blocker.name+"/"+state, func(t *testing.T) {
				_, store, _ := newTestManager(t)
				insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
				insertPutBlockerState(t, store.DB(), state, true)
				if err := blocker.fn(t.Context(), store.DB(), "home"); err != nil {
					t.Fatal(err)
				}
				var count, metadata int
				if err := store.DB().QueryRow(`select count(*),coalesce(sum(case when stage_name is not null or backup_name is not null or stage_removed!=0 or backup_removed!=0 or parent_synced!=0 then 1 else 0 end),0) from put_transfers where context_name='home'`).Scan(&count, &metadata); err != nil {
					t.Fatal(err)
				}
				wantCount := 0
				if state == "finalized committed cleanup" || state == "finalized Windows committed cleanup" || state == "resolved accept current" {
					wantCount = 1
				}
				if count != wantCount || metadata != 0 {
					t.Fatalf("rows=%d metadata=%d wantRows=%d", count, metadata, wantCount)
				}
			})
		}
	}
}

func TestPutBlockersRetainUnfinishedCleanup(t *testing.T) {
	for _, blocker := range []struct {
		name string
		fn   func(context.Context, putBlockerQuery, string) error
	}{
		{name: "authority change", fn: blockDurablePutAuthorityChange},
		{name: "context removal", fn: blockDurablePutRemoval},
	} {
		t.Run(blocker.name, func(t *testing.T) {
			_, store, _ := newTestManager(t)
			insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
			insertPutBlockerState(t, store.DB(), "finalized cleanup", false)
			if err := blocker.fn(t.Context(), store.DB(), "home"); !errors.Is(err, ErrContextAuthorityBlocked) {
				t.Fatalf("blocker error=%v", err)
			}
		})
	}
}

func TestPutBlockersRetainUnfinishedCommittedCleanup(t *testing.T) {
	for _, blocker := range []struct {
		name string
		fn   func(context.Context, putBlockerQuery, string) error
	}{
		{name: "authority change", fn: blockDurablePutAuthorityChange},
		{name: "context removal", fn: blockDurablePutRemoval},
	} {
		t.Run(blocker.name, func(t *testing.T) {
			_, store, _ := newTestManager(t)
			insertTestContext(t, store.DB(), "home", t.TempDir(), t.TempDir())
			insertPutBlockerState(t, store.DB(), "finalized committed cleanup", false)
			if err := blocker.fn(t.Context(), store.DB(), "home"); !errors.Is(err, ErrContextAuthorityBlocked) {
				t.Fatalf("blocker error=%v", err)
			}
			var metadata int
			if err := store.DB().QueryRow(`select count(*) from put_transfers where context_name='home' and stage_name is not null and parent_synced=0`).Scan(&metadata); err != nil || metadata != 1 {
				t.Fatalf("unfinished metadata=%d err=%v", metadata, err)
			}
		})
	}
}

func insertPutBlockerState(t *testing.T, db *sql.DB, state string, safe bool) {
	t.Helper()
	created := time.Now().Add(-2 * time.Hour).Unix()
	expires := time.Now().Add(-time.Hour).Unix()
	if state == "expired sender" {
		_, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,state,created_at,updated_at,expires_at,next_retry_at) values('send','11111111111111111111111111111111','home','peer','local','peer','result','create',1,?,32768,8,7,'/source','transferring',?,?,?,?)`, strings.Repeat("0", 64), created, created, expires, created)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if state == "finalized committed cleanup" {
		parentSynced := 0
		if safe {
			parentSynced = 1
		}
		_, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,state,acknowledged_bytes,created,durability,stage_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at) values('receive','33333333333333333333333333333333','home','peer','local','peer','result','create',1,?,32768,8,7,?,'unix1:0000000000000001:0000000000000001','.px-33333333333333333333333333333333.put','unix1:0000000000000002:0000000000000002','committed',1,1,'durability_confirmed',1,?,?,?,?,?)`, strings.Repeat("0", 64), t.TempDir(), parentSynced, created, created, expires, created)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if state == "finalized Windows committed cleanup" {
		removed := 0
		if safe {
			removed = 1
		}
		identity := "windows1:0000000000000001:00000000000000000000000000000002"
		_, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,replaced,durability,stage_removed,backup_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at) values('receive','44444444444444444444444444444444','home','peer','local','peer','result','replace',1,?,32768,8,7,?,?,?,?,?,0,0,32,'windowsmeta:test',?,?,1,'committed',1,1,'durability_confirmed',1,?,?, ?,?,?,?)`, strings.Repeat("0", 64), t.TempDir(), identity, ".px-44444444444444444444444444444444.put", "windows1:0000000000000001:00000000000000000000000000000003", identity, ".px-55555555555555555555555555555555.bak", identity, removed, removed, created, created, expires, created)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if state == "resolved accept current" {
		identity := "unix1:0000000000000001:0000000000000002"
		_, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,state,acknowledged_bytes,created_at,updated_at,expires_at,next_retry_at) values('receive','55555555555555555555555555555555','home','peer','local','peer','result','create',1,?,32768,8,7,?,'unix1:0000000000000001:0000000000000001','.px-55555555555555555555555555555555.put',?,'outcome_unknown',1,?,?,?,?)`, strings.Repeat("0", 64), t.TempDir(), identity, created, created, expires, created)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`update put_transfers set state='accept_current_intent',resolution_destination_identity=? where direction='receive' and transfer_id='55555555555555555555555555555555'`, identity); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`update put_transfers set state='resolved_accept_current',parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,resolved_at=?,updated_at=? where direction='receive' and transfer_id='55555555555555555555555555555555'`, created, created); err != nil {
			t.Fatal(err)
		}
		return
	}
	parentSynced := 0
	if safe {
		parentSynced = 1
	}
	_, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,state,stage_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at) values('receive','22222222222222222222222222222222','home','peer','local','peer','result','create',1,?,32768,8,7,?,'unix1:0000000000000001:0000000000000001','.px-22222222222222222222222222222222.put','cleanup_not_attempted',1,?,?,?,?,?)`, strings.Repeat("0", 64), t.TempDir(), parentSynced, created, created, expires, created)
	if err != nil {
		t.Fatal(err)
	}
}

func insertTestContext(t *testing.T, db *sql.DB, name, offeredRoot, inboxRoot string) {
	t.Helper()
	now := time.Now().Unix()
	_, err := db.Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values (?, 'https://px.example', 'server-id', 'device-id', ?, ?, 'device', 'pending', 1, ?, ?, ?, ?)`, name, name+".key", name+".pub", offeredRoot, inboxRoot, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

func newBlockingEnrollmentServer(t *testing.T, blockedRequest int32) (*httptest.Server, <-chan struct{}, chan struct{}) {
	t.Helper()
	started := make(chan struct{})
	release := make(chan struct{})
	var enrollments atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/server":
			_ = json.NewEncoder(w).Encode(rendezvousproto.ServerInfo{Version: rendezvousproto.Version, ServerID: "server", Authority: "server"})
		case "/v1/enrollments":
			if enrollments.Add(1) == blockedRequest {
				close(started)
				<-release
			}
			_ = json.NewEncoder(w).Encode(membership.Enrollment{State: "pending", Code: "AAAA-AAAA", ExpiresAt: time.Now().Add(time.Hour)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, started, release
}

func newEnrollmentServer(t *testing.T) (*httptest.Server, *membership.Store) {
	t.Helper()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "authority.key")
	publicPath := filepath.Join(dir, "server.pub")
	if err := membership.Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	authority, err := membership.Load(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindServer, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Stop(context.Background()) })
	store := membership.NewStore(databaseStore.DB(), authority, membership.DefaultMaxPending)
	handler := serverapi.New(store, authority, serverapi.NewHub(), nil)
	server := httptest.NewServer(handler.Handler())
	t.Cleanup(server.Close)
	return server, store
}
