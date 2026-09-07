package rendezvousapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/rendezvousproto"
)

func TestEnrollmentEndpointIsBoundedAndRateLimited(t *testing.T) {
	handler, store, _, _ := newTestHandler(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := json.Marshal(EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: "device"})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < rateRequests; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(requestBody))
		request.RemoteAddr = "192.0.2.1:1234"
		request.Header.Set("Forwarded", fmt.Sprintf("for=198.51.100.%d", attempt+1))
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", attempt+1))
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d: %s", attempt, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(requestBody))
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(make([]byte, MaxRequestBytes+1)))
	request.RemoteAddr = "192.0.2.2:1234"
	request.Header.Set("Forwarded", "for=192.0.2.1")
	request.Header.Set("X-Forwarded-For", "192.0.2.1")
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized status = %d", response.Code)
	}
	pending, err := store.ListPending(context.Background(), time.Now())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if got := handler.hub.Snapshot().Counters.EnrollmentRejected; got != 2 {
		t.Fatalf("enrollment rejected = %d, want 2", got)
	}
}

func TestServerInfoAdvertisesAuthenticationAndControlProtocols(t *testing.T) {
	handler, _, _, _ := newTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/server", nil)
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	var info ServerInfo
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &info) != nil {
		t.Fatalf("server info = %d: %s", response.Code, response.Body.String())
	}
	if info.Version != Version || info.ControlVersion != Version || info.AuthenticationVersion != AuthenticationVersion || info.InviteVersion != 1 {
		t.Fatalf("server protocol info = %+v", info)
	}
}

func TestInviteRedemptionEndpointIsStrictUniformAndIndependent(t *testing.T) {
	handler, store, _, _ := newTestHandler(t)
	created, err := store.CreateInvite(t.Context(), "Invited", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, _ := json.Marshal(InviteRedemptionRequest{Version: 1, Token: created.Token, DeviceKey: identity.ID(publicKey), Label: "Invited"})
	request := httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", bytes.NewReader(requestBody))
	request.RemoteAddr = "192.0.2.50:1234"
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	var redemption InviteRedemption
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &redemption) != nil || redemption.Version != 1 || redemption.State != "enrolled" {
		t.Fatalf("redemption = %d %s", response.Code, response.Body.String())
	}
	claims, err := membership.VerifyCredential(redemption.Credential, handler.authority.PublicKey(), handler.authority.ServerID())
	if err != nil || claims.DeviceKey != identity.ID(publicKey) || claims.Label != "Invited" || claims.Revision != 1 {
		t.Fatalf("credential = %+v, %v", claims, err)
	}
	wrongLabel, err := store.CreateInvite(t.Context(), "ExactLabel", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.CreateInvite(t.Context(), "Expired", time.Hour, "local", "", time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.CreateInvite(t.Context(), "Revoked", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeInvite(t.Context(), revoked.InviteID, "local", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	encode := func(token, label string) []byte {
		body, _ := json.Marshal(InviteRedemptionRequest{Version: 1, Token: token, DeviceKey: identity.ID(otherKey), Label: label})
		return body
	}

	uniform := ""
	for _, body := range [][]byte{
		requestBody,
		encode(wrongLabel.Token, "OtherLabel"),
		encode(expired.Token, "Expired"),
		encode(revoked.Token, "Revoked"),
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", bytes.NewReader(body))
		request.RemoteAddr = "192.0.2.51:1234"
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"invite_unavailable"`) || strings.Contains(response.Body.String(), created.Invite.InviteID) || strings.Contains(response.Body.String(), created.Token) || strings.Contains(response.Body.String(), wrongLabel.InviteID) {
			t.Fatalf("uniform failure = %d %s", response.Code, response.Body.String())
		}
		if uniform == "" {
			uniform = response.Body.String()
		} else if response.Body.String() != uniform {
			t.Fatalf("failures differ: %q != %q", response.Body.String(), uniform)
		}
	}

	for _, body := range []string{
		`{"version":2,"token":"x","device_key":"x","label":"x"}`,
		`{"version":1,"token":"x","device_key":"x","label":"x","extra":true}`,
		`{"version":1,"token":"x","device_key":"x","label":"x"} {}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", strings.NewReader(body))
		request.RemoteAddr = "192.0.2.52:1234"
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) || strings.Contains(response.Body.String(), body) {
			t.Fatalf("invalid request = %d %s", response.Code, response.Body.String())
		}
	}

	for range rateRequests {
		if !handler.allowEnrollment("198.51.100.9", time.Now()) {
			t.Fatal("pending enrollment limiter filled unexpectedly")
		}
	}
	for attempt := range 11 {
		request := httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", strings.NewReader(`{}`))
		request.RemoteAddr = "198.51.100.9:1234"
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if attempt < 10 && response.Code != http.StatusBadRequest || attempt == 10 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("invite rate attempt %d = %d", attempt, response.Code)
		}
	}
	for range cap(handler.inviteSlots) {
		handler.inviteSlots <- struct{}{}
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", bytes.NewReader(requestBody))
	request.RemoteAddr = "203.0.113.9:1234"
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("invite capacity = %d", response.Code)
	}
	for range cap(handler.inviteSlots) {
		<-handler.inviteSlots
	}
}

func TestInviteRedemptionRequiresCanonicalDeviceKey(t *testing.T) {
	handler, store, _, _ := newTestHandler(t)
	created, err := store.CreateInvite(t.Context(), "Canonical", time.Hour, "local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	canonical := identity.ID(publicKey)
	decoded, _ := base64.RawURLEncoding.DecodeString(canonical)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alias := ""
	for _, candidate := range alphabet {
		value := canonical[:len(canonical)-1] + string(candidate)
		other, decodeErr := base64.RawURLEncoding.DecodeString(value)
		if decodeErr == nil && value != canonical && bytes.Equal(other, decoded) {
			alias = value
			break
		}
	}
	if alias == "" {
		t.Fatal("could not construct noncanonical public-key encoding")
	}
	body, _ := json.Marshal(InviteRedemptionRequest{Version: 1, Token: created.Token, DeviceKey: alias, Label: "Canonical"})
	request := httptest.NewRequest(http.MethodPost, "/v1/invites/redeem", bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.60:1234"
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("noncanonical device key = %d %s", response.Code, response.Body.String())
	}
}

func TestHealthSeparatesLivenessFromInjectedReadinessDegradation(t *testing.T) {
	handler, _, authority, _ := newTestHandler(t)
	state := NewOperationalState()
	state.SetHTTPReady(true)
	state.SetLifecycleReady(true)
	handler.operational = state

	for path, want := range map[string]int{"/livez": http.StatusNoContent, "/readyz": http.StatusNoContent} {
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want || response.Body.Len() != 0 {
			t.Fatalf("%s = %d body %q", path, response.Code, response.Body.String())
		}
	}

	degradedStore := membership.NewStoreProvider(func() *sql.DB { return nil }, authority, membership.DefaultMaxPending)
	degraded := New(degradedStore, authority, NewHub(), nil, WithOperationalState(state))
	response := httptest.NewRecorder()
	degraded.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("degraded readiness = %d body %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	degraded.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("degraded liveness = %d body %q", response.Code, response.Body.String())
	}
}

func TestMembershipStoreFailuresAreRedactedFromPublicAndControlResponses(t *testing.T) {
	_, sourceStore, authority, _ := newTestHandler(t)
	store := membership.NewStoreProvider(func() *sql.DB { return nil }, authority, membership.DefaultMaxPending)
	var logs bytes.Buffer
	handler := New(store, authority, NewHub(), slog.New(slog.NewTextHandler(&logs, nil)))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: "device"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "membership service unavailable") {
		t.Fatalf("public store failure = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "database") {
		t.Fatalf("public store failure disclosed database detail: %s", response.Body.String())
	}

	_, _, err = handler.handleMemberMessage(context.Background(), &client{}, []byte(`{"version":2,"type":"members.list","request_id":"0123456789abcdef0123456789abcdef"}`))
	if err == nil || err.Error() != "member operation failed" {
		t.Fatalf("control store failure = %v", err)
	}

	_, privateKey, credential := enrollMember(t, sourceStore, "store-failure")
	server := httptest.NewServer(handler.Handler())
	t.Cleanup(server.Close)
	conn := connectMember(t, server.URL, privateKey, credential)
	defer conn.CloseNow()
	_, _, err = conn.Read(context.Background())
	if websocket.CloseStatus(err) != websocket.StatusInternalError || !strings.Contains(err.Error(), "authentication unavailable") {
		t.Fatalf("authentication store failure = %v", err)
	}

	cfg, err := database.Config(database.KindServer, filepath.Join(t.TempDir(), "corrupt.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := databaseStore.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	corruptStore := membership.NewStore(databaseStore.DB(), authority, membership.DefaultMaxPending)
	corruptKey, _, _ := enrollMember(t, corruptStore, "corrupt")
	if _, err := databaseStore.DB().Exec(`update members set credential = ? where device_id = ?`, "not-json", identity.ID(corruptKey)); err != nil {
		t.Fatal(err)
	}
	corruptBody, err := json.Marshal(EnrollmentRequest{DeviceKey: identity.ID(corruptKey), Label: "corrupt"})
	if err != nil {
		t.Fatal(err)
	}
	corruptRequest := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(corruptBody))
	corruptRequest.RemoteAddr = "192.0.2.2:1234"
	corruptResponse := httptest.NewRecorder()
	New(corruptStore, authority, NewHub(), handler.logger).Handler().ServeHTTP(corruptResponse, corruptRequest)
	if corruptResponse.Code != http.StatusInternalServerError || !strings.Contains(corruptResponse.Body.String(), "membership service unavailable") || strings.Contains(corruptResponse.Body.String(), "credential") {
		t.Fatalf("stored decoding failure = %d: %s", corruptResponse.Code, corruptResponse.Body.String())
	}
	if !strings.Contains(logs.String(), "membership database is not ready") {
		t.Fatalf("detailed store failure was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "decode stored credential") {
		t.Fatalf("detailed decoding failure was not logged: %s", logs.String())
	}
}

func TestReadinessProbeCachesFloodsAndTracksRecovery(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var calls atomic.Uint64
	var healthy atomic.Bool
	healthy.Store(true)
	probe := &readinessProbe{
		check: func(context.Context, time.Time) error {
			calls.Add(1)
			if !healthy.Load() {
				return errors.New("degraded")
			}
			return nil
		},
		now: func() time.Time { return now }, ttl: readinessCacheTTL, timeout: readinessProbeTimeout,
	}
	if !probe.ready(context.Background()) || calls.Load() != 1 {
		t.Fatalf("initial readiness = %v, calls %d", probe.ready(context.Background()), calls.Load())
	}
	for range 1000 {
		if !probe.ready(context.Background()) {
			t.Fatal("healthy cached readiness failed")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cached probe calls = %d", calls.Load())
	}
	healthy.Store(false)
	now = now.Add(readinessCacheTTL)
	if probe.ready(context.Background()) || calls.Load() != 2 {
		t.Fatalf("degraded readiness remained healthy, calls %d", calls.Load())
	}
	healthy.Store(true)
	if probe.ready(context.Background()) || calls.Load() != 2 {
		t.Fatalf("failure cache was bypassed, calls %d", calls.Load())
	}
	now = now.Add(readinessCacheTTL)
	if !probe.ready(context.Background()) || calls.Load() != 3 {
		t.Fatalf("readiness did not recover, calls %d", calls.Load())
	}
	now = now.Add(readinessCacheTTL)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !probe.ready(canceled) || calls.Load() != 4 {
		t.Fatalf("request cancellation poisoned readiness, calls %d", calls.Load())
	}
}

func TestReadinessProbeAllowsOneInflightCheck(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Uint64
	probe := &readinessProbe{
		check: func(ctx context.Context, _ time.Time) error {
			calls.Add(1)
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		now: time.Now, ttl: readinessCacheTTL, timeout: time.Second,
	}
	first := make(chan bool, 1)
	go func() { first <- probe.ready(context.Background()) }()
	<-started
	var wait sync.WaitGroup
	for range 1000 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if probe.ready(context.Background()) {
				t.Error("request passed while first probe was in flight")
			}
		}()
	}
	wait.Wait()
	if calls.Load() != 1 {
		t.Fatalf("in-flight probe calls = %d", calls.Load())
	}
	close(release)
	if !<-first {
		t.Fatal("first probe did not return healthy")
	}
	if !probe.ready(context.Background()) || calls.Load() != 1 {
		t.Fatalf("fresh result was not cached, calls %d", calls.Load())
	}
}

func TestLifecycleFalseSkipsReadinessProbe(t *testing.T) {
	handler, _, _, _ := newTestHandler(t)
	state := NewOperationalState()
	state.SetHTTPReady(true)
	handler.operational = state
	var calls atomic.Uint64
	handler.readiness.check = func(context.Context, time.Time) error {
		calls.Add(1)
		return nil
	}
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("lifecycle-false readiness = %d, calls %d", response.Code, calls.Load())
	}
}

func TestTrustedProxyEnrollmentAddresses(t *testing.T) {
	prefixes, err := ParseTrustedProxyCIDRs([]string{"127.0.0.0/8", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newTestHandler(t, WithTrustedProxies(prefixes))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := json.Marshal(EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: "proxied"})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < rateRequests+1; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewReader(requestBody))
		request.RemoteAddr = "127.0.0.1:8080"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d, 10.0.0.2", attempt+1))
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("independent proxied client %d status = %d: %s", attempt, response.Code, response.Body.String())
		}
	}
}

func TestTrustedProxyAddressParsingIsFailClosed(t *testing.T) {
	prefixes, err := ParseTrustedProxyCIDRs([]string{"127.0.0.0/8", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{trustedProxies: prefixes}
	tests := []struct {
		name      string
		remote    string
		forwarded string
		xff       string
		want      string
		wantError bool
	}{
		{name: "untrusted peer ignores spoofed malformed header", remote: "192.0.2.10:1234", xff: "not-an-ip", want: "192.0.2.10"},
		{name: "rightmost untrusted xff hop", remote: "127.0.0.1:1234", xff: "198.51.100.8, 10.0.0.2", want: "198.51.100.8"},
		{name: "quoted forwarded IPv6", remote: "127.0.0.1:1234", forwarded: `for="[2001:db8::8]:443";proto=https, for=10.0.0.2`, want: "2001:db8::8"},
		{name: "matching headers", remote: "127.0.0.1:1234", forwarded: "for=198.51.100.8", xff: "198.51.100.8", want: "198.51.100.8"},
		{name: "disagreeing headers", remote: "127.0.0.1:1234", forwarded: "for=198.51.100.8", xff: "203.0.113.9", wantError: true},
		{name: "malformed trusted header", remote: "127.0.0.1:1234", xff: "not-an-ip", wantError: true},
		{name: "empty forwarded element", remote: "127.0.0.1:1234", xff: "198.51.100.8, ", wantError: true},
		{name: "oversized chain", remote: "127.0.0.1:1234", xff: strings.Repeat("198.51.100.8,", maxForwardedHops+1), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/enrollments", nil)
			request.RemoteAddr = test.remote
			if test.forwarded != "" {
				request.Header.Set("Forwarded", test.forwarded)
			}
			if test.xff != "" {
				request.Header.Set("X-Forwarded-For", test.xff)
			}
			got, err := handler.clientIP(request)
			if test.wantError && err == nil {
				t.Fatalf("clientIP = %q, want error", got)
			}
			if !test.wantError && (err != nil || got != test.want) {
				t.Fatalf("clientIP = %q, %v, want %q", got, err, test.want)
			}
		})
	}
	tooMany := make([]string, MaxTrustedProxies+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("10.%d.0.0/16", index)
	}
	if _, err := ParseTrustedProxyCIDRs(tooMany); err == nil {
		t.Fatal("excess trusted proxy CIDRs accepted")
	}
	if _, err := ParseTrustedProxyCIDRs([]string{"127.0.0.1"}); err == nil {
		t.Fatal("trusted proxy address without CIDR accepted")
	}
}

func TestUnauthenticatedResourceLimits(t *testing.T) {
	handler, _, _, _ := newTestHandler(t)
	now := time.Now()
	for index := 0; index < 1024; index++ {
		if !handler.allowEnrollment(fmt.Sprintf("192.0.%d.%d", index/256, index%256), now) {
			t.Fatalf("rate entry %d rejected early", index)
		}
	}
	if handler.allowEnrollment("198.51.100.1", now) {
		t.Fatal("rate map exceeded capacity")
	}
	for range cap(handler.authSlots) {
		handler.authSlots <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/connect", nil)
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("authentication capacity status = %d", response.Code)
	}
	if got := handler.hub.Snapshot().Counters.AuthenticationFailed; got != 1 {
		t.Fatalf("authentication failed = %d, want 1", got)
	}
}

func TestAuthenticationCounterIgnoresAbandonAndCountsMalformedWorkOnce(t *testing.T) {
	handler, _, _, server := newTestHandler(t)
	abandoned, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := abandoned.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	abandoned.CloseNow()
	for range 100 {
		if handler.hub.Snapshot().Counters.AuthenticationFailed != 0 {
			t.Fatal("abandoned WebSocket counted as failed authentication")
		}
		time.Sleep(time.Millisecond)
	}

	malformed, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.CloseNow()
	if _, _, err := malformed.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeWebSocketMessage(t, malformed, map[string]string{"type": "invalid"})
	if _, _, err := malformed.Read(context.Background()); err == nil {
		t.Fatal("malformed authentication remained connected")
	} else if websocket.CloseStatus(err) != websocket.StatusPolicyViolation || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("malformed authentication close = %v", err)
	}
	if got := handler.hub.Snapshot().Counters.AuthenticationFailed; got != 1 {
		t.Fatalf("authentication failed = %d, want 1", got)
	}

	oversized, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer oversized.CloseNow()
	if _, _, err := oversized.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := oversized.Write(context.Background(), websocket.MessageText, make([]byte, MaxControlBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oversized.Read(context.Background()); err == nil {
		t.Fatal("oversized authentication remained connected")
	}
	for range 100 {
		if handler.hub.Snapshot().Counters.AuthenticationFailed == 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("authentication failed = %d, want 2", handler.hub.Snapshot().Counters.AuthenticationFailed)
}

func TestAuthenticatedPresenceSignalingApprovalAndRevocation(t *testing.T) {
	handler, store, authority, server := newTestHandler(t)
	publicA, privateA, credentialA := enrollMember(t, store, "alpha")
	publicB, privateB, credentialB := enrollMember(t, store, "beta")
	connA := connectMember(t, server.URL, privateA, credentialA)
	defer connA.CloseNow()
	authenticatedA := readType(t, connA, "authenticated")
	if len(authenticatedA.Members) != 0 {
		t.Fatalf("initial peers = %+v", authenticatedA.Members)
	}
	connB := connectMember(t, server.URL, privateB, credentialB)
	defer connB.CloseNow()
	authenticatedB := readType(t, connB, "authenticated")
	if len(authenticatedB.Members) != 1 || authenticatedB.Members[0].DeviceID != identity.ID(publicA) {
		t.Fatalf("beta peers = %+v", authenticatedB.Members)
	}
	joined := readType(t, connA, "presence.joined")
	if joined.Member == nil || joined.Member.DeviceID != identity.ID(publicB) {
		t.Fatalf("joined = %+v", joined)
	}

	payload := json.RawMessage(`{"description":"offer"}`)
	writeWire(t, connA, wireMessage{Version: Version, Type: "signal", To: identity.ID(publicB), Payload: payload})
	signal := readType(t, connB, "signal")
	if signal.From != identity.ID(publicA) || string(signal.Payload) != string(payload) {
		t.Fatalf("signal = %+v", signal)
	}

	publicC, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.RequestEnrollment(context.Background(), publicC, "gamma", "192.0.2.3", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeWire(t, connA, wireMessage{Version: Version, Type: "members.list", RequestID: "00000000000000000000000000000001"})
	members := readType(t, connA, "members.list")
	if members.Version != Version || members.RequestID != "00000000000000000000000000000001" || len(members.Members) != 2 || members.Members[0].Label != "alpha" || members.Members[1].Label != "beta" {
		t.Fatalf("members list = %+v", members)
	}

	writeWire(t, connA, wireMessage{Version: Version, Type: "pending.list", RequestID: "00000000000000000000000000000002"})
	pendingList := readType(t, connA, "pending.list")
	encodedPending, err := json.Marshal(pendingList)
	if err != nil {
		t.Fatal(err)
	}
	if pendingList.RequestID != "00000000000000000000000000000002" || len(pendingList.Pending) != 1 || pendingList.Pending[0].Code != pending.Code || bytes.Contains(encodedPending, []byte("192.0.2.3")) || bytes.Contains(encodedPending, []byte("source")) {
		t.Fatalf("pending list = %+v", pendingList.Pending)
	}
	writeWire(t, connA, wireMessage{Version: Version, Type: "pending.approve", RequestID: "00000000000000000000000000000003", Code: strings.ToLower(pending.Code)})
	approved := readType(t, connA, "pending.approved")
	if approved.RequestID != "00000000000000000000000000000003" || approved.Member == nil || approved.Member.Label != "gamma" {
		t.Fatalf("approved = %+v", approved)
	}
	writeWire(t, connA, wireMessage{Version: Version, Type: "pending.approve", RequestID: "00000000000000000000000000000004", Code: pending.Code})
	duplicate := readType(t, connA, "pending.approve.error")
	if duplicate.RequestID != "00000000000000000000000000000004" || duplicate.Error != "pending enrollment not found or expired" {
		t.Fatalf("duplicate approval error = %+v", duplicate)
	}
	writeWire(t, connA, wireMessage{Version: Version, Type: "pending.list", RequestID: "bad"})
	invalidID := readType(t, connA, "pending.list.error")
	if invalidID.RequestID != "" || invalidID.Error != "invalid request ID" {
		t.Fatalf("invalid request ID error = %+v", invalidID)
	}

	active, err := store.ActiveMember(context.Background(), identity.ID(publicB))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), identity.ID(publicB), active.Revision, "local", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler.hub.Revoke(identity.ID(publicB))
	revoked := readType(t, connB, "revoked")
	if revoked.DeviceID != identity.ID(publicB) {
		t.Fatalf("revoked = %+v", revoked)
	}
	if _, err := store.Authenticate(context.Background(), credentialB); err == nil {
		t.Fatal("revoked member reauthenticated")
	}
	if authority.ServerID() == "" {
		t.Fatal("missing authority identity")
	}
}

func TestAuthenticatedControlErrorsAreVersionedAndConnectionStaysHealthy(t *testing.T) {
	handler, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "fault-client")
	conn := connectMember(t, server.URL, privateKey, credential)
	defer conn.CloseNow()
	readType(t, conn, "authenticated")

	offlineKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeWire(t, conn, wireMessage{Version: Version, Type: "signal", To: identity.ID(offlineKey), Payload: json.RawMessage(`{"description":"offer"}`)})
	signalError := readType(t, conn, "signal.error")
	if signalError.Version != Version || signalError.Error != "signaling target is not online" {
		t.Fatalf("signal error = %+v", signalError)
	}

	requestID := "00000000000000000000000000000001"
	malformed := []byte(`{"version":2,"type":"members.list","request_id":"` + requestID + `","extra":true}`)
	if err := conn.Write(t.Context(), websocket.MessageText, malformed); err != nil {
		t.Fatal(err)
	}
	strictError := readType(t, conn, "members.list.error")
	if strictError.Version != Version || strictError.RequestID != requestID {
		t.Fatalf("strict error = %+v", strictError)
	}

	if err := conn.Write(t.Context(), websocket.MessageBinary, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	binaryError := readType(t, conn, "error")
	if binaryError.Version != Version || binaryError.Error != "text control messages required" {
		t.Fatalf("binary error = %+v", binaryError)
	}

	pingID := "00000000000000000000000000000002"
	writeWire(t, conn, wireMessage{Version: Version, Type: "ping.request", RequestID: pingID})
	pong := readType(t, conn, "ping.response")
	if pong.Version != Version || pong.RequestID != pingID || handler.hub.Snapshot().AuthenticatedConnections != 1 {
		t.Fatalf("healthy control = %+v, snapshot=%+v", pong, handler.hub.Snapshot())
	}
}

func TestAuthenticatedUnrecoverableMalformedControlCloses(t *testing.T) {
	_, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "malformed-client")
	conn := connectMember(t, server.URL, privateKey, credential)
	defer conn.CloseNow()
	readType(t, conn, "authenticated")
	if err := conn.Write(t.Context(), websocket.MessageText, []byte(`{"version":2,"type":"members.list"`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(t.Context()); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("malformed control close = %v", err)
	}
}

func TestMemberInviteControlIsStrictCorrelatedAndCoded(t *testing.T) {
	handler, store, _, _ := newTestHandler(t)
	publicKey, _, _ := enrollMember(t, store, "issuer")
	member, err := store.ActiveMember(context.Background(), identity.ID(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	sender := &client{member: member, send: make(chan outbound, 8), cancel: func() {}}
	requestID := "00000000000000000000000000000001"
	create := inviteapi.ControlCreateRequest{Type: "invite.create", RequestID: requestID, CreateRequest: inviteapi.CreateRequest{Version: inviteapi.Version, Label: "invitee", LifetimeSeconds: 3600}}
	data, _ := json.Marshal(create)
	operation, correlated, err := handler.handleMemberMessage(context.Background(), sender, data)
	if err != nil || operation != create.Type || correlated != requestID {
		t.Fatalf("create dispatch = %q %q %v", operation, correlated, err)
	}
	var created inviteapi.ControlCreation
	if err := json.Unmarshal((<-sender.send).data, &created); err != nil || created.Type != "invite.created" || created.RequestID != requestID || created.IssuerType != "member" || created.IssuerDeviceID != member.DeviceID || created.Token == "" {
		t.Fatalf("created response invalid: decode_error=%v type=%q correlated=%t issuer_type=%q issuer_matches=%t token_length=%d", err, created.Type, created.RequestID == requestID, created.IssuerType, created.IssuerDeviceID == member.DeviceID, len(created.Token))
	}

	requestID = "00000000000000000000000000000002"
	list := inviteapi.ControlListRequest{Type: "invite.list", RequestID: requestID, Version: inviteapi.Version}
	data, _ = json.Marshal(list)
	if _, _, err := handler.handleMemberMessage(context.Background(), sender, data); err != nil {
		t.Fatal(err)
	}
	var listed inviteapi.ControlList
	listedData := (<-sender.send).data
	listedDecodeErr := json.Unmarshal(listedData, &listed)
	listedTokenLeak := bytes.Contains(listedData, []byte(created.Token))
	listedTokenField := bytes.Contains(listedData, []byte(`"token"`))
	if listedDecodeErr != nil || listed.Type != "invite.listed" || listed.RequestID != requestID || len(listed.Invites) != 1 || listed.Invites[0].InviteID != created.InviteID || listedTokenLeak || listedTokenField {
		t.Fatalf("listed response invalid: decode_error=%v type=%q correlated=%t count=%d id_matches=%t response_bytes=%d token_leak=%t token_field=%t", listedDecodeErr, listed.Type, listed.RequestID == requestID, len(listed.Invites), len(listed.Invites) == 1 && listed.Invites[0].InviteID == created.InviteID, len(listedData), listedTokenLeak, listedTokenField)
	}

	malformed := []byte(`{"type":"invite.create","request_id":"00000000000000000000000000000003","version":1,"label":"other","lifetime_seconds":3600,"code":"known-union-field"}`)
	operation, correlated, err = handler.handleMemberMessage(context.Background(), sender, malformed)
	var inviteErr *inviteControlError
	if operation != "invite.create" || correlated == "" || !errors.As(err, &inviteErr) || inviteErr.code != "invalid_request" {
		t.Fatalf("strict create = %q %q %#v", operation, correlated, err)
	}

	requestID = "00000000000000000000000000000004"
	revoke := inviteapi.ControlRevokeRequest{Type: "invite.revoke", RequestID: requestID, Version: inviteapi.Version, InviteID: created.InviteID}
	data, _ = json.Marshal(revoke)
	if _, _, err := handler.handleMemberMessage(context.Background(), sender, data); err != nil {
		t.Fatal(err)
	}
	var revoked inviteapi.ControlRevocation
	if err := json.Unmarshal((<-sender.send).data, &revoked); err != nil || revoked.Type != "invite.revoked" || revoked.RequestID != requestID || revoked.State != "revoked" || revoked.Invite.InviteID != created.InviteID {
		t.Fatalf("revoked = %+v, %v", revoked, err)
	}

	revoke.RequestID = "00000000000000000000000000000005"
	data, _ = json.Marshal(revoke)
	operation, correlated, err = handler.handleMemberMessage(context.Background(), sender, data)
	if operation != "invite.revoke" || correlated != revoke.RequestID || !errors.As(err, &inviteErr) || inviteErr.code != string(membership.CodeInviteUnavailable) || strings.Contains(err.Error(), created.Token) {
		t.Fatalf("unavailable revoke = %q %q %#v", operation, correlated, err)
	}
}

func TestChallengeReplayAndAuthorityMismatchFail(t *testing.T) {
	_, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "member")
	first, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, firstData, err := first.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var firstChallenge Challenge
	if err := json.Unmarshal(firstData, &firstChallenge); err != nil {
		t.Fatal(err)
	}
	firstSignature, err := SignChallenge(privateKey, firstChallenge)
	if err != nil {
		t.Fatal(err)
	}
	first.CloseNow()

	second, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.CloseNow()
	if _, _, err := second.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeWebSocketMessage(t, second, Authentication{Version: AuthenticationVersion, Type: "authenticate", Credential: credential, Signature: firstSignature})
	if _, _, err := second.Read(context.Background()); err == nil {
		t.Fatal("replayed challenge signature authenticated")
	}

	_, otherStore, _, otherServer := newTestHandler(t)
	_, otherPrivate, otherCredential := enrollMember(t, otherStore, "other")
	conn, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, challengeData, err := conn.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var challenge Challenge
	if err := json.Unmarshal(challengeData, &challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := SignChallenge(otherPrivate, challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeWebSocketMessage(t, conn, Authentication{Version: AuthenticationVersion, Type: "authenticate", Credential: otherCredential, Signature: signature})
	if _, _, err := conn.Read(context.Background()); err == nil {
		t.Fatal("foreign authority credential authenticated")
	}
	otherServer.Close()
}

func TestChallengeRequiresValidAuthorityProof(t *testing.T) {
	handler, _, authority, _ := newTestHandler(t)
	now := time.Now()
	challenge, err := handler.challenge(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerChallenge(challenge, authority.ServerID(), now); err != nil {
		t.Fatalf("valid authority challenge rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Challenge){
		"unsigned": func(value *Challenge) { value.AuthoritySignature = "" },
		"wrong key": func(value *Challenge) {
			value.AuthoritySignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"tampered nonce": func(value *Challenge) { value.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"old protocol":   func(value *Challenge) { value.Version = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			forged := challenge
			mutate(&forged)
			if err := VerifyServerChallenge(forged, authority.ServerID(), now); err == nil {
				t.Fatal("forged authority challenge verified")
			}
		})
	}
	if err := VerifyServerChallenge(challenge, authority.ServerID(), now.Add(authenticationLimit+time.Second)); err == nil {
		t.Fatal("expired authority challenge verified")
	}
	future := challenge
	future.ExpiresAt = now.Add(authenticationLimit + time.Minute).Unix()
	canonical, err := rendezvousproto.ServerChallengeBytes(future)
	if err != nil {
		t.Fatal(err)
	}
	future.AuthoritySignature = base64.RawURLEncoding.EncodeToString(authority.Sign(canonical))
	if err := VerifyServerChallenge(future, authority.ServerID(), now); err == nil {
		t.Fatal("overlong authority challenge verified")
	}
}

func TestAuthenticationVersionOneIsRejected(t *testing.T) {
	_, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "old-client")
	conn, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, data, err := conn.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var challenge Challenge
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeWebSocketMessage(t, conn, Authentication{Version: 1, Type: "authenticate", Credential: credential, Signature: signature})
	if _, _, err := conn.Read(context.Background()); websocket.CloseStatus(err) != websocket.StatusPolicyViolation || !strings.Contains(err.Error(), "unsupported_protocol") {
		t.Fatalf("Version 1 authentication response close = %v", err)
	}
}

func TestUnsupportedAuthenticatedControlClosesConnection(t *testing.T) {
	_, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "future-control")
	conn := connectMember(t, server.URL, privateKey, credential)
	defer conn.CloseNow()
	readType(t, conn, "authenticated")
	writeWire(t, conn, wireMessage{Version: Version + 1, Type: "signal"})
	if _, _, err := conn.Read(t.Context()); websocket.CloseStatus(err) != websocket.StatusPolicyViolation || !strings.Contains(err.Error(), "unsupported_protocol") {
		t.Fatalf("unsupported control close = %v", err)
	}
}

func TestPingControlIsStrictAndCorrelated(t *testing.T) {
	handler, _, _, _ := newTestHandler(t)
	sender := &client{send: make(chan outbound, 4)}
	requestID := "0123456789abcdef0123456789abcdef"
	operation, correlated, err := handler.handleMemberMessage(t.Context(), sender, []byte(`{"version":2,"type":"ping.request","request_id":"`+requestID+`"}`))
	if err != nil || operation != "ping.request" || correlated != requestID {
		t.Fatalf("valid ping = %q, %q, %v", operation, correlated, err)
	}
	var response rendezvousproto.PingControl
	if err := json.Unmarshal((<-sender.send).data, &response); err != nil || response.Version != Version || response.Type != "ping.response" || response.RequestID != requestID {
		t.Fatalf("response = %+v, %v", response, err)
	}
	for _, data := range []string{
		`{"version":2,"type":"ping.request","request_id":"bad"}`,
		`{"version":2,"type":"ping.request","request_id":"` + requestID + `","payload":{}}`,
		`{"version":2,"type":"ping.request","request_id":"` + requestID + `"} {}`,
		`{"version":1,"type":"ping.request","request_id":"` + requestID + `"}`,
	} {
		if _, _, err := handler.handleMemberMessage(t.Context(), sender, []byte(data)); err == nil {
			t.Fatalf("accepted malformed ping: %s", data)
		}
	}
}

func TestAuthenticatedProofBindsChallengeDeviceRevisionAndClientProof(t *testing.T) {
	handler, store, authority, _ := newTestHandler(t)
	publicKey, privateKey, credential := enrollMember(t, store, "proof-device")
	now := time.Now()
	challenge, err := handler.challenge(now)
	if err != nil {
		t.Fatal(err)
	}
	deviceSignature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	authentication := Authentication{Version: AuthenticationVersion, Type: "authenticate", Credential: credential, Signature: deviceSignature}
	encoded, err := json.Marshal(authentication)
	if err != nil {
		t.Fatal(err)
	}
	member, verifiedAuthentication, err := handler.authenticate(context.Background(), challenge, encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := handler.authenticatedProof(challenge, member, verifiedAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := identity.ID(publicKey)
	if err := VerifyAuthenticatedProof(challenge, proof, authority.ServerID(), deviceID, deviceID, member.Revision, deviceSignature); err != nil {
		t.Fatalf("valid authenticated proof rejected: %v", err)
	}

	otherPublic, _, otherCredential := enrollMember(t, store, "other-proof-device")
	otherID := identity.ID(otherPublic)
	secondChallenge, err := handler.challenge(now)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		challenge Challenge
		proof     AuthenticatedProof
		deviceID  string
		deviceKey string
		revision  int64
		signature string
	}{
		{name: "forged authority signature", challenge: challenge, proof: func() AuthenticatedProof {
			value := proof
			value.AuthoritySignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			return value
		}(), deviceID: deviceID, deviceKey: deviceID, revision: member.Revision, signature: deviceSignature},
		{name: "tampered revision", challenge: challenge, proof: proof, deviceID: deviceID, deviceKey: deviceID, revision: member.Revision + 1, signature: deviceSignature},
		{name: "other challenge", challenge: secondChallenge, proof: proof, deviceID: deviceID, deviceKey: deviceID, revision: member.Revision, signature: deviceSignature},
		{name: "other device", challenge: challenge, proof: proof, deviceID: otherID, deviceKey: otherCredential.Claims.DeviceKey, revision: otherCredential.Claims.Revision, signature: deviceSignature},
		{name: "other client proof", challenge: challenge, proof: proof, deviceID: deviceID, deviceKey: deviceID, revision: member.Revision, signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyAuthenticatedProof(test.challenge, test.proof, authority.ServerID(), test.deviceID, test.deviceKey, test.revision, test.signature); err == nil {
				t.Fatal("tampered authenticated proof verified")
			}
		})
	}
}

func TestOversizedAuthenticatedFrameClosesSession(t *testing.T) {
	_, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "bounded")
	conn := connectMember(t, server.URL, privateKey, credential)
	defer conn.CloseNow()
	readType(t, conn, "authenticated")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, make([]byte, MaxControlBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("oversized frame did not close session")
	}
}

func TestHubCloseEndsSessionsAndRejectsNewPresence(t *testing.T) {
	handler, store, _, server := newTestHandler(t)
	_, privateKey, credential := enrollMember(t, store, "shutdown")
	conn := connectMember(t, server.URL, privateKey, credential)
	readType(t, conn, "authenticated")
	handler.hub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("active session survived hub shutdown")
	}
	conn.CloseNow()

	replacement := connectMember(t, server.URL, privateKey, credential)
	defer replacement.CloseNow()
	if _, _, err := replacement.Read(ctx); err == nil {
		t.Fatal("new session registered after hub shutdown")
	}
}

func newTestHandler(t *testing.T, options ...Option) (*Handler, *membership.Store, *membership.Authority, *httptest.Server) {
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
	handler := New(store, authority, NewHub(), nil, options...)
	server := httptest.NewServer(handler.Handler())
	t.Cleanup(server.Close)
	return handler, store, authority, server
}

func enrollMember(t *testing.T, store *membership.Store, label string) (ed25519.PublicKey, ed25519.PrivateKey, membership.Credential) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pending, err := store.RequestEnrollment(context.Background(), publicKey, label, "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
		t.Fatal(err)
	}
	enrolled, err := store.RequestEnrollment(context.Background(), publicKey, label, "192.0.2.1", now)
	if err != nil || enrolled.Credential == nil {
		t.Fatalf("enrolled = %+v, err = %v", enrolled, err)
	}
	return publicKey, privateKey, *enrolled.Credential
}

func connectMember(t *testing.T, serverURL string, privateKey ed25519.PrivateKey, credential membership.Credential) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(context.Background(), websocketURL(serverURL), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var challenge Challenge
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerChallenge(challenge, credential.Claims.ServerID, time.Now()); err != nil {
		t.Fatal(err)
	}
	signature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeWebSocketMessage(t, conn, Authentication{Version: AuthenticationVersion, Type: "authenticate", Credential: credential, Signature: signature})
	return conn
}

func readType(t *testing.T, conn *websocket.Conn, messageType string) wireMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var message wireMessage
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == messageType {
			return message
		}
	}
}

func writeWire(t *testing.T, conn *websocket.Conn, message wireMessage) {
	t.Helper()
	writeWebSocketMessage(t, conn, message)
}

func writeWebSocketMessage(t *testing.T, conn *websocket.Conn, message any) {
	t.Helper()
	data, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func websocketURL(serverURL string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + "/v1/connect"
}
