package rendezvousproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/membership"
)

const goldenIdentity = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func TestJSONGolden(t *testing.T) {
	proof := &AuthenticatedProof{
		Version: AuthenticationVersion, ChallengeDigest: "digest", DeviceID: "device", DeviceKey: "key",
		MembershipRevision: 3, DeviceSignature: "device-signature", AuthoritySignature: "authority-signature",
	}
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "enrollment request", value: EnrollmentRequest{DeviceKey: "device", Label: "laptop"}, want: `{"device_key":"device","label":"laptop"}`},
		{name: "invite redemption request", value: InviteRedemptionRequest{Version: 1, Token: "token", DeviceKey: "device", Label: "laptop"}, want: `{"version":1,"token":"token","device_key":"device","label":"laptop"}`},
		{name: "pending enrollment", value: Enrollment{State: "pending", Code: "AAAA-AAAA", ExpiresAt: time.Unix(60, 0).UTC()}, want: `{"state":"pending","code":"AAAA-AAAA","expires_at":"1970-01-01T00:01:00Z"}`},
		{name: "server info", value: ServerInfo{Version: Version, ServerID: "server", Authority: "authority"}, want: `{"version":2,"server_id":"server","authority":"authority"}`},
		{name: "challenge", value: Challenge{Version: AuthenticationVersion, Type: "challenge", ServerID: "server", Nonce: "nonce", ExpiresAt: 7, AuthoritySignature: "signature"}, want: `{"version":2,"type":"challenge","server_id":"server","nonce":"nonce","expires_at":7,"authority_signature":"signature"}`},
		{name: "authentication", value: Authentication{Version: AuthenticationVersion, Type: "authenticate", Signature: "signature"}, want: `{"version":2,"type":"authenticate","credential":{"claims":{"version":0,"server_id":"","device_key":"","label":"","revision":0,"issued_at":0},"signature":""},"signature":"signature"}`},
		{name: "authenticated proof", value: proof, want: `{"version":2,"challenge_digest":"digest","device_id":"device","device_key":"key","membership_revision":3,"device_signature":"device-signature","authority_signature":"authority-signature"}`},
		{name: "control field order", value: ControlMessage{Version: Version, Type: "signal", RequestID: strings.Repeat("a", 32), To: "to", From: "from", DeviceID: "device", Code: "code", Payload: json.RawMessage(`{"candidate":"x"}`), Members: []membership.Member{}, Pending: []membership.Pending{}, AuthenticationProof: proof, Error: "failure"}, want: `{"version":2,"type":"signal","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to":"to","from":"from","device_id":"device","code":"code","payload":{"candidate":"x"},"authentication_proof":{"version":2,"challenge_digest":"digest","device_id":"device","device_key":"key","membership_revision":3,"device_signature":"device-signature","authority_signature":"authority-signature"},"error":"failure"}`},
		{name: "legacy unversioned control", value: ControlMessage{Type: "pending.list", Pending: []membership.Pending{{Code: "AAAA-AAAA", DeviceID: "device", Label: "laptop", CreatedAt: time.Unix(0, 0).UTC(), ExpiresAt: time.Unix(60, 0).UTC()}}}, want: `{"type":"pending.list","pending":[{"code":"AAAA-AAAA","device_id":"device","label":"laptop","created_at":"1970-01-01T00:00:00Z","expires_at":"1970-01-01T00:01:00Z"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("JSON mismatch\n got: %s\nwant: %s", got, test.want)
			}
		})
	}
}

func TestCanonicalBytesGolden(t *testing.T) {
	challenge := Challenge{Version: AuthenticationVersion, Type: "challenge", ServerID: goldenIdentity, Nonce: goldenIdentity, ExpiresAt: 1700000010}
	claims := `{"version":2,"server_id":"` + goldenIdentity + `","nonce":"` + goldenIdentity + `","expires_at":1700000010}`
	server, err := ServerChallengeBytes(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if want := "px-server-auth-v2\x00" + claims; string(server) != want {
		t.Fatalf("server canonical bytes mismatch\n got: %q\nwant: %q", server, want)
	}
	device, err := DeviceChallengeBytes(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if want := "px-device-auth-v2\x00" + claims; string(device) != want {
		t.Fatalf("device canonical bytes mismatch\n got: %q\nwant: %q", device, want)
	}

	digest := sha256.Sum256(server)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	proof := AuthenticatedProof{Version: AuthenticationVersion, ChallengeDigest: base64.RawURLEncoding.EncodeToString(digest[:]), DeviceID: goldenIdentity, DeviceKey: goldenIdentity, MembershipRevision: 4, DeviceSignature: signature}
	proofBytes, err := AuthenticatedProofBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("px-server-authenticated-v2\x00{\"version\":2,\"challenge_digest\":%q,\"device_id\":%q,\"device_key\":%q,\"membership_revision\":4,\"device_signature\":%q}", proof.ChallengeDigest, goldenIdentity, goldenIdentity, signature)
	if string(proofBytes) != want {
		t.Fatalf("proof canonical bytes mismatch\n got: %q\nwant: %q", proofBytes, want)
	}
}

func TestSignAndVerifyHelpers(t *testing.T) {
	serverPublic, serverPrivate := keyFromByte(1)
	devicePublic, devicePrivate := keyFromByte(2)
	now := time.Unix(1700000000, 0)
	challenge := Challenge{
		Version: AuthenticationVersion, Type: "challenge", ServerID: identity.ID(serverPublic),
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: now.Add(AuthenticationLimit).Unix(),
	}
	challenge, err := SignServerChallenge(serverPrivate, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerChallenge(challenge, identity.ID(serverPublic), now); err != nil {
		t.Fatal(err)
	}
	deviceSignature, err := SignChallenge(devicePrivate, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChallengeSignature(devicePublic, challenge, deviceSignature); err != nil {
		t.Fatal(err)
	}
	proof, err := NewAuthenticatedProof(challenge, identity.ID(devicePublic), identity.ID(devicePublic), 1, deviceSignature)
	if err != nil {
		t.Fatal(err)
	}
	proof, err = SignAuthenticatedProof(serverPrivate, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthenticatedProof(challenge, proof, identity.ID(serverPublic), identity.ID(devicePublic), identity.ID(devicePublic), 1, deviceSignature); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRequestID(t *testing.T) {
	if err := ValidateRequestID(strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("g", 32)} {
		if err := ValidateRequestID(value); err == nil {
			t.Fatalf("ValidateRequestID(%q) succeeded", value)
		}
	}
}

func TestProtocolMismatchGuidanceUsesProtocolDirection(t *testing.T) {
	older := (&ProtocolMismatch{Boundary: "control", Expected: 2, Actual: 1, Remote: "server"}).Error()
	newer := (&ProtocolMismatch{Boundary: "authentication", Expected: 2, Actual: 3, Remote: "server"}).Error()
	if !strings.Contains(older, "expected 2") || !strings.Contains(older, "server reported 1") || !strings.Contains(older, "upgrade px-server") {
		t.Fatalf("older-server guidance = %q", older)
	}
	if !strings.Contains(newer, "expected 2") || !strings.Contains(newer, "server reported 3") || !strings.Contains(newer, "upgrade the PX agent/CLI") {
		t.Fatalf("newer-server guidance = %q", newer)
	}
}

func keyFromByte(value byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = value
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}
