package signalproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

func TestEnvelopeRoundTripAndTamper(t *testing.T) {
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	encoded, err := Sign(privateA, "session", identity.ID(publicB), KindCandidate, map[string]string{"candidate": "host"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded, publicA, identity.ID(publicB), "session", now); err != nil {
		t.Fatal(err)
	}

	encoded[len(encoded)-2] ^= 1
	if _, err := Verify(encoded, publicA, identity.ID(publicB), "session", now); err == nil {
		t.Fatal("expected tampered envelope to fail")
	}
}

func TestEnvelopeExpiry(t *testing.T) {
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	encoded, err := Sign(privateA, "session", identity.ID(publicB), KindDescription, map[string]string{"sdp": "value"}, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded, publicA, identity.ID(publicB), "session", now); err == nil {
		t.Fatal("expected expired envelope to fail")
	}
}
