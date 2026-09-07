package signalproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

const (
	Version          = 1
	KindDescription  = "description"
	KindCandidate    = "candidate"
	MaxEnvelopeBytes = 64 << 10
	MaxPayloadBytes  = 60 << 10
)

type Envelope struct {
	Version   int             `json:"version"`
	Session   string          `json:"session"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Kind      string          `json:"kind"`
	ExpiresAt int64           `json:"expires_at"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type unsignedEnvelope struct {
	Version   int             `json:"version"`
	Session   string          `json:"session"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Kind      string          `json:"kind"`
	ExpiresAt int64           `json:"expires_at"`
	Payload   json.RawMessage `json:"payload"`
}

func Sign(privateKey ed25519.PrivateKey, session, peerID, kind string, payload any, expiresAt time.Time) ([]byte, error) {
	if kind != KindDescription && kind != KindCandidate {
		return nil, fmt.Errorf("unsupported signaling kind %q", kind)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal signaling payload: %w", err)
	}
	if len(payloadJSON) > MaxPayloadBytes {
		return nil, fmt.Errorf("signaling payload is %d bytes, limit is %d", len(payloadJSON), MaxPayloadBytes)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	unsigned := unsignedEnvelope{
		Version:   Version,
		Session:   session,
		From:      identity.ID(publicKey),
		To:        peerID,
		Kind:      kind,
		ExpiresAt: expiresAt.Unix(),
		Payload:   payloadJSON,
	}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("marshal signed signaling fields: %w", err)
	}
	envelope := Envelope{
		Version:   unsigned.Version,
		Session:   unsigned.Session,
		From:      unsigned.From,
		To:        unsigned.To,
		Kind:      unsigned.Kind,
		ExpiresAt: unsigned.ExpiresAt,
		Payload:   unsigned.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal signaling envelope: %w", err)
	}
	if len(encoded) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("signaling envelope is %d bytes, limit is %d", len(encoded), MaxEnvelopeBytes)
	}
	return encoded, nil
}

func Verify(data []byte, peerKey ed25519.PublicKey, ownID, session string, now time.Time) (Envelope, error) {
	if len(data) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("signaling envelope is %d bytes, limit is %d", len(data), MaxEnvelopeBytes)
	}
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode signaling envelope: %w", err)
	}
	if envelope.Version != Version {
		return Envelope{}, fmt.Errorf("unsupported signaling version %d", envelope.Version)
	}
	if envelope.Session != session {
		return Envelope{}, errors.New("signaling session mismatch")
	}
	if envelope.From != identity.ID(peerKey) {
		return Envelope{}, errors.New("signaling sender mismatch")
	}
	if envelope.To != ownID {
		return Envelope{}, errors.New("signaling recipient mismatch")
	}
	if envelope.Kind != KindDescription && envelope.Kind != KindCandidate {
		return Envelope{}, fmt.Errorf("unsupported signaling kind %q", envelope.Kind)
	}
	if len(envelope.Payload) > MaxPayloadBytes {
		return Envelope{}, fmt.Errorf("signaling payload is %d bytes, limit is %d", len(envelope.Payload), MaxPayloadBytes)
	}
	if now.Unix() > envelope.ExpiresAt {
		return Envelope{}, errors.New("signaling envelope expired")
	}
	if envelope.ExpiresAt > now.Add(5*time.Minute).Unix() {
		return Envelope{}, errors.New("signaling envelope expiry is too far in the future")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Envelope{}, fmt.Errorf("decode signaling signature: %w", err)
	}
	unsigned := unsignedEnvelope{
		Version:   envelope.Version,
		Session:   envelope.Session,
		From:      envelope.From,
		To:        envelope.To,
		Kind:      envelope.Kind,
		ExpiresAt: envelope.ExpiresAt,
		Payload:   envelope.Payload,
	}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal signed signaling fields: %w", err)
	}
	if !ed25519.Verify(peerKey, canonical, signature) {
		return Envelope{}, errors.New("invalid signaling signature")
	}
	return envelope, nil
}
