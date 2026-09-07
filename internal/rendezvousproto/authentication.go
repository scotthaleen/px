package rendezvousproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/membership"
)

const (
	serverChallengeDomain    = "px-server-auth-v2\x00"
	deviceChallengeDomain    = "px-device-auth-v2\x00"
	authenticatedProofDomain = "px-server-authenticated-v2\x00"
)

type Challenge struct {
	Version            int    `json:"version"`
	Type               string `json:"type"`
	ServerID           string `json:"server_id"`
	Nonce              string `json:"nonce"`
	ExpiresAt          int64  `json:"expires_at"`
	AuthoritySignature string `json:"authority_signature"`
}

type Authentication struct {
	Version    int                   `json:"version"`
	Type       string                `json:"type"`
	Credential membership.Credential `json:"credential"`
	Signature  string                `json:"signature"`
}

type AuthenticatedProof struct {
	Version            int    `json:"version"`
	ChallengeDigest    string `json:"challenge_digest"`
	DeviceID           string `json:"device_id"`
	DeviceKey          string `json:"device_key"`
	MembershipRevision int64  `json:"membership_revision"`
	DeviceSignature    string `json:"device_signature"`
	AuthoritySignature string `json:"authority_signature"`
}

type authenticationChallengeClaims struct {
	Version   int    `json:"version"`
	ServerID  string `json:"server_id"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}

func SignChallenge(privateKey ed25519.PrivateKey, challenge Challenge) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid device private key")
	}
	canonical, err := DeviceChallengeBytes(challenge)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)), nil
}

func SignServerChallenge(privateKey ed25519.PrivateKey, challenge Challenge) (Challenge, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Challenge{}, errors.New("invalid authority private key")
	}
	canonical, err := ServerChallengeBytes(challenge)
	if err != nil {
		return Challenge{}, err
	}
	challenge.AuthoritySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return challenge, nil
}

func VerifyChallengeSignature(publicKey ed25519.PublicKey, challenge Challenge, signature string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid device public key")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return errors.New("invalid challenge signature encoding")
	}
	canonical, err := DeviceChallengeBytes(challenge)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, decoded) {
		return errors.New("invalid challenge signature")
	}
	return nil
}

func VerifyServerChallenge(challenge Challenge, expectedServerID string, now time.Time) error {
	if challenge.ServerID != expectedServerID || now.Unix() > challenge.ExpiresAt || challenge.ExpiresAt > now.Add(AuthenticationLimit).Unix() {
		return errors.New("authentication challenge expired or mismatched")
	}
	publicKey, err := identity.ParseID(expectedServerID)
	if err != nil {
		return errors.New("invalid pinned server identity")
	}
	signature, err := base64.RawURLEncoding.DecodeString(challenge.AuthoritySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid authority challenge signature encoding")
	}
	canonical, err := ServerChallengeBytes(challenge)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("invalid authority challenge signature")
	}
	return nil
}

func NewAuthenticatedProof(challenge Challenge, deviceID, deviceKey string, revision int64, deviceSignature string) (AuthenticatedProof, error) {
	challengeCanonical, err := ServerChallengeBytes(challenge)
	if err != nil {
		return AuthenticatedProof{}, err
	}
	if _, err := identity.ParseID(deviceID); err != nil {
		return AuthenticatedProof{}, errors.New("invalid authenticated device ID")
	}
	if _, err := identity.ParseID(deviceKey); err != nil || deviceID != deviceKey {
		return AuthenticatedProof{}, errors.New("invalid authenticated device key")
	}
	if revision <= 0 {
		return AuthenticatedProof{}, errors.New("invalid authenticated membership revision")
	}
	decodedDeviceSignature, err := base64.RawURLEncoding.DecodeString(deviceSignature)
	if err != nil || len(decodedDeviceSignature) != ed25519.SignatureSize {
		return AuthenticatedProof{}, errors.New("invalid authenticated device signature")
	}
	digest := sha256.Sum256(challengeCanonical)
	return AuthenticatedProof{
		Version: AuthenticationVersion, ChallengeDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
		DeviceID: deviceID, DeviceKey: deviceKey, MembershipRevision: revision, DeviceSignature: deviceSignature,
	}, nil
}

func SignAuthenticatedProof(privateKey ed25519.PrivateKey, proof AuthenticatedProof) (AuthenticatedProof, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return AuthenticatedProof{}, errors.New("invalid authority private key")
	}
	canonical, err := AuthenticatedProofBytes(proof)
	if err != nil {
		return AuthenticatedProof{}, err
	}
	proof.AuthoritySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return proof, nil
}

func VerifyAuthenticatedProof(challenge Challenge, proof AuthenticatedProof, expectedServerID, expectedDeviceID, expectedDeviceKey string, expectedRevision int64, deviceSignature string) error {
	if challenge.ServerID != expectedServerID {
		return errors.New("authenticated proof challenge does not match pinned server identity")
	}
	if proof.Version != AuthenticationVersion || proof.DeviceID != expectedDeviceID || proof.DeviceKey != expectedDeviceKey || proof.MembershipRevision != expectedRevision || proof.DeviceSignature != deviceSignature {
		return errors.New("authenticated proof does not match client authentication")
	}
	expected, err := NewAuthenticatedProof(challenge, expectedDeviceID, expectedDeviceKey, expectedRevision, deviceSignature)
	if err != nil {
		return err
	}
	if proof.ChallengeDigest != expected.ChallengeDigest {
		return errors.New("authenticated proof does not match challenge")
	}
	publicKey, err := identity.ParseID(expectedServerID)
	if err != nil {
		return errors.New("invalid pinned server identity")
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof.AuthoritySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid authenticated proof signature encoding")
	}
	canonical, err := AuthenticatedProofBytes(proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("invalid authenticated proof signature")
	}
	return nil
}

func ServerChallengeBytes(challenge Challenge) ([]byte, error) {
	return challengeBytes(serverChallengeDomain, challenge)
}

func DeviceChallengeBytes(challenge Challenge) ([]byte, error) {
	return challengeBytes(deviceChallengeDomain, challenge)
}

func challengeBytes(domain string, challenge Challenge) ([]byte, error) {
	claims, err := challengeClaims(challenge)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), encoded...), nil
}

func AuthenticatedProofBytes(proof AuthenticatedProof) ([]byte, error) {
	if proof.Version != AuthenticationVersion || proof.ChallengeDigest == "" || proof.DeviceID == "" || proof.DeviceKey == "" || proof.MembershipRevision <= 0 || proof.DeviceSignature == "" {
		return nil, errors.New("invalid authenticated proof")
	}
	digest, err := base64.RawURLEncoding.DecodeString(proof.ChallengeDigest)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("invalid authenticated proof challenge digest")
	}
	if _, err := identity.ParseID(proof.DeviceID); err != nil {
		return nil, errors.New("invalid authenticated proof device ID")
	}
	if _, err := identity.ParseID(proof.DeviceKey); err != nil || proof.DeviceID != proof.DeviceKey {
		return nil, errors.New("invalid authenticated proof device key")
	}
	deviceSignature, err := base64.RawURLEncoding.DecodeString(proof.DeviceSignature)
	if err != nil || len(deviceSignature) != ed25519.SignatureSize {
		return nil, errors.New("invalid authenticated proof device signature")
	}
	claims := struct {
		Version            int    `json:"version"`
		ChallengeDigest    string `json:"challenge_digest"`
		DeviceID           string `json:"device_id"`
		DeviceKey          string `json:"device_key"`
		MembershipRevision int64  `json:"membership_revision"`
		DeviceSignature    string `json:"device_signature"`
	}{proof.Version, proof.ChallengeDigest, proof.DeviceID, proof.DeviceKey, proof.MembershipRevision, proof.DeviceSignature}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return append([]byte(authenticatedProofDomain), encoded...), nil
}

func challengeClaims(challenge Challenge) (authenticationChallengeClaims, error) {
	if challenge.Version != AuthenticationVersion || challenge.Type != "challenge" || challenge.ServerID == "" || challenge.Nonce == "" || challenge.ExpiresAt <= 0 {
		return authenticationChallengeClaims{}, errors.New("invalid authentication challenge")
	}
	if _, err := identity.ParseID(challenge.ServerID); err != nil {
		return authenticationChallengeClaims{}, errors.New("invalid authentication challenge server identity")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != 32 {
		return authenticationChallengeClaims{}, errors.New("invalid authentication challenge nonce")
	}
	return authenticationChallengeClaims{Version: challenge.Version, ServerID: challenge.ServerID, Nonce: challenge.Nonce, ExpiresAt: challenge.ExpiresAt}, nil
}
