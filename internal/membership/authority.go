package membership

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

const credentialVersion = 1

type Authority struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	serverID   string
}

type Credential struct {
	Claims    CredentialClaims `json:"claims"`
	Signature string           `json:"signature"`
}

type CredentialClaims struct {
	Version   int    `json:"version"`
	ServerID  string `json:"server_id"`
	DeviceKey string `json:"device_key"`
	Label     string `json:"label"`
	Revision  int64  `json:"revision"`
	IssuedAt  int64  `json:"issued_at"`
}

func Initialize(privatePath, publicPath string) error {
	if err := identity.WriteFiles(privatePath, publicPath); err != nil {
		return fmt.Errorf("initialize server authority: %w", err)
	}
	return nil
}

func Load(privatePath, publicPath string) (*Authority, error) {
	privateKey, err := identity.LoadPrivate(privatePath)
	if err != nil {
		return nil, fmt.Errorf("load server authority key: %w", err)
	}
	publicKey, err := identity.LoadPublic(publicPath)
	if err != nil {
		return nil, fmt.Errorf("load server identity: %w", err)
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, errors.New("server identity does not match authority key")
	}
	return &Authority{privateKey: privateKey, publicKey: publicKey, serverID: identity.ID(publicKey)}, nil
}

func (a *Authority) ServerID() string {
	return a.serverID
}

func (a *Authority) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), a.publicKey...)
}

func (a *Authority) Sign(message []byte) []byte {
	return ed25519.Sign(a.privateKey, message)
}

func (a *Authority) Issue(deviceKey ed25519.PublicKey, label string, revision int64, now time.Time) (Credential, error) {
	if len(deviceKey) != ed25519.PublicKeySize || revision <= 0 {
		return Credential{}, errors.New("valid device key and positive revision are required")
	}
	if err := ValidateLabel(label); err != nil {
		return Credential{}, err
	}
	claims := CredentialClaims{
		Version:   credentialVersion,
		ServerID:  a.serverID,
		DeviceKey: identity.ID(deviceKey),
		Label:     label,
		Revision:  revision,
		IssuedAt:  now.Unix(),
	}
	canonical, err := json.Marshal(claims)
	if err != nil {
		return Credential{}, fmt.Errorf("encode membership claims: %w", err)
	}
	return Credential{
		Claims:    claims,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(a.privateKey, canonical)),
	}, nil
}

func VerifyCredential(credential Credential, authorityKey ed25519.PublicKey, expectedServerID string) (CredentialClaims, error) {
	if len(authorityKey) != ed25519.PublicKeySize {
		return CredentialClaims{}, errors.New("invalid authority public key")
	}
	claims := credential.Claims
	if claims.Version != credentialVersion || claims.ServerID != expectedServerID || claims.Revision <= 0 {
		return CredentialClaims{}, errors.New("invalid membership claims")
	}
	if _, err := identity.ParseID(claims.DeviceKey); err != nil {
		return CredentialClaims{}, errors.New("invalid membership device key")
	}
	if err := ValidateLabel(claims.Label); err != nil {
		return CredentialClaims{}, fmt.Errorf("invalid membership label: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(credential.Signature)
	if err != nil {
		return CredentialClaims{}, errors.New("invalid membership signature encoding")
	}
	canonical, err := json.Marshal(claims)
	if err != nil {
		return CredentialClaims{}, fmt.Errorf("encode membership claims: %w", err)
	}
	if !ed25519.Verify(authorityKey, canonical, signature) {
		return CredentialClaims{}, errors.New("invalid membership signature")
	}
	return claims, nil
}
