package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

const privateKeyType = "PRIVATE KEY"

func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 identity: %w", err)
	}
	return publicKey, privateKey, nil
}

func WriteFiles(privatePath, publicPath string) error {
	publicKey, privateKey, err := Generate()
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyType, Bytes: privateDER})
	if err := writeExclusive(privatePath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	publicData := []byte(ID(publicKey) + "\n")
	if err := writeExclusive(publicPath, publicData, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != privateKeyType || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("parse private key: expected one PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("parse private key: key is not Ed25519")
	}
	return privateKey, nil
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return ParseID(strings.TrimSpace(string(data)))
}

func ID(key ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func ParseID(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decode public key: got %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}
