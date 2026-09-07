package identity

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "device.key")
	publicPath := filepath.Join(dir, "device.pub")
	if err := WriteFiles(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	privateKey, err := LoadPrivate(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := LoadPublic(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		t.Fatal("private and public key differ")
	}
}

func TestWriteFilesRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "device.key")
	publicPath := filepath.Join(dir, "device.pub")
	if err := WriteFiles(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := WriteFiles(privatePath, publicPath); err == nil {
		t.Fatal("expected overwrite error")
	}
}
