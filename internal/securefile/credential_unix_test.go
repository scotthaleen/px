//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixCredentialRejectsWrongOwnerMetadata(t *testing.T) {
	if err := validateUnixMetadata(0o600, 1000, 1001); err == nil {
		t.Fatal("wrong credential owner was accepted")
	}
}

func TestUnixCredentialRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "credential")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnerOnly(link); err == nil {
		t.Fatal("credential symlink was accepted")
	}
}

func TestUnixCredentialReadUsesOpenedDescriptorAcrossReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("original"))
	if _, err := file.Read(data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("opened credential changed to %q", data)
	}
}
