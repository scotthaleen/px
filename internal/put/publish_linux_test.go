//go:build linux

package put

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublishPinnedThroughProcFDWithoutCapabilities(t *testing.T) {
	if err := nativePublicationSupported(); err != nil {
		t.Fatalf("ordinary Linux runtime lacks required procfs: %v", err)
	}
	root := t.TempDir()
	stagePath := filepath.Join(root, "stage")
	if err := os.WriteFile(stagePath, []byte("pinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := os.Open(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	parentFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(parentFD), root)
	defer parent.Close()
	identity, err := fileIdentity(stage, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishPinned(stage, parent, "ignored", "destination"); err != nil {
		t.Fatalf("pinned publication required unexpected capability: %v", err)
	}
	created, known := destinationHasIdentity(parent, "destination", identity)
	if !known || !created {
		t.Fatalf("destination identity mismatch: known=%t created=%t", known, created)
	}
}
