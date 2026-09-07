//go:build linux || darwin

package contexts

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfferedRootRejectsReadableButNonSearchableDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "offered")
	if err := os.Mkdir(root, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	directory, err := os.Open(root)
	if err != nil {
		t.Skipf("directory read capability is not independently observable: %v", err)
	}
	_, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		t.Skipf("directory list capability is not independently observable: read=%v close=%v", readErr, closeErr)
	}

	manager := &Manager{}
	if _, err := manager.configuredRoot(root, false); err == nil {
		t.Skip("current user can search the directory despite mode 0400")
	} else if !strings.Contains(err.Error(), "search/traversal") {
		t.Fatalf("non-searchable root error = %v", err)
	}
}
