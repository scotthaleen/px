//go:build windows

package apphome

import (
	"path/filepath"
	"testing"

	"github.com/scotthaleen/go-toolbelt/privatedir"
)

func TestEnsureDirectoriesUsePrivateWindowsACLs(t *testing.T) {
	paths, err := Resolve(filepath.Join(t.TempDir(), "px"))
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureAgent(); err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureServer(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Root, paths.AgentDir, paths.AgentKeys, paths.AgentTransfers, paths.ServerDir, paths.ServerAuthority, paths.RunDir} {
		if err := privatedir.Validate(path); err != nil {
			t.Errorf("validate %q: %v", path, err)
		}
	}
}
