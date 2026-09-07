//go:build !windows

package securefile

import (
	"os"
	"syscall"
	"testing"
)

func TestCreateOwnerOnlyDirUsesExactModeAndCurrentUID(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := CreateOwnerOnlyDir(root, t.TempDir(), "stage")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("directory metadata = mode %v stat %#v", info.Mode(), info.Sys())
	}
}

func TestValidateProtectedParentUnixModes(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{name: "private", mode: 0o700, ok: true},
		{name: "readable", mode: 0o755, ok: true},
		{name: "group writable", mode: 0o770},
		{name: "world writable", mode: 0o777},
		{name: "sticky shared", mode: os.ModeSticky | 0o777, ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			err = ValidateProtectedParent(file)
			if (err == nil) != test.ok {
				t.Fatalf("mode %v validation = %v", test.mode, err)
			}
		})
	}
}
