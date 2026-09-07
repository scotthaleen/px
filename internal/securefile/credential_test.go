package securefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateExclusiveCredentialIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	file, err := CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("secret\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerOnly(path); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateExclusive(path); err == nil {
		t.Fatal("exclusive credential creation overwrote a file")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := ValidateOwnerOnly(path); err == nil {
			t.Fatal("shared Unix credential permissions were accepted")
		}
	}
}
