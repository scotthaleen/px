package putroot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalRejectsDriveRelativeExistingRoot(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir("relative", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.VolumeName(root) + "relative", filepath.VolumeName(root)} {
		if canonical, err := Canonical(path); err == nil {
			t.Errorf("accepted ambiguous root %q as %q", path, canonical)
		}
	}
}
