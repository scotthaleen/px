package putroot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCanonicalRequiresExistingNarrowNonLinkDirectory(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	got, err := Canonical(root)
	if err != nil || got != root {
		t.Fatalf("canonical=%q err=%v", got, err)
	}
	if _, err := Canonical(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing root accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err == nil {
		if _, err := Canonical(link); err == nil {
			t.Fatal("symlink root accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := Canonical("/"); err == nil {
			t.Fatal("filesystem root accepted")
		}
	}
}

func TestWindowsRootFormsFailClosed(t *testing.T) {
	for _, path := range []string{`C:`, `C:\`, `C:/`, `C:relative`, `C:r`, `\relative`, `/relative`, `\\server\share`, `\\?\C:\root`, `\\?\Volume{1234}\`} {
		if !broadOrUnsupported(path, "windows") {
			t.Errorf("accepted unsafe Windows form %q", path)
		}
	}
	for _, path := range []string{`C:\root`, `C:/root`, `d:\root\child`} {
		if broadOrUnsupported(path, "windows") {
			t.Errorf("rejected narrow Windows form %q", path)
		}
	}
}
