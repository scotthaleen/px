//go:build windows

package cli

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func currentOnboardingRoots(home string) (string, string) {
	documents, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DEFAULT)
	if err != nil || documents == "" {
		documents = filepath.Join(home, "Documents")
	}
	base := filepath.Join(documents, "PX")
	return filepath.Join(base, "shared"), filepath.Join(base, "inbox")
}
