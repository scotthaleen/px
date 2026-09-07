package contexts

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

const (
	OfferedRootScopeNarrow         = "narrow"
	OfferedRootScopeFilesystemRoot = "filesystem-root"
)

func classifyOfferedRoot(path string) string {
	return classifyOfferedRootForOS(path, runtime.GOOS)
}

func ValidateOfferedRootPath(path string) error {
	_, err := offeredRootScopeForOS(path, runtime.GOOS)
	return err
}

func OfferedRootScope(path string) (string, error) {
	return offeredRootScopeForOS(path, runtime.GOOS)
}

func classifyOfferedRootForOS(path, goos string) string {
	scope, _ := offeredRootScopeForOS(path, goos)
	return scope
}

func offeredRootScopeForOS(path, goos string) (string, error) {
	if goos == "windows" {
		if len(path) == 3 && isASCIILetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
			return OfferedRootScopeFilesystemRoot, nil
		}
		if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
			return "", errors.New("UNC, extended-prefix, and volume-GUID offered roots are unsupported")
		}
		if strings.HasPrefix(path, `\`) || strings.HasPrefix(path, `/`) {
			return "", errors.New("drive-relative offered roots are unsupported")
		}
		if len(path) >= 2 && isASCIILetter(path[0]) && path[1] == ':' && (len(path) == 2 || path[2] != '\\' && path[2] != '/') {
			return "", errors.New("drive-relative offered roots are unsupported")
		}
		return OfferedRootScopeNarrow, nil
	}
	if path == "/" {
		return OfferedRootScopeFilesystemRoot, nil
	}
	return OfferedRootScopeNarrow, nil
}

func validateOfferedRootAuthority(state State) error {
	derived := classifyOfferedRoot(state.OfferedRoot)
	if derived == "" {
		return fmt.Errorf("offered-root path form is unsupported")
	}
	if state.OfferedRootRevision <= 0 || state.OfferedRootScope != derived || state.FilesystemRootAcknowledged != (derived == OfferedRootScopeFilesystemRoot) {
		return errors.New("offered-root authority is inconsistent; repair it with context configure and --allow-filesystem-root when selecting a filesystem root")
	}
	return nil
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
