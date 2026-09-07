package putroot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrInvalid = errors.New("put root must be an existing canonical narrow writable directory whose root entry is not a symlink or reparse point")

func Canonical(path string) (string, error) {
	if path == "" {
		return "", ErrInvalid
	}
	// Reject ambiguous Windows roots before Abs resolves them against a drive's working directory.
	if runtime.GOOS == "windows" && (filepath.VolumeName(path) != "" || strings.HasPrefix(path, `/`) || strings.HasPrefix(path, `\`)) && broadOrUnsupported(path, "windows") {
		return "", ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	absolute = filepath.Clean(absolute)
	if broadOrUnsupported(absolute, runtime.GOOS) {
		return "", ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", ErrInvalid
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || filepath.Clean(resolved) != absolute {
		return "", ErrInvalid
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalid
	}
	if err := validateNativeRoot(absolute); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return absolute, nil
}

func Valid(path *string) bool {
	if path == nil {
		return true
	}
	canonical, err := Canonical(*path)
	return err == nil && canonical == *path
}

func broadOrUnsupported(path, goos string) bool {
	if goos != "windows" {
		return path == string(os.PathSeparator)
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) || strings.HasPrefix(path, `\`) || strings.HasPrefix(path, `/`) {
		return true
	}
	if len(path) >= 2 && isLetter(path[0]) && path[1] == ':' {
		return len(path) <= 3 || path[2] != '\\' && path[2] != '/'
	}
	return true
}

func isLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
