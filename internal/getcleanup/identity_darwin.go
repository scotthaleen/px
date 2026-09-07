//go:build darwin

package getcleanup

import (
	"fmt"
	"os"
	"syscall"
)

func directoryIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return "", errInvalidIdentity
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errInvalidIdentity
	}
	return fmt.Sprintf("darwin1:%016x:%016x", uint64(stat.Dev), stat.Ino), nil
}
