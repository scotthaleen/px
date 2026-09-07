//go:build process && smoke && !windows

package testscript_test

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func nativeTestFileIdentity(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("native file identity is unavailable")
	}
	return fmt.Sprintf("unix1:%016x:%016x", uint64(stat.Dev), stat.Ino)
}
