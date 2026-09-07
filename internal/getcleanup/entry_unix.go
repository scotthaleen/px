//go:build !windows

package getcleanup

import (
	"os"
)

func safeRegular(_ *os.Root, _ string, info os.FileInfo) bool {
	return info.Mode().IsRegular()
}
