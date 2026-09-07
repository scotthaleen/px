//go:build windows

package getcleanup

import (
	"os"

	"golang.org/x/sys/windows"
)

func syncDirectory(file *os.File) error {
	return windows.FlushFileBuffers(windows.Handle(file.Fd()))
}
