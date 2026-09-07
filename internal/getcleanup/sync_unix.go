//go:build !windows

package getcleanup

import "os"

func syncDirectory(file *os.File) error { return file.Sync() }
