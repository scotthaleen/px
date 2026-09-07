//go:build !windows

package getcleanup

import "os"

func openDirectory(path string) (*os.File, error) { return os.Open(path) }
