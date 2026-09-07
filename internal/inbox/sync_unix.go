//go:build !windows

package inbox

import "os"

func openSyncDirectory(path string) (*os.File, error) { return os.Open(path) }

func syncDirectory(file *os.File) error { return file.Sync() }
