//go:build windows

package getcleanup

import "testing"

func TestWindowsDirectoryHandleFlushes(t *testing.T) {
	directory, err := openDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := syncDirectory(directory); err != nil {
		t.Fatalf("FlushFileBuffers directory: %v", err)
	}
}
