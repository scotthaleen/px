//go:build !windows

package transfer

import "os"

func syncRootDirectory(root *os.Root, directory string) error {
	if directory == "" {
		directory = "."
	}
	file, err := root.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
