//go:build linux || darwin

package contexts

import "golang.org/x/sys/unix"

func validateRootSearch(path string) error {
	return unix.Access(path, unix.X_OK)
}
