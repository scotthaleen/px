//go:build !windows

package putroot

import "golang.org/x/sys/unix"

func validateNativeRoot(path string) error {
	return unix.Access(path, unix.R_OK|unix.W_OK|unix.X_OK)
}
