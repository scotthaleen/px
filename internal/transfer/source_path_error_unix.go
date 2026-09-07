//go:build !windows

package transfer

import (
	"errors"
	"os"
	"syscall"
)

func invalidSourcePathError(err error) bool {
	return errors.Is(err, os.ErrInvalid) || errors.Is(err, syscall.ENAMETOOLONG)
}
