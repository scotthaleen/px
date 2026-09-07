//go:build windows

package getcleanup

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isWindowsSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
