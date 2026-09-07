//go:build !windows

package getcleanup

func isWindowsSharingViolation(error) bool { return false }
