//go:build process && smoke && windows

package testscript_test

import "testing"

func nativeTestFileIdentity(t *testing.T, _ string) string {
	t.Helper()
	t.Skip("manual NTFS campaign owns Windows accept-current identity validation")
	return ""
}
