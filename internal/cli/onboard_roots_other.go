//go:build !windows

package cli

import "runtime"

func currentOnboardingRoots(home string) (string, string) {
	return onboardingRoots(runtime.GOOS, home)
}
