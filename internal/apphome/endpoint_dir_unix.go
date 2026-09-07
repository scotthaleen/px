//go:build linux || darwin

package apphome

import (
	"fmt"

	"github.com/scotthaleen/go-toolbelt/privatedir"
)

func ensurePrivateEndpointDir(path string) error {
	if err := privatedir.Ensure(path); err != nil {
		return fmt.Errorf("ensure private endpoint directory %q: %w", path, err)
	}
	return nil
}
