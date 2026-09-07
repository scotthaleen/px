//go:build linux || darwin

package startup

import "os"

func currentUID() int { return os.Getuid() }
