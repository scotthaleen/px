//go:build !windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CreateOwnerOnlyDir creates one directory entry beneath root and validates the
// opened object rather than trusting path metadata.
func CreateOwnerOnlyDir(root *os.Root, _ string, name string) (*os.File, error) {
	if err := root.Mkdir(name, 0o700); err != nil {
		return nil, err
	}
	directory, err := root.Open(name)
	if err != nil {
		_ = root.Remove(name)
		return nil, err
	}
	err = ValidateOwnerOnlyDir(directory)
	if err != nil {
		directory.Close()
		_ = root.Remove(name)
		return nil, err
	}
	return directory, nil
}

func ValidateProtectedPath(path string) error {
	volume := filepath.VolumeName(path)
	relative := strings.TrimPrefix(path, volume)
	parts := strings.Split(strings.TrimPrefix(relative, string(os.PathSeparator)), string(os.PathSeparator))
	current := volume + string(os.PathSeparator)
	euid := uint32(os.Geteuid())
	for _, part := range parts {
		parent, err := os.Open(current)
		if err != nil {
			return ErrProtectionIdentity
		}
		parentInfo, statErr := parent.Stat()
		parent.Close()
		if statErr != nil {
			return ErrProtectionIdentity
		}
		parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
		if !ok || !parentInfo.IsDir() {
			return ErrProtectionIdentity
		}
		if parentInfo.Mode()&os.ModeSymlink != 0 {
			return ErrProtectionReparse
		}
		if parentStat.Uid != euid && parentStat.Uid != 0 {
			return ErrProtectionOwner
		}
		if parentInfo.Mode().Perm()&0o022 != 0 && !(parentInfo.Mode()&os.ModeSticky != 0 && (parentStat.Uid == euid || parentStat.Uid == 0)) {
			return ErrProtectionACL
		}
		next := filepath.Join(current, part)
		if parentInfo.Mode()&os.ModeSticky != 0 {
			childInfo, err := os.Lstat(next)
			if err != nil {
				return ErrProtectionIdentity
			}
			if childInfo.Mode()&os.ModeSymlink != 0 {
				return ErrProtectionReparse
			}
			childStat, ok := childInfo.Sys().(*syscall.Stat_t)
			if !ok {
				return ErrProtectionIdentity
			}
			if childStat.Uid != euid && childStat.Uid != 0 {
				return ErrProtectionOwner
			}
		}
		current = next
	}
	return nil
}

func ValidateProtectedParentFileInfo(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return ErrProtectionIdentity
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrProtectionReparse
	}
	euid := uint32(os.Geteuid())
	if stat.Uid == euid && info.Mode().Perm()&0o022 == 0 {
		return nil
	}
	if info.Mode()&os.ModeSticky != 0 && (stat.Uid == euid || stat.Uid == 0) {
		return nil
	}
	if stat.Uid != euid && stat.Uid != 0 {
		return ErrProtectionOwner
	}
	return ErrProtectionACL
}

// ValidateProtectedParent rejects parents where another unprivileged account
// can rename or delete the current user's staging entries.
func ValidateProtectedParent(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return ErrProtectionIdentity
	}
	return ValidateProtectedParentFileInfo(info)
}

func ValidateOwnerOnlyDir(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("staging directory metadata is unavailable")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("staging directory permissions are %04o, require 0700", info.Mode().Perm())
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("staging directory is not owned by the effective user")
	}
	return nil
}
