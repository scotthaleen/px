//go:build !windows

package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func CreateExclusive(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateOpenedUnix(file); err != nil {
		file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func ValidateOwnerOnly(path string) error {
	file, err := openOwnerOnly(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func ReadOwnerOnly(path string) ([]byte, error) {
	file, err := openOwnerOnly(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func openOwnerOnly(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("open owner-only credential file")
	}
	if err := validateOpenedUnix(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenedUnix(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("credential file owner is unavailable")
	}
	return validateUnixMetadata(info.Mode(), stat.Uid, uint32(os.Geteuid()))
}

func validateUnixMetadata(mode os.FileMode, ownerUID, effectiveUID uint32) error {
	if !mode.IsRegular() {
		return errors.New("credential path is not a regular file")
	}
	if mode.Perm() != 0o600 {
		return fmt.Errorf("credential file permissions are %04o, require 0600", mode.Perm())
	}
	if ownerUID != effectiveUID {
		return errors.New("credential file is not owned by the effective user")
	}
	return nil
}
