//go:build linux

package put

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func nativePublicationSupported() error {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/fd", &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.Join(ErrNativeUnsupported, errors.New("procfs /proc/self/fd is unavailable"))
	}
	return nil
}

func nativeReplacementSupported() error { return nil }

func validateReplacementPlatform(file *os.File, _ *syscall.Stat_t) error {
	return validateLinuxFileMetadata(file)
}

func validateStagePlatform(file *os.File, _ *syscall.Stat_t) error {
	return validateLinuxFileMetadata(file)
}

func validateDirectoryPlatform(directory *os.File) error {
	return validateLinuxFileMetadata(directory)
}

func validateLinuxFileMetadata(file *os.File) error {
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return errors.New("filesystem metadata model is unavailable")
	}
	// ext, XFS, tmpfs, btrfs, and overlayfs have descriptor xattr enumeration
	// and the Linux inode-flags ioctl used below. Unknown models fail closed.
	switch uint64(filesystem.Type) {
	case 0xef53, 0x58465342, 0x01021994, 0x9123683e, 0x794c7630:
	default:
		return errors.Join(ErrNativeUnsupported, errors.New("filesystem metadata model is unsupported"))
	}
	count, err := unix.Flistxattr(int(file.Fd()), nil)
	if err != nil {
		return errors.New("enumerate extended attributes failed")
	}
	if count != 0 {
		return errors.New("file has extended attributes or an extended ACL")
	}
	flags, err := unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return errors.New("enumerate native flags failed")
	}
	const extentsLayoutFlag = 0x00080000
	if flags & ^extentsLayoutFlag != 0 {
		return errors.New("file has native flags")
	}
	return nil
}

func publishPinned(stage, parent *os.File, _ string, destination string) error {
	if err := nativePublicationSupported(); err != nil {
		return err
	}
	path := fmt.Sprintf("/proc/self/fd/%d", stage.Fd())
	probe, err := os.Open(path)
	if err != nil {
		return errors.Join(ErrNativeUnsupported, errors.New("procfs cannot reopen the pinned put stage"))
	}
	stageInfo, stageErr := stage.Stat()
	probeInfo, probeErr := probe.Stat()
	_ = probe.Close()
	if stageErr != nil || probeErr != nil || !os.SameFile(stageInfo, probeInfo) {
		return errors.Join(ErrNativeUnsupported, errors.New("procfs stage descriptor identity probe failed"))
	}
	return unix.Linkat(unix.AT_FDCWD, path, int(parent.Fd()), destination, unix.AT_SYMLINK_FOLLOW)
}

const nativePublicationResidual = "none: Linux follows /proc/self/fd/<pinned-stage-fd> only at the hard-link source"
