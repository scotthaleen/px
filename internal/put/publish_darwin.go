//go:build darwin

package put

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	attrCMNExtendedSecurity = 0x00400000
	attrCMNReturnedAttrs    = 0x80000000
	kauthFileSecMagic       = 0x012cc16d
	kauthFileSecNoACL       = ^uint32(0)

	attributeResponsePrefixSize = 4 + 5*4 + 8
	kauthFileSecHeaderSize      = 44
	kauthACESize                = 24
	kauthACLMaxEntries          = 128
	attributeResponseBufferSize = attributeResponsePrefixSize + kauthFileSecHeaderSize + kauthACLMaxEntries*kauthACESize
)

func publishPinned(_ *os.File, parent *os.File, stageName, destination string) error {
	// Darwin has no AT_EMPTY_PATH equivalent. Protected ancestry excludes other
	// accounts; the stage entry is identity-checked immediately before linkat and
	// the destination is identity-checked immediately afterward. A process with
	// the same credential can still race the source name and force outcome_unknown.
	return unix.Linkat(int(parent.Fd()), stageName, int(parent.Fd()), destination, 0)
}

func nativePublicationSupported() error { return nil }

func nativeReplacementSupported() error { return nil }

func validateReplacementPlatform(file *os.File, stat *syscall.Stat_t) error {
	return validateDarwinFileMetadata(file, stat)
}

func validateStagePlatform(file *os.File, stat *syscall.Stat_t) error {
	return validateDarwinFileMetadata(file, stat)
}

func validateDirectoryPlatform(directory *os.File) error {
	if err := requireAPFS(directory); err != nil {
		return err
	}
	return validateDarwinACL(directory, true)
}

func validateDarwinFileMetadata(file *os.File, stat *syscall.Stat_t) error {
	if stat.Flags != 0 {
		return errors.New("file has native flags")
	}
	if err := requireAPFS(file); err != nil {
		return err
	}
	if err := validateDarwinACL(file, true); err != nil {
		return err
	}
	return validateDarwinXattrs(file)
}

func requireAPFS(file *os.File) error {
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &filesystem); err != nil {
		return errors.New("filesystem metadata model is unavailable")
	}
	if filesystemTypeName(filesystem.Fstypename) != "apfs" {
		return errors.Join(ErrNativeUnsupported, errors.New("filesystem metadata model is unsupported"))
	}
	// XNU's vfs_attrlist omits ATTR_CMN_EXTENDED_SECURITY, its attrreference,
	// and payload when va_acl is absent. Accept that fixed 32-byte response only
	// after this descriptor's Fstatfs has conclusively identified APFS.
	return nil
}

func validateDarwinXattrs(file *os.File) error {
	count, err := unix.Flistxattr(int(file.Fd()), nil)
	if err != nil {
		return errors.New("enumerate replacement destination extended attributes failed")
	}
	if count == 0 {
		return nil
	}
	buffer := make([]byte, count)
	count, err = unix.Flistxattr(int(file.Fd()), buffer)
	if err != nil || count != len(buffer) {
		return errors.New("enumerate replacement destination extended attributes failed")
	}
	for _, name := range bytes.Split(buffer, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		// macOS attaches this kernel-maintained provenance marker to ordinary
		// process-created files on some systems. It carries no ACL or write
		// authority and may be non-removable; every other xattr fails closed.
		if string(name) != "com.apple.provenance" {
			return errors.New("replacement destination has extended attributes")
		}
	}
	return nil
}

func validateDarwinACL(file *os.File, allowAbsentAPFSACL bool) error {
	attributes := unix.Attrlist{
		Bitmapcount: 5,
		Commonattr:  attrCMNReturnedAttrs | attrCMNExtendedSecurity,
	}
	buffer := make([]byte, attributeResponseBufferSize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FGETATTRLIST,
		file.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
		0,
	)
	runtime.KeepAlive(file)
	runtime.KeepAlive(&attributes)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return errors.New("enumerate replacement destination extended ACL failed")
	}
	return parseDarwinACLResponse(buffer, allowAbsentAPFSACL)
}

func parseDarwinACLResponse(buffer []byte, allowAbsentAPFSACL bool) error {
	if len(buffer) < attributeResponsePrefixSize {
		return errors.New("replacement destination extended ACL response is truncated")
	}
	totalLength := uint64(binary.LittleEndian.Uint32(buffer[0:4]))
	if totalLength < attributeResponsePrefixSize || totalLength > uint64(len(buffer)) || totalLength%4 != 0 {
		return errors.New("replacement destination extended ACL response has invalid length")
	}
	returnedCommon := binary.LittleEndian.Uint32(buffer[4:8])
	returnedVolume := binary.LittleEndian.Uint32(buffer[8:12])
	returnedDirectory := binary.LittleEndian.Uint32(buffer[12:16])
	returnedFile := binary.LittleEndian.Uint32(buffer[16:20])
	returnedFork := binary.LittleEndian.Uint32(buffer[20:24])
	if returnedVolume != 0 || returnedDirectory != 0 || returnedFile != 0 || returnedFork != 0 {
		return errors.New("replacement destination extended ACL response has unexpected attributes")
	}
	if returnedCommon == attrCMNReturnedAttrs {
		// The caller may allow XNU's fixed no-va_acl omission only after proving
		// the descriptor is on APFS. Every other missing or partial form fails.
		if allowAbsentAPFSACL && totalLength == attributeResponsePrefixSize && binary.LittleEndian.Uint64(buffer[24:32]) == 0 {
			return nil
		}
		return errors.New("replacement destination extended ACL attribute was not returned")
	}
	if returnedCommon != attrCMNReturnedAttrs|attrCMNExtendedSecurity {
		return errors.New("replacement destination extended ACL attribute was not returned")
	}

	referenceOffset := int64(int32(binary.LittleEndian.Uint32(buffer[24:28])))
	payloadLength := uint64(binary.LittleEndian.Uint32(buffer[28:32]))
	payloadStart := int64(24) + referenceOffset
	if referenceOffset%4 != 0 || payloadStart != attributeResponsePrefixSize || payloadLength%4 != 0 ||
		payloadLength > totalLength-attributeResponsePrefixSize || uint64(payloadStart)+payloadLength != totalLength {
		return errors.New("replacement destination extended ACL response has invalid reference")
	}
	payload := buffer[payloadStart:totalLength]
	if len(payload) < kauthFileSecHeaderSize || binary.LittleEndian.Uint32(payload[0:4]) != kauthFileSecMagic {
		return errors.New("replacement destination extended ACL payload is malformed")
	}
	entryCount := binary.LittleEndian.Uint32(payload[36:40])
	if entryCount == kauthFileSecNoACL {
		if len(payload) != kauthFileSecHeaderSize {
			return errors.New("replacement destination extended ACL payload is malformed")
		}
		return nil
	}
	if entryCount > kauthACLMaxEntries || uint64(len(payload)) != kauthFileSecHeaderSize+uint64(entryCount)*kauthACESize {
		return errors.New("replacement destination extended ACL payload is malformed")
	}
	return errors.New("replacement destination has an extended ACL")
}

func filesystemTypeName(name [16]byte) string {
	length := 0
	for length < len(name) && name[length] != 0 {
		length++
	}
	return string(name[:length])
}

const nativePublicationResidual = "Darwin publication has a same-credential source-name race; identity mismatch is outcome_unknown"
