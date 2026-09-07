//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func CreateOwnerOnlyDir(root *os.Root, parentPath, name string) (*os.File, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%[1]sD:P(A;OICI;GA;;;%[1]s)", sid.String()))
	if err != nil {
		return nil, fmt.Errorf("create owner-only directory descriptor: %w", err)
	}
	path, err := windows.UTF16PtrFromString(filepath.Join(parentPath, name))
	if err != nil {
		return nil, err
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(path, security); err != nil {
		return nil, err
	}
	directory, err := root.Open(name)
	if err != nil {
		_ = root.Remove(name)
		return nil, err
	}
	if err := ValidateOwnerOnlyDir(directory); err != nil {
		directory.Close()
		_ = root.Remove(name)
		return nil, err
	}
	return directory, nil
}

func ValidateProtectedParent(directory *os.File) error {
	const parentRights = uint32(0x00000002 | 0x00000004 | 0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000)
	return validateProtectedWindowsDirectory(directory, parentRights, true)
}

func validateProtectedWindowsDirectory(directory *os.File, dangerous uint32, requireTrustedOwner bool) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: destination parent is not a directory", ErrProtectionIdentity)
	}
	type attributeTagInfo struct {
		Attributes uint32
		ReparseTag uint32
	}
	var attributes attributeTagInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(directory.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&attributes)), uint32(unsafe.Sizeof(attributes))); err != nil {
		return fmt.Errorf("%w: inspect destination parent attributes failed", ErrProtectionIdentity)
	}
	if attributes.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: destination parent is a reparse point", ErrProtectionReparse)
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(directory.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("%w: inspect destination parent security failed", ErrProtectionACL)
	}
	current, err := currentUserSID()
	if err != nil {
		return err
	}
	trusted, err := trustedWindowsProtectionSIDs(current)
	if err != nil {
		return err
	}
	if requireTrustedOwner {
		owner, _, err := descriptor.Owner()
		if err != nil || !trustedWindowsSID(owner, trusted) {
			return fmt.Errorf("%w: destination parent has an untrusted owner", ErrProtectionOwner)
		}
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: destination parent has no effective DACL", ErrProtectionACL)
	}
	type rawACE struct {
		Header windows.ACE_HEADER
		Mask   uint32
	}
	const (
		accessAllowedObjectACEType         = 5
		accessDeniedObjectACEType          = 6
		accessAllowedCallbackACEType       = 9
		accessDeniedCallbackACEType        = 10
		accessAllowedCallbackObjectACEType = 11
		accessDeniedCallbackObjectACEType  = 12
	)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var value *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &value); err != nil || value == nil {
			return fmt.Errorf("%w: inspect destination parent ACL failed", ErrProtectionACL)
		}
		ace := (*rawACE)(unsafe.Pointer(value))
		if ace.Header.AceSize < uint16(unsafe.Sizeof(rawACE{})) {
			return fmt.Errorf("%w: destination parent ACL contains a malformed ACE", ErrProtectionACL)
		}
		sidOffset := uintptr(unsafe.Sizeof(rawACE{}))
		allowed := false
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedCallbackACEType:
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
			allowed = true
		case accessDeniedObjectACEType, accessDeniedCallbackObjectACEType, accessAllowedObjectACEType, accessAllowedCallbackObjectACEType:
			allowed = ace.Header.AceType == accessAllowedObjectACEType || ace.Header.AceType == accessAllowedCallbackObjectACEType
			if ace.Header.AceSize < 12 {
				return fmt.Errorf("%w: destination parent ACL contains a malformed object ACE", ErrProtectionACL)
			}
			flags := *(*uint32)(unsafe.Add(unsafe.Pointer(value), sidOffset))
			if flags & ^uint32(windows.ACE_OBJECT_TYPE_PRESENT|windows.ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 {
				return fmt.Errorf("%w: destination parent ACL contains unsupported object ACE flags", ErrProtectionACL)
			}
			sidOffset += 4
			if flags&windows.ACE_OBJECT_TYPE_PRESENT != 0 {
				sidOffset += 16
			}
			if flags&windows.ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
				sidOffset += 16
			}
		default:
			return fmt.Errorf("%w: destination parent ACL contains an unsupported ACE", ErrProtectionACL)
		}
		if sidOffset+8 > uintptr(ace.Header.AceSize) {
			return fmt.Errorf("%w: destination parent ACL contains a malformed SID", ErrProtectionACL)
		}
		sid := (*windows.SID)(unsafe.Add(unsafe.Pointer(value), sidOffset))
		if !sid.IsValid() || sidOffset+uintptr(sid.Len()) > uintptr(ace.Header.AceSize) {
			return fmt.Errorf("%w: destination parent ACL contains an invalid SID", ErrProtectionACL)
		}
		if !allowed || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if trustedWindowsSID(sid, trusted) {
			continue
		}
		if ace.Mask&dangerous != 0 {
			return fmt.Errorf("%w: destination parent grants another account replacement rights", ErrProtectionACL)
		}
	}
	return nil
}

func trustedWindowsProtectionSIDs(current *windows.SID) ([]*windows.SID, error) {
	if current == nil || !current.IsValid() {
		return nil, errors.New("current Windows user SID is unavailable")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{current, system, admins, installer}, nil
}

func trustedWindowsSID(sid *windows.SID, trusted []*windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	for _, candidate := range trusted {
		if candidate != nil && candidate.IsValid() && sid.Equals(candidate) {
			return true
		}
	}
	return false
}

func ValidateProtectedPath(path string) error {
	volume := filepath.VolumeName(path)
	current := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(strings.TrimPrefix(path, volume), string(os.PathSeparator))
	parts := strings.Split(relative, string(os.PathSeparator))
	// Ancestors need replacement/security-change protection, but may grant
	// ordinary create/write rights that do not replace an existing component.
	const ancestorRights = uint32(0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000)
	for index := 0; index <= len(parts); index++ {
		directory, err := os.Open(current)
		if err != nil {
			return ErrProtectionIdentity
		}
		err = validateProtectedWindowsDirectory(directory, ancestorRights, true)
		directory.Close()
		if err != nil {
			return err
		}
		if index < len(parts) {
			current = filepath.Join(current, parts[index])
		}
	}
	return nil
}

func ValidateOwnerOnlyDir(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("staging directory is not a non-reparse directory")
	}
	type attributeTagInfo struct {
		Attributes uint32
		ReparseTag uint32
	}
	var attributes attributeTagInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(directory.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&attributes)), uint32(unsafe.Sizeof(attributes))); err != nil || attributes.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("staging directory is a reparse point")
	}
	if err := validateCurrentUserACL(directory, "staging directory"); err != nil {
		return err
	}
	return nil
}
