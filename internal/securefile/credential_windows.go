//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateExclusive(path string) (*os.File, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%[1]sD:P(A;;GA;;;%[1]s)", sid.String()))
	if err != nil {
		return nil, fmt.Errorf("create owner-only credential descriptor: %w", err)
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		_ = os.Remove(path)
		return nil, errors.New("open owner-only credential file")
	}
	if err := validateOpenedWindows(file); err != nil {
		file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func ValidateOwnerOnly(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return validateOpenedWindows(file)
}

func ReadOwnerOnly(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := validateOpenedWindows(file); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func validateOpenedWindows(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("credential path is not a regular file")
	}
	return validateCurrentUserACL(file, "credential file")
}

func validateCurrentUserACL(file *os.File, description string) error {
	want, err := currentUserSID()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect %s ACL: %w", description, err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("%s has no valid security descriptor", description)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s DACL is not protected from inheritance", description)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(want) {
		return fmt.Errorf("%s is not owned by the current Windows user", description)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf("%s ACL must contain exactly one current-user grant", description)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return fmt.Errorf("%s ACL is not one current-user allow grant", description)
	}
	if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		return fmt.Errorf("%s ACL contains an inherited grant", description)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(want) {
		return fmt.Errorf("%s ACL grants another principal", description)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user.User.Sid == nil {
		return nil, errors.New("current Windows user has no SID")
	}
	return user.User.Sid, nil
}
