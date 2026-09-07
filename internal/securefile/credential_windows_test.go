//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestValidateOwnerOnlyRejectsSharedWindowsACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-credential")
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		t.Fatal("open shared credential test file")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOwnerOnly(path); err == nil {
		t.Fatal("Everyone Windows ACL was accepted as current-user-only")
	}
}

func TestValidateOwnerOnlyRejectsUnprotectedWindowsDACL(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unprotected-credential")
	createWindowsTestFile(t, path, "D:(A;;GA;;;"+sid.String()+")")
	if err := ValidateOwnerOnly(path); err == nil {
		t.Fatal("unprotected Windows DACL was accepted")
	}
}

func TestValidateOwnerOnlyRejectsInheritedWindowsACE(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inherited-credential")
	createWindowsTestFile(t, path, "D:P(A;ID;GA;;;"+sid.String()+")")
	if err := ValidateOwnerOnly(path); err == nil {
		t.Fatal("inherited Windows ACE was accepted")
	}
}

func createWindowsTestFile(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		t.Fatal("open Windows ACL test file")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
