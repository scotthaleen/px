//go:build windows

package putroot

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateNativeRoot(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	type attributeTagInfo struct {
		Attributes uint32
		ReparseTag uint32
	}
	var info attributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	if info.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("root entry is a reparse point")
	}
	return nil
}
