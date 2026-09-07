//go:build windows

package getcleanup

import (
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsFileIDInfo struct {
	VolumeSerial uint64
	FileID       [16]byte
}

func directoryIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errInvalidIdentity
	}
	type attributeTagInfo struct {
		Attributes uint32
		ReparseTag uint32
	}
	var attributes attributeTagInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&attributes)), uint32(unsafe.Sizeof(attributes))); err != nil || attributes.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errInvalidIdentity
	}
	var value windowsFileIDInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value))); err != nil {
		return "", errInvalidIdentity
	}
	return fmt.Sprintf("windows1:%016x:%s", value.VolumeSerial, hex.EncodeToString(value.FileID[:])), nil
}
