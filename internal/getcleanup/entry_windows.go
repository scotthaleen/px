//go:build windows

package getcleanup

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func safeRegular(root *os.Root, name string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	file, err := root.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	type attributeTagInfo struct {
		Attributes uint32
		ReparseTag uint32
	}
	var attributes attributeTagInfo
	return windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&attributes)), uint32(unsafe.Sizeof(attributes))) == nil && attributes.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
