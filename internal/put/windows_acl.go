package put

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	windowsAccessAllowedACE = 0
	windowsAccessDeniedACE  = 1
	windowsObjectInheritACE = 0x01
	windowsContainerACE     = 0x02
	windowsNoPropagateACE   = 0x04
	windowsInheritOnlyACE   = 0x08
	windowsInheritedACE     = 0x10
	windowsGenericWrite     = 0x40000000
	windowsGenericAll       = 0x10000000
	windowsMaximumAllowed   = 0x02000000
	windowsFileGenericWrite = 0x00120116
	windowsFileAllAccess    = 0x001f01ff
)

func validateWindowsSecurity(owner, acl []byte, trusted [][]byte, dangerous uint32) error {
	if !validWindowsSID(owner) || !trustedWindowsSID(owner, trusted) {
		return errors.New("Windows object has an untrusted owner")
	}
	if len(acl) < 8 || acl[0] != 2 || binary.LittleEndian.Uint16(acl[2:4]) != uint16(len(acl)) {
		return errors.New("Windows object has a malformed or unsupported ACL")
	}
	offset := 8
	inherited := false
	explicitAllow := false
	for index := 0; index < int(binary.LittleEndian.Uint16(acl[4:6])); index++ {
		if offset+8 > len(acl) {
			return errors.New("Windows object ACL contains a malformed ACE")
		}
		typ, flags := acl[offset], acl[offset+1]
		size := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if size < 12 || size%4 != 0 || offset+size > len(acl) || flags & ^byte(windowsObjectInheritACE|windowsContainerACE|windowsNoPropagateACE|windowsInheritOnlyACE|windowsInheritedACE) != 0 {
			return errors.New("Windows object ACL contains a malformed ACE")
		}
		if typ != windowsAccessDeniedACE && typ != windowsAccessAllowedACE {
			return errors.New("Windows object ACL contains unsupported object, callback, conditional, or audit semantics")
		}
		aceInherited := flags&windowsInheritedACE != 0
		if inherited && !aceInherited || !aceInherited && explicitAllow && typ == windowsAccessDeniedACE {
			return errors.New("Windows object ACL is noncanonical")
		}
		if aceInherited {
			inherited = true
		} else if typ == windowsAccessAllowedACE {
			explicitAllow = true
		}
		sid := acl[offset+8 : offset+size]
		if !validWindowsSID(sid) || len(sid) != size-8 {
			return errors.New("Windows object ACL contains an invalid SID")
		}
		if typ == windowsAccessAllowedACE && flags&windowsInheritOnlyACE == 0 && !trustedWindowsSID(sid, trusted) {
			mask := binary.LittleEndian.Uint32(acl[offset+4 : offset+8])
			if mask&windowsMaximumAllowed != 0 {
				return errors.New("Windows object ACL grants unprovable maximum access")
			}
			if mask&windowsGenericWrite != 0 {
				mask |= windowsFileGenericWrite
			}
			if mask&windowsGenericAll != 0 {
				mask |= windowsFileAllAccess
			}
			if mask&dangerous != 0 {
				return errors.New("Windows object grants an untrusted principal mutation authority")
			}
		}
		offset += size
	}
	if offset != len(acl) {
		return errors.New("Windows object ACL has unparsed data")
	}
	return nil
}

func validWindowsSID(sid []byte) bool {
	return len(sid) >= 8 && sid[0] == 1 && sid[1] <= 15 && len(sid) == 8+4*int(sid[1])
}

func trustedWindowsSID(sid []byte, trusted [][]byte) bool {
	for _, candidate := range trusted {
		if bytes.Equal(sid, candidate) {
			return true
		}
	}
	return false
}

func validateWindowsResourceAttributeACL(acl []byte) (string, error) {
	if len(acl) < 8 || acl[0] != 2 || binary.LittleEndian.Uint16(acl[2:4]) != uint16(len(acl)) {
		return "", errors.New("replacement destination security resource attributes are malformed")
	}
	offset := 8
	count := binary.LittleEndian.Uint16(acl[4:6])
	for range count {
		if offset+4 > len(acl) {
			return "", errors.New("replacement destination security resource attributes are malformed")
		}
		size := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if acl[offset] != 0x12 || size < 20 || size%4 != 0 || offset+size > len(acl) {
			return "", errors.New("replacement destination has unsupported security resource attributes")
		}
		ace := acl[offset : offset+size]
		sidLength, ok := windowsResourceSIDLength(ace[8:])
		if !ok || 8+sidLength+20 > len(ace) || !validWindowsResourceClaim(ace[8+sidLength:]) {
			return "", errors.New("replacement destination security resource attributes are malformed")
		}
		offset += size
	}
	if offset != len(acl) {
		return "", errors.New("replacement destination security resource attributes are malformed")
	}
	if count == 0 {
		return "", nil
	}
	digest := sha256.Sum256(acl)
	return hex.EncodeToString(digest[:]), nil
}

func windowsResourceSIDLength(value []byte) (int, bool) {
	if len(value) < 8 || value[0] != 1 || value[1] > 15 {
		return 0, false
	}
	length := 8 + 4*int(value[1])
	return length, length <= len(value)
}

func validWindowsResourceClaim(claim []byte) bool {
	if len(claim) < 20 {
		return false
	}
	nameOffset := int(binary.LittleEndian.Uint32(claim[0:4]))
	valueType := binary.LittleEndian.Uint16(claim[4:6])
	reserved := binary.LittleEndian.Uint16(claim[6:8])
	count := int(binary.LittleEndian.Uint32(claim[12:16]))
	if reserved != 0 || count < 1 || count > (len(claim)-16)/4 || nameOffset < 16+count*4 || nameOffset%2 != 0 || !boundedWindowsUTF16(claim, nameOffset) {
		return false
	}
	switch valueType {
	case 1, 2, 6: // Signed integer, unsigned integer, or boolean values.
		for index := range count {
			offset := int(binary.LittleEndian.Uint32(claim[16+index*4:]))
			if offset%8 != 0 || offset < 16+count*4 || offset > len(claim)-8 {
				return false
			}
		}
		return true
	case 3: // UTF-16 string offsets.
		for index := range count {
			offset := int(binary.LittleEndian.Uint32(claim[16+index*4:]))
			if offset%2 != 0 || offset < 16+count*4 || !boundedWindowsUTF16(claim, offset) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func boundedWindowsUTF16(value []byte, offset int) bool {
	if offset < 0 || offset+2 > len(value) {
		return false
	}
	for index := offset; index+2 <= len(value); index += 2 {
		if binary.LittleEndian.Uint16(value[index:index+2]) == 0 {
			return index > offset
		}
	}
	return false
}
