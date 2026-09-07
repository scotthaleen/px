package put

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestValidateWindowsSecurity(t *testing.T) {
	owner := testWindowsSID(1000)
	trusted := [][]byte{owner, testWindowsSID(18), testWindowsSID(544)}
	readers := testWindowsSID(545)
	const dangerous = uint32(0x00010000 | 0x00040000 | 0x00080000 | 0x00000002 | 0x00000004)
	tests := []struct {
		name string
		acl  []byte
		ok   bool
	}{
		{name: "trusted write and untrusted read", acl: testWindowsACL(testWindowsACE(0, 0, windowsGenericAll, owner), testWindowsACE(0, windowsInheritedACE, 0x00120089, readers)), ok: true},
		{name: "untrusted write", acl: testWindowsACL(testWindowsACE(0, 0, windowsGenericWrite, readers))},
		{name: "untrusted maximum", acl: testWindowsACL(testWindowsACE(0, 0, windowsMaximumAllowed, readers))},
		{name: "inherit only checked on child instead", acl: testWindowsACL(testWindowsACE(0, windowsInheritOnlyACE|windowsObjectInheritACE, windowsGenericAll, readers)), ok: true},
		{name: "inherited parent allow before grandparent deny", acl: testWindowsACL(testWindowsACE(0, windowsInheritedACE, 0x00120089, readers), testWindowsACE(1, windowsInheritedACE, dangerous, readers)), ok: true},
		{name: "inherited deny does not excuse dangerous allow", acl: testWindowsACL(testWindowsACE(0, windowsInheritedACE, windowsGenericWrite, readers), testWindowsACE(1, windowsInheritedACE, windowsGenericWrite, readers))},
		{name: "noncanonical", acl: testWindowsACL(testWindowsACE(0, 0, 1, owner), testWindowsACE(1, 0, dangerous, readers))},
		{name: "explicit after inherited", acl: testWindowsACL(testWindowsACE(0, windowsInheritedACE, 1, owner), testWindowsACE(0, 0, 1, owner))},
		{name: "callback rejected", acl: testWindowsACL(testWindowsACE(9, 0, 1, owner))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWindowsSecurity(owner, test.acl, trusted, dangerous)
			if (err == nil) != test.ok {
				t.Fatalf("validation error=%v, want success=%t", err, test.ok)
			}
		})
	}
	if err := validateWindowsSecurity(readers, testWindowsACL(), trusted, dangerous); err == nil {
		t.Fatal("untrusted owner accepted")
	}
}

func TestValidateWindowsResourceAttributeACL(t *testing.T) {
	imageLoad, err := hex.DecodeString("02004c00010000001210440000000000010100000000000100000000140000000200000000000000010000002800000049004d004100470045004c004f004100440000000100000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if evidence, err := validateWindowsResourceAttributeACL(imageLoad); err != nil || len(evidence) != 64 {
		t.Fatalf("IMAGELOAD evidence=%q err=%v", evidence, err)
	}
	claim := make([]byte, 64)
	binary.LittleEndian.PutUint32(claim[0:4], 24)
	binary.LittleEndian.PutUint16(claim[4:6], 2)
	binary.LittleEndian.PutUint32(claim[12:16], 2)
	binary.LittleEndian.PutUint32(claim[16:20], 48)
	binary.LittleEndian.PutUint32(claim[20:24], 56)
	copy(claim[24:], []byte{'I', 0, 'M', 0, 'A', 0, 'G', 0, 'E', 0, 'L', 0, 'O', 0, 'A', 0, 'D', 0})
	binary.LittleEndian.PutUint64(claim[48:56], 1)
	binary.LittleEndian.PutUint64(claim[56:64], 2)
	ace := append(testWindowsACE(0x12, 0, 0, testWindowsSID(1000)), claim...)
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	multiValue := testWindowsACL(ace)
	if evidence, err := validateWindowsResourceAttributeACL(multiValue); err != nil || len(evidence) != 64 {
		t.Fatalf("multi-value evidence=%q err=%v", evidence, err)
	}
	if evidence, err := validateWindowsResourceAttributeACL(testWindowsACL()); err != nil || evidence != "" {
		t.Fatalf("empty evidence=%q err=%v", evidence, err)
	}
	for name, acl := range map[string][]byte{
		"non-resource ACE": testWindowsACL(testWindowsACE(0, 0, 0, testWindowsSID(1000))),
		"truncated ACE":    {2, 0, 12, 0, 1, 0, 0, 0, 0x12, 0, 20, 0},
		"invalid claim":    testWindowsACL(testWindowsACE(0x12, 0, 0, testWindowsSID(1000))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateWindowsResourceAttributeACL(acl); err == nil {
				t.Fatal("unsafe resource attribute ACL accepted")
			}
		})
	}
}

func testWindowsSID(rid uint32) []byte {
	value := make([]byte, 12)
	value[0], value[1], value[7] = 1, 1, 5
	binary.LittleEndian.PutUint32(value[8:], rid)
	return value
}

func testWindowsACE(typ, flags byte, mask uint32, sid []byte) []byte {
	value := make([]byte, 8+len(sid))
	value[0], value[1] = typ, flags
	binary.LittleEndian.PutUint16(value[2:], uint16(len(value)))
	binary.LittleEndian.PutUint32(value[4:], mask)
	copy(value[8:], sid)
	return value
}

func testWindowsACL(aces ...[]byte) []byte {
	size := 8
	for _, ace := range aces {
		size += len(ace)
	}
	value := make([]byte, size)
	value[0] = 2
	binary.LittleEndian.PutUint16(value[2:], uint16(size))
	binary.LittleEndian.PutUint16(value[4:], uint16(len(aces)))
	offset := 8
	for _, ace := range aces {
		copy(value[offset:], ace)
		offset += len(ace)
	}
	return value
}
