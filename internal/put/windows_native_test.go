package put

import (
	"encoding/binary"
	"testing"
)

func TestWindowsFileIdentityUsesVolumeAnd128BitID(t *testing.T) {
	id := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := windowsFileIdentity(0x1020304050607080, id); got != "windows1:1020304050607080:000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("identity=%q", got)
	}
}

func TestBuildWindowsBaseLinkInformation(t *testing.T) {
	tests := []struct {
		name, linkName                                                     string
		pointerSize, headerSize, structureSize, fileNameLength, bufferSize int
	}{
		{name: "386 one character", linkName: "x", pointerSize: 4, headerSize: 12, structureSize: 16, fileNameLength: 2, bufferSize: 16},
		{name: "386 longer name", linkName: "result.txt", pointerSize: 4, headerSize: 12, structureSize: 16, fileNameLength: 20, bufferSize: 32},
		{name: "64-bit one character", linkName: "x", pointerSize: 8, headerSize: 20, structureSize: 24, fileNameLength: 2, bufferSize: 24},
		{name: "64-bit longer name", linkName: "result.txt", pointerSize: 8, headerSize: 20, structureSize: 24, fileNameLength: 20, bufferSize: 40},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := buildWindowsLinkInformation(test.linkName, test.pointerSize, 0x01020304)
			if err != nil {
				t.Fatal(err)
			}
			rootOffset, lengthOffset := test.pointerSize, test.pointerSize+4
			if test.pointerSize == 8 {
				rootOffset, lengthOffset = 8, 16
			}
			var root uint64
			if test.pointerSize == 4 {
				root = uint64(binary.LittleEndian.Uint32(value[rootOffset:]))
			} else {
				root = binary.LittleEndian.Uint64(value[rootOffset:])
			}
			if root != 0x01020304 || binary.LittleEndian.Uint32(value[lengthOffset:]) != uint32(test.fileNameLength) || value[0] != 0 || len(value) != test.bufferSize {
				t.Fatalf("pointer=%d header=%d sizeof=%d malformed link buffer %x", test.pointerSize, test.headerSize, test.structureSize, value)
			}
			if got := binary.LittleEndian.Uint16(value[test.headerSize:]); got != uint16(test.linkName[0]) {
				t.Fatalf("first filename code unit=%#x", got)
			}
		})
	}
}

func TestClassifyWindowsPublication(t *testing.T) {
	if got := classifyWindowsPublication(true, true, true, 2); got != windowsPublicationPublished {
		t.Fatalf("published=%d", got)
	}
	if got := classifyWindowsPublication(true, false, true, 1); got != windowsPublicationNotPublished {
		t.Fatalf("not published=%d", got)
	}
	for _, got := range []windowsPublicationClass{
		classifyWindowsPublication(false, false, true, 1),
		classifyWindowsPublication(true, true, true, 1),
		classifyWindowsPublication(true, false, false, 0),
	} {
		if got != windowsPublicationUnknown {
			t.Fatalf("ambiguous classification=%d", got)
		}
	}
}

func TestClassifyWindowsReplacement(t *testing.T) {
	const oldIdentity, replacementIdentity = "old", "replacement"
	tests := []struct {
		name     string
		evidence windowsReplacementEvidence
		want     windowsPublicationClass
	}{
		{
			name: "published",
			evidence: windowsReplacementEvidence{
				DestinationKnown: true, DestinationIdentity: replacementIdentity,
				StageKnown:  true,
				BackupKnown: true, BackupIdentity: oldIdentity,
			},
			want: windowsPublicationPublished,
		},
		{
			name: "not published",
			evidence: windowsReplacementEvidence{
				DestinationKnown: true, DestinationIdentity: oldIdentity,
				StageKnown: true, StageIdentity: replacementIdentity,
				BackupKnown: true,
			},
			want: windowsPublicationNotPublished,
		},
		{
			name: "backup missing after publication",
			evidence: windowsReplacementEvidence{
				DestinationKnown: true, DestinationIdentity: replacementIdentity,
				StageKnown:  true,
				BackupKnown: true,
			},
			want: windowsPublicationUnknown,
		},
		{
			name: "inaccessible stage",
			evidence: windowsReplacementEvidence{
				DestinationKnown: true, DestinationIdentity: oldIdentity,
				BackupKnown: true,
			},
			want: windowsPublicationUnknown,
		},
		{
			name: "unexpected identities",
			evidence: windowsReplacementEvidence{
				DestinationKnown: true, DestinationIdentity: "other",
				StageKnown: true, StageIdentity: replacementIdentity,
				BackupKnown: true,
			},
			want: windowsPublicationUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyWindowsReplacement(test.evidence, oldIdentity, replacementIdentity); got != test.want {
				t.Fatalf("classification=%d want=%d", got, test.want)
			}
		})
	}
}
