package put

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf16"
)

type windowsPublicationClass uint8

const (
	windowsPublicationUnknown windowsPublicationClass = iota
	windowsPublicationNotPublished
	windowsPublicationPublished
)

type windowsReplacementEvidence struct {
	DestinationKnown, StageKnown, BackupKnown          bool
	DestinationIdentity, StageIdentity, BackupIdentity string
}

func windowsFileIdentity(volume uint64, id [16]byte) string {
	return fmt.Sprintf("windows1:%016x:%s", volume, hex.EncodeToString(id[:]))
}

func classifyWindowsPublication(destinationKnown, destinationMatches, stageKnown bool, stageLinks uint32) windowsPublicationClass {
	if destinationKnown && destinationMatches && stageKnown && stageLinks == 2 {
		return windowsPublicationPublished
	}
	if destinationKnown && !destinationMatches && stageKnown && stageLinks == 1 {
		return windowsPublicationNotPublished
	}
	return windowsPublicationUnknown
}

func classifyWindowsReplacement(evidence windowsReplacementEvidence, oldIdentity, replacementIdentity string) windowsPublicationClass {
	if evidence.DestinationKnown && evidence.DestinationIdentity == replacementIdentity &&
		evidence.StageKnown && evidence.StageIdentity == "" &&
		evidence.BackupKnown && evidence.BackupIdentity == oldIdentity {
		return windowsPublicationPublished
	}
	if evidence.DestinationKnown && evidence.DestinationIdentity == oldIdentity &&
		evidence.StageKnown && evidence.StageIdentity == replacementIdentity &&
		evidence.BackupKnown && evidence.BackupIdentity == "" {
		return windowsPublicationNotPublished
	}
	return windowsPublicationUnknown
}

func buildWindowsLinkInformation(name string, pointerSize int, root uint64) ([]byte, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return nil, errors.New("unsupported Windows pointer size")
	}
	encoded := utf16.Encode([]rune(name))
	if len(encoded) == 0 || len(encoded) > 255 {
		return nil, errors.New("invalid Windows link name")
	}
	headerSize, structureSize := 12, 16
	if pointerSize == 8 {
		headerSize, structureSize = 20, 24
	}
	bufferSize := headerSize + len(encoded)*2
	if bufferSize < structureSize {
		bufferSize = structureSize
	}
	value := make([]byte, bufferSize)
	if pointerSize == 4 {
		binary.LittleEndian.PutUint32(value[4:8], uint32(root))
		binary.LittleEndian.PutUint32(value[8:12], uint32(len(encoded)*2))
	} else {
		binary.LittleEndian.PutUint64(value[8:16], root)
		binary.LittleEndian.PutUint32(value[16:20], uint32(len(encoded)*2))
	}
	for index, code := range encoded {
		binary.LittleEndian.PutUint16(value[headerSize+index*2:], code)
	}
	return value, nil
}
