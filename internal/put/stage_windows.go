//go:build windows

package put

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsParentDangerous   = uint32(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x00000040 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)
	windowsAncestorDangerous = uint32(0x00000040 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)
	windowsStageDangerous    = uint32(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)
	windowsTraversalAccess   = uint32(0x00000020 | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE)
	windowsFileAddFile       = uint32(windows.FILE_WRITE_DATA) // Directory-specific alias for this access bit.
	windowsFinalParentAccess = windowsTraversalAccess | windows.FILE_LIST_DIRECTORY | windowsFileAddFile
	windowsMetadataAccess    = uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.DELETE | windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER)
	windowsBaseLinkClass     = 11
	windowsAlternateNameInfo = 21
	maxWindowsParentNames    = 4096
	maxWindowsStreamInfo     = 64 << 10
	windowsReplacementAttrs  = uint32(windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
	windowsTrustedInstaller  = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

var (
	ntdll                        = windows.NewLazySystemDLL("ntdll.dll")
	ntFlushBuffersFileEx         = ntdll.NewProc("NtFlushBuffersFileEx")
	ntQueryVolumeInformationFile = ntdll.NewProc("NtQueryVolumeInformationFile")
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	replaceFileW                 = kernel32.NewProc("ReplaceFileW")
	setFileShortNameW            = kernel32.NewProc("SetFileShortNameW")
)

type windowsFileIDInfo struct {
	VolumeSerial uint64
	FileID       [16]byte
}

type windowsFileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
	_              [2]byte
}

type windowsAttributeTagInfo struct {
	Attributes uint32
	ReparseTag uint32
}

type windowsFileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	Attributes                                              uint32
	_                                                       uint32
}

type windowsNativeInfo struct {
	identity   string
	links      uint32
	directory  bool
	attributes uint32
	deleting   bool
}

type openedParent struct {
	anchorPath string
	anchorGUID string
	path       string
	components []string
	dirs       []*os.File
	identities []string
}

type Stage struct {
	File                                       *os.File
	Name, Identity, ParentPath, ParentIdentity string
	parent                                     *openedParent
	oldDestination                             *os.File
	record                                     Record
	cleanupLinks                               uint32
}

type replacementEvidence struct {
	Identity string
	Metadata string
	UID      uint32
	GID      uint32
	Mode     uint32
	Size     int64
}

func nativeReceiveSupported() error {
	if err := ntFlushBuffersFileEx.Find(); err != nil {
		return errors.Join(ErrNativeUnsupported, errors.New("NtFlushBuffersFileEx is unavailable"))
	}
	if err := ntQueryVolumeInformationFile.Find(); err != nil {
		return errors.Join(ErrNativeUnsupported, errors.New("NtQueryVolumeInformationFile is unavailable"))
	}
	return nil
}

func nativeReplacementSupported() error {
	if err := nativeReceiveSupported(); err != nil {
		return err
	}
	if err := replaceFileW.Find(); err != nil {
		return errors.Join(ErrNativeUnsupported, errors.New("ReplaceFileW is unavailable"))
	}
	return nil
}

func openDestinationParent(root, destination string, requireAbsent bool) (*openedParent, error) {
	parts := strings.Split(filepath.ToSlash(destination), "/")
	volume := filepath.VolumeName(root)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(root) {
		return nil, errors.Join(ErrNativeUnsupported, errors.New("Windows put root must be an absolute drive-letter path"))
	}
	volumeRoot := volume + `\`
	rootRelative, err := filepath.Rel(volumeRoot, filepath.Clean(root))
	if err != nil || rootRelative == ".." || strings.HasPrefix(rootRelative, `..\`) {
		return nil, ErrUnsafeState
	}
	components := make([]string, 0, len(parts)+8)
	if rootRelative != "." {
		components = append(components, strings.Split(rootRelative, `\`)...)
	}
	components = append(components, parts[:len(parts)-1]...)
	anchorAccess := windowsTraversalAccess
	if len(components) == 0 {
		anchorAccess = windowsFinalParentAccess
	}
	rootFile, err := ntOpenVolumeRoot(volumeRoot, anchorAccess)
	if err != nil {
		if ntStatusIs(err, windows.STATUS_ACCESS_DENIED) {
			return nil, errors.New("Windows put destination parent is not writable")
		}
		return nil, classifyWindowsOpenError(err, "Windows put volume anchor is unavailable or unsafe")
	}
	result := &openedParent{anchorPath: volumeRoot, path: volumeRoot, components: components, dirs: []*os.File{rootFile}}
	if err := requireNTFS(rootFile); err != nil {
		result.Close()
		return nil, err
	}
	if err := requireWindowsVolumeRoot(rootFile); err != nil {
		result.Close()
		return nil, err
	}
	result.anchorGUID, err = windowsVolumeGUIDPath(rootFile)
	if err != nil || !windowsVolumeGUIDRoot(result.anchorGUID) {
		result.Close()
		return nil, errors.Join(ErrNativeUnsupported, errors.New("Windows put volume GUID identity is unavailable"))
	}
	anchorDangerous := windowsAncestorDangerous
	if len(components) == 0 {
		anchorDangerous = windowsParentDangerous
	}
	if err := result.captureDirectory(rootFile, anchorDangerous); err != nil {
		result.Close()
		return nil, err
	}
	current := rootFile
	for index, component := range components {
		access := windowsTraversalAccess
		dangerous := windowsAncestorDangerous
		if index == len(components)-1 {
			access = windowsFinalParentAccess
			dangerous = windowsParentDangerous
		}
		next, openErr := ntOpenRelative(current, component, access, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE)
		if openErr != nil {
			result.Close()
			return nil, classifyWindowsOpenError(openErr, "put parent is missing, unsafe, or not writable")
		}
		current = next
		result.dirs = append(result.dirs, current)
		result.path = filepath.Join(result.path, component)
		if err := result.captureDirectory(current, dangerous); err != nil {
			result.Close()
			return nil, err
		}
	}
	if err := flushWindowsHandle(windows.Handle(result.Parent().Fd())); err != nil {
		result.Close()
		if ntStatusIs(err, windows.STATUS_ACCESS_DENIED) {
			return nil, errors.New("Windows put destination parent cannot be synchronized")
		}
		return nil, errors.Join(ErrNativeUnsupported, errors.New("Windows put destination parent does not support directory synchronization"))
	}
	if requireAbsent {
		if err := rejectWindowsCaseCollision(result.Parent(), parts[len(parts)-1]); err != nil {
			result.Close()
			return nil, err
		}
	}
	return result, nil
}

func (p *openedParent) captureDirectory(directory *os.File, dangerous uint32) error {
	info, err := windowsHandleInfo(directory)
	if err != nil || !info.directory {
		return errors.New("put ancestry is not a non-reparse directory")
	}
	if err := validateProtectedWindowsHandle(directory, dangerous); err != nil {
		return errors.New("put ancestry ownership or DACL is unsafe")
	}
	p.identities = append(p.identities, info.identity)
	return nil
}

func (p *openedParent) Parent() *os.File { return p.dirs[len(p.dirs)-1] }

func parentDurableIdentity(parent *openedParent) string {
	return strings.ToLower(parent.anchorGUID) + "|" + parent.identities[len(parent.identities)-1]
}

func parentMatchesIdentity(parent *openedParent, identity string) bool {
	return identity == parentDurableIdentity(parent)
}

func (p *openedParent) Revalidate() error {
	if len(p.dirs) == 0 || len(p.dirs) != len(p.identities) {
		return ErrUnsafeState
	}
	anchorAccess := windowsTraversalAccess
	if len(p.components) == 0 {
		anchorAccess = windowsFinalParentAccess
	}
	root, err := ntOpenVolumeRoot(p.anchorPath, anchorAccess)
	if err != nil {
		if errors.Is(classifyWindowsOpenError(err, ""), errNativeRetryable) {
			return errNativeRetryable
		}
		return ErrUnsafeState
	}
	rootInfo, rootErr := windowsHandleInfo(root)
	rootNameErr := requireWindowsVolumeRoot(root)
	rootGUID, rootGUIDErr := windowsVolumeGUIDPath(root)
	_ = root.Close()
	if rootErr != nil || rootNameErr != nil || rootGUIDErr != nil || !strings.EqualFold(rootGUID, p.anchorGUID) || rootInfo.identity != p.identities[0] {
		return ErrUnsafeState
	}
	for index, directory := range p.dirs {
		info, infoErr := windowsHandleInfo(directory)
		dangerous := windowsAncestorDangerous
		if index == len(p.dirs)-1 {
			dangerous = windowsParentDangerous
		}
		if infoErr != nil || !info.directory || info.identity != p.identities[index] || validateProtectedWindowsHandle(directory, dangerous) != nil {
			return ErrUnsafeState
		}
		if index > 0 {
			entry, openErr := ntOpenRelative(p.dirs[index-1], p.components[index-1], windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE)
			if openErr != nil {
				if errors.Is(classifyWindowsOpenError(openErr, ""), errNativeRetryable) {
					return errNativeRetryable
				}
				return ErrUnsafeState
			}
			entryInfo, entryErr := windowsHandleInfo(entry)
			_ = entry.Close()
			if entryErr != nil || entryInfo.identity != info.identity {
				return ErrUnsafeState
			}
		}
	}
	return nil
}

func (p *openedParent) Close() error {
	var result error
	for index := len(p.dirs) - 1; index >= 0; index-- {
		result = errors.Join(result, p.dirs[index].Close())
	}
	p.dirs = nil
	return result
}

func validateCreateDestination(parent *openedParent, destination string) error {
	return rejectWindowsCaseCollision(parent.Parent(), destination)
}

func createOrOpenStage(parent *openedParent, _ Manifest, record Record) (*Stage, bool, error) {
	if record.StageName == "" || record.ParentPath != parent.path || !parentMatchesIdentity(parent, record.ParentIdentity) || record.Mode != "create" && record.Mode != "replace" {
		return nil, false, ErrUnsafeState
	}
	var oldDestination *os.File
	if record.Mode == "replace" {
		if record.BackupName == "" || record.BackupIdentity != record.OldIdentity || record.BackupSize < 0 {
			return nil, false, ErrUnsafeState
		}
		var evidence replacementEvidence
		var err error
		oldDestination, evidence, err = openWindowsReplacementDestination(parent, filepath.Base(filepath.FromSlash(record.Destination)))
		if err != nil || evidence.Identity != record.OldIdentity || evidence.Metadata != record.OldMetadata || evidence.Size != record.BackupSize {
			if oldDestination != nil {
				_ = oldDestination.Close()
			}
			if errors.Is(err, errNativeRetryable) {
				return nil, false, err
			}
			return nil, false, ErrUnsafeState
		}
		if err := rejectWindowsCaseCollision(parent.Parent(), record.BackupName); err != nil {
			_ = oldDestination.Close()
			return nil, false, err
		}
	}
	attachIdentity := record.StageIdentity == ""
	disposition := uint32(windows.FILE_OPEN)
	if attachIdentity {
		disposition = windows.FILE_CREATE
	}
	file, err := ntOpenRelative(parent.Parent(), record.StageName, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL, disposition, windows.FILE_NON_DIRECTORY_FILE)
	if attachIdentity && ntStatusIs(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		file, err = ntOpenRelative(parent.Parent(), record.StageName, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	}
	if err != nil {
		if oldDestination != nil {
			_ = oldDestination.Close()
		}
		if errors.Is(classifyWindowsOpenError(err, ""), errNativeRetryable) {
			return nil, false, errNativeRetryable
		}
		return nil, false, errors.New("open exact-parent Windows put stage failed")
	}
	identity, validationErr := validateWindowsStage(file, 1)
	if validationErr != nil || record.StageIdentity != "" && identity != record.StageIdentity {
		_ = file.Close()
		if oldDestination != nil {
			_ = oldDestination.Close()
		}
		if validationErr != nil {
			return nil, false, validationErr
		}
		return nil, false, ErrUnsafeState
	}
	stage := &Stage{File: file, Name: record.StageName, Identity: identity, ParentPath: parent.path, ParentIdentity: record.ParentIdentity, parent: parent, oldDestination: oldDestination, record: record, cleanupLinks: 1}
	if err := validateWindowsEntry(parent.Parent(), stage.Name, stage.Identity, 1); err != nil {
		stage.Close()
		return nil, false, err
	}
	if err := file.Truncate(0); err != nil {
		stage.Close()
		return nil, false, errors.New("truncate validated Windows put stage failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		stage.Close()
		return nil, false, errors.New("rewind validated Windows put stage failed")
	}
	return stage, attachIdentity, nil
}

func (s *Stage) VerifyContent(ctx context.Context, manifest Manifest) error {
	if s.File == nil || s.parent == nil {
		return ErrUnsafeState
	}
	if err := s.parent.Revalidate(); err != nil {
		return err
	}
	if identity, err := validateWindowsStage(s.File, 1); err != nil || identity != s.Identity {
		return ErrUnsafeState
	}
	if err := validateWindowsEntry(s.parent.Parent(), s.Name, s.Identity, 1); err != nil {
		return err
	}
	info, err := windowsHandleInfo(s.File)
	if err != nil || info.directory || info.links != 1 {
		return errors.New("put stage metadata changed")
	}
	stat, err := s.File.Stat()
	if err != nil || stat.Size() != manifest.Size {
		return errors.New("put stage size does not match manifest")
	}
	if _, err := s.File.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind put stage for verification failed")
	}
	hasher := sha256.New()
	if _, err := io.CopyN(&contextWriter{ctx: ctx, writer: hasher}, s.File, manifest.Size); err != nil {
		return errors.New("read put stage for verification failed")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != manifest.SHA256 {
		return errors.New("put stage digest does not match manifest")
	}
	if _, err := s.File.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind verified put stage failed")
	}
	return nil
}

func (s *Stage) Publish(ctx context.Context, destination string, manifest Manifest) (bool, string, error) {
	if s.File == nil || s.parent == nil {
		return false, "", ErrUnsafeState
	}
	if err := s.parent.Revalidate(); err != nil {
		if errors.Is(err, errNativeRetryable) {
			return false, "", errors.Join(errPublishNotAttempted, err)
		}
		return false, "", ErrUnsafeState
	}
	if manifest.Mode == "replace" {
		return s.publishReplacement(ctx, destination, manifest)
	}
	if manifest.Mode != "create" {
		return false, "", ErrUnsafeState
	}
	if err := rejectWindowsCaseCollision(s.parent.Parent(), destination); err != nil {
		return false, "", err
	}
	if identity, err := validateWindowsStage(s.File, 1); err != nil || identity != s.Identity {
		return false, "", ErrUnsafeState
	}
	if err := validateWindowsEntry(s.parent.Parent(), s.Name, s.Identity, 1); err != nil {
		if errors.Is(err, errNativeRetryable) {
			return false, "", errors.Join(errPublishNotAttempted, err)
		}
		return false, "", ErrUnsafeState
	}
	if ctx.Err() != nil {
		return false, "", errPublishNotAttempted
	}
	buffer, err := buildWindowsLinkInformation(destination, int(unsafe.Sizeof(uintptr(0))), uint64(s.parent.Parent().Fd()))
	if err != nil {
		return false, "", err
	}
	var status windows.IO_STATUS_BLOCK
	linkErr := windows.NtSetInformationFile(windows.Handle(s.File.Fd()), &status, &buffer[0], uint32(len(buffer)), windowsBaseLinkClass)
	class := windowsPublicationEvidence(s.parent.Parent(), destination, s.File, s.Identity)
	if class == windowsPublicationNotPublished {
		if linkErr != nil {
			if errors.Is(classifyWindowsOpenError(linkErr, ""), errNativeRetryable) {
				return false, "", errors.Join(errPublishNotAttempted, errNativeRetryable)
			}
			return false, "", fmt.Errorf("%w: exclusive Windows put publication failed: %v", errPublishNotAttempted, linkErr)
		}
		return false, "", errors.Join(errPublishNotAttempted, errors.New("exclusive Windows put publication did not create the destination"))
	}
	if class != windowsPublicationPublished {
		return false, "", ErrOutcomeUnknown
	}
	durability := "durability_confirmed"
	if err := flushWindowsHandle(windows.Handle(s.parent.Parent().Fd())); err != nil {
		durability = "durability_unconfirmed"
	}
	return true, durability, nil
}

func (s *Stage) publishReplacement(ctx context.Context, destination string, manifest Manifest) (bool, string, error) {
	if s.oldDestination == nil || s.record.BackupName == "" || s.record.BackupIdentity != s.record.OldIdentity {
		return false, "", ErrUnsafeState
	}
	evidence, err := validateWindowsReplacementFile(s.oldDestination)
	if err != nil || evidence.Identity != s.record.OldIdentity || evidence.Metadata != s.record.OldMetadata || evidence.Size != s.record.BackupSize {
		return false, "", ErrUnsafeState
	}
	if err := validateWindowsEntry(s.parent.Parent(), destination, s.record.OldIdentity, 1); err != nil {
		if errors.Is(err, errNativeRetryable) {
			return false, "", errors.Join(errPublishNotAttempted, err)
		}
		return false, "", ErrUnsafeState
	}
	if manifest.ExpectSHA256 != "" {
		digest, err := hashWindowsPinnedFile(ctx, s.oldDestination)
		if err != nil {
			return false, "", err
		}
		if digest != manifest.ExpectSHA256 {
			return false, "", errors.Join(errPublishNotAttempted, ErrCASMismatch)
		}
	}
	revalidatedDestination, revalidatedEvidence, err := openWindowsReplacementDestination(s.parent, destination)
	if revalidatedDestination != nil {
		_ = revalidatedDestination.Close()
	}
	if errors.Is(err, errNativeRetryable) {
		return false, "", errors.Join(errPublishNotAttempted, err)
	}
	if err != nil || revalidatedEvidence.Identity != s.record.OldIdentity || revalidatedEvidence.Metadata != s.record.OldMetadata || revalidatedEvidence.Size != s.record.BackupSize {
		return false, "", errPublishNotAttempted
	}
	if identity, err := validateWindowsStage(s.File, 1); err != nil || identity != s.Identity {
		return false, "", ErrUnsafeState
	}
	completionStage, err := ntOpenRelative(s.parent.Parent(), s.Name, windowsMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return false, "", errors.Join(errPublishNotAttempted, classifyWindowsOpenError(err, "Windows replacement stage lacks metadata-completion authority"))
	}
	proofIdentity, proofErr := validateWindowsStage(completionStage, 1)
	closeErr := completionStage.Close()
	if proofErr != nil || proofIdentity != s.Identity || closeErr != nil {
		return false, "", errPublishNotAttempted
	}
	completionDestination, err := ntOpenRelative(s.parent.Parent(), destination, windowsMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return false, "", errors.Join(errPublishNotAttempted, classifyWindowsOpenError(err, "Windows replacement destination lacks metadata-completion authority"))
	}
	completionEvidence, completionErr := validateWindowsReplacementFile(completionDestination)
	closeErr = completionDestination.Close()
	if completionErr != nil || completionEvidence.Identity != s.record.OldIdentity || completionEvidence.Metadata != s.record.OldMetadata || completionEvidence.Size != s.record.BackupSize || closeErr != nil {
		return false, "", errPublishNotAttempted
	}
	if err := validateWindowsEntry(s.parent.Parent(), s.Name, s.Identity, 1); err != nil {
		if errors.Is(err, errNativeRetryable) {
			return false, "", errors.Join(errPublishNotAttempted, err)
		}
		return false, "", ErrUnsafeState
	}
	if err := rejectWindowsCaseCollision(s.parent.Parent(), s.record.BackupName); err != nil {
		return false, "", errPublishNotAttempted
	}
	absoluteParent, err := windowsVolumeGUIDPath(s.parent.Parent())
	if err != nil {
		return false, "", errors.Join(errPublishNotAttempted, err)
	}
	if err := s.parent.Revalidate(); err != nil {
		if errors.Is(err, errNativeRetryable) {
			return false, "", errors.Join(errPublishNotAttempted, err)
		}
		return false, "", errPublishNotAttempted
	}
	if ctx.Err() != nil {
		return false, "", errPublishNotAttempted
	}
	if err := s.File.Close(); err != nil {
		return false, "", errors.Join(errPublishNotAttempted, errors.New("close Windows replacement stage failed"))
	}
	s.File = nil
	if err := s.oldDestination.Close(); err != nil {
		s.oldDestination = nil
		return false, "", errors.Join(errPublishNotAttempted, errors.New("close Windows replacement destination failed"))
	}
	s.oldDestination = nil
	if err := s.parent.Revalidate(); errors.Is(err, errNativeRetryable) {
		return false, "", errors.Join(errPublishNotAttempted, err)
	} else if err != nil {
		return false, "", errPublishNotAttempted
	}
	if err := validateWindowsEntry(s.parent.Parent(), destination, s.record.OldIdentity, 1); errors.Is(err, errNativeRetryable) {
		return false, "", errors.Join(errPublishNotAttempted, err)
	} else if err != nil {
		return false, "", errPublishNotAttempted
	}
	if err := validateWindowsEntry(s.parent.Parent(), s.Name, s.Identity, 1); errors.Is(err, errNativeRetryable) {
		return false, "", errors.Join(errPublishNotAttempted, err)
	} else if err != nil || ctx.Err() != nil {
		return false, "", errPublishNotAttempted
	}
	replaceErr := replaceWindowsFile(
		filepath.Join(absoluteParent, destination),
		filepath.Join(absoluteParent, s.Name),
		filepath.Join(absoluteParent, s.record.BackupName),
	)
	class := windowsReplacementPublicationEvidence(s.parent.Parent(), destination, s.Name, s.record.BackupName, s.record.OldIdentity, s.Identity)
	if class == windowsPublicationNotPublished {
		if replaceErr != nil {
			if windowsReplaceRetryable(replaceErr) {
				return false, "", errors.Join(errPublishNotAttempted, errNativeRetryable)
			}
			return false, "", fmt.Errorf("%w: Windows replacement failed: %v", errPublishNotAttempted, replaceErr)
		}
		return false, "", errPublishNotAttempted
	}
	if class != windowsPublicationPublished {
		return false, "", ErrOutcomeUnknown
	}
	if replaceErr != nil {
		return true, "", ErrOutcomeUnknown
	}
	published, openErr := ntOpenRelative(s.parent.Parent(), destination, windowsMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if openErr != nil {
		return true, "", ErrOutcomeUnknown
	}
	// ReplaceFileW merges ACL entries and can synthesize a short name. Complete
	// the recorded metadata contract from the identity-proven backup.
	backup, openErr := ntOpenRelative(s.parent.Parent(), s.record.BackupName, windows.FILE_GENERIC_READ|windows.DELETE|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if openErr != nil {
		_ = published.Close()
		return true, "", ErrOutcomeUnknown
	}
	backupEvidence, validationErr := validateWindowsReplacementFile(backup)
	if validationErr != nil || backupEvidence.Identity != s.record.OldIdentity || backupEvidence.Metadata != s.record.OldMetadata || backupEvidence.Size != s.record.BackupSize {
		_ = backup.Close()
		_ = published.Close()
		return true, "", ErrOutcomeUnknown
	}
	if err := restoreWindowsSecurity(published, backup); err != nil {
		_ = backup.Close()
		_ = published.Close()
		return true, "", ErrOutcomeUnknown
	}
	if err := clearWindowsShortName(windows.Handle(published.Fd())); err != nil {
		_ = backup.Close()
		_ = published.Close()
		return true, "", ErrOutcomeUnknown
	}
	publishedEvidence, validationErr := validateWindowsReplacementFile(published)
	if validationErr != nil || publishedEvidence.Identity != s.Identity || publishedEvidence.Metadata != s.record.OldMetadata {
		_ = backup.Close()
		_ = published.Close()
		return true, "", ErrOutcomeUnknown
	}
	fileSyncErr := flushWindowsHandle(windows.Handle(published.Fd()))
	_ = published.Close()
	_ = backup.Close()
	durability := "durability_confirmed"
	if fileSyncErr != nil || flushWindowsHandle(windows.Handle(s.parent.Parent().Fd())) != nil {
		durability = "durability_unconfirmed"
	}
	return true, durability, nil
}

func (s *Stage) Close() error {
	var result error
	if s.File != nil {
		result = s.File.Close()
		s.File = nil
	}
	if s.oldDestination != nil {
		result = errors.Join(result, s.oldDestination.Close())
		s.oldDestination = nil
	}
	if s.parent != nil {
		result = errors.Join(result, s.parent.Close())
		s.parent = nil
	}
	return result
}

func (s *Stage) RemoveEntry() (bool, error) {
	if s.parent == nil || s.parent.Revalidate() != nil {
		return false, ErrUnsafeState
	}
	if s.File == nil {
		_, state := windowsEntryIdentity(s.parent.Parent(), s.Name)
		return state == windowsEntryAbsent, nil
	}
	wantLinks := s.cleanupLinks
	if wantLinks == 0 {
		wantLinks = 1
		if s.record.State == "committed" && s.record.Mode == "create" {
			wantLinks = 2
		}
	}
	if identity, err := validateWindowsStage(s.File, wantLinks); err != nil || identity != s.Identity || validateWindowsEntry(s.parent.Parent(), s.Name, s.Identity, wantLinks) != nil {
		return false, ErrUnsafeState
	}
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS)
	if err := windows.SetFileInformationByHandle(windows.Handle(s.File.Fd()), windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags))); err != nil {
		return false, err
	}
	closeErr := s.File.Close()
	s.File = nil
	if closeErr != nil {
		return false, closeErr
	}
	_, state := windowsEntryIdentity(s.parent.Parent(), s.Name)
	if state != windowsEntryAbsent {
		return false, ErrUnsafeState
	}
	return true, nil
}

func (s *Stage) SyncParent() error {
	if s.parent == nil || s.parent.Revalidate() != nil {
		return ErrUnsafeState
	}
	return flushWindowsHandle(windows.Handle(s.parent.Parent().Fd()))
}

func openCleanupStage(record Record) (*Stage, error) {
	stage, _, err := openCleanupArtifacts(record)
	return stage, err
}

func openCleanupArtifacts(record Record) (*Stage, *Stage, error) {
	stageLinks := uint32(1)
	if record.State == "committed" && record.Mode == "create" {
		stageLinks = 2
	} else if record.State == "accept_current_intent" {
		stageLinks = 0
	}
	stage, err := openWindowsCleanupArtifact(record, record.StageName, record.StageIdentity, stageLinks)
	if err != nil {
		return nil, nil, err
	}
	if record.BackupName == "" {
		return stage, nil, nil
	}
	backup, err := openWindowsCleanupArtifact(record, record.BackupName, record.BackupIdentity, 1)
	if err != nil {
		stage.Close()
		return nil, nil, err
	}
	return stage, backup, nil
}

func openWindowsCleanupArtifact(record Record, name, identity string, links uint32) (*Stage, error) {
	parent, err := openDestinationParent(recordRoot(record), record.Destination, false)
	if err != nil {
		return nil, err
	}
	if parent.path != record.ParentPath || !parentMatchesIdentity(parent, record.ParentIdentity) {
		parent.Close()
		return nil, ErrUnsafeState
	}
	file, err := ntOpenRelative(parent.Parent(), name, windows.FILE_GENERIC_READ|windows.DELETE|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if ntStatusIs(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) && (record.State == "committed" || record.State == "cleanup_not_attempted" || record.State == "accept_current_intent") {
		return &Stage{Name: name, Identity: identity, ParentPath: record.ParentPath, ParentIdentity: record.ParentIdentity, parent: parent, record: record, cleanupLinks: links}, nil
	}
	if err != nil {
		parent.Close()
		return nil, err
	}
	actualLinks := links
	if actualLinks == 0 {
		info, infoErr := windowsHandleInfo(file)
		if infoErr != nil || info.links < 1 || info.links > 2 {
			file.Close()
			parent.Close()
			return nil, ErrUnsafeState
		}
		actualLinks = info.links
	}
	actualIdentity, validationErr := validateWindowsStage(file, actualLinks)
	if validationErr != nil || identity != "" && actualIdentity != identity {
		file.Close()
		parent.Close()
		return nil, ErrUnsafeState
	}
	return &Stage{File: file, Name: name, Identity: actualIdentity, ParentPath: record.ParentPath, ParentIdentity: record.ParentIdentity, parent: parent, record: record, cleanupLinks: actualLinks}, nil
}

func reconcilePublication(record Record) (Result, bool, error) {
	parent, err := openDestinationParent(recordRoot(record), record.Destination, false)
	if err != nil {
		return Result{}, false, err
	}
	defer parent.Close()
	if parent.path != record.ParentPath || !parentMatchesIdentity(parent, record.ParentIdentity) {
		return Result{}, false, ErrUnsafeState
	}
	destination := filepath.Base(filepath.FromSlash(record.Destination))
	if record.Mode == "replace" {
		class := windowsReplacementPublicationEvidence(parent.Parent(), destination, record.StageName, record.BackupName, record.OldIdentity, record.StageIdentity)
		switch class {
		case windowsPublicationPublished:
			if err := validateWindowsRecoveredReplacement(parent, destination, record); err != nil {
				return Result{}, false, ErrOutcomeUnknown
			}
			return resultFrom(record.Manifest, "durability_unconfirmed"), true, nil
		case windowsPublicationNotPublished:
			return Result{}, false, errPublishNotAttempted
		default:
			return Result{}, false, ErrOutcomeUnknown
		}
	}
	if record.Mode != "create" {
		return Result{}, false, ErrUnsafeState
	}
	stage, stageErr := ntOpenRelative(parent.Parent(), record.StageName, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if stageErr != nil {
		return Result{}, false, ErrOutcomeUnknown
	}
	defer stage.Close()
	if windowsPublicationEvidence(parent.Parent(), destination, stage, record.StageIdentity) != windowsPublicationPublished {
		return Result{}, false, ErrOutcomeUnknown
	}
	return resultFrom(record.Manifest, "durability_unconfirmed"), true, nil
}

func validateWindowsRecoveredReplacement(parent *openedParent, destination string, record Record) error {
	published, err := ntOpenRelative(parent.Parent(), destination, windowsMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if err != nil {
		return err
	}
	defer published.Close()
	backup, err := ntOpenRelative(parent.Parent(), record.BackupName, windows.FILE_GENERIC_READ|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return err
	}
	defer backup.Close()
	backupEvidence, backupErr := validateWindowsReplacementFile(backup)
	if backupErr != nil || backupEvidence.Identity != record.OldIdentity || backupEvidence.Metadata != record.OldMetadata || backupEvidence.Size != record.BackupSize {
		return ErrUnsafeState
	}
	// This is idempotent metadata completion on the proven published identity,
	// not another replacement or a content rollback.
	if err := restoreWindowsSecurity(published, backup); err != nil || clearWindowsShortName(windows.Handle(published.Fd())) != nil {
		return ErrUnsafeState
	}
	publishedEvidence, publishedErr := validateWindowsReplacementFile(published)
	if publishedErr != nil || publishedEvidence.Identity != record.StageIdentity || publishedEvidence.Metadata != record.OldMetadata {
		return ErrUnsafeState
	}
	_ = flushWindowsHandle(windows.Handle(published.Fd()))
	_ = flushWindowsHandle(windows.Handle(parent.Parent().Fd()))
	return nil
}

func recordRoot(record Record) string {
	root := record.ParentPath
	parts := strings.Split(filepath.ToSlash(record.Destination), "/")
	for range parts[:len(parts)-1] {
		root = filepath.Dir(root)
	}
	return root
}

func preflightAcceptCurrent(root string, record Record) (string, error) {
	parent, err := openDestinationParent(root, record.Destination, false)
	if err != nil {
		return "", err
	}
	if parent.path != record.ParentPath || !parentMatchesIdentity(parent, record.ParentIdentity) {
		parent.Close()
		return "", ErrUnsafeState
	}
	destination := filepath.Base(filepath.FromSlash(record.Destination))
	identity, err := validateWindowsAcceptCurrentDestination(parent, destination, record)
	parent.Close()
	if err != nil {
		return "", err
	}
	if record.ResolutionDestinationIdentity != "" && record.ResolutionDestinationIdentity != identity {
		return "", ErrUnsafeState
	}
	resolutionRecord := record
	resolutionRecord.State = "accept_current_intent"
	stage, backup, err := openCleanupArtifacts(resolutionRecord)
	if stage != nil {
		defer stage.Close()
	}
	if backup != nil {
		defer backup.Close()
	}
	if err != nil {
		return "", err
	}
	return identity, nil
}

func validateAcceptCurrent(record Record) error {
	identity, err := preflightAcceptCurrent(recordRoot(record), record)
	if err != nil || identity != record.ResolutionDestinationIdentity {
		return errors.Join(ErrUnsafeState, err)
	}
	return nil
}

func validateWindowsAcceptCurrentDestination(parent *openedParent, destination string, record Record) (string, error) {
	file, err := ntOpenRelative(parent.Parent(), destination, windows.FILE_GENERIC_READ|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return "", ErrUnsafeState
	}
	defer file.Close()
	info, err := windowsHandleInfo(file)
	if err != nil || info.directory || info.links < 1 || info.links > 2 {
		return "", ErrUnsafeState
	}
	if info.links == 2 && (record.StageIdentity != info.identity || validateWindowsEntry(parent.Parent(), record.StageName, info.identity, 2) != nil) {
		return "", ErrUnsafeState
	}
	evidence, err := validateWindowsReplacementFileLinks(file, info.links)
	if err != nil || evidence.Identity != info.identity {
		return "", errors.Join(ErrUnsafeState, err)
	}
	if err := validateWindowsEntry(parent.Parent(), destination, info.identity, info.links); err != nil {
		return "", err
	}
	return info.identity, nil
}

func inspectReplacementDestination(parent *openedParent, destination string) (replacementEvidence, error) {
	file, evidence, err := openWindowsReplacementDestination(parent, destination)
	if file != nil {
		_ = file.Close()
	}
	return evidence, err
}

func replacementBackupEvidence(parent *openedParent, id string, evidence replacementEvidence) (string, int64, error) {
	name := ".px-" + id + ".bak"
	if evidence.Identity == "" || evidence.Size < 0 {
		return "", 0, ErrUnsafeState
	}
	if err := rejectWindowsCaseCollision(parent.Parent(), name); err != nil {
		return "", 0, err
	}
	return name, evidence.Size, nil
}

func openWindowsReplacementDestination(parent *openedParent, destination string) (*os.File, replacementEvidence, error) {
	file, err := ntOpenRelative(parent.Parent(), destination, windows.FILE_GENERIC_READ|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		if errors.Is(classifyWindowsOpenError(err, ""), errNativeRetryable) {
			return nil, replacementEvidence{}, errNativeRetryable
		}
		return nil, replacementEvidence{}, errors.New("replacement destination is unavailable")
	}
	evidence, err := validateWindowsReplacementFile(file)
	if err != nil {
		file.Close()
		return nil, replacementEvidence{}, err
	}
	if err := validateWindowsEntry(parent.Parent(), destination, evidence.Identity, 1); err != nil {
		file.Close()
		return nil, replacementEvidence{}, err
	}
	return file, evidence, nil
}

func validateWindowsReplacementFile(file *os.File) (replacementEvidence, error) {
	return validateWindowsReplacementFileLinks(file, 1)
}

func validateWindowsReplacementFileLinks(file *os.File, links uint32) (replacementEvidence, error) {
	info, err := windowsHandleInfo(file)
	if err != nil || info.directory || info.links != links || links < 1 || links > 2 {
		return replacementEvidence{}, errors.New("replacement destination is not a non-reparse regular file with the expected link count")
	}
	if info.attributes&^windowsReplacementAttrs != 0 || info.attributes&windows.FILE_ATTRIBUTE_NORMAL != 0 && info.attributes != windows.FILE_ATTRIBUTE_NORMAL {
		return replacementEvidence{}, errors.New("replacement destination has unsupported Windows attributes")
	}
	var basic windowsFileBasicInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil || basic.Attributes != info.attributes {
		return replacementEvidence{}, errors.New("replacement destination basic metadata is unavailable")
	}
	if err := validateWindowsUnnamedDataStream(file); err != nil {
		return replacementEvidence{}, err
	}
	if err := validateWindowsNoShortName(file); err != nil {
		return replacementEvidence{}, err
	}
	if err := validateWindowsNoObjectID(file); err != nil {
		return replacementEvidence{}, err
	}
	resourceAttributes, err := windowsResourceAttributeEvidence(file)
	if err != nil {
		return replacementEvidence{}, err
	}
	if err := requireAssignableWindowsOwner(file); err != nil {
		return replacementEvidence{}, err
	}
	security, err := windowsSecurityEvidence(file, windowsStageDangerous)
	if err != nil {
		return replacementEvidence{}, errors.New("replacement destination owner or inherited DACL is unsafe")
	}
	stat, err := file.Stat()
	if err != nil || stat.Size() < 0 {
		return replacementEvidence{}, ErrUnsafeState
	}
	metadata := fmt.Sprintf("windowsmeta2:%08x:%016x:%s", basic.Attributes, uint64(basic.CreationTime), security)
	if resourceAttributes != "" {
		metadataDigest := sha256.Sum256([]byte(security + ":" + resourceAttributes))
		metadata = fmt.Sprintf("windowsmeta3:%08x:%016x:%s", basic.Attributes, uint64(basic.CreationTime), hex.EncodeToString(metadataDigest[:]))
	}
	return replacementEvidence{Identity: info.identity, Metadata: metadata, Mode: basic.Attributes, Size: stat.Size()}, nil
}

func validateWindowsUnnamedDataStream(file *os.File) error {
	buffer := make([]byte, maxWindowsStreamInfo)
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileStreamInfo, &buffer[0], uint32(len(buffer))); err != nil {
		return errors.New("replacement destination stream metadata is unavailable")
	}
	const streamHeaderSize = 24
	if len(buffer) < streamHeaderSize {
		return errors.New("replacement destination stream metadata is malformed")
	}
	next := binary.LittleEndian.Uint32(buffer[0:4])
	nameBytes := binary.LittleEndian.Uint32(buffer[4:8])
	if next != 0 || nameBytes != uint32(len("::$DATA")*2) || streamHeaderSize+int(nameBytes) > len(buffer) {
		return errors.New("replacement destination has unsupported named streams")
	}
	encoded := make([]uint16, nameBytes/2)
	for index := range encoded {
		encoded[index] = binary.LittleEndian.Uint16(buffer[streamHeaderSize+index*2:])
	}
	if windows.UTF16ToString(encoded) != "::$DATA" {
		return errors.New("replacement destination has unsupported named streams")
	}
	return nil
}

func validateWindowsNoShortName(file *os.File) error {
	buffer := make([]byte, 4+24*2)
	var status windows.IO_STATUS_BLOCK
	err := windows.NtQueryInformationFile(windows.Handle(file.Fd()), &status, &buffer[0], uint32(len(buffer)), windowsAlternateNameInfo)
	if ntStatusIs(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil || status.Status != windows.STATUS_SUCCESS || status.Information < 4 || status.Information > uintptr(len(buffer)) {
		return errors.New("replacement destination short-name metadata is unavailable")
	}
	length := binary.LittleEndian.Uint32(buffer[:4])
	if length%2 != 0 || uint64(length) > uint64(status.Information-4) {
		return errors.New("replacement destination short-name metadata is malformed")
	}
	if length != 0 {
		return errors.New("replacement destination has an unsupported short name")
	}
	return nil
}

func clearWindowsShortName(handle windows.Handle) error {
	return setWindowsShortName(handle, "")
}

func setWindowsShortName(handle windows.Handle, name string) error {
	value, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	result, _, callErr := setFileShortNameW.Call(uintptr(handle), uintptr(unsafe.Pointer(value)))
	if result == 0 {
		return callErr
	}
	return nil
}

func restoreWindowsSecurity(destination, source *os.File) error {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("replacement backup security is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return errors.New("replacement backup security is malformed")
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("replacement backup owner is unavailable")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("replacement backup DACL is unavailable")
	}
	attributes, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, windows.ATTRIBUTE_SECURITY_INFORMATION)
	if err != nil || attributes == nil || !attributes.IsValid() {
		return errors.New("replacement backup resource attributes are unavailable")
	}
	sacl, _, err := attributes.SACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return errors.New("replacement backup resource attributes are unavailable")
	}
	if sacl == nil {
		empty := struct {
			Revision byte
			_        byte
			Size     uint16
			Count    uint16
			_        uint16
		}{Revision: 2, Size: 8}
		sacl = (*windows.ACL)(unsafe.Pointer(&empty))
	}
	if err := windows.SetSecurityInfo(windows.Handle(destination.Fd()), windows.SE_FILE_OBJECT, information, owner, nil, dacl, nil); err != nil {
		return errors.New("restore replacement destination security failed")
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		if err := windows.SetSecurityInfo(windows.Handle(destination.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return errors.New("normalize replacement destination DACL failed")
		}
	}
	if err := windows.SetSecurityInfo(windows.Handle(destination.Fd()), windows.SE_FILE_OBJECT, windows.ATTRIBUTE_SECURITY_INFORMATION, nil, nil, nil, sacl); err != nil {
		return errors.New("restore replacement destination resource attributes failed")
	}
	return nil
}

func validateWindowsNoObjectID(file *os.File) error {
	buffer := make([]byte, 64)
	var returned uint32
	err := windows.DeviceIoControl(windows.Handle(file.Fd()), windows.FSCTL_GET_OBJECT_ID, nil, 0, &buffer[0], uint32(len(buffer)), &returned, nil)
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return errors.New("replacement destination object-ID metadata is unavailable")
	}
	if returned != uint32(len(buffer)) {
		return errors.New("replacement destination object-ID metadata is malformed")
	}
	return errors.New("replacement destination has an unsupported object ID")
}

func windowsResourceAttributeEvidence(file *os.File) (string, error) {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.ATTRIBUTE_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return "", errors.New("replacement destination security resource attributes are unavailable")
	}
	sacl, _, err := descriptor.SACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("replacement destination security resource attributes are malformed")
	}
	if sacl == nil {
		return "", nil
	}
	type aclHeader struct {
		Revision byte
		_        byte
		Size     uint16
		Count    uint16
		_        uint16
	}
	descriptorLength := uintptr(descriptor.Length())
	descriptorStart := uintptr(unsafe.Pointer(descriptor))
	aclStart := uintptr(unsafe.Pointer(sacl))
	headerSize := unsafe.Sizeof(aclHeader{})
	if aclStart < descriptorStart || aclStart-descriptorStart > descriptorLength || headerSize > descriptorLength-(aclStart-descriptorStart) {
		return "", errors.New("replacement destination security resource attributes are malformed")
	}
	header := (*aclHeader)(unsafe.Pointer(sacl))
	if header.Size < uint16(headerSize) || uintptr(header.Size) > descriptorLength-(aclStart-descriptorStart) {
		return "", errors.New("replacement destination security resource attributes are malformed")
	}
	acl := unsafe.Slice((*byte)(unsafe.Pointer(sacl)), int(header.Size))
	return validateWindowsResourceAttributeACL(acl)
}

func ntOpenVolumeRoot(path string, access uint32) (*os.File, error) {
	name, err := windows.NewNTUnicodeString(`\??\` + filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return ntCreateFile(0, name, path, access, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, false)
}

func ntOpenRelative(parent *os.File, name string, access, disposition, options uint32) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	return ntCreateFile(windows.Handle(parent.Fd()), objectName, name, access, disposition, options, true)
}

func ntCreateFile(root windows.Handle, name *windows.NTUnicodeString, label string, access, disposition, options uint32, dontReparse bool) (*os.File, error) {
	attributeFlags := uint32(windows.OBJ_CASE_INSENSITIVE)
	if dontReparse {
		attributeFlags |= windows.OBJ_DONT_REPARSE
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: root, ObjectName: name, Attributes: attributeFlags}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err := windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), label), nil
}

func requireWindowsVolumeRoot(file *os.File) error {
	buffer := make([]byte, 12)
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileNameInfo, &buffer[0], uint32(len(buffer))); err != nil {
		return errors.New("Windows put volume anchor identity is unavailable")
	}
	length := binary.LittleEndian.Uint32(buffer[:4])
	if length != 2 || binary.LittleEndian.Uint16(buffer[4:6]) != '\\' {
		return errors.New("Windows put drive mapping does not identify a volume root")
	}
	return nil
}

func windowsVolumeGUIDPath(file *os.File) (string, error) {
	const volumeNameGUID = 1
	buffer := make([]uint16, 512)
	for len(buffer) <= 32768 {
		length, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), volumeNameGUID)
		if err == nil && length > 0 && int(length) < len(buffer) {
			value := windows.UTF16ToString(buffer[:length])
			if strings.HasPrefix(value, `\\?\Volume{`) && strings.Contains(value, `}\`) {
				return value, nil
			}
			return "", errors.New("Windows replacement volume identity is unavailable")
		}
		if length == 0 || length > 32768 {
			return "", errors.New("Windows replacement volume identity is unavailable")
		}
		buffer = make([]uint16, int(length)+1)
	}
	return "", errors.New("Windows replacement volume identity is unavailable")
}

func windowsVolumeGUIDRoot(value string) bool {
	if !strings.HasPrefix(value, `\\?\Volume{`) || !strings.HasSuffix(value, `}\`) {
		return false
	}
	return strings.Count(value, `\`) == 4
}

func requireNTFS(file *os.File) error {
	type deviceInformation struct {
		DeviceType      uint32
		Characteristics uint32
	}
	const (
		fileFsDeviceInformation  = 4
		fileDeviceDisk           = 7
		fileDeviceDiskFilesystem = 8
		fileRemoteDevice         = 0x10
	)
	var device deviceInformation
	var status windows.IO_STATUS_BLOCK
	result, _, _ := ntQueryVolumeInformationFile.Call(uintptr(file.Fd()), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), fileFsDeviceInformation)
	if windows.NTStatus(result) != windows.STATUS_SUCCESS || device.DeviceType != fileDeviceDisk && device.DeviceType != fileDeviceDiskFilesystem || device.Characteristics&fileRemoteDevice != 0 {
		return errors.Join(ErrNativeUnsupported, errors.New("Windows create-only put requires a local disk filesystem"))
	}
	name := make([]uint16, 32)
	if err := windows.GetVolumeInformationByHandle(windows.Handle(file.Fd()), nil, 0, nil, nil, nil, &name[0], uint32(len(name))); err != nil {
		return errors.Join(ErrNativeUnsupported, errors.New("put root filesystem cannot be identified"))
	}
	if windows.UTF16ToString(name) != "NTFS" {
		return errors.Join(ErrNativeUnsupported, errors.New("Windows create-only put currently requires NTFS"))
	}
	return nil
}

func windowsHandleInfo(file *os.File) (windowsNativeInfo, error) {
	info, err := queryWindowsHandleInfo(file)
	if err != nil {
		return windowsNativeInfo{}, err
	}
	if info.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.deleting || info.links == 0 {
		return windowsNativeInfo{}, ErrUnsafeState
	}
	if info.directory != (info.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return windowsNativeInfo{}, ErrUnsafeState
	}
	return info, nil
}

func queryWindowsHandleInfo(file *os.File) (windowsNativeInfo, error) {
	var id windowsFileIDInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return windowsNativeInfo{}, err
	}
	var standard windowsFileStandardInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard))); err != nil {
		return windowsNativeInfo{}, err
	}
	var attributes windowsAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&attributes)), uint32(unsafe.Sizeof(attributes))); err != nil {
		return windowsNativeInfo{}, err
	}
	directory := standard.Directory != 0
	return windowsNativeInfo{identity: windowsFileIdentity(id.VolumeSerial, id.FileID), links: standard.NumberOfLinks, directory: directory, attributes: attributes.Attributes, deleting: standard.DeletePending != 0}, nil
}

func validateWindowsStage(file *os.File, links uint32) (string, error) {
	info, err := windowsHandleInfo(file)
	if err != nil || info.directory || info.links != links {
		return "", errors.New("Windows put stage is not a non-reparse regular file with the expected link count")
	}
	if err := validateProtectedWindowsHandle(file, windowsStageDangerous); err != nil {
		return "", errors.New("Windows put stage owner or inherited DACL is unsafe")
	}
	return info.identity, nil
}

func validateWindowsEntry(parent *os.File, name, identity string, links uint32) error {
	entry, err := ntOpenRelative(parent, name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		if errors.Is(classifyWindowsOpenError(err, ""), errNativeRetryable) {
			return errNativeRetryable
		}
		return ErrUnsafeState
	}
	defer entry.Close()
	info, err := windowsHandleInfo(entry)
	if err != nil || info.directory || info.identity != identity || info.links != links {
		return ErrUnsafeState
	}
	return nil
}

type windowsEntryState uint8

const (
	windowsEntryUnknown windowsEntryState = iota
	windowsEntryAbsent
	windowsEntryPresent
)

func windowsEntryIdentity(parent *os.File, name string) (string, windowsEntryState) {
	entry, err := ntOpenRelative(parent, name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, 0)
	if ntStatusIs(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return "", windowsEntryAbsent
	}
	if err != nil {
		return "", windowsEntryUnknown
	}
	defer entry.Close()
	info, err := windowsHandleInfo(entry)
	if err != nil {
		return "", windowsEntryUnknown
	}
	return info.identity, windowsEntryPresent
}

func windowsPublicationEvidence(parent *os.File, destination string, stage *os.File, identity string) windowsPublicationClass {
	destinationKnown, destinationMatches := false, false
	destinationFile, err := ntOpenRelative(parent, destination, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, 0)
	if ntStatusIs(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		destinationKnown = true
	} else if err == nil {
		info, infoErr := queryWindowsHandleInfo(destinationFile)
		_ = destinationFile.Close()
		if infoErr == nil {
			if info.identity != identity {
				destinationKnown = true
			} else if !info.directory && !info.deleting && info.links == 2 && info.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
				destinationKnown, destinationMatches = true, true
			}
		}
	}
	stageInfo, stageErr := windowsHandleInfo(stage)
	stageKnown := stageErr == nil && !stageInfo.directory && stageInfo.identity == identity
	return classifyWindowsPublication(destinationKnown, destinationMatches, stageKnown, stageInfo.links)
}

func windowsReplacementPublicationEvidence(parent *os.File, destination, stage, backup, oldIdentity, replacementIdentity string) windowsPublicationClass {
	destinationIdentity, destinationState := windowsRegularEntryIdentity(parent, destination)
	stageIdentity, stageState := windowsRegularEntryIdentity(parent, stage)
	backupIdentity, backupState := windowsRegularEntryIdentity(parent, backup)
	return classifyWindowsReplacement(windowsReplacementEvidence{
		DestinationKnown:    destinationState != windowsEntryUnknown,
		DestinationIdentity: destinationIdentity,
		StageKnown:          stageState != windowsEntryUnknown,
		StageIdentity:       stageIdentity,
		BackupKnown:         backupState != windowsEntryUnknown,
		BackupIdentity:      backupIdentity,
	}, oldIdentity, replacementIdentity)
}

func windowsRegularEntryIdentity(parent *os.File, name string) (string, windowsEntryState) {
	if name == "" {
		return "", windowsEntryUnknown
	}
	entry, err := ntOpenRelative(parent, name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if ntStatusIs(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return "", windowsEntryAbsent
	}
	if err != nil {
		return "", windowsEntryUnknown
	}
	defer entry.Close()
	info, err := windowsHandleInfo(entry)
	if err != nil || info.directory || info.links != 1 {
		return "", windowsEntryUnknown
	}
	return info.identity, windowsEntryPresent
}

func hashWindowsPinnedFile(ctx context.Context, file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("rewind replacement destination failed")
	}
	hasher := sha256.New()
	if _, err := io.Copy(&contextWriter{ctx: ctx, writer: hasher}, file); err != nil {
		return "", errors.New("hash replacement destination failed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func replaceWindowsFile(destination, replacement, backup string) error {
	destinationName, err := windows.UTF16PtrFromString(windowsExtendedPath(destination))
	if err != nil {
		return err
	}
	replacementName, err := windows.UTF16PtrFromString(windowsExtendedPath(replacement))
	if err != nil {
		return err
	}
	backupName, err := windows.UTF16PtrFromString(windowsExtendedPath(backup))
	if err != nil {
		return err
	}
	result, _, callErr := replaceFileW.Call(
		uintptr(unsafe.Pointer(destinationName)),
		uintptr(unsafe.Pointer(replacementName)),
		uintptr(unsafe.Pointer(backupName)),
		0,
		0,
		0,
	)
	if result != 0 {
		return nil
	}
	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		return callErr
	}
	return errors.New("ReplaceFileW failed without an error code")
}

func windowsExtendedPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	return `\\?\` + filepath.Clean(path)
}

func rejectWindowsCaseCollision(parent *os.File, destination string) error {
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return errors.New("open process for Windows collision validation failed")
	}
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(parent.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return errors.New("duplicate Windows put parent for collision validation failed")
	}
	directory := os.NewFile(uintptr(duplicate), "put-parent-enumeration")
	defer directory.Close()
	names, readErr := directory.Readdirnames(maxWindowsParentNames + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.New("enumerate Windows put parent for case collision failed")
	}
	if len(names) > maxWindowsParentNames {
		return errors.New("Windows put parent exceeds bounded case-collision validation")
	}
	for _, name := range names {
		if strings.EqualFold(name, destination) {
			return errors.New("put destination already exists or case-collides")
		}
	}
	return nil
}

func validateProtectedWindowsHandle(file *os.File, dangerous uint32) error {
	_, err := windowsSecurityEvidence(file, dangerous)
	return err
}

func requireAssignableWindowsOwner(file *os.File) error {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("replacement destination owner is unavailable")
	}
	owner, defaulted, err := descriptor.Owner()
	if err != nil || owner == nil || defaulted || !owner.IsValid() {
		return errors.New("replacement destination owner is unavailable")
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("replacement process identity is unavailable")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("replacement process identity is unavailable")
	}
	if windowsTokenCanAssignOwner(token, owner, user.User.Sid) {
		return nil
	}
	return errors.New("replacement destination owner cannot be restored by the current process")
}

func windowsTokenCanAssignOwner(token windows.Token, owner, user *windows.SID) bool {
	if owner == nil || user == nil {
		return false
	}
	if owner.Equals(user) {
		return true
	}
	groups, err := token.GetTokenGroups()
	if err != nil || groups == nil {
		return false
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Attributes&windows.SE_GROUP_OWNER != 0 && owner.Equals(group.Sid) {
			return true
		}
	}
	return false
}

func windowsSecurityEvidence(file *os.File, dangerous uint32) (string, error) {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return "", errors.New("inspect Windows object security failed")
	}
	control, revision, err := descriptor.Control()
	if err != nil || revision != 1 || control&windows.SE_DACL_PRESENT == 0 {
		return "", errors.New("Windows object security descriptor is malformed")
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || owner == nil || ownerDefaulted || !owner.IsValid() {
		return "", errors.New("Windows object owner is unavailable")
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || dacl == nil || daclDefaulted {
		return "", errors.New("Windows object has a null or defaulted DACL")
	}
	trusted, err := trustedWindowsSIDs()
	if err != nil {
		return "", err
	}
	ownerBytes := copyWindowsSID(owner)
	type aclHeader struct {
		Revision byte
		_        byte
		Size     uint16
		Count    uint16
		_        uint16
	}
	header := (*aclHeader)(unsafe.Pointer(dacl))
	if header.Size < uint16(unsafe.Sizeof(*header)) {
		return "", errors.New("Windows object ACL is malformed")
	}
	aclBytes := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(dacl)), int(header.Size))...)
	if err := validateWindowsSecurity(ownerBytes, aclBytes, trusted, dangerous); err != nil {
		return "", err
	}
	var controlBytes [2]byte
	const evidenceControl = windows.SE_DACL_PROTECTED
	binary.LittleEndian.PutUint16(controlBytes[:], uint16(control&evidenceControl))
	hash := sha256.New()
	_, _ = hash.Write(ownerBytes)
	_, _ = hash.Write(controlBytes[:])
	_, _ = hash.Write(aclBytes)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func trustedWindowsSIDs() ([][]byte, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
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
	installer, err := windows.StringToSid(windowsTrustedInstaller)
	if err != nil {
		return nil, err
	}
	return [][]byte{copyWindowsSID(user.User.Sid), copyWindowsSID(system), copyWindowsSID(admins), copyWindowsSID(installer)}, nil
}

func copyWindowsSID(sid *windows.SID) []byte {
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sid)), int(sid.Len()))...)
}

func flushWindowsHandle(handle windows.Handle) error {
	var status windows.IO_STATUS_BLOCK
	result, _, _ := ntFlushBuffersFileEx.Call(uintptr(handle), 0, 0, 0, uintptr(unsafe.Pointer(&status)))
	if windows.NTStatus(result) != windows.STATUS_SUCCESS {
		return windows.NTStatus(result)
	}
	return nil
}

func ntStatusIs(err error, status windows.NTStatus) bool {
	var native windows.NTStatus
	return errors.As(err, &native) && native == status
}

func classifyWindowsOpenError(err error, message string) error {
	if ntStatusIs(err, windows.STATUS_SHARING_VIOLATION) || ntStatusIs(err, windows.STATUS_FILE_LOCK_CONFLICT) || ntStatusIs(err, windows.STATUS_INSUFFICIENT_RESOURCES) || ntStatusIs(err, windows.STATUS_NO_MEMORY) {
		return errors.Join(errNativeRetryable, errors.New(message))
	}
	return errors.New(message)
}

func windowsReplaceRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_NOT_ENOUGH_MEMORY) || errors.Is(err, windows.ERROR_OUTOFMEMORY)
}

const nativePublicationResidual = "none: Windows links exclusively from the pinned stage handle with NtSetInformationFile"
