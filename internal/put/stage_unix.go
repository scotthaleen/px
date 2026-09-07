//go:build linux || darwin

package put

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/scotthaleen/px/internal/securefile"
	"golang.org/x/sys/unix"
)

const maxCaseFoldEntries = 4096

type openedParent struct {
	rootPath   string
	path       string
	components []string
	dirs       []*os.File
	identities []string
}

type Stage struct {
	File                                       *os.File
	Name, Identity, ParentPath, ParentIdentity string
	record                                     Record
	oldDestination                             *os.File
	parent                                     *openedParent
}

type replacementEvidence struct {
	Identity string
	Metadata string
	UID, GID uint32
	Mode     uint32
}

func nativeReceiveSupported() error { return nativePublicationSupported() }

func openDestinationParent(root, destination string, requireAbsent bool) (*openedParent, error) {
	parts := strings.Split(filepath.ToSlash(destination), "/")
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open put root without following links failed")
	}
	result := &openedParent{rootPath: root, path: root, components: append([]string(nil), parts[:len(parts)-1]...)}
	current := os.NewFile(uintptr(rootFD), root)
	result.dirs = append(result.dirs, current)
	if err := result.captureDirectory(current); err != nil {
		result.Close()
		return nil, err
	}
	for _, part := range result.components {
		fd, openErr := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			result.Close()
			return nil, errors.New("put parent is missing or contains a symlink")
		}
		current = os.NewFile(uintptr(fd), part)
		result.dirs = append(result.dirs, current)
		result.path = filepath.Join(result.path, part)
		if err := result.captureDirectory(current); err != nil {
			result.Close()
			return nil, err
		}
	}
	if requireAbsent {
		if err := rejectCaseCollision(result.Parent(), parts[len(parts)-1]); err != nil {
			result.Close()
			return nil, err
		}
	}
	return result, nil
}

func (p *openedParent) captureDirectory(directory *os.File) error {
	if err := securefile.ValidateProtectedParent(directory); err != nil {
		return errors.New("put ancestry permits another account to replace entries")
	}
	if err := validateDirectoryPlatform(directory); err != nil {
		return errors.New("put ancestry has unsupported extended authority")
	}
	id, err := fileIdentity(directory, true)
	if err != nil {
		return errors.New("put ancestry identity is unavailable")
	}
	p.identities = append(p.identities, id)
	return nil
}

func (p *openedParent) Parent() *os.File { return p.dirs[len(p.dirs)-1] }

func parentDurableIdentity(parent *openedParent) string {
	return parent.identities[len(parent.identities)-1]
}

func (p *openedParent) Revalidate() error {
	if len(p.dirs) != len(p.identities) {
		return ErrUnsafeState
	}
	for index, directory := range p.dirs {
		id, err := fileIdentity(directory, true)
		if err != nil || id != p.identities[index] || securefile.ValidateProtectedParent(directory) != nil || validateDirectoryPlatform(directory) != nil {
			return ErrUnsafeState
		}
		if index == 0 {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(p.dirs[index-1].Fd()), p.components[index-1], &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || identityFromUnixStat(&stat) != id || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrUnsafeState
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

func rejectCaseCollision(parent *os.File, destination string) error {
	duplicate, err := unix.Dup(int(parent.Fd()))
	if err != nil {
		return errors.New("duplicate put parent for collision validation failed")
	}
	directory := os.NewFile(uintptr(duplicate), "put-parent-enumeration")
	defer directory.Close()
	names, readErr := directory.Readdirnames(maxCaseFoldEntries + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.New("enumerate put parent for case collision failed")
	}
	if len(names) > maxCaseFoldEntries {
		return errors.New("put parent exceeds bounded case-collision validation")
	}
	for _, name := range names {
		if strings.EqualFold(name, destination) {
			return errors.New("put destination already exists or case-collides")
		}
	}
	return nil
}

func validateCreateDestination(parent *openedParent, destination string) error {
	return rejectCaseCollision(parent.Parent(), destination)
}

func createOrOpenStage(parent *openedParent, _ Manifest, record Record) (*Stage, bool, error) {
	name := record.StageName
	if name == "" || record.ParentPath != parent.path || record.ParentIdentity != parent.identities[len(parent.identities)-1] {
		return nil, false, ErrUnsafeState
	}
	attachIdentity := record.StageIdentity == ""
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if attachIdentity {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(parent.Parent().Fd()), name, flags, 0o600)
	if attachIdentity && errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(parent.Parent().Fd()), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, false, errors.New("open exact-parent put stage failed")
	}
	file := os.NewFile(uintptr(fd), name)
	if attachIdentity && record.Mode == "replace" {
		if err := unix.Fchown(fd, int(record.OldUID), int(record.OldGID)); err != nil {
			file.Close()
			return nil, false, errors.New("preserve replacement ownership on put stage failed")
		}
		if err := unix.Fchmod(fd, record.OldMode); err != nil {
			file.Close()
			return nil, false, errors.New("preserve replacement mode on put stage failed")
		}
	}
	identity, err := validateStageFileForRecord(file, 1, record)
	if err != nil || record.StageIdentity != "" && identity != record.StageIdentity {
		file.Close()
		if err != nil {
			return nil, false, err
		}
		return nil, false, ErrUnsafeState
	}
	stage := &Stage{File: file, Name: name, Identity: identity, ParentPath: parent.path, ParentIdentity: parent.identities[len(parent.identities)-1], parent: parent, record: record}
	if record.Mode == "replace" {
		old, evidence, openErr := openReplacementDestination(parent, filepath.Base(filepath.FromSlash(record.Destination)))
		if openErr != nil || evidence.Identity != record.OldIdentity || evidence.UID != record.OldUID || evidence.GID != record.OldGID || evidence.Mode != record.OldMode {
			stage.Close()
			return nil, false, ErrUnsafeState
		}
		stage.oldDestination = old
	}
	if err := file.Truncate(0); err != nil {
		stage.Close()
		return nil, false, errors.New("truncate validated put stage failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		stage.Close()
		return nil, false, errors.New("rewind validated put stage failed")
	}
	return stage, attachIdentity, nil
}

func (s *Stage) VerifyContent(ctx context.Context, manifest Manifest) error {
	if s.File == nil || s.parent == nil || s.parent.Revalidate() != nil {
		return ErrUnsafeState
	}
	if _, err := validateStageFileForRecord(s.File, 1, s.record); err != nil {
		return ErrUnsafeState
	}
	if err := validateStageEntry(s.parent.Parent(), s.Name, s.Identity); err != nil {
		return err
	}
	info, err := s.File.Stat()
	if err != nil || info.Size() != manifest.Size {
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

func (s *Stage) Publish(ctx context.Context, destination string, manifest Manifest) (bool, string, error) {
	if s.File == nil || s.parent == nil || s.parent.Revalidate() != nil {
		return false, "", ErrUnsafeState
	}
	if manifest.Mode == "create" {
		if err := rejectCaseCollision(s.parent.Parent(), destination); err != nil {
			return false, "", err
		}
	}
	if _, err := validateStageFileForRecord(s.File, 1, s.record); err != nil {
		return false, "", ErrUnsafeState
	}
	if err := validateStageEntry(s.parent.Parent(), s.Name, s.Identity); err != nil {
		return false, "", err
	}
	if ctx.Err() != nil {
		return false, "", errPublishNotAttempted
	}
	if manifest.Mode == "replace" {
		return s.publishReplacement(ctx, destination, manifest)
	}
	if err := publishPinned(s.File, s.parent.Parent(), s.Name, destination); err != nil {
		created, known := destinationHasIdentity(s.parent.Parent(), destination, s.Identity)
		if known {
			if !created {
				return false, "", err
			}
			durability := "durability_confirmed"
			if syncErr := unix.Fsync(int(s.parent.Parent().Fd())); syncErr != nil {
				durability = "durability_unconfirmed"
			}
			return true, durability, nil
		}
		return false, "", ErrOutcomeUnknown
	}
	created, known := destinationHasIdentity(s.parent.Parent(), destination, s.Identity)
	if !known || !created {
		return true, "", ErrOutcomeUnknown
	}
	durability := "durability_confirmed"
	if err := unix.Fsync(int(s.parent.Parent().Fd())); err != nil {
		durability = "durability_unconfirmed"
	}
	return true, durability, nil
}

func (s *Stage) publishReplacement(ctx context.Context, destination string, manifest Manifest) (bool, string, error) {
	if s.oldDestination == nil {
		return false, "", ErrUnsafeState
	}
	evidence, err := validateReplacementFile(s.oldDestination)
	if err != nil || evidence.Identity != s.record.OldIdentity || evidence.UID != s.record.OldUID || evidence.GID != s.record.OldGID || evidence.Mode != s.record.OldMode {
		return false, "", ErrUnsafeState
	}
	if err := validateDestinationEntry(s.parent.Parent(), destination, s.record.OldIdentity); err != nil {
		return false, "", ErrUnsafeState
	}
	if manifest.ExpectSHA256 != "" {
		digest, err := hashPinnedFile(ctx, s.oldDestination)
		if err != nil {
			return false, "", err
		}
		if digest != manifest.ExpectSHA256 {
			return false, "", errors.Join(errPublishNotAttempted, ErrCASMismatch)
		}
	}
	if _, err := validateStageFileForRecord(s.File, 1, s.record); err != nil {
		return false, "", ErrUnsafeState
	}
	if err := validateDestinationEntry(s.parent.Parent(), destination, s.record.OldIdentity); err != nil || validateStageEntry(s.parent.Parent(), s.Name, s.Identity) != nil {
		return false, "", ErrUnsafeState
	}
	if ctx.Err() != nil {
		return false, "", errPublishNotAttempted
	}
	renameErr := unix.Renameat(int(s.parent.Parent().Fd()), s.Name, int(s.parent.Parent().Fd()), destination)
	published, notPublished := replacementPublicationEvidence(s.parent.Parent(), destination, s.Name, s.Identity, s.record.OldIdentity)
	if !published {
		if notPublished {
			if renameErr != nil {
				return false, "", fmt.Errorf("%w: %v", errPublishNotAttempted, renameErr)
			}
			return false, "", errPublishNotAttempted
		}
		return false, "", ErrOutcomeUnknown
	}
	durability := "durability_confirmed"
	if err := unix.Fsync(int(s.parent.Parent().Fd())); err != nil {
		durability = "durability_unconfirmed"
	}
	return true, durability, nil
}

func inspectReplacementDestination(parent *openedParent, destination string) (replacementEvidence, error) {
	file, evidence, err := openReplacementDestination(parent, destination)
	if file != nil {
		_ = file.Close()
	}
	return evidence, err
}

func replacementBackupEvidence(*openedParent, string, replacementEvidence) (string, int64, error) {
	return "", 0, nil
}

func openReplacementDestination(parent *openedParent, destination string) (*os.File, replacementEvidence, error) {
	fd, err := unix.Openat(int(parent.Parent().Fd()), destination, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, replacementEvidence{}, errors.New("replacement destination is unavailable")
	}
	file := os.NewFile(uintptr(fd), destination)
	evidence, err := validateReplacementFile(file)
	if err != nil {
		file.Close()
		return nil, replacementEvidence{}, err
	}
	if err := validateDestinationEntry(parent.Parent(), destination, evidence.Identity); err != nil {
		file.Close()
		return nil, replacementEvidence{}, err
	}
	return file, evidence, nil
}

func validateReplacementFile(file *os.File) (replacementEvidence, error) {
	info, err := file.Stat()
	if err != nil {
		return replacementEvidence{}, ErrUnsafeState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mode := uint32(info.Mode().Perm())
	if !ok || !info.Mode().IsRegular() || uint64(stat.Nlink) != 1 || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 || mode&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return replacementEvidence{}, errors.New("replacement destination has unsafe ownership, links, or mode")
	}
	if err := validateReplacementPlatform(file, stat); err != nil {
		return replacementEvidence{}, err
	}
	return replacementEvidence{Identity: identityFromStat(stat), UID: stat.Uid, GID: stat.Gid, Mode: mode}, nil
}

func validateDestinationEntry(parent *os.File, name, identity string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || identityFromUnixStat(&stat) != identity {
		return ErrUnsafeState
	}
	return nil
}

func hashPinnedFile(ctx context.Context, file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("rewind replacement destination failed")
	}
	hasher := sha256.New()
	if _, err := io.Copy(&contextWriter{ctx: ctx, writer: hasher}, file); err != nil {
		return "", errors.New("hash replacement destination failed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func replacementPublicationEvidence(parent *os.File, destination, stageName, stageIdentity, oldIdentity string) (published, notPublished bool) {
	atDestination, destinationKnown := destinationHasIdentity(parent, destination, stageIdentity)
	if destinationKnown && atDestination {
		return true, false
	}
	oldAtDestination, oldKnown := destinationHasIdentity(parent, destination, oldIdentity)
	var stageStat unix.Stat_t
	stagePresent := unix.Fstatat(int(parent.Fd()), stageName, &stageStat, unix.AT_SYMLINK_NOFOLLOW) == nil && identityFromUnixStat(&stageStat) == stageIdentity && stageStat.Mode&unix.S_IFMT == unix.S_IFREG
	return false, oldKnown && oldAtDestination && stagePresent
}

func validateStageEntry(parent *os.File, name, identity string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || identityFromUnixStat(&stat) != identity || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrUnsafeState
	}
	return nil
}

func destinationHasIdentity(parent *os.File, name, identity string) (bool, bool) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	file := os.NewFile(uintptr(fd), name)
	id, idErr := fileIdentity(file, false)
	file.Close()
	if idErr != nil {
		return false, false
	}
	return id == identity, true
}

func (s *Stage) RemoveEntry() (bool, error) {
	if s.parent == nil || s.parent.Revalidate() != nil {
		return false, ErrUnsafeState
	}
	var stat unix.Stat_t
	err := unix.Fstatat(int(s.parent.Parent().Fd()), s.Name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil || identityFromUnixStat(&stat) != s.Identity || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, ErrUnsafeState
	}
	if err := unix.Unlinkat(int(s.parent.Parent().Fd()), s.Name, 0); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Stage) SyncParent() error { return unix.Fsync(int(s.parent.Parent().Fd())) }

func openCleanupStage(record Record) (*Stage, error) {
	return openOwnedStage(record)
}

func openCleanupArtifacts(record Record) (*Stage, *Stage, error) {
	stage, err := openCleanupStage(record)
	return stage, nil, err
}

func openOwnedStage(record Record) (*Stage, error) {
	root := recordRoot(record)
	parent, err := openDestinationParent(root, record.Destination, false)
	if err != nil {
		return nil, err
	}
	if parent.path != record.ParentPath || parent.identities[len(parent.identities)-1] != record.ParentIdentity {
		parent.Close()
		return nil, ErrUnsafeState
	}
	fd, err := unix.Openat(int(parent.Parent().Fd()), record.StageName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && (record.State == "committed" || record.State == "cleanup_not_attempted" || record.State == "accept_current_intent") {
		return &Stage{Name: record.StageName, Identity: record.StageIdentity, ParentPath: record.ParentPath, ParentIdentity: record.ParentIdentity, parent: parent, record: record}, nil
	}
	if err != nil {
		parent.Close()
		return nil, err
	}
	file := os.NewFile(uintptr(fd), record.StageName)
	links := uint64(1)
	if record.State == "committed" {
		links = 2
	}
	if record.State == "accept_current_intent" {
		info, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			parent.Close()
			return nil, ErrUnsafeState
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink < 1 || stat.Nlink > 2 {
			file.Close()
			parent.Close()
			return nil, ErrUnsafeState
		}
		links = uint64(stat.Nlink)
	}
	id, validationErr := validateStageFileForRecord(file, links, record)
	if validationErr != nil || record.StageIdentity != "" && id != record.StageIdentity {
		file.Close()
		parent.Close()
		return nil, ErrUnsafeState
	}
	return &Stage{File: file, Name: record.StageName, Identity: id, ParentPath: record.ParentPath, ParentIdentity: record.ParentIdentity, parent: parent, record: record}, nil
}

func preflightAcceptCurrent(root string, record Record) (string, error) {
	parent, err := openDestinationParent(root, record.Destination, false)
	if err != nil {
		return "", err
	}
	if parent.path != record.ParentPath || parent.identities[len(parent.identities)-1] != record.ParentIdentity {
		parent.Close()
		return "", ErrUnsafeState
	}
	destination := filepath.Base(filepath.FromSlash(record.Destination))
	identity, err := validateUnixAcceptCurrentDestination(parent, destination, record)
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

func validateUnixAcceptCurrentDestination(parent *openedParent, destination string, record Record) (string, error) {
	fd, err := unix.Openat(int(parent.Parent().Fd()), destination, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", ErrUnsafeState
	}
	file := os.NewFile(uintptr(fd), destination)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", ErrUnsafeState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 || uint32(info.Mode().Perm())&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "", ErrUnsafeState
	}
	identity := identityFromStat(stat)
	links := uint64(stat.Nlink)
	if links != 1 {
		if links != 2 || record.StageIdentity != identity || validateStageEntry(parent.Parent(), record.StageName, identity) != nil {
			return "", ErrUnsafeState
		}
	}
	if err := validateReplacementPlatform(file, stat); err != nil {
		return "", err
	}
	if err := validateDestinationEntry(parent.Parent(), destination, identity); err != nil {
		return "", err
	}
	return identity, nil
}

func recordRoot(record Record) string {
	root := record.ParentPath
	parts := strings.Split(filepath.ToSlash(record.Destination), "/")
	for range parts[:len(parts)-1] {
		root = filepath.Dir(root)
	}
	return root
}

func reconcilePublication(record Record) (Result, bool, error) {
	parent, err := openDestinationParent(recordRoot(record), record.Destination, false)
	if err != nil {
		return Result{}, false, err
	}
	defer parent.Close()
	if parent.path != record.ParentPath || parent.identities[len(parent.identities)-1] != record.ParentIdentity {
		return Result{}, false, ErrUnsafeState
	}
	destination := filepath.Base(filepath.FromSlash(record.Destination))
	created, known := destinationHasIdentity(parent.Parent(), destination, record.StageIdentity)
	if !known {
		return Result{}, false, ErrOutcomeUnknown
	}
	if !created {
		if record.Mode == "replace" {
			_, notPublished := replacementPublicationEvidence(parent.Parent(), destination, record.StageName, record.StageIdentity, record.OldIdentity)
			if notPublished {
				return Result{}, false, errPublishNotAttempted
			}
			return Result{}, false, ErrOutcomeUnknown
		}
		return Result{}, false, nil
	}
	return resultFrom(record.Manifest, "durability_unconfirmed"), true, nil
}

func fileIdentity(file *os.File, directory bool) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return "", errors.New("unexpected file type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("native identity unavailable")
	}
	return identityFromStat(stat), nil
}

func identityFromStat(stat *syscall.Stat_t) string {
	return fmt.Sprintf("unix1:%016x:%016x", uint64(stat.Dev), stat.Ino)
}

func identityFromUnixStat(stat *unix.Stat_t) string {
	return fmt.Sprintf("unix1:%016x:%016x", uint64(stat.Dev), stat.Ino)
}

func validateStageFile(file *os.File, links uint64) (string, error) {
	return validateStageFileForRecord(file, links, Record{Manifest: Manifest{Mode: "create"}})
}

func validateStageFileForRecord(file *os.File, links uint64, record Record) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("put stage native metadata is unavailable")
	}
	wantUID, wantGID, wantMode := uint32(os.Geteuid()), stat.Gid, uint32(0o600)
	if record.Mode == "replace" {
		wantUID, wantGID, wantMode = record.OldUID, record.OldGID, record.OldMode
	}
	if !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != wantMode || stat.Uid != wantUID || stat.Gid != wantGID || uint64(stat.Nlink) != links {
		return "", errors.New("put stage is not an owner-only single-link regular file")
	}
	if err := validateStagePlatform(file, stat); err != nil {
		return "", errors.New("put stage has unsupported platform metadata")
	}
	return identityFromStat(stat), nil
}
