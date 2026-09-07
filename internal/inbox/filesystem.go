package inbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/transfer"
)

const (
	ResultVersion      = 1
	MoveStateMoved     = "moved"
	MoveStateRetained  = "destination_committed_source_retained"
	MoveStateUncertain = "destination_committed_source_removal_uncertain"
	MaxEntries         = 256
	MaxEncodedBytes    = 48 << 10
	maxScannedEntries  = 4096
)

var (
	ErrUnavailable        = errors.New("inbox is unavailable")
	ErrInvalidSender      = errors.New("invalid inbox sender")
	ErrInvalidPath        = errors.New("invalid inbox path")
	ErrInvalidDestination = errors.New("invalid inbox move destination")
	ErrEntryChanged       = errors.New("inbox file changed during operation")
)

type Entry struct {
	Sender string `json:"sender"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
}

type PathResult struct {
	Version int    `json:"version"`
	Source  string `json:"source"`
	Path    string `json:"path"`
}

type MoveResult struct {
	Version                int    `json:"version"`
	Source                 string `json:"source"`
	Destination            string `json:"destination"`
	State                  string `json:"state"`
	DestinationCommitted   bool   `json:"destination_committed"`
	SourceRemovalConfirmed bool   `json:"source_removal_confirmed"`
	DurabilityUnconfirmed  bool   `json:"durability_unconfirmed,omitempty"`
	Warning                string `json:"warning,omitempty"`
}

type Source struct {
	root          *os.Root
	contextDir    *os.File
	senderDir     *os.File
	syncDir       *os.File
	file          *os.File
	info          os.FileInfo
	entryPath     string
	absolutePath  string
	portablePath  string
	senderDirPath string
	beforeClaim   func()
	afterClaim    func(string)
}

func Open(rootPath, contextName, portablePath string) (*Source, error) {
	sender, name, err := ValidatePath(portablePath)
	if err != nil {
		return nil, err
	}
	if err := membership.ValidateLabel(contextName); err != nil {
		return nil, fmt.Errorf("context name: %w", err)
	}
	absoluteRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	root, err := os.OpenRoot(absoluteRoot)
	if err != nil {
		return nil, ErrUnavailable
	}
	source := &Source{root: root, portablePath: portablePath}
	closeOnError := func() {
		_ = source.Close()
	}
	source.contextDir, err = openDirectory(root, contextName, nil)
	if err != nil {
		closeOnError()
		return nil, ErrUnavailable
	}
	source.senderDirPath = filepath.Join(contextName, sender)
	source.senderDir, err = openDirectory(root, source.senderDirPath, nil)
	if err != nil {
		closeOnError()
		return nil, ErrUnavailable
	}
	source.syncDir, err = openSyncDirectory(filepath.Join(absoluteRoot, source.senderDirPath))
	if err != nil {
		closeOnError()
		return nil, ErrUnavailable
	}
	if !sameOpenedDirectory(source.senderDir, source.syncDir) {
		closeOnError()
		return nil, ErrUnavailable
	}
	source.entryPath = filepath.Join(source.senderDirPath, name)
	source.absolutePath = filepath.Join(absoluteRoot, source.entryPath)
	pathInfo, err := root.Lstat(source.entryPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		closeOnError()
		return nil, ErrUnavailable
	}
	source.file, err = root.Open(source.entryPath)
	if err != nil {
		closeOnError()
		return nil, ErrUnavailable
	}
	source.info, err = source.file.Stat()
	if err != nil || !source.info.Mode().IsRegular() || !os.SameFile(source.info, pathInfo) {
		closeOnError()
		return nil, ErrUnavailable
	}
	if err := source.Revalidate(); err != nil {
		closeOnError()
		return nil, err
	}
	return source, nil
}

func ValidatePath(portablePath string) (string, string, error) {
	if strings.Count(portablePath, "/") != 1 || strings.Contains(portablePath, `\`) {
		return "", "", ErrInvalidPath
	}
	sender, name, _ := strings.Cut(portablePath, "/")
	if membership.ValidateLabel(sender) != nil || transfer.ValidatePortableName(name) != nil || transfer.IsReservedName(name) {
		return "", "", ErrInvalidPath
	}
	return sender, name, nil
}

func (s *Source) PathResult() PathResult {
	return PathResult{Version: ResultVersion, Source: s.portablePath, Path: s.absolutePath}
}

func (s *Source) Size() int64 { return s.info.Size() }

func (s *Source) CopyTo(ctx context.Context, destination io.Writer) error {
	reader := &contextReader{ctx: ctx, reader: s.file}
	written, err := io.CopyN(destination, reader, s.info.Size())
	if err != nil || written != s.info.Size() {
		return errors.New("copy inbox file failed")
	}
	var extra [1]byte
	if count, readErr := reader.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		return ErrEntryChanged
	}
	return s.Revalidate()
}

func (s *Source) Revalidate() error {
	opened, err := s.file.Stat()
	if err != nil || !sameFileState(s.info, opened) {
		return ErrEntryChanged
	}
	pathInfo, err := s.root.Lstat(s.entryPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !sameFileState(s.info, pathInfo) {
		return ErrEntryChanged
	}
	senderInfo, err := s.senderDir.Stat()
	currentSender, pathErr := s.root.Lstat(s.senderDirPath)
	if err != nil || pathErr != nil || !senderInfo.IsDir() || !currentSender.IsDir() || currentSender.Mode()&os.ModeSymlink != 0 || !os.SameFile(senderInfo, currentSender) {
		return ErrEntryChanged
	}
	return nil
}

func (s *Source) Remove() (bool, error) {
	if err := s.Revalidate(); err != nil {
		return false, err
	}
	if s.beforeClaim != nil {
		s.beforeClaim()
	}
	claimDirectory, claimPath, err := s.claimPath()
	if err != nil {
		return false, err
	}
	if err := s.root.Rename(s.entryPath, claimPath); err != nil {
		_ = s.root.Remove(claimDirectory)
		return false, errors.New("claim inbox source failed")
	}
	if s.afterClaim != nil {
		s.afterClaim(claimPath)
	}
	claimed, statErr := s.root.Lstat(claimPath)
	opened, openErr := s.file.Stat()
	if statErr != nil || openErr != nil || !sameFileState(s.info, opened) || !sameFileState(s.info, claimed) {
		// Link restores without replacing a file that appeared after the claim.
		if s.root.Link(claimPath, s.entryPath) == nil {
			_ = s.root.Remove(claimPath)
			_ = s.root.Remove(claimDirectory)
			_ = syncDirectory(s.syncDir)
			return false, ErrEntryChanged
		}
		_ = syncDirectory(s.syncDir)
		return true, ErrEntryChanged
	}
	if err := s.root.Remove(claimPath); err != nil {
		return true, errors.New("remove claimed inbox source failed")
	}
	if err := s.root.Remove(claimDirectory); err != nil {
		return true, errors.New("remove inbox source claim failed")
	}
	if err := syncDirectory(s.syncDir); err != nil {
		return true, errors.New("sync inbox source directory failed")
	}
	return true, nil
}

func (s *Source) claimPath() (string, string, error) {
	for range 4 {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return "", "", errors.New("generate inbox source claim failed")
		}
		directory := filepath.Join(s.senderDirPath, transfer.ReservedNamePrefix+hex.EncodeToString(value)+".move")
		if err := s.root.Mkdir(directory, 0o700); err == nil {
			return directory, filepath.Join(directory, filepath.Base(s.entryPath)), nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", "", errors.New("create inbox source claim failed")
		}
	}
	return "", "", errors.New("create unique inbox source claim failed")
}

func (s *Source) Close() error {
	return errors.Join(closeFile(s.file), closeFile(s.syncDir), closeFile(s.senderDir), closeFile(s.contextDir), closeRoot(s.root))
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func sameFileState(expected, actual os.FileInfo) bool {
	return actual != nil && actual.Mode().IsRegular() && os.SameFile(expected, actual) && expected.Size() == actual.Size() && expected.ModTime().Equal(actual.ModTime())
}

func sameOpenedDirectory(first, second *os.File) bool {
	firstInfo, firstErr := first.Stat()
	secondInfo, secondErr := second.Stat()
	return firstErr == nil && secondErr == nil && firstInfo.IsDir() && secondInfo.IsDir() && os.SameFile(firstInfo, secondInfo)
}

func closeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}

func closeRoot(root *os.Root) error {
	if root == nil {
		return nil
	}
	return root.Close()
}

func List(rootPath, contextName, sender string) ([]Entry, error) {
	if err := membership.ValidateLabel(contextName); err != nil {
		return nil, fmt.Errorf("context name: %w", err)
	}
	if sender != "" {
		if err := membership.ValidateLabel(sender); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSender, err)
		}
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	contextDirectory, err := openDirectory(root, contextName, nil)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	defer contextDirectory.Close()
	senders, err := readDirectory(contextDirectory)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	scanned := len(senders)
	encodedBytes := 2
	seenSenders := make([]string, 0, len(senders))
	for _, value := range senders {
		if value.Type()&os.ModeSymlink != 0 || !value.IsDir() || membership.ValidateLabel(value.Name()) != nil || sender != "" && value.Name() != sender {
			continue
		}
		if containsFold(seenSenders, value.Name()) {
			return nil, errors.New("inbox contains a portable sender case collision")
		}
		seenSenders = append(seenSenders, value.Name())
		expected, err := value.Info()
		if err != nil {
			return nil, ErrUnavailable
		}
		directory, err := openDirectory(root, filepath.Join(contextName, value.Name()), expected)
		if err != nil {
			return nil, ErrUnavailable
		}
		files, readErr := readDirectory(directory)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			return nil, ErrUnavailable
		}
		scanned += len(files)
		if scanned > maxScannedEntries {
			return nil, errors.New("inbox contains too many entries to scan safely")
		}
		for _, file := range files {
			if file.Type()&os.ModeSymlink != 0 || file.IsDir() || transfer.IsReservedName(file.Name()) || transfer.ValidatePortableName(file.Name()) != nil {
				continue
			}
			fileInfo, err := file.Info()
			if err != nil {
				return nil, ErrUnavailable
			}
			if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
				continue
			}
			entry := Entry{Sender: value.Name(), Name: file.Name(), Path: value.Name() + "/" + file.Name(), Size: fileInfo.Size()}
			encoded, err := json.Marshal(entry)
			if err != nil {
				return nil, ErrUnavailable
			}
			encodedBytes += len(encoded)
			if len(entries) != 0 {
				encodedBytes++
			}
			if encodedBytes > MaxEncodedBytes {
				return nil, errors.New("inbox listing exceeds the safe response size")
			}
			entries = append(entries, entry)
			if len(entries) > MaxEntries {
				return nil, fmt.Errorf("inbox contains more than %d files", MaxEntries)
			}
		}
	}
	seenPaths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if containsFold(seenPaths, entry.Path) {
			return nil, errors.New("inbox contains a portable case collision")
		}
		seenPaths = append(seenPaths, entry.Path)
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return entries, nil
}

func openDirectory(root *os.Root, path string, expected os.FileInfo) (*os.File, error) {
	pathInfo, err := root.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return nil, errOrUnavailable(err)
	}
	directory, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	info, statErr := directory.Stat()
	current, pathErr := root.Lstat(path)
	if statErr != nil || pathErr != nil || !info.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(info, current) || expected != nil && !os.SameFile(info, expected) {
		directory.Close()
		return nil, ErrUnavailable
	}
	return directory, nil
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func errOrUnavailable(err error) error {
	if err != nil {
		return err
	}
	return ErrUnavailable
}

func readDirectory(directory *os.File) ([]os.DirEntry, error) {
	entries := make([]os.DirEntry, 0)
	for {
		values, err := directory.ReadDir(128)
		entries = append(entries, values...)
		if len(entries) > maxScannedEntries {
			return nil, errors.New("inbox contains too many entries to scan safely")
		}
		if errors.Is(err, io.EOF) || len(values) == 0 {
			return entries, nil
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	}
}
