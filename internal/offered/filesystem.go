package offered

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/scotthaleen/px/internal/transfer"
)

const (
	MaxPathBytes      = 4096
	MaxPathDepth      = 128
	MaxEntries        = 1024
	maxScannedEntries = 4096
)

var (
	ErrUnavailable  = errors.New("offered path is unavailable")
	ErrNotRegular   = errors.New("offered path is not a regular file")
	ErrNotDirectory = errors.New("offered path is not a directory")
)

type Entry struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Size int64  `json:"size,omitempty"`
}

func ValidatePath(path string, allowEmpty bool) error {
	if path == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("path is required")
	}
	if len(path) > MaxPathBytes || !utf8.ValidString(path) {
		return fmt.Errorf("path must be valid UTF-8 and at most %d bytes", MaxPathBytes)
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return errors.New("path must be relative without leading or trailing separators")
	}
	parts := strings.Split(path, "/")
	if len(parts) > MaxPathDepth {
		return fmt.Errorf("path has more than %d components", MaxPathDepth)
	}
	for _, part := range parts {
		if err := transfer.ValidatePortableName(part); err != nil {
			return fmt.Errorf("invalid path component: %w", err)
		}
		if transfer.IsReservedName(part) {
			return errors.New("path uses a reserved internal name")
		}
	}
	return nil
}

func List(rootPath, path string) ([]Entry, error) {
	if err := ValidatePath(path, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer root.Close()
	nativePath := filepath.FromSlash(path)
	if nativePath == "" {
		nativePath = "."
	}
	directory, err := root.Open(nativePath)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	if !info.IsDir() {
		return nil, ErrNotDirectory
	}
	entries := make([]Entry, 0, MaxEntries)
	scanned := 0
	for {
		values, err := directory.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, ErrUnavailable
		}
		scanned += len(values)
		if scanned > maxScannedEntries {
			return nil, errors.New("directory contains too many entries to scan safely")
		}
		for _, value := range values {
			if transfer.IsReservedName(value.Name()) {
				continue
			}
			if err := transfer.ValidatePortableName(value.Name()); err != nil {
				continue
			}
			entryInfo, err := value.Info()
			if err != nil {
				return nil, ErrUnavailable
			}
			switch {
			case entryInfo.IsDir():
				entries = append(entries, Entry{Name: value.Name(), Kind: "directory"})
			case entryInfo.Mode().IsRegular():
				entries = append(entries, Entry{Name: value.Name(), Kind: "file", Size: entryInfo.Size()})
			}
			if len(entries) > MaxEntries {
				return nil, fmt.Errorf("directory contains more than %d entries", MaxEntries)
			}
		}
		if errors.Is(err, io.EOF) || len(values) == 0 {
			break
		}
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	for index := 1; index < len(entries); index++ {
		if strings.EqualFold(entries[index-1].Name, entries[index].Name) {
			return nil, errors.New("directory contains a portable case collision")
		}
	}
	return entries, nil
}

func Open(rootPath, path string) (*os.File, os.FileInfo, error) {
	if err := ValidatePath(path, false); err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer root.Close()
	file, err := root.Open(filepath.FromSlash(path))
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, ErrUnavailable
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, ErrNotRegular
	}
	return file, info, nil
}
