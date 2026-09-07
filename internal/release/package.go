package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Metadata struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type Options struct {
	InputDir  string
	OutputDir string
	License   string
	Notices   string
	Version   string
	Commit    string
	BuildDate time.Time
	Platforms []Platform
}

type Platform struct {
	OS   string
	Arch string
}

func Package(options Options) ([]string, error) {
	if strings.ContainsAny(options.Version, "/\\\r\n") || options.Version == "" {
		return nil, errors.New("release version is empty or unsafe")
	}
	if options.BuildDate.IsZero() {
		return nil, errors.New("release build date is required")
	}
	if len(options.Platforms) == 0 {
		options.Platforms = SupportedPlatforms()
	}
	for _, platform := range options.Platforms {
		if !supported(platform) {
			return nil, fmt.Errorf("unsupported release platform %s/%s", platform.OS, platform.Arch)
		}
	}
	license, err := os.ReadFile(options.License)
	if err != nil {
		return nil, fmt.Errorf("read license: %w", err)
	}
	notices, err := os.ReadFile(options.Notices)
	if err != nil {
		return nil, fmt.Errorf("read notices: %w", err)
	}
	if err := os.MkdirAll(options.OutputDir, 0o755); err != nil {
		return nil, err
	}
	created := make([]string, 0, len(options.Platforms))
	for _, platform := range options.Platforms {
		path, packageErr := packagePlatform(options, platform, license, notices)
		if packageErr != nil {
			for _, createdPath := range created {
				_ = os.Remove(createdPath)
			}
			return nil, packageErr
		}
		created = append(created, path)
	}
	if err := writeChecksums(options.OutputDir, created); err != nil {
		for _, createdPath := range created {
			_ = os.Remove(createdPath)
		}
		return nil, err
	}
	return created, nil
}

func supported(candidate Platform) bool {
	for _, platform := range SupportedPlatforms() {
		if candidate == platform {
			return true
		}
	}
	return false
}

func SupportedPlatforms() []Platform {
	return []Platform{
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "windows", Arch: "amd64"},
		{OS: "windows", Arch: "arm64"},
	}
}

func packagePlatform(options Options, platform Platform, license, notices []byte) (string, error) {
	extension := ""
	archiveExtension := ".tar.gz"
	if platform.OS == "windows" {
		extension = ".exe"
		archiveExtension = ".zip"
	}
	entries := map[string][]byte{"LICENSE": license, "THIRD_PARTY_NOTICES.md": notices}
	for _, name := range []string{"px", "px-server"} {
		path := filepath.Join(options.InputDir, name+"-"+platform.OS+"-"+platform.Arch+extension)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s binary: %w", name, err)
		}
		entries[name+extension] = data
	}
	manifest, err := json.MarshalIndent(Metadata{Version: options.Version, Commit: options.Commit, Built: options.BuildDate.UTC().Format(time.RFC3339), OS: platform.OS, Arch: platform.Arch}, "", "  ")
	if err != nil {
		return "", err
	}
	entries["release-manifest.json"] = append(manifest, '\n')
	filename := "px-" + options.Version + "-" + platform.OS + "-" + platform.Arch + archiveExtension
	path := filepath.Join(options.OutputDir, filename)
	temporary := path + ".tmp"
	if platform.OS == "windows" {
		err = writeZip(temporary, entries, options.BuildDate)
	} else {
		err = writeTarGzip(temporary, entries, options.BuildDate)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return path, nil
}

func writeTarGzip(path string, entries map[string][]byte, timestamp time.Time) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = timestamp
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range entryNames(entries) {
		mode := int64(0o644)
		if name == "px" || name == "px-server" {
			mode = 0o755
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(entries[name])), ModTime: timestamp, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tarWriter.Write(entries[name]); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeZip(path string, entries map[string][]byte, timestamp time.Time) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	for _, name := range entryNames(entries) {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetModTime(timestamp)
		if strings.HasSuffix(name, ".exe") {
			header.SetMode(0o755)
		} else {
			header.SetMode(0o644)
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := entry.Write(entries[name]); err != nil {
			return err
		}
	}
	return writer.Close()
}

func writeChecksums(outputDir string, paths []string) error {
	sort.Strings(paths)
	var output strings.Builder
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		output.WriteString(hex.EncodeToString(digest.Sum(nil)))
		output.WriteString("  ")
		output.WriteString(filepath.Base(path))
		output.WriteByte('\n')
	}
	path := filepath.Join(outputDir, "SHA256SUMS")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(output.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func entryNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
