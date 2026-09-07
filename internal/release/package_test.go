package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPackageCreatesArchivesAndChecksums(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	platforms := []Platform{{OS: "linux", Arch: "arm64"}, {OS: "windows", Arch: "amd64"}}
	for _, platform := range platforms {
		extension := ""
		if platform.OS == "windows" {
			extension = ".exe"
		}
		for _, name := range []string{"px", "px-server"} {
			if err := os.WriteFile(filepath.Join(input, name+"-"+platform.OS+"-"+platform.Arch+extension), []byte(name+"-"+platform.OS), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	license := filepath.Join(root, "LICENSE")
	notices := filepath.Join(root, "NOTICES")
	if err := os.WriteFile(license, []byte("license"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notices, []byte("notices"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "release")
	buildDate := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	paths, err := Package(Options{InputDir: input, OutputDir: output, License: license, Notices: notices, Version: "2026.07.28", Commit: "abc123", BuildDate: buildDate, Platforms: platforms})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("archives = %v", paths)
	}
	if got, want := filepath.Base(paths[0]), "px-2026.07.28-linux-arm64.tar.gz"; got != want {
		t.Fatalf("Linux archive = %q, want %q", got, want)
	}
	if got, want := filepath.Base(paths[1]), "px-2026.07.28-windows-amd64.zip"; got != want {
		t.Fatalf("Windows archive = %q, want %q", got, want)
	}
	wantEntries := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "px", "px-server", "release-manifest.json"}
	if got := tarNames(t, paths[0]); !reflect.DeepEqual(got, wantEntries) {
		t.Fatalf("tar entries = %v, want %v", got, wantEntries)
	}
	wantZipEntries := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "px-server.exe", "px.exe", "release-manifest.json"}
	if got := zipNames(t, paths[1]); !reflect.DeepEqual(got, wantZipEntries) {
		t.Fatalf("zip entries = %v, want %v", got, wantZipEntries)
	}
	checksums, err := os.ReadFile(filepath.Join(output, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], filepath.Base(paths[0])) || !strings.Contains(lines[1], filepath.Base(paths[1])) {
		t.Fatalf("checksums = %q", checksums)
	}
}

func TestPackageRejectsUnsafeOrIncompleteInput(t *testing.T) {
	root := t.TempDir()
	options := Options{InputDir: root, OutputDir: filepath.Join(root, "out"), License: filepath.Join(root, "LICENSE"), Notices: filepath.Join(root, "NOTICES"), Version: "../bad", BuildDate: time.Now(), Platforms: []Platform{{OS: "linux", Arch: "amd64"}}}
	if _, err := Package(options); err == nil {
		t.Fatal("unsafe version succeeded")
	}
	options.Version = "2026.07.28"
	if err := os.WriteFile(options.License, []byte("license"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Notices, []byte("notices"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Package(options); err == nil {
		t.Fatal("missing binaries succeeded")
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
}

func zipNames(t *testing.T, path string) []string {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	return names
}
