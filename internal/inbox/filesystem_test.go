package inbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOpenPathCopyAndRemove(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "home", "alice", "report.txt", "report")
	source, err := Open(root, "home", "alice/report.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	result := source.PathResult()
	if result.Version != ResultVersion || result.Source != "alice/report.txt" || result.Path != filepath.Join(root, "home", "alice", "report.txt") {
		t.Fatalf("path result = %+v", result)
	}
	var copied bytes.Buffer
	if err := source.CopyTo(context.Background(), &copied); err != nil || copied.String() != "report" {
		t.Fatalf("copy = %q, %v", copied.String(), err)
	}
	removed, err := source.Remove()
	if err != nil || !removed {
		t.Fatalf("remove = %v, %v", removed, err)
	}
	if _, err := os.Lstat(result.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed path error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(result.Path))
	if err != nil || len(entries) != 0 {
		t.Fatalf("source directory entries = %v, %v", entries, err)
	}
}

func TestOpenRejectsInvalidAndUnsafePaths(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "home", "alice", "report.txt", "report")
	for _, value := range []string{"", "alice", "alice/one/two", "@alice/report.txt", "alice/../report.txt", `alice\report.txt`, "alice/CON"} {
		if _, err := Open(root, "home", value); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("Open(%q) error = %v", value, err)
		}
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "home", "alice", "linked.txt")); err == nil {
		if _, err := Open(root, "home", "alice/linked.txt"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("symlink error = %v", err)
		}
	}
}

func TestSourceReplacementIsNeverRemoved(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "home", "alice", "report.txt", "original")
	source, err := Open(root, "home", "alice/report.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(root, "home", "alice", "report.txt")
	source.beforeClaim = func() {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := source.Remove(); removed || !errors.Is(err, ErrEntryChanged) {
		t.Fatalf("replacement remove = %v, %v", removed, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "replacement" {
		t.Fatalf("replacement = %q, %v", content, err)
	}
}

func TestClaimReplacementWithOccupiedSourceIsUncertain(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "home", "alice", "report.txt", "original")
	source, err := Open(root, "home", "alice/report.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(root, "home", "alice", "report.txt")
	source.afterClaim = func(claimPath string) {
		absoluteClaim := filepath.Join(root, claimPath)
		if err := os.Rename(absoluteClaim, absoluteClaim+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absoluteClaim, []byte("claim replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("source replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := source.Remove(); !removed || !errors.Is(err, ErrEntryChanged) {
		t.Fatalf("claim replacement remove = %v, %v", removed, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "source replacement" {
		t.Fatalf("source replacement = %q, %v", content, err)
	}
}

func TestListIsContextAndSenderScoped(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "home", "alice", "report.txt", "alice report")
	writeInboxFile(t, root, "home", "bob", "report.txt", "bob report")
	writeInboxFile(t, root, "work", "alice", "report.txt", "work report")
	writeInboxFile(t, root, "home", "alice", "notes.txt", "notes")
	if err := os.Mkdir(filepath.Join(root, "home", "alice", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "home", "alice", "nested", "hidden.txt"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "home", "alice", "linked.txt")
	_ = os.Symlink(filepath.Join(root, "work", "alice", "report.txt"), link)

	entries, err := List(root, "home", "")
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	if want := []string{"alice/notes.txt", "alice/report.txt", "bob/report.txt"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	filtered, err := List(root, "home", "alice")
	if err != nil || len(filtered) != 2 || filtered[0].Sender != "alice" {
		t.Fatalf("filtered = %+v, %v", filtered, err)
	}
	empty, err := List(root, "absent", "")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty = %+v, %v", empty, err)
	}
}

func TestListRejectsContextSymlinkAndPortableCollisions(t *testing.T) {
	root := t.TempDir()
	writeInboxFile(t, root, "work", "alice", "report.txt", "work")
	if err := os.Symlink(filepath.Join(root, "work"), filepath.Join(root, "home")); err == nil {
		if _, err := List(root, "home", ""); err == nil {
			t.Fatal("context symlink was listed")
		}
	}
	collisionRoot := t.TempDir()
	writeInboxFile(t, collisionRoot, "home", "alice", "A.txt", "a")
	writeInboxFile(t, collisionRoot, "home", "alice", "B.txt", "b")
	writeInboxFile(t, collisionRoot, "home", "alice", "a.txt", "c")
	values, err := os.ReadDir(filepath.Join(collisionRoot, "home", "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) < 3 {
		t.Skip("filesystem is case-insensitive")
	}
	if _, err := List(collisionRoot, "home", ""); err == nil || !strings.Contains(err.Error(), "case collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestOpenDirectoryRejectsEnumeratedSenderReplacement(t *testing.T) {
	rootPath := t.TempDir()
	writeInboxFile(t, rootPath, "home", "alice", "first.txt", "first")
	contextDirectory, err := os.Open(filepath.Join(rootPath, "home"))
	if err != nil {
		t.Fatal(err)
	}
	values, err := contextDirectory.ReadDir(-1)
	contextDirectory.Close()
	if err != nil || len(values) != 1 {
		t.Fatalf("senders = %v, %v", values, err)
	}
	expected, err := values[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rootPath, "home", "alice"), filepath.Join(rootPath, "home", "old-alice")); err != nil {
		t.Fatal(err)
	}
	writeInboxFile(t, rootPath, "home", "alice", "second.txt", "second")
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if directory, err := openDirectory(root, filepath.Join("home", "alice"), expected); err == nil {
		directory.Close()
		t.Fatal("replacement sender directory matched enumerated identity")
	}
}

func TestContainsFoldUsesUnicodeCaseEquivalence(t *testing.T) {
	if !containsFold([]string{"Σ.txt"}, "ς.txt") {
		t.Fatal("Unicode case-equivalent names did not collide")
	}
}

func TestListBoundsEncodedResponse(t *testing.T) {
	root := t.TempDir()
	for index := range MaxEntries {
		name := fmt.Sprintf("%03d-%s.txt", index, strings.Repeat("x", 180))
		writeInboxFile(t, root, "home", "alice", name, "x")
	}
	if _, err := List(root, "home", ""); err == nil || !strings.Contains(err.Error(), "response size") {
		t.Fatalf("response bound error = %v", err)
	}
}

func writeInboxFile(t *testing.T, root, contextName, sender, name, content string) {
	t.Helper()
	directory := filepath.Join(root, contextName, sender)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
