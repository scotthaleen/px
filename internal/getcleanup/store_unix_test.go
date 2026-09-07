//go:build !windows

package getcleanup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStickySharedParentAccepted(t *testing.T) {
	store, _ := testStore(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatalf("owned sticky parent rejected: %v", err)
	}
	if err := stage.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeWritableAncestorRejected(t *testing.T) {
	store, _ := testStore(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1); !errors.Is(err, ErrUnsafeParent) {
		t.Fatalf("unsafe ancestor error = %v", err)
	}
}

func TestCleanupRejectsSymlinkAndSpecialEntries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Stage, string)
	}{
		{name: "marker symlink", mutate: func(t *testing.T, stage *Stage, path string) {
			if err := os.Remove(filepath.Join(path, stage.markerName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(path, stage.markerName)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}},
		{name: "data symlink", mutate: func(t *testing.T, _ *Stage, path string) {
			if err := os.Remove(filepath.Join(path, "data.part")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(path, "data.part")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}},
		{name: "data fifo", mutate: func(t *testing.T, _ *Stage, path string) {
			if err := os.Remove(filepath.Join(path, "data.part")); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(path, "data.part"), 0o600); err != nil {
				t.Skipf("fifo unavailable: %v", err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, db := testStore(t)
			parent := t.TempDir()
			stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, stage.stageName)
			simulateCrash(stage)
			test.mutate(t, stage, path)
			clearLease(t, db, stage.id)
			result, err := reapParent(t, NewStore(db.DB), parent)
			if err != nil || result.Retained != 1 || result.Removed != 0 {
				t.Fatalf("unsafe entry reap = %+v, %v", result, err)
			}
			if _, err := os.Lstat(filepath.Join(path, "data.part")); test.name != "marker symlink" && errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe data entry was removed")
			}
		})
	}
}
