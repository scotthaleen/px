package getcleanup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/securefile"
)

func TestStagePublishesAndDeletesRowLast(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result.bin"), 3)
	if err != nil {
		t.Fatal(err)
	}
	var phase, parentPath, markerToken, lease string
	if err := db.DB().QueryRow(`select phase,parent_path,marker_token,lease_token from get_cleanup`).Scan(&phase, &parentPath, &markerToken, &lease); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	if phase != "data_created" || parentPath != resolved || !hex64.MatchString(markerToken) || !hex64.MatchString(lease) {
		t.Fatalf("reserved row = phase %q parent %q token=%t lease=%t", phase, parentPath, hex64.MatchString(markerToken), hex64.MatchString(lease))
	}
	if _, err := stage.File().Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	committed, err := stage.Publish(context.Background(), "result.bin")
	if err != nil || !committed {
		t.Fatalf("publish = %t, %v", committed, err)
	}
	content, err := os.ReadFile(filepath.Join(parent, "result.bin"))
	if err != nil || string(content) != "abc" {
		t.Fatalf("published content = %q, %v", content, err)
	}
	assertRows(t, db, 0)
}

func TestStartupIsDBOnlyAndSameParentGetRecoversCrash(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "first"), 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, stage.stageName)
	simulateCrash(stage)
	restarted := NewStore(db.DB)
	startup, err := restarted.Startup(context.Background())
	if err != nil || startup.Rows != 1 || startup.ClearedLeases != 1 {
		t.Fatalf("startup = %+v, %v", startup, err)
	}
	if _, err := os.Stat(stagePath); err != nil {
		t.Fatalf("startup touched staging: %v", err)
	}
	second, err := restarted.Create(context.Background(), filepath.Join(parent, "second"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Cleanup(context.Background())
	if _, err := os.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("same-parent get did not recover old stage: %v", err)
	}
	assertRows(t, db, 1)
}

func TestUnrelatedUnavailableParentDoesNotBlockGet(t *testing.T) {
	store, db := testStore(t)
	base := t.TempDir()
	firstParent := filepath.Join(base, "first")
	secondParent := filepath.Join(base, "second")
	for _, path := range []string{firstParent, secondParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := store.Create(context.Background(), filepath.Join(firstParent, "first"), 1)
	if err != nil {
		t.Fatal(err)
	}
	simulateCrash(stage)
	if _, err := NewStore(db.DB).Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(firstParent, firstParent+"-gone"); err != nil {
		t.Fatal(err)
	}
	second, err := NewStore(db.DB).Create(context.Background(), filepath.Join(secondParent, "second"), 1)
	if err != nil {
		t.Fatalf("unrelated unavailable parent blocked get: %v", err)
	}
	defer second.Cleanup(context.Background())
	assertRows(t, db, 2)
}

func TestLiveParentRenameAndSymlinkToOriginalRejectPublication(t *testing.T) {
	for _, replacement := range []string{"missing", "symlink-to-original"} {
		t.Run(replacement, func(t *testing.T) {
			store, db := testStore(t)
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stage.File().Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			moved := parent + "-moved"
			if err := os.Rename(parent, moved); err != nil {
				if isWindowsSharingViolation(err) {
					if _, statErr := os.Stat(filepath.Join(parent, "result")); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("sharing-denied parent swap published: %v", statErr)
					}
					_ = stage.Cleanup(context.Background())
					return
				}
				t.Fatal(err)
			}
			if replacement == "symlink-to-original" {
				if err := os.Symlink(moved, parent); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			committed, err := stage.Publish(context.Background(), "result")
			if err == nil || committed {
				t.Fatalf("renamed parent publish = %t, %v", committed, err)
			}
			if _, err := os.Stat(filepath.Join(moved, "result")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published into renamed parent: %v", err)
			}
			_ = stage.Cleanup(context.Background())
			assertRows(t, db, 1)
		})
	}
}

func TestStageSwapFailsClosedBeforeRecovery(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, stage.stageName)
	simulateCrash(stage)
	clearLease(t, db, stage.id)
	owned := stagePath + ".owned"
	if err := os.Rename(stagePath, owned); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stagePath, "sentinel")
	if err := os.WriteFile(sentinel, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := reapParent(t, NewStore(db.DB), parent)
	if err != nil || result.Retained != 1 || result.Removed != 0 {
		t.Fatalf("swapped stage reap = %+v, %v", result, err)
	}
	if content, err := os.ReadFile(sentinel); err != nil || string(content) != "replacement" {
		t.Fatalf("replacement mutated = %q, %v", content, err)
	}
}

func TestStageSwapFailsClosedBeforePublication(t *testing.T) {
	store, _ := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(parent, stage.stageName)
	if err := os.Rename(stagePath, stagePath+".owned"); err != nil {
		if isWindowsSharingViolation(err) {
			if _, statErr := os.Stat(filepath.Join(parent, "result")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("sharing-denied stage swap published: %v", statErr)
			}
			_ = stage.Cleanup(context.Background())
			return
		}
		t.Fatal(err)
	}
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	committed, err := stage.Publish(context.Background(), "result")
	if err == nil || committed {
		t.Fatalf("swapped stage publish = %t, %v", committed, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "result")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("swapped stage published: %v", err)
	}
}

func TestParentIdentityMismatchIsNotSelectedOrMutated(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "first"), 1)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(parent, stage.stageName)
	simulateCrash(stage)
	clearLease(t, db, stage.id)
	if _, err := db.DB().Exec(`update get_cleanup set parent_identity='darwin1:ffffffffffffffff:ffffffffffffffff' where cleanup_id=?`, stage.id); err != nil {
		t.Fatal(err)
	}
	second, err := NewStore(db.DB).Create(context.Background(), filepath.Join(parent, "second"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Cleanup(context.Background())
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("identity-mismatched stage changed: %v", err)
	}
	assertRows(t, db, 2)
}

func TestInitiallySymlinkedParentPersistsCanonicalTarget(t *testing.T) {
	store, db := testStore(t)
	base := t.TempDir()
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stage, err := store.Create(context.Background(), filepath.Join(link, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup(context.Background())
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err := db.DB().QueryRow(`select parent_path from get_cleanup`).Scan(&persisted); err != nil || persisted != canonicalTarget {
		t.Fatalf("canonical parent = %q, %v", persisted, err)
	}
}

func TestRootAndIdentityHandleMismatchRejected(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	firstPath, _ := canonicalParent(first)
	secondPath, _ := canonicalParent(second)
	firstRoot, firstDir, firstID, err := openProtectedParent(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer firstRoot.Close()
	defer firstDir.Close()
	secondRoot, secondDir, _, err := openProtectedParent(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRoot.Close()
	defer secondDir.Close()
	if !errors.Is(verifyOpenedParent(firstPath, firstID, secondRoot, firstDir), ErrUnsafeState) {
		t.Fatal("split parent handles were accepted")
	}
}

func TestSecondStoreCannotReapActiveLease(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	active, err := store.Create(context.Background(), filepath.Join(parent, "active"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Cleanup(context.Background())
	if _, err := db.DB().Exec(`update get_cleanup set lease_expires_at=created_at where cleanup_id=?`, active.id); err != nil {
		t.Fatal(err)
	}
	result, err := reapParent(t, NewStore(db.DB), parent)
	if err != nil || result.Examined != 0 {
		t.Fatalf("second store reaped active lease = %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(parent, active.stageName, "data.part")); err != nil {
		t.Fatalf("active data changed: %v", err)
	}
}

func TestCanceledClaimReleasesProcessLease(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	simulateCrash(stage)
	clearLease(t, db, stage.id)
	restarted := NewStore(db.DB)
	restarted.fault = func(point string) error {
		if point == "after_claim" {
			return context.Canceled
		}
		return nil
	}
	if _, err := reapParent(t, restarted, parent); !errors.Is(err, context.Canceled) {
		t.Fatalf("reap error = %v", err)
	}
	var lease any
	if err := db.DB().QueryRow(`select lease_token from get_cleanup where cleanup_id=?`, stage.id).Scan(&lease); err != nil || lease != nil {
		t.Fatalf("lease = %#v, %v", lease, err)
	}
}

func TestFailedAttemptSettlementReleasesProcessLease(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(parent, stage.stageName, "unknown"), nil)
	simulateCrash(stage)
	clearLease(t, db, stage.id)
	restarted := NewStore(db.DB)
	restarted.fault = func(point string) error {
		if point == "before_finish_attempt" {
			return errors.New("settlement failed")
		}
		return nil
	}
	result, err := reapParent(t, restarted, parent)
	if err == nil || result.Retained != 1 {
		t.Fatalf("reap = %+v, %v", result, err)
	}
	var lease any
	if err := db.DB().QueryRow(`select lease_token from get_cleanup where cleanup_id=?`, stage.id).Scan(&lease); err != nil || lease != nil {
		t.Fatalf("lease = %#v, %v", lease, err)
	}
}

func TestInactiveSelectionBeforeLimitAndBoundedPass(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	var stages []*Stage
	for index := 0; index < MaxReap+3; index++ {
		stage, err := store.Create(context.Background(), filepath.Join(parent, fmt.Sprintf("result-%d", index)), 0)
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, stage)
	}
	for _, stage := range stages {
		simulateCrash(stage)
		clearLease(t, db, stage.id)
	}
	// Keep the first two due rows actively leased. They must not consume LIMIT.
	now := time.Now().Unix()
	if _, err := db.DB().Exec(`update get_cleanup set lease_token=?,lease_expires_at=? where cleanup_id in (?,?)`, strings.Repeat("f", 64), now+3600, stages[0].id, stages[1].id); err != nil {
		t.Fatal(err)
	}
	result, err := reapParent(t, NewStore(db.DB), parent)
	if err != nil || result.Examined != MaxReap || result.Removed != MaxReap {
		t.Fatalf("bounded inactive reap = %+v, %v", result, err)
	}
	assertRows(t, db, 3)
}

func TestCleanupRejectsUnknownOversizeAndReplacedEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *Stage, string)
	}{
		{name: "unknown", mutate: func(t *testing.T, _ *Stage, path string) { mustWrite(t, filepath.Join(path, "unknown"), nil) }},
		{name: "oversize", mutate: func(t *testing.T, _ *Stage, path string) {
			mustWrite(t, filepath.Join(path, "data.part"), []byte("too large"))
		}},
		{name: "marker directory", mutate: func(t *testing.T, stage *Stage, path string) {
			if err := os.Remove(filepath.Join(path, stage.markerName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(path, stage.markerName), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing marker", mutate: func(t *testing.T, stage *Stage, path string) {
			if err := os.Remove(filepath.Join(path, stage.markerName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "data directory", mutate: func(t *testing.T, _ *Stage, path string) {
			if err := os.Remove(filepath.Join(path, "data.part")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(path, "data.part"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, db := testStore(t)
			parent := t.TempDir()
			stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
			if err != nil {
				t.Fatal(err)
			}
			stagePath := filepath.Join(parent, stage.stageName)
			simulateCrash(stage)
			test.mutate(t, stage, stagePath)
			clearLease(t, db, stage.id)
			result, err := reapParent(t, NewStore(db.DB), parent)
			if err != nil || result.Retained != 1 {
				t.Fatalf("reap = %+v, %v", result, err)
			}
		})
	}
}

func TestPublicationCleanupFaultsKeepDestinationAndRow(t *testing.T) {
	for _, point := range []string{"after_link", "after_cleanup_authorized", "after_data_remove", "after_marker_remove", "after_stage_remove"} {
		t.Run(point, func(t *testing.T) {
			store, db := testStore(t)
			parent := t.TempDir()
			stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stage.File().Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			fired := false
			store.fault = func(actual string) error {
				if !fired && actual == point {
					fired = true
					return errors.New("fault")
				}
				return nil
			}
			committed, err := stage.Publish(context.Background(), "result")
			if !committed || !IsCommittedCleanupPending(err) || !fired {
				t.Fatalf("publish = %t, %v fired=%t", committed, err, fired)
			}
			if content, readErr := os.ReadFile(filepath.Join(parent, "result")); readErr != nil || string(content) != "x" {
				t.Fatalf("destination = %q, %v", content, readErr)
			}
			assertRows(t, db, 1)
			store.fault = nil
			clearLease(t, db, stage.id)
			restarted := NewStore(db.DB)
			syncDirectory := restarted.syncDir
			syncCalls := 0
			restarted.syncDir = func(file *os.File) error {
				syncCalls++
				return syncDirectory(file)
			}
			result, reapErr := reapParent(t, restarted, parent)
			if reapErr != nil || result.Removed != 1 {
				t.Fatalf("reap after %s = %+v, %v", point, result, reapErr)
			}
			if point == "after_stage_remove" && syncCalls == 0 {
				t.Fatal("absent-stage recovery deleted its row without syncing the parent")
			}
			assertRows(t, db, 0)
		})
	}
}

func TestRecoveryHandlesSelfCreatedCrashWindows(t *testing.T) {
	for _, phase := range []string{"reserved-empty", "link-probe"} {
		t.Run(phase, func(t *testing.T) {
			store, db := testStore(t)
			parent := t.TempDir()
			stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
			if err != nil {
				t.Fatal(err)
			}
			stagePath := filepath.Join(parent, stage.stageName)
			simulateCrash(stage)
			switch phase {
			case "reserved-empty":
				if err := os.Remove(filepath.Join(stagePath, "data.part")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(stagePath, stage.markerName)); err != nil {
					t.Fatal(err)
				}
				if _, err := db.DB().Exec(`update get_cleanup set phase='reserved',stage_identity=null where cleanup_id=?`, stage.id); err != nil {
					t.Fatal(err)
				}
			case "link-probe":
				if err := os.Link(filepath.Join(stagePath, "data.part"), filepath.Join(stagePath, ".link-test")); err != nil {
					t.Fatal(err)
				}
			}
			clearLease(t, db, stage.id)
			result, err := reapParent(t, NewStore(db.DB), parent)
			if err != nil || result.Removed != 1 {
				t.Fatalf("reap = %+v, %v", result, err)
			}
			assertRows(t, db, 0)
			if _, err := os.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stage remains: %v", err)
			}
		})
	}
}

func TestCanceledCleanupReleasesDurableLease(t *testing.T) {
	store, db := testStore(t)
	stage, err := store.Create(context.Background(), filepath.Join(t.TempDir(), "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stage.Cleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error = %v", err)
	}
	var lease any
	if err := db.DB().QueryRow(`select lease_token from get_cleanup where cleanup_id=?`, stage.id).Scan(&lease); err != nil || lease != nil {
		t.Fatalf("lease = %#v, %v", lease, err)
	}
}

func TestFaultAfterRowDeleteLeavesDestinationWithoutPendingClaim(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	store.fault = func(point string) error {
		if point == "after_row_delete" {
			return errors.New("fault")
		}
		return nil
	}
	committed, err := stage.Publish(context.Background(), "result")
	if !committed || err == nil || IsCommittedCleanupPending(err) {
		t.Fatalf("publish = %t, %v", committed, err)
	}
	assertRows(t, db, 0)
	if content, readErr := os.ReadFile(filepath.Join(parent, "result")); readErr != nil || string(content) != "x" {
		t.Fatalf("destination = %q, %v", content, readErr)
	}
}

func TestPublicationDirectorySyncFailureIsCommittedPending(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	store.syncDir = func(file *os.File) error {
		id, _ := directoryIdentity(file)
		if id == stage.parentID {
			return errors.New("flush unsupported")
		}
		return syncDirectory(file)
	}
	committed, err := stage.Publish(context.Background(), "result")
	if !committed || !IsCommittedCleanupPending(err) {
		t.Fatalf("publish = %t, %v", committed, err)
	}
	assertRows(t, db, 1)
}

func TestPendingReleaseLoadFailureReleasesProcessLease(t *testing.T) {
	store, db := testStore(t)
	stage, err := store.Create(context.Background(), filepath.Join(t.TempDir(), "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	store.fault = func(point string) error {
		if point == "before_release_load" {
			return errors.New("load failed")
		}
		return nil
	}
	if err := stage.releasePending(); err == nil {
		t.Fatal("pending release succeeded")
	}
	var lease any
	if err := db.DB().QueryRow(`select lease_token from get_cleanup where cleanup_id=?`, stage.id).Scan(&lease); err != nil || lease != nil {
		t.Fatalf("lease = %#v, %v", lease, err)
	}
}

func TestQuotaAtomicAndExpiredRowsRemainCharged(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stages := make(chan *Stage, MaxRows+1)
	errs := make(chan error, MaxRows+1)
	var wait sync.WaitGroup
	for index := 0; index < MaxRows+1; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			stage, err := store.Create(context.Background(), filepath.Join(parent, fmt.Sprintf("result-%d", index)), 0)
			if err != nil {
				errs <- err
				return
			}
			stages <- stage
		}(index)
	}
	wait.Wait()
	close(stages)
	close(errs)
	if len(stages) != MaxRows || len(errs) != 1 {
		t.Fatalf("success=%d errors=%d", len(stages), len(errs))
	}
	for err := range errs {
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("capacity error = %v", err)
		}
	}
	if _, err := db.DB().Exec(`update get_cleanup set expires_at=created_at`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), filepath.Join(parent, "blocked"), 0); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expired capacity = %v", err)
	}
	for stage := range stages {
		_ = stage.Cleanup(context.Background())
	}
}

func TestExpiredUnsafeRowNotifiesOnceAndRetriesDaily(t *testing.T) {
	store, db := testStore(t)
	parent := t.TempDir()
	stage, err := store.Create(context.Background(), filepath.Join(parent, "result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(parent, stage.stageName, "unknown"), nil)
	simulateCrash(stage)
	clearLease(t, db, stage.id)
	if _, err := db.DB().Exec(`update get_cleanup set expires_at=created_at,next_retry_at=created_at`); err != nil {
		t.Fatal(err)
	}
	notifications := 0
	restarted := NewStore(db.DB, WithNotifications(func(result ReapResult) { notifications += result.Expired }))
	now := time.Now().UTC()
	restarted.now = func() time.Time { return now }
	result, err := reapParent(t, restarted, parent)
	if err != nil || result.Expired != 1 || result.Retained != 1 {
		t.Fatalf("first = %+v, %v", result, err)
	}
	var next int64
	if err := db.DB().QueryRow(`select next_retry_at from get_cleanup`).Scan(&next); err != nil || next != now.Add(expiredInterval).Unix() {
		t.Fatalf("next=%d err=%v", next, err)
	}
	if _, err := db.DB().Exec(`update get_cleanup set next_retry_at=created_at`); err != nil {
		t.Fatal(err)
	}
	result, err = reapParent(t, restarted, parent)
	if err != nil || result.Expired != 0 || notifications != 1 {
		t.Fatalf("second=%+v notifications=%d err=%v", result, notifications, err)
	}
}

func testStore(t *testing.T) (*Store, *sqlite.Store) {
	t.Helper()
	cfg, err := database.Config(database.KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := sqlite.New(cfg)
	if err := db.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Stop(context.Background()) })
	return NewStore(db.DB), db
}

func reapParent(t *testing.T, store *Store, parent string) (ReapResult, error) {
	t.Helper()
	path, err := canonicalParent(parent)
	if err != nil {
		return ReapResult{}, err
	}
	root, directory, identity, err := openProtectedParent(path)
	if err != nil {
		return ReapResult{}, err
	}
	defer root.Close()
	defer directory.Close()
	return store.reapParentOpened(context.Background(), path, identity, root, directory, MaxReap)
}

func simulateCrash(stage *Stage) {
	if stage.file != nil {
		_ = stage.file.Close()
		stage.file = nil
	}
	stage.store.mu.Lock()
	delete(stage.store.active, stage.id)
	stage.store.mu.Unlock()
	stage.closeHandles()
}

func clearLease(t *testing.T, db *sqlite.Store, id string) {
	t.Helper()
	if _, err := db.DB().Exec(`update get_cleanup set lease_token=null,lease_expires_at=null,next_retry_at=created_at where cleanup_id=?`, id); err != nil {
		t.Fatal(err)
	}
}

func assertRows(t *testing.T, db *sqlite.Store, want int) {
	t.Helper()
	var count int
	if err := db.DB().QueryRow(`select count(*) from get_cleanup`).Scan(&count); err != nil || count != want {
		t.Fatalf("rows=%d want=%d err=%v", count, want, err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecordValidationRejectsUntrustedValues(t *testing.T) {
	valid := record{id: strings.Repeat("a", 64), token: strings.Repeat("b", 64), lease: strings.Repeat("c", 64), parentPath: t.TempDir(), stageName: ".px-" + strings.Repeat("a", 64) + ".get", markerName: ".owner-" + strings.Repeat("b", 64), phase: "reserved"}
	if err := validateRecord(valid); err != nil {
		t.Fatal(err)
	}
	valid.parentPath = "relative"
	if !errors.Is(validateRecord(valid), ErrUnsafeState) {
		t.Fatal("relative parent passed")
	}
}

func TestUnsafeSharedParentRejectedBeforeStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by Windows ACL tests")
	}
	_, db := testStore(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(db.DB).Create(context.Background(), filepath.Join(parent, "result"), 1); !errors.Is(err, ErrUnsafeParent) {
		t.Fatalf("unsafe parent error = %v", err)
	}
	assertRows(t, db, 0)
}

func TestUnsafeParentErrorsAreBoundedAndDistinct(t *testing.T) {
	for _, test := range []struct {
		name, want string
		cause      error
	}{
		{name: "owner", cause: securefile.ErrProtectionOwner, want: "owner is not trusted"},
		{name: "ACL", cause: securefile.ErrProtectionACL, want: "ACL is unsafe or unsupported"},
		{name: "reparse", cause: securefile.ErrProtectionReparse, want: "contains a reparse or symbolic link"},
		{name: "identity", cause: securefile.ErrProtectionIdentity, want: "identity is unavailable or changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := unsafeParentError(fmt.Errorf("C:\\private\\unrelated: %w", test.cause))
			if !errors.Is(err, ErrUnsafeParent) || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe parent error = %v", err)
			}
		})
	}
}

func TestCanonicalParentClassifiesLinksWithoutExposingPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reparse behavior requires native coverage")
	}
	realParent := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	if err := canonicalPathUnchanged(link); !errors.Is(err, securefile.ErrProtectionReparse) {
		t.Fatalf("final link classification = %v", err)
	}
	child := filepath.Join(realParent, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := canonicalPathUnchanged(filepath.Join(link, "child")); !errors.Is(err, securefile.ErrProtectionReparse) {
		t.Fatalf("ancestor link classification = %v", err)
	}
	missing := filepath.Join(t.TempDir(), "private-destination")
	err := revalidateParentPath(missing, "unavailable")
	if !errors.Is(err, ErrUnsafeState) || !errors.Is(err, securefile.ErrProtectionIdentity) || strings.Contains(err.Error(), missing) {
		t.Fatalf("missing path revalidation = %v", err)
	}
}
