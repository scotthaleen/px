package getcleanup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/scotthaleen/px/internal/securefile"
)

const (
	MaxRows               = 64
	MaxBytes        int64 = 4 << 30
	MaxFileBytes          = 1 << 30
	MaxReap               = 8
	retryInterval         = time.Hour
	expiryAge             = 24 * time.Hour
	expiredInterval       = 24 * time.Hour
	leaseLifetime         = 24 * time.Hour
)

var (
	ErrCapacity          = errors.New("get cleanup capacity is full; restore an unavailable destination parent or inspect protected cleanup state")
	ErrDestinationExists = errors.New("destination already exists")
	ErrUnsafeParent      = errors.New("destination parent does not provide protected persistent staging")
	ErrUnsafeState       = errors.New("get staging ownership proof is unavailable")
	errInvalidIdentity   = errors.New("directory identity is unavailable")
	hex64                = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type CommittedCleanupPendingError struct{ cause error }

func (e *CommittedCleanupPendingError) Error() string {
	return "get committed; durable staging cleanup remains pending"
}

func (e *CommittedCleanupPendingError) Unwrap() error { return e.cause }

func (e *CommittedCleanupPendingError) CleanupPending() bool { return true }

func IsCommittedCleanupPending(err error) bool {
	var pending *CommittedCleanupPendingError
	return errors.As(err, &pending)
}

type Store struct {
	database func() *sql.DB
	mu       sync.Mutex
	active   map[string]struct{}
	now      func() time.Time
	notify   func(ReapResult)
	syncDir  func(*os.File) error
	fault    func(string) error
}

type Stage struct {
	store      *Store
	id         string
	lease      string
	parentPath string
	parentID   string
	stageName  string
	stageID    string
	markerName string
	token      string
	declared   int64
	file       *os.File
	parentRoot *os.Root
	parentDir  *os.File
	stageRoot  *os.Root
	stageDir   *os.File
	released   bool
}

type ReapResult struct {
	Examined int
	Removed  int
	Retained int
	Expired  int
}

type StartupResult struct {
	Rows          int
	ClearedLeases int
	Due           int
}

type record struct {
	id, parentPath, parentID, stageName, stageID, markerName, token, phase string
	lease                                                                  string
	declared                                                               int64
	created, expires, nextRetry                                            time.Time
	expiredNotified                                                        bool
}

type Option func(*Store)

func WithNotifications(notify func(ReapResult)) Option {
	return func(store *Store) { store.notify = notify }
}

func NewStore(database func() *sql.DB, options ...Option) *Store {
	store := &Store{
		database: database,
		active:   make(map[string]struct{}),
		now:      func() time.Time { return time.Now().UTC() },
		syncDir:  syncDirectory,
	}
	for _, option := range options {
		option(store)
	}
	return store
}

// Startup is DB-only. The process lock makes every inherited lease stale.
func (s *Store) Startup(ctx context.Context) (StartupResult, error) {
	now := s.now()
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return StartupResult{}, err
	}
	defer tx.Rollback()
	var result StartupResult
	if err := tx.QueryRowContext(ctx, `select count(*),coalesce(sum(lease_token is not null),0),coalesce(sum(next_retry_at <= ?),0) from get_cleanup`, now.Unix()).Scan(&result.Rows, &result.ClearedLeases, &result.Due); err != nil {
		return StartupResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `update get_cleanup set lease_token=null,lease_expires_at=null where lease_token is not null`); err != nil {
		return StartupResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return StartupResult{}, err
	}
	s.mu.Lock()
	clear(s.active)
	s.mu.Unlock()
	return result, nil
}

func (s *Store) Create(ctx context.Context, destination string, declared int64) (*Stage, error) {
	if declared < 0 || declared > MaxFileBytes {
		return nil, errors.New("get size exceeds staging limit")
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return nil, errors.New("resolve local destination failed")
	}
	parentPath, err := canonicalParent(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("resolve local destination directory failed")
	}
	parentRoot, parentDir, parentID, err := openProtectedParent(parentPath)
	if err != nil {
		if errors.Is(err, ErrUnsafeParent) {
			return nil, err
		}
		return nil, errors.New("open protected local destination directory failed")
	}
	closeParent := true
	defer func() {
		if closeParent {
			parentDir.Close()
			parentRoot.Close()
		}
	}()
	if _, err := s.reapParentOpened(ctx, parentPath, parentID, parentRoot, parentDir, MaxReap); err != nil {
		return nil, err
	}
	if err := revalidateParentPath(parentPath, parentID); err != nil {
		return nil, ErrUnsafeState
	}
	destinationBase := filepath.Base(absolute)
	if _, err := parentRoot.Lstat(destinationBase); err == nil {
		return nil, ErrDestinationExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect local destination failed")
	}
	id, err := randomHex()
	if err != nil {
		return nil, errors.New("create staging identity failed")
	}
	token, err := randomHex()
	if err != nil {
		return nil, errors.New("create staging ownership proof failed")
	}
	lease, err := randomHex()
	if err != nil {
		return nil, errors.New("create staging lease failed")
	}
	stage := &Stage{
		store: s, id: id, lease: lease, parentPath: parentPath, parentID: parentID,
		stageName: ".px-" + id + ".get", markerName: ".owner-" + token,
		token: token, declared: declared, parentRoot: parentRoot, parentDir: parentDir,
	}
	s.mu.Lock()
	err = s.reserveLocked(ctx, stage)
	if err == nil {
		s.active[id] = struct{}{}
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	closeParent = false
	if err := stage.createFilesystem(ctx); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = stage.Cleanup(cleanupCtx)
		cancel()
		return nil, err
	}
	return stage, nil
}

func (s *Store) reserveLocked(ctx context.Context, stage *Stage) error {
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	var bytes int64
	if err := tx.QueryRowContext(ctx, `select count(*),coalesce(sum(declared_bytes),0) from get_cleanup`).Scan(&count, &bytes); err != nil {
		return err
	}
	if count >= MaxRows || bytes > MaxBytes-stage.declared {
		return ErrCapacity
	}
	now := s.now()
	_, err = tx.ExecContext(ctx, `insert into get_cleanup(cleanup_id,parent_path,parent_identity,stage_name,marker_name,marker_token,declared_bytes,phase,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at) values(?,?,?,?,?,?,?,'reserved',?,?,?,?,?,?)`, stage.id, stage.parentPath, stage.parentID, stage.stageName, stage.markerName, stage.token, stage.declared, now.Unix(), now.Unix(), now.Add(expiryAge).Unix(), now.Unix(), stage.lease, now.Add(leaseLifetime).Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) reapParentOpened(ctx context.Context, parentPath, parentID string, parentRoot *os.Root, parentDir *os.File, limit int) (ReapResult, error) {
	now := s.now()
	rows, err := s.database().QueryContext(ctx, `select cleanup_id from get_cleanup where parent_path=? and parent_identity=? and next_retry_at<=? and lease_token is null order by next_retry_at,created_at,cleanup_id limit ?`, parentPath, parentID, now.Unix(), limit)
	if err != nil {
		return ReapResult{}, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return ReapResult{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return ReapResult{}, err
	}
	result := ReapResult{}
	for _, id := range ids {
		lease, err := randomHex()
		if err != nil {
			return result, err
		}
		value, claimed, err := s.claim(ctx, id, lease, now)
		if err != nil {
			return result, err
		}
		if !claimed {
			continue
		}
		result.Examined++
		removed, cleanupErr := s.cleanupOpened(ctx, value, parentRoot, parentDir)
		if removed {
			result.Removed++
			continue
		}
		result.Retained++
		notified := value.expiredNotified
		if !now.Before(value.expires) && !notified {
			result.Expired++
			notified = true
		}
		interval := retryInterval
		if !now.Before(value.expires) {
			interval = expiredInterval
		}
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		finishErr := s.runFault("before_finish_attempt")
		if finishErr == nil {
			finishErr = s.finishAttempt(settleCtx, value.id, value.lease, now.Add(interval), notified)
		}
		cancel()
		if finishErr != nil {
			return result, errors.Join(finishErr, s.releaseClaim(value.id, value.lease))
		}
		_ = cleanupErr
	}
	if result.Expired > 0 && s.notify != nil {
		s.notify(result)
	}
	return result, nil
}

func (s *Store) claim(ctx context.Context, id, lease string, now time.Time) (record, bool, error) {
	s.mu.Lock()
	_, active := s.active[id]
	s.mu.Unlock()
	if active {
		return record{}, false, nil
	}
	result, err := s.database().ExecContext(ctx, `update get_cleanup set lease_token=?,lease_expires_at=? where cleanup_id=? and lease_token is null`, lease, now.Add(leaseLifetime).Unix(), id)
	if err != nil {
		return record{}, false, errors.Join(err, s.releaseClaim(id, lease))
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return record{}, false, errors.Join(err, s.releaseClaim(id, lease))
	}
	if rows != 1 {
		return record{}, false, nil
	}
	if err := s.runFault("after_claim"); err != nil {
		return record{}, false, errors.Join(err, s.releaseClaim(id, lease))
	}
	value, exists, err := s.load(ctx, id)
	if err != nil || !exists {
		return record{}, false, errors.Join(err, s.releaseClaim(id, lease))
	}
	if value.lease != lease {
		return record{}, false, nil
	}
	return value, true, nil
}

func (s *Store) releaseClaim(id, lease string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.database().ExecContext(ctx, `update get_cleanup set lease_token=null,lease_expires_at=null where cleanup_id=? and lease_token=?`, id, lease)
	return err
}

func (s *Store) cleanupOpened(ctx context.Context, value record, parentRoot *os.Root, parentDir *os.File) (bool, error) {
	if err := validateRecord(value); err != nil {
		return false, err
	}
	if err := verifyOpenedParent(value.parentPath, value.parentID, parentRoot, parentDir); err != nil {
		return false, err
	}
	info, err := parentRoot.Lstat(value.stageName)
	if errors.Is(err, os.ErrNotExist) {
		if err := revalidateParentPath(value.parentPath, value.parentID); err != nil {
			return false, err
		}
		if err := s.syncDir(parentDir); err != nil {
			return false, err
		}
		return s.deleteClaimedRow(ctx, value.id, value.lease)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, ErrUnsafeState
	}
	if value.stageID == "" {
		return s.cleanupReservedStage(ctx, value, parentRoot, parentDir)
	}
	stageRoot, stageDir, err := openStageRoot(parentRoot, value.parentPath, value.stageName, value.stageID)
	if err != nil {
		return false, err
	}
	defer stageRoot.Close()
	defer stageDir.Close()
	names, err := stageDir.Readdirnames(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	sort.Strings(names)
	allowed := map[string]bool{value.markerName: true, "data.part": true, ".link-test": true}
	for _, name := range names {
		if !allowed[name] {
			return false, ErrUnsafeState
		}
	}
	marker, markerErr := stageRoot.Lstat(value.markerName)
	if markerErr != nil || !safeRegular(stageRoot, value.markerName, marker) || marker.Size() != 0 {
		if value.phase == "cleanup_authorized" && len(names) == 0 {
			if err := closeStagePair(stageRoot, stageDir); err != nil {
				return false, err
			}
			return s.removeEmptyStage(ctx, value, parentRoot, parentDir)
		}
		return false, ErrUnsafeState
	}
	probe, probeErr := stageRoot.Lstat(".link-test")
	if probeErr == nil {
		if !safeRegular(stageRoot, ".link-test", probe) || probe.Size() > value.declared {
			return false, ErrUnsafeState
		}
	} else if !errors.Is(probeErr, os.ErrNotExist) {
		return false, probeErr
	}
	data, dataErr := stageRoot.Lstat("data.part")
	if dataErr == nil {
		if !safeRegular(stageRoot, "data.part", data) || data.Size() > value.declared {
			return false, ErrUnsafeState
		}
	} else if !errors.Is(dataErr, os.ErrNotExist) {
		return false, dataErr
	}
	if value.phase != "cleanup_authorized" {
		if err := s.authorizeClaimed(ctx, value.id, value.lease, ""); err != nil {
			return false, err
		}
		value.phase = "cleanup_authorized"
	}
	if probeErr == nil {
		if err := stageRoot.Remove(".link-test"); err != nil {
			return false, err
		}
		if err := s.syncDir(stageDir); err != nil {
			return false, err
		}
	}
	if dataErr == nil {
		if err := stageRoot.Remove("data.part"); err != nil {
			return false, err
		}
		if err := s.runFault("after_data_remove"); err != nil {
			return false, err
		}
		if err := s.syncDir(stageDir); err != nil {
			return false, err
		}
	}
	if err := stageRoot.Remove(value.markerName); err != nil {
		return false, err
	}
	if err := s.runFault("after_marker_remove"); err != nil {
		return false, err
	}
	if err := s.syncDir(stageDir); err != nil {
		return false, err
	}
	if err := closeStagePair(stageRoot, stageDir); err != nil {
		return false, err
	}
	return s.removeEmptyStage(ctx, value, parentRoot, parentDir)
}

func (s *Store) cleanupReservedStage(ctx context.Context, value record, parentRoot *os.Root, parentDir *os.File) (bool, error) {
	if value.phase != "reserved" {
		return false, ErrUnsafeState
	}
	stageRoot, stageDir, err := openStageRoot(parentRoot, value.parentPath, value.stageName, "")
	if err != nil {
		return false, err
	}
	defer stageRoot.Close()
	defer stageDir.Close()
	names, err := stageDir.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if len(names) != 0 {
		return false, ErrUnsafeState
	}
	stageID, err := directoryIdentity(stageDir)
	if err != nil {
		return false, ErrUnsafeState
	}
	if err := s.authorizeClaimed(ctx, value.id, value.lease, stageID); err != nil {
		return false, err
	}
	value.stageID = stageID
	value.phase = "cleanup_authorized"
	if err := closeStagePair(stageRoot, stageDir); err != nil {
		return false, err
	}
	return s.removeEmptyStage(ctx, value, parentRoot, parentDir)
}

func (s *Store) authorizeClaimed(ctx context.Context, id, lease, stageID string) error {
	now := s.now().Unix()
	query := `update get_cleanup set phase='cleanup_authorized',updated_at=? where cleanup_id=? and lease_token=?`
	args := []any{now, id, lease}
	if stageID != "" {
		query = `update get_cleanup set phase='cleanup_authorized',stage_identity=?,updated_at=? where cleanup_id=? and lease_token=? and phase='reserved' and stage_identity is null`
		args = []any{stageID, now, id, lease}
	}
	result, err := s.database().ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("get cleanup authorization failed")
	}
	return nil
}

func (s *Store) removeEmptyStage(ctx context.Context, value record, parentRoot *os.Root, parentDir *os.File) (bool, error) {
	if err := verifyOpenedParent(value.parentPath, value.parentID, parentRoot, parentDir); err != nil {
		return false, err
	}
	currentID, err := stageEntryIdentity(parentRoot, value.stageName)
	if err != nil || currentID != value.stageID {
		return false, ErrUnsafeState
	}
	if err := parentRoot.Remove(value.stageName); err != nil {
		return false, err
	}
	if err := s.runFault("after_stage_remove"); err != nil {
		return false, err
	}
	if err := s.syncDir(parentDir); err != nil {
		return false, err
	}
	removed, err := s.deleteClaimedRow(ctx, value.id, value.lease)
	if err == nil && removed {
		err = s.runFault("after_row_delete")
	}
	return removed, err
}

func (s *Store) deleteClaimedRow(ctx context.Context, id, lease string) (bool, error) {
	result, err := s.database().ExecContext(ctx, `delete from get_cleanup where cleanup_id=? and lease_token=?`, id, lease)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func (s *Store) finishAttempt(ctx context.Context, id, lease string, next time.Time, notified bool) error {
	result, err := s.database().ExecContext(ctx, `update get_cleanup set updated_at=?,next_retry_at=?,expired_notified=?,lease_token=null,lease_expires_at=null where cleanup_id=? and lease_token=?`, s.now().Unix(), next.Unix(), boolInt(notified), id, lease)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("get cleanup lease disappeared")
	}
	return nil
}

func (stage *Stage) createFilesystem(ctx context.Context) error {
	directory, err := securefile.CreateOwnerOnlyDir(stage.parentRoot, stage.parentPath, stage.stageName)
	if err != nil {
		return errors.New("create protected staging directory failed")
	}
	directory.Close()
	stageRoot, stageDir, err := openStageRoot(stage.parentRoot, stage.parentPath, stage.stageName, "")
	if err != nil {
		return ErrUnsafeState
	}
	stageID, err := directoryIdentity(stageDir)
	if err != nil {
		stageRoot.Close()
		stageDir.Close()
		return ErrUnsafeState
	}
	stage.stageID, stage.stageRoot, stage.stageDir = stageID, stageRoot, stageDir
	if err := stage.update(ctx, "stage_created", true); err != nil {
		return err
	}
	if err := stage.store.syncDir(stage.parentDir); err != nil {
		return errors.New("sync staging parent failed")
	}
	marker, err := stage.stageRoot.OpenFile(stage.markerName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create staging ownership marker failed")
	}
	if err := marker.Sync(); err != nil {
		marker.Close()
		return errors.New("sync staging ownership marker failed")
	}
	if err := marker.Close(); err != nil {
		return errors.New("close staging ownership marker failed")
	}
	if err := stage.store.syncDir(stage.stageDir); err != nil {
		return errors.New("sync staging directory failed")
	}
	if err := stage.update(ctx, "marker_created", false); err != nil {
		return err
	}
	file, err := stage.stageRoot.OpenFile("data.part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create staged data failed")
	}
	if err := stage.store.syncDir(stage.stageDir); err != nil {
		file.Close()
		return errors.New("sync staged data entry failed")
	}
	if err := stage.stageRoot.Link("data.part", ".link-test"); err != nil {
		file.Close()
		return errors.New("destination filesystem does not support exclusive hard-link publication")
	}
	if err := stage.stageRoot.Remove(".link-test"); err != nil {
		file.Close()
		return errors.New("remove hard-link capability probe failed")
	}
	if err := stage.store.syncDir(stage.stageDir); err != nil {
		file.Close()
		return errors.New("sync hard-link capability probe failed")
	}
	if err := stage.update(ctx, "data_created", false); err != nil {
		file.Close()
		return err
	}
	stage.file = file
	return nil
}

func (stage *Stage) File() *os.File { return stage.file }

func (stage *Stage) Publish(ctx context.Context, destinationBase string) (bool, error) {
	if stage.file == nil {
		return false, errors.New("staged data is unavailable")
	}
	if err := stage.file.Sync(); err != nil {
		return false, errors.New("sync local destination failed")
	}
	if err := stage.file.Close(); err != nil {
		return false, errors.New("close local destination failed")
	}
	stage.file = nil
	if err := stage.update(ctx, "publishing", false); err != nil {
		return false, err
	}
	if err := verifyOpenedParent(stage.parentPath, stage.parentID, stage.parentRoot, stage.parentDir); err != nil {
		return false, err
	}
	stageRoot, stageDir, err := openStageRoot(stage.parentRoot, stage.parentPath, stage.stageName, stage.stageID)
	if err != nil {
		return false, err
	}
	defer stageRoot.Close()
	defer stageDir.Close()
	marker, err := stageRoot.Lstat(stage.markerName)
	if err != nil || !safeRegular(stageRoot, stage.markerName, marker) || marker.Size() != 0 {
		return false, ErrUnsafeState
	}
	data, err := stageRoot.Lstat("data.part")
	if err != nil || !safeRegular(stageRoot, "data.part", data) || data.Size() > stage.declared {
		return false, ErrUnsafeState
	}
	currentStageID, err := stageEntryIdentity(stage.parentRoot, stage.stageName)
	if err != nil || currentStageID != stage.stageID {
		return false, ErrUnsafeState
	}
	if err := revalidateParentPath(stage.parentPath, stage.parentID); err != nil {
		return false, ErrUnsafeState
	}
	if err := stage.parentRoot.Link(filepath.Join(stage.stageName, "data.part"), destinationBase); err != nil {
		if _, statErr := stage.parentRoot.Lstat(destinationBase); statErr == nil {
			return false, ErrDestinationExists
		}
		return false, errors.New("commit local destination failed")
	}
	if err := stage.store.runFault("after_link"); err != nil {
		return true, stage.pending(err)
	}
	if err := stage.store.syncDir(stage.parentDir); err != nil {
		return true, stage.pending(errors.New("sync published destination failed"))
	}
	if err := stage.update(ctx, "cleanup_authorized", false); err != nil {
		return true, stage.pending(err)
	}
	if err := stage.store.runFault("after_cleanup_authorized"); err != nil {
		return true, stage.pending(err)
	}
	if err := closeStagePair(stageRoot, stageDir); err != nil {
		return true, stage.pending(err)
	}
	if err := stage.Cleanup(ctx); err != nil {
		return true, stage.pending(err)
	}
	return true, nil
}

func (stage *Stage) pending(cause error) error {
	releaseErr := stage.releasePending()
	exists, existsErr := stage.store.rowExists(stage.id)
	if exists || existsErr != nil {
		return &CommittedCleanupPendingError{cause: errors.Join(cause, releaseErr, existsErr)}
	}
	return errors.Join(cause, releaseErr)
}

func (stage *Stage) releasePending() error {
	if stage.released {
		return nil
	}
	defer stage.releaseLocal()
	now := stage.store.now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	loadErr := stage.store.runFault("before_release_load")
	value, exists, err := record{}, false, loadErr
	if err == nil {
		value, exists, err = stage.store.load(ctx, stage.id)
	}
	if err != nil {
		return errors.Join(err, stage.store.releaseClaim(stage.id, stage.lease))
	}
	if exists && value.lease == stage.lease {
		interval := retryInterval
		if !now.Before(value.expires) {
			interval = expiredInterval
		}
		finishErr := stage.store.finishAttempt(ctx, value.id, value.lease, now.Add(interval), value.expiredNotified)
		if finishErr != nil {
			return errors.Join(finishErr, stage.store.releaseClaim(value.id, value.lease))
		}
	}
	return nil
}

func (stage *Stage) releaseLocal() {
	stage.store.mu.Lock()
	delete(stage.store.active, stage.id)
	stage.store.mu.Unlock()
	stage.released = true
	stage.closeHandles()
}

func (stage *Stage) Cleanup(ctx context.Context) error {
	if stage.released {
		return nil
	}
	if stage.file != nil {
		_ = stage.file.Close()
		stage.file = nil
	}
	if err := stage.closeStageHandles(); err != nil {
		return errors.Join(err, stage.releasePending())
	}
	value, exists, err := stage.store.load(ctx, stage.id)
	removed := false
	if err == nil && exists && value.lease == stage.lease {
		removed, err = stage.store.cleanupOpened(ctx, value, stage.parentRoot, stage.parentDir)
	}
	if removed {
		stage.releaseLocal()
		return err
	}
	releaseErr := stage.releasePending()
	if err == nil {
		err = releaseErr
	}
	return err
}

func (stage *Stage) update(ctx context.Context, phase string, identity bool) error {
	now := stage.store.now()
	query := `update get_cleanup set phase=?,updated_at=?,next_retry_at=?,lease_expires_at=? where cleanup_id=? and lease_token=?`
	args := []any{phase, now.Unix(), now.Unix(), now.Add(leaseLifetime).Unix(), stage.id, stage.lease}
	if identity {
		query = `update get_cleanup set phase=?,stage_identity=?,updated_at=?,next_retry_at=?,lease_expires_at=? where cleanup_id=? and lease_token=?`
		args = []any{phase, stage.stageID, now.Unix(), now.Unix(), now.Add(leaseLifetime).Unix(), stage.id, stage.lease}
	}
	result, err := stage.store.database().ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("get cleanup lease disappeared")
	}
	return nil
}

func (s *Store) load(ctx context.Context, id string) (record, bool, error) {
	var value record
	var created, expires, next int64
	var notified int
	var lease sql.NullString
	var leaseExpires sql.NullInt64
	err := s.database().QueryRowContext(ctx, `select cleanup_id,parent_path,parent_identity,stage_name,coalesce(stage_identity,''),marker_name,marker_token,declared_bytes,phase,created_at,expires_at,next_retry_at,expired_notified,lease_token,lease_expires_at from get_cleanup where cleanup_id=?`, id).Scan(&value.id, &value.parentPath, &value.parentID, &value.stageName, &value.stageID, &value.markerName, &value.token, &value.declared, &value.phase, &created, &expires, &next, &notified, &lease, &leaseExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return record{}, false, nil
	}
	if err != nil {
		return record{}, false, err
	}
	value.created, value.expires, value.nextRetry = time.Unix(created, 0), time.Unix(expires, 0), time.Unix(next, 0)
	value.expiredNotified = notified == 1
	if lease.Valid {
		value.lease = lease.String
	}
	return value, true, nil
}

func validateRecord(value record) error {
	if !hex64.MatchString(value.id) || !hex64.MatchString(value.token) || value.stageName != ".px-"+value.id+".get" || value.markerName != ".owner-"+value.token || value.declared < 0 || value.declared > MaxFileBytes || !filepath.IsAbs(value.parentPath) {
		return ErrUnsafeState
	}
	if value.lease == "" || !hex64.MatchString(value.lease) {
		return ErrUnsafeState
	}
	switch value.phase {
	case "reserved", "stage_created", "marker_created", "data_created", "publishing", "cleanup_authorized":
		return nil
	default:
		return ErrUnsafeState
	}
}

func canonicalParent(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}

func openProtectedParent(path string) (*os.Root, *os.File, string, error) {
	if err := canonicalPathUnchanged(path); err != nil {
		return nil, nil, "", unsafeParentError(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, "", err
	}
	rootProbe, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, "", err
	}
	rootDir, err := openDirectory(path)
	if err != nil {
		rootProbe.Close()
		root.Close()
		return nil, nil, "", err
	}
	probeID, probeErr := directoryIdentity(rootProbe)
	rootID, rootErr := directoryIdentity(rootDir)
	rootProbe.Close()
	if rootErr != nil || probeErr != nil || rootID != probeID {
		rootDir.Close()
		root.Close()
		return nil, nil, "", unsafeParentError(securefile.ErrProtectionIdentity)
	}
	if err := securefile.ValidateProtectedParent(rootDir); err != nil {
		rootDir.Close()
		root.Close()
		return nil, nil, "", unsafeParentError(err)
	}
	if err := revalidateParentPath(path, rootID); err != nil {
		rootDir.Close()
		root.Close()
		return nil, nil, "", unsafeParentError(err)
	}
	return root, rootDir, rootID, nil
}

func verifyOpenedParent(path, wantID string, root *os.Root, directory *os.File) error {
	directoryID, err := directoryIdentity(directory)
	if err != nil || directoryID != wantID || securefile.ValidateProtectedParent(directory) != nil {
		return ErrUnsafeState
	}
	rootDir, err := root.Open(".")
	if err != nil {
		return ErrUnsafeState
	}
	rootID, err := directoryIdentity(rootDir)
	rootDir.Close()
	if err != nil || rootID != wantID {
		return ErrUnsafeState
	}
	return revalidateParentPath(path, wantID)
}

func revalidateParentPath(path, wantID string) error {
	if err := canonicalPathUnchanged(path); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeState, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeState, securefile.ErrProtectionIdentity)
	}
	defer file.Close()
	id, err := directoryIdentity(file)
	if err != nil || id != wantID {
		return fmt.Errorf("%w: %w", ErrUnsafeState, securefile.ErrProtectionIdentity)
	}
	if err := securefile.ValidateProtectedParent(file); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeState, err)
	}
	return nil
}

func canonicalPathUnchanged(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return securefile.ErrProtectionIdentity
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return securefile.ErrProtectionReparse
	}
	if !info.IsDir() {
		return securefile.ErrProtectionIdentity
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return securefile.ErrProtectionIdentity
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return securefile.ErrProtectionIdentity
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return securefile.ErrProtectionReparse
	}
	if err := securefile.ValidateProtectedPath(path); err != nil {
		return err
	}
	return nil
}

func unsafeParentError(cause error) error {
	detail := "destination ancestry protection could not be verified"
	switch {
	case errors.Is(cause, securefile.ErrProtectionOwner):
		detail = "destination ancestry owner is not trusted"
	case errors.Is(cause, securefile.ErrProtectionACL):
		detail = "destination ancestry ACL is unsafe or unsupported"
	case errors.Is(cause, securefile.ErrProtectionReparse):
		detail = "destination ancestry contains a reparse or symbolic link"
	case errors.Is(cause, securefile.ErrProtectionIdentity):
		detail = "destination ancestry identity is unavailable or changed"
	}
	return fmt.Errorf("%w: %s", ErrUnsafeParent, detail)
}

func openStageRoot(parentRoot *os.Root, parentPath, name, wantID string) (*os.Root, *os.File, error) {
	entry, err := parentRoot.Open(name)
	if err != nil {
		return nil, nil, ErrUnsafeState
	}
	entryID, err := directoryIdentity(entry)
	if err != nil || securefile.ValidateOwnerOnlyDir(entry) != nil || (wantID != "" && entryID != wantID) {
		entry.Close()
		return nil, nil, ErrUnsafeState
	}
	stageRoot, err := os.OpenRoot(filepath.Join(parentPath, name))
	if err != nil {
		entry.Close()
		return nil, nil, ErrUnsafeState
	}
	stageProbe, err := stageRoot.Open(".")
	if err != nil {
		stageRoot.Close()
		entry.Close()
		return nil, nil, ErrUnsafeState
	}
	stageDir, err := openDirectory(filepath.Join(parentPath, name))
	if err != nil {
		stageProbe.Close()
		stageRoot.Close()
		entry.Close()
		return nil, nil, ErrUnsafeState
	}
	probeID, probeErr := directoryIdentity(stageProbe)
	stageID, err := directoryIdentity(stageDir)
	stageProbe.Close()
	entry.Close()
	if err != nil || probeErr != nil || stageID != probeID || stageID != entryID || securefile.ValidateOwnerOnlyDir(stageDir) != nil {
		stageDir.Close()
		stageRoot.Close()
		return nil, nil, ErrUnsafeState
	}
	return stageRoot, stageDir, nil
}

func stageEntryIdentity(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrUnsafeState
	}
	file, err := root.Open(name)
	if err != nil {
		return "", ErrUnsafeState
	}
	defer file.Close()
	if err := securefile.ValidateOwnerOnlyDir(file); err != nil {
		return "", ErrUnsafeState
	}
	return directoryIdentity(file)
}

func (s *Store) rowExists(id string) (bool, error) {
	var exists int
	err := s.database().QueryRow(`select exists(select 1 from get_cleanup where cleanup_id=?)`, id).Scan(&exists)
	return exists == 1, err
}

func (s *Store) runFault(point string) error {
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}

func (stage *Stage) closeHandles() {
	_ = stage.closeStageHandles()
	if stage.parentRoot != nil {
		_ = stage.parentRoot.Close()
		stage.parentRoot = nil
	}
	if stage.parentDir != nil {
		_ = stage.parentDir.Close()
		stage.parentDir = nil
	}
}

func (stage *Stage) closeStageHandles() error {
	var result error
	if stage.stageRoot != nil {
		result = errors.Join(result, stage.stageRoot.Close())
		stage.stageRoot = nil
	}
	if stage.stageDir != nil {
		result = errors.Join(result, stage.stageDir.Close())
		stage.stageDir = nil
	}
	return result
}

func closeStagePair(root *os.Root, directory *os.File) error {
	return errors.Join(root.Close(), directory.Close())
}

func randomHex() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (result ReapResult) String() string {
	return fmt.Sprintf("examined=%d removed=%d retained=%d expired=%d", result.Examined, result.Removed, result.Retained, result.Expired)
}
