package membership

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	FactPendingAdmitted = "enrollment.pending_admitted"
	FactPendingExpired  = "enrollment.pending_expired"
	FactMemberApproved  = "enrollment.member_approved"
	FactMemberRevoked   = "enrollment.member_revoked"

	MaxFactRows       = 16_832
	FactHistoryTarget = 16_384
	MaxFactPage       = 256
)

type ErrorCode string

const (
	CodeFactCapacity           ErrorCode = "fact_capacity"
	CodeCursorExpired          ErrorCode = "cursor_expired"
	CodeAdapterCapacity        ErrorCode = "adapter_capacity"
	CodeCommandCapacity        ErrorCode = "command_capacity"
	CodeReceiptCapacity        ErrorCode = "receipt_capacity"
	CodeReceiptExpired         ErrorCode = "receipt_expired"
	CodeCommandTimeInvalid     ErrorCode = "command_time_invalid"
	CodeRequestConflict        ErrorCode = "request_conflict"
	CodeAdapterUnauthorized    ErrorCode = "adapter_unauthorized"
	CodeAdapterInvalid         ErrorCode = "adapter_invalid"
	CodeCommandInvalid         ErrorCode = "command_invalid"
	CodeEnrollmentInvalid      ErrorCode = "enrollment_invalid"
	CodeReceiptNotFound        ErrorCode = "receipt_not_found"
	CodeFactReplayInvalid      ErrorCode = "fact_replay_invalid"
	CodeMembershipInvalid      ErrorCode = "membership_invalid"
	CodeMembershipConflict     ErrorCode = "membership_conflict"
	CodeMembershipCapacity     ErrorCode = "membership_capacity"
	CodeMembershipNotFound     ErrorCode = "membership_not_found"
	CodeMembershipRevoked      ErrorCode = "membership_revoked"
	CodeInviteLabelUnavailable ErrorCode = "invite_label_unavailable"
	CodeInviteCapacity         ErrorCode = "invite_capacity"
	CodeInviteUnavailable      ErrorCode = "invite_unavailable"
	CodeEnrollmentUnavailable  ErrorCode = "enrollment_unavailable"
)

type StoreError struct {
	Code      ErrorCode
	Message   string
	Floor     int64
	HighWater int64
}

func (e *StoreError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func HasCode(err error, code ErrorCode) bool {
	var storeErr *StoreError
	return errors.As(err, &storeErr) && storeErr.Code == code
}

type EnrollmentFact struct {
	Seq            int64
	Kind           string
	EnrollmentID   string
	OccurredAt     time.Time
	DeviceID       string
	Label          string
	ExpiresAt      *time.Time
	MemberRevision int64
}

type FactPage struct {
	Facts     []EnrollmentFact
	Floor     int64
	HighWater int64
}

type PendingSnapshot struct {
	EnrollmentID string
	DeviceID     string
	Label        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type PendingSnapshotPage struct {
	Pending   []PendingSnapshot
	HighWater int64
}

func (s *Store) ReplayFacts(ctx context.Context, adapterID string, credential AdapterCredential, cursor, highWater int64, limit int) (FactPage, error) {
	return s.replayFactsRead(ctx, adapterID, &credential, cursor, highWater, limit)
}

// replayFacts is server-internal and intentionally bypasses adapter authorization.
func (s *Store) replayFacts(ctx context.Context, cursor, highWater int64, limit int) (FactPage, error) {
	return s.replayFactsRead(ctx, "", nil, cursor, highWater, limit)
}

func (s *Store) replayFactsRead(ctx context.Context, adapterID string, credential *AdapterCredential, cursor, highWater int64, limit int) (FactPage, error) {
	if cursor < 0 || highWater < 0 || limit <= 0 || limit > MaxFactPage {
		return FactPage{}, &StoreError{Code: CodeFactReplayInvalid}
	}
	db, err := s.db()
	if err != nil {
		return FactPage{}, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FactPage{}, fmt.Errorf("begin fact replay: %w", err)
	}
	defer tx.Rollback()
	if credential != nil {
		if err := authorizeAdapterRead(ctx, tx, adapterID, *credential); err != nil {
			return FactPage{}, err
		}
	}
	var floor, current int64
	if err := tx.QueryRowContext(ctx, `select replay_floor from enrollment_fact_metadata where singleton = 1`).Scan(&floor); err != nil {
		return FactPage{}, fmt.Errorf("read fact floor: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `select coalesce(max(seq), ?) from enrollment_facts`, floor).Scan(&current); err != nil {
		return FactPage{}, fmt.Errorf("read fact high-water: %w", err)
	}
	if highWater == 0 {
		highWater = current
	}
	if cursor < floor {
		return FactPage{}, &StoreError{Code: CodeCursorExpired, Floor: floor, HighWater: current}
	}
	if cursor > highWater || highWater > current {
		return FactPage{}, &StoreError{Code: CodeFactReplayInvalid}
	}
	rows, err := tx.QueryContext(ctx, `select seq, kind, enrollment_id, occurred_at, device_id, label, expires_at, member_revision from enrollment_facts where seq > ? and seq <= ? order by seq limit ?`, cursor, highWater, limit)
	if err != nil {
		return FactPage{}, fmt.Errorf("query enrollment facts: %w", err)
	}
	defer rows.Close()
	page := FactPage{Facts: make([]EnrollmentFact, 0, limit), Floor: floor, HighWater: highWater}
	for rows.Next() {
		fact, err := scanFact(rows)
		if err != nil {
			return FactPage{}, err
		}
		page.Facts = append(page.Facts, fact)
	}
	if err := rows.Err(); err != nil {
		return FactPage{}, err
	}
	if err := rows.Close(); err != nil {
		return FactPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return FactPage{}, fmt.Errorf("finish fact replay: %w", err)
	}
	return page, nil
}

func (s *Store) CurrentPendingSnapshot(ctx context.Context, adapterID string, credential AdapterCredential, now time.Time) (PendingSnapshotPage, error) {
	return s.currentPendingSnapshotRead(ctx, adapterID, &credential, now)
}

// currentPendingSnapshot is server-internal and bypasses adapter authorization.
func (s *Store) currentPendingSnapshot(ctx context.Context, now time.Time) (PendingSnapshotPage, error) {
	return s.currentPendingSnapshotRead(ctx, "", nil, now)
}

func (s *Store) currentPendingSnapshotRead(ctx context.Context, adapterID string, credential *AdapterCredential, now time.Time) (PendingSnapshotPage, error) {
	changed := false
	if credential == nil {
		if err := s.SettleExpired(ctx, now); err != nil {
			return PendingSnapshotPage{}, err
		}
	}
	db, err := s.db()
	if err != nil {
		return PendingSnapshotPage{}, err
	}
	options := &sql.TxOptions{ReadOnly: credential == nil}
	tx, err := db.BeginTx(ctx, options)
	if err != nil {
		return PendingSnapshotPage{}, err
	}
	defer tx.Rollback()
	if credential != nil {
		if err := authorizeAdapterRead(ctx, tx, adapterID, *credential); err != nil {
			return PendingSnapshotPage{}, err
		}
		changed, err = deleteExpired(ctx, tx, now)
		if err != nil {
			return PendingSnapshotPage{}, err
		}
	}
	var floor int64
	if err := tx.QueryRowContext(ctx, `select replay_floor from enrollment_fact_metadata where singleton = 1`).Scan(&floor); err != nil {
		return PendingSnapshotPage{}, err
	}
	page := PendingSnapshotPage{Pending: make([]PendingSnapshot, 0)}
	if err := tx.QueryRowContext(ctx, `select coalesce(max(seq), ?) from enrollment_facts`, floor).Scan(&page.HighWater); err != nil {
		return PendingSnapshotPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `select enrollment_id, device_id, label, created_at, expires_at from pending_enrollments order by created_at, enrollment_id limit ?`, s.maxPending+1)
	if err != nil {
		return PendingSnapshotPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var pending PendingSnapshot
		var created, expires int64
		if err := rows.Scan(&pending.EnrollmentID, &pending.DeviceID, &pending.Label, &created, &expires); err != nil {
			return PendingSnapshotPage{}, err
		}
		pending.CreatedAt = time.Unix(created, 0).UTC()
		pending.ExpiresAt = time.Unix(expires, 0).UTC()
		page.Pending = append(page.Pending, pending)
	}
	if len(page.Pending) > s.maxPending {
		return PendingSnapshotPage{}, errors.New("pending enrollment capacity exceeded")
	}
	if err := rows.Err(); err != nil {
		return PendingSnapshotPage{}, err
	}
	if err := rows.Close(); err != nil {
		return PendingSnapshotPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return PendingSnapshotPage{}, err
	}
	if changed {
		s.notifyFacts()
	}
	return page, nil
}

func scanFact(scanner interface{ Scan(...any) error }) (EnrollmentFact, error) {
	var fact EnrollmentFact
	var occurred int64
	var expires, revision sql.NullInt64
	if err := scanner.Scan(&fact.Seq, &fact.Kind, &fact.EnrollmentID, &occurred, &fact.DeviceID, &fact.Label, &expires, &revision); err != nil {
		return EnrollmentFact{}, fmt.Errorf("scan enrollment fact: %w", err)
	}
	fact.OccurredAt = time.Unix(occurred, 0).UTC()
	if expires.Valid {
		value := time.Unix(expires.Int64, 0).UTC()
		fact.ExpiresAt = &value
	}
	if revision.Valid {
		fact.MemberRevision = revision.Int64
	}
	return fact, nil
}

func newEnrollmentID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate enrollment ID: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func insertFact(ctx context.Context, tx *sql.Tx, kind, enrollmentID, deviceID, label string, occurred time.Time, expiresAt int64, revision int64) error {
	if err := validateFactOrder(ctx, tx, kind, enrollmentID); err != nil {
		return err
	}
	var expires, memberRevision any
	if kind == FactPendingAdmitted {
		expires = expiresAt
	}
	if kind == FactMemberApproved || kind == FactMemberRevoked {
		memberRevision = revision
	}
	if _, err := tx.ExecContext(ctx, `insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at, member_revision) values (?, ?, ?, ?, ?, ?, ?)`, kind, enrollmentID, occurred.Unix(), deviceID, label, expires, memberRevision); err != nil {
		return fmt.Errorf("append enrollment fact: %w", err)
	}
	return nil
}

func validateFactOrder(ctx context.Context, tx *sql.Tx, kind, enrollmentID string) error {
	var admitted, expired, approved, revoked int
	if err := tx.QueryRowContext(ctx, `select count(*) filter (where kind = ?), count(*) filter (where kind = ?), count(*) filter (where kind = ?), count(*) filter (where kind = ?) from enrollment_facts where enrollment_id = ?`, FactPendingAdmitted, FactPendingExpired, FactMemberApproved, FactMemberRevoked, enrollmentID).Scan(&admitted, &expired, &approved, &revoked); err != nil {
		return err
	}
	valid := false
	switch kind {
	case FactPendingAdmitted:
		valid = admitted+expired+approved+revoked == 0
	case FactPendingExpired:
		valid = admitted == 1 && expired+approved+revoked == 0
	case FactMemberApproved:
		valid = admitted == 1 && expired+approved+revoked == 0
	case FactMemberRevoked:
		// Migrated members intentionally have no synthetic approval fact.
		valid = revoked == 0 && expired == 0 && (approved == 1 || admitted == 0)
	}
	if !valid {
		return errors.New("invalid or duplicate enrollment fact transition")
	}
	return nil
}

func factOccupancy(ctx context.Context, tx *sql.Tx) (int, error) {
	var facts, pending, active int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_facts`).Scan(&facts); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `select count(*) from pending_enrollments`).Scan(&pending); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `select count(*) from members where revoked_at is null`).Scan(&active); err != nil {
		return 0, err
	}
	return facts + 2*pending + active, nil
}

func ensureFactAdmissionCapacity(ctx context.Context, tx *sql.Tx) error {
	for {
		occupancy, err := factOccupancy(ctx, tx)
		if err != nil {
			return err
		}
		if occupancy+3 <= MaxFactRows {
			return nil
		}
		pruned, err := pruneOneFactPrefix(ctx, tx, true, time.Time{})
		if err != nil {
			return err
		}
		if !pruned {
			return &StoreError{Code: CodeFactCapacity}
		}
	}
}

func ensureFactMemberCapacity(ctx context.Context, tx *sql.Tx) error {
	for {
		occupancy, err := factOccupancy(ctx, tx)
		if err != nil {
			return err
		}
		if occupancy+1 <= MaxFactRows {
			return nil
		}
		pruned, err := pruneOneFactPrefix(ctx, tx, true, time.Time{})
		if err != nil {
			return err
		}
		if !pruned {
			return &StoreError{Code: CodeFactCapacity}
		}
	}
}

func pruneOneFactPrefix(ctx context.Context, tx *sql.Tx, pressure bool, now time.Time) (bool, error) {
	var seq, occurred int64
	var protected int
	err := tx.QueryRowContext(ctx, `select f.seq, f.occurred_at, exists(select 1 from pending_enrollments p where p.enrollment_id = f.enrollment_id and f.kind = ?) from enrollment_facts f order by f.seq limit 1`, FactPendingAdmitted).Scan(&seq, &occurred, &protected)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if protected != 0 {
		return false, nil
	}
	if !pressure {
		var newerUnprotected int
		if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_facts f where f.seq > ? and not exists(select 1 from pending_enrollments p where p.enrollment_id = f.enrollment_id and f.kind = ?)`, seq, FactPendingAdmitted).Scan(&newerUnprotected); err != nil {
			return false, err
		}
		if occurred > now.Add(-30*24*time.Hour).Unix() && newerUnprotected < FactHistoryTarget {
			return false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `delete from enrollment_facts where seq = ?`, seq); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `update enrollment_fact_metadata set replay_floor = ? where singleton = 1`, seq); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) PruneFacts(ctx context.Context, now time.Time) (int, error) {
	db, err := s.db()
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count := 0
	for {
		pruned, err := pruneOneFactPrefix(ctx, tx, false, now)
		if err != nil {
			return 0, err
		}
		if !pruned {
			break
		}
		count++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if count != 0 {
		s.notifyFacts()
	}
	return count, nil
}
