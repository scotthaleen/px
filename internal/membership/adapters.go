package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

const (
	MaxAdapters                   = 64
	MaxReceipts                   = 16_384
	MaxAdmittedReceipts           = 1_024
	MaxAdmittedReceiptsPerAdapter = 64
	ApprovalCommandSchemaVersion  = 1
	ApprovalCommandAction         = "enrollment.approve"

	ReceiptAdmitted  = "admitted"
	ReceiptCommitted = "committed"
	ReceiptRejected  = "rejected"
)

var adapterIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type RejectionCode string

const (
	RejectionEnrollmentExpired    RejectionCode = "enrollment_expired"
	RejectionSettledElsewhere     RejectionCode = "settled_elsewhere"
	RejectionNotPending           RejectionCode = "not_pending"
	RejectionMemberCapacity       RejectionCode = "member_capacity"
	RejectionInvalidEnrollmentKey RejectionCode = "invalid_enrollment_key"
)

type AdapterCredential [32]byte

type AdapterAuthority struct {
	ID            string
	Active        bool
	LastCommandID string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AdapterProvisioning struct {
	Authority  AdapterAuthority
	Credential AdapterCredential
}

type ApprovalCommand struct {
	CommandID    string
	EnrollmentID string
}

type ApprovalResult struct {
	EnrollmentID string
	DeviceID     string
	Label        string
	Revision     int64
}

type CommandReceipt struct {
	AdapterID     string
	CommandID     string
	ReceiptSeq    int64
	Fingerprint   [32]byte
	EnrollmentID  string
	State         string
	AdmittedAt    time.Time
	SettledAt     *time.Time
	RejectionCode RejectionCode
	Result        *ApprovalResult
}

func (s *Store) ProvisionAdapter(ctx context.Context, adapterID string, now time.Time) (AdapterProvisioning, error) {
	if !adapterIDPattern.MatchString(adapterID) {
		return AdapterProvisioning{}, errors.New("invalid adapter ID")
	}
	credential, err := newAdapterCredential()
	if err != nil {
		return AdapterProvisioning{}, err
	}
	digest := sha256.Sum256(credential[:])
	db, err := s.db()
	if err != nil {
		return AdapterProvisioning{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterProvisioning{}, err
	}
	defer tx.Rollback()
	var existing int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&existing); err != nil {
		return AdapterProvisioning{}, err
	}
	if existing != 0 {
		return AdapterProvisioning{}, errors.New("adapter ID is already provisioned")
	}
	var count int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_adapters`).Scan(&count); err != nil {
		return AdapterProvisioning{}, err
	}
	if count >= MaxAdapters {
		return AdapterProvisioning{}, &StoreError{Code: CodeAdapterCapacity}
	}
	now = secondTime(now)
	if _, err := tx.ExecContext(ctx, `insert into enrollment_adapters(adapter_id, active, credential_hash, created_at, updated_at) values (?, 1, ?, ?, ?)`, adapterID, digest[:], now.Unix(), now.Unix()); err != nil {
		return AdapterProvisioning{}, fmt.Errorf("provision adapter: %w", err)
	}
	s.runAdapterMutationTestHook("provision_before_commit")
	if err := tx.Commit(); err != nil {
		return AdapterProvisioning{}, err
	}
	authority := AdapterAuthority{ID: adapterID, Active: true, CreatedAt: now, UpdatedAt: now}
	return AdapterProvisioning{Authority: authority, Credential: credential}, nil
}

func (s *Store) SetAdapterActive(ctx context.Context, adapterID string, active bool, now time.Time) (AdapterAuthority, error) {
	s.adapterAuthorizationMu.Lock()
	defer s.adapterAuthorizationMu.Unlock()
	if !adapterIDPattern.MatchString(adapterID) {
		return AdapterAuthority{}, errors.New("invalid adapter ID")
	}
	value := 0
	if active {
		value = 1
	}
	db, err := s.db()
	if err != nil {
		return AdapterAuthority{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterAuthority{}, err
	}
	defer tx.Rollback()
	now = secondTime(now)
	result, err := tx.ExecContext(ctx, `update enrollment_adapters set active = ?, updated_at = ? where adapter_id = ?`, value, now.Unix(), adapterID)
	if err != nil {
		return AdapterAuthority{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AdapterAuthority{}, errors.New("adapter not found")
	}
	authority, err := queryAdapterAuthority(ctx, tx, adapterID)
	if err != nil {
		return AdapterAuthority{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdapterAuthority{}, err
	}
	return authority, nil
}

func (s *Store) RotateAdapterCredential(ctx context.Context, adapterID string, now time.Time) (AdapterProvisioning, error) {
	s.adapterAuthorizationMu.Lock()
	defer s.adapterAuthorizationMu.Unlock()
	if !adapterIDPattern.MatchString(adapterID) {
		return AdapterProvisioning{}, errors.New("invalid adapter ID")
	}
	credential, err := newAdapterCredential()
	if err != nil {
		return AdapterProvisioning{}, err
	}
	digest := sha256.Sum256(credential[:])
	db, err := s.db()
	if err != nil {
		return AdapterProvisioning{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterProvisioning{}, err
	}
	defer tx.Rollback()
	now = secondTime(now)
	result, err := tx.ExecContext(ctx, `update enrollment_adapters set credential_hash = ?, updated_at = ? where adapter_id = ?`, digest[:], now.Unix(), adapterID)
	if err != nil {
		return AdapterProvisioning{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AdapterProvisioning{}, errors.New("adapter not found")
	}
	authority, err := queryAdapterAuthority(ctx, tx, adapterID)
	if err != nil {
		return AdapterProvisioning{}, err
	}
	s.runAdapterMutationTestHook("rotate_before_commit")
	if err := tx.Commit(); err != nil {
		return AdapterProvisioning{}, err
	}
	return AdapterProvisioning{Authority: authority, Credential: credential}, nil
}

func (s *Store) Adapter(ctx context.Context, adapterID string) (AdapterAuthority, error) {
	if !adapterIDPattern.MatchString(adapterID) {
		return AdapterAuthority{}, errors.New("invalid adapter ID")
	}
	db, err := s.db()
	if err != nil {
		return AdapterAuthority{}, err
	}
	return queryAdapterAuthority(ctx, db, adapterID)
}

func queryAdapterAuthority(ctx context.Context, query receiptQuerier, adapterID string) (AdapterAuthority, error) {
	var authority AdapterAuthority
	var active int
	var last sql.NullString
	var created, updated int64
	err := query.QueryRowContext(ctx, `select adapter_id, active, last_command_id, created_at, updated_at from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&authority.ID, &active, &last, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return AdapterAuthority{}, errors.New("adapter not found")
	}
	if err != nil {
		return AdapterAuthority{}, err
	}
	authority.Active = active != 0
	authority.LastCommandID = last.String
	authority.CreatedAt = time.Unix(created, 0).UTC()
	authority.UpdatedAt = time.Unix(updated, 0).UTC()
	return authority, nil
}

func (s *Store) runAdapterMutationTestHook(stage string) {
	if s.adapterMutationTestHook != nil {
		s.adapterMutationTestHook(stage)
	}
}

func ApprovalCommandFingerprint(command ApprovalCommand) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("px.enrollment-command-fingerprint.v1\x00"))
	for _, value := range []string{command.CommandID, "1", ApprovalCommandAction, command.EnrollmentID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (s *Store) AdmitApprovalCommand(ctx context.Context, adapterID string, credential AdapterCredential, command ApprovalCommand, now time.Time) (CommandReceipt, error) {
	if !adapterIDPattern.MatchString(adapterID) {
		return CommandReceipt{}, &StoreError{Code: CodeAdapterInvalid}
	}
	issuedAt, err := validateUUIDv7(command.CommandID)
	if err != nil {
		return CommandReceipt{}, &StoreError{Code: CodeCommandInvalid}
	}
	fingerprint := ApprovalCommandFingerprint(command)
	digest := sha256.Sum256(credential[:])
	db, err := s.db()
	if err != nil {
		return CommandReceipt{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CommandReceipt{}, err
	}
	defer tx.Rollback()
	var active int
	var storedDigest []byte
	var last sql.NullString
	err = tx.QueryRowContext(ctx, `select active, credential_hash, last_command_id from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&active, &storedDigest, &last)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (active != 1 || len(storedDigest) != sha256.Size || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1) {
		return CommandReceipt{}, &StoreError{Code: CodeAdapterUnauthorized}
	}
	if err != nil {
		return CommandReceipt{}, err
	}
	receipt, err := queryReceipt(ctx, tx, adapterID, command.CommandID)
	if err == nil {
		if receipt.Fingerprint != fingerprint {
			return CommandReceipt{}, &StoreError{Code: CodeRequestConflict}
		}
		return receipt, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CommandReceipt{}, err
	}
	if !validEnrollmentID(command.EnrollmentID) {
		return CommandReceipt{}, &StoreError{Code: CodeEnrollmentInvalid}
	}
	if last.Valid && command.CommandID <= last.String {
		return CommandReceipt{}, &StoreError{Code: CodeReceiptExpired}
	}
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return CommandReceipt{}, &StoreError{Code: CodeCommandTimeInvalid}
	}
	if !issuedAt.After(now.Add(-30 * 24 * time.Hour)) {
		return CommandReceipt{}, &StoreError{Code: CodeReceiptExpired}
	}
	var globalAdmitted, adapterAdmitted int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_command_receipts where state = ?`, ReceiptAdmitted).Scan(&globalAdmitted); err != nil {
		return CommandReceipt{}, err
	}
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_command_receipts where state = ? and adapter_id = ?`, ReceiptAdmitted, adapterID).Scan(&adapterAdmitted); err != nil {
		return CommandReceipt{}, err
	}
	if globalAdmitted >= MaxAdmittedReceipts || adapterAdmitted >= MaxAdmittedReceiptsPerAdapter {
		return CommandReceipt{}, &StoreError{Code: CodeCommandCapacity}
	}
	var total int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_command_receipts`).Scan(&total); err != nil {
		return CommandReceipt{}, err
	}
	if total >= MaxReceipts {
		result, err := tx.ExecContext(ctx, `delete from enrollment_command_receipts where receipt_seq = (select receipt_seq from enrollment_command_receipts where state <> ? order by receipt_seq limit 1)`, ReceiptAdmitted)
		if err != nil {
			return CommandReceipt{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return CommandReceipt{}, &StoreError{Code: CodeReceiptCapacity}
		}
	}
	now = secondTime(now)
	result, err := tx.ExecContext(ctx, `insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at) values (?, ?, ?, 1, ?, ?, ?, ?)`, adapterID, command.CommandID, fingerprint[:], ApprovalCommandAction, command.EnrollmentID, ReceiptAdmitted, now.Unix())
	if err != nil {
		return CommandReceipt{}, fmt.Errorf("admit adapter command: %w", err)
	}
	seq, err := result.LastInsertId()
	if err != nil {
		return CommandReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, `update enrollment_adapters set last_command_id = ?, updated_at = ? where adapter_id = ?`, command.CommandID, now.Unix(), adapterID); err != nil {
		return CommandReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return CommandReceipt{}, err
	}
	return CommandReceipt{AdapterID: adapterID, CommandID: command.CommandID, ReceiptSeq: seq, Fingerprint: fingerprint, EnrollmentID: command.EnrollmentID, State: ReceiptAdmitted, AdmittedAt: now}, nil
}

func (s *Store) QueryCommand(ctx context.Context, adapterID string, credential AdapterCredential, commandID string) (CommandReceipt, error) {
	if !adapterIDPattern.MatchString(adapterID) {
		return CommandReceipt{}, &StoreError{Code: CodeAdapterInvalid}
	}
	if _, err := validateUUIDv7(commandID); err != nil {
		return CommandReceipt{}, &StoreError{Code: CodeCommandInvalid}
	}
	db, err := s.db()
	if err != nil {
		return CommandReceipt{}, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CommandReceipt{}, err
	}
	defer tx.Rollback()
	if err := authorizeAdapterRead(ctx, tx, adapterID, credential); err != nil {
		return CommandReceipt{}, err
	}
	receipt, err := queryCommand(ctx, tx, adapterID, commandID)
	if err != nil {
		return CommandReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return CommandReceipt{}, err
	}
	return receipt, nil
}

// queryCommandInternal is server-internal and bypasses adapter authorization.
func (s *Store) queryCommandInternal(ctx context.Context, adapterID, commandID string) (CommandReceipt, error) {
	db, err := s.db()
	if err != nil {
		return CommandReceipt{}, err
	}
	return queryCommand(ctx, db, adapterID, commandID)
}

func queryCommand(ctx context.Context, query receiptQuerier, adapterID, commandID string) (CommandReceipt, error) {
	receipt, err := queryReceipt(ctx, query, adapterID, commandID)
	if errors.Is(err, sql.ErrNoRows) {
		var last sql.NullString
		if queryErr := query.QueryRowContext(ctx, `select last_command_id from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&last); errors.Is(queryErr, sql.ErrNoRows) {
			return CommandReceipt{}, &StoreError{Code: CodeAdapterUnauthorized}
		} else if queryErr != nil {
			return CommandReceipt{}, queryErr
		}
		if last.Valid && commandID <= last.String {
			return CommandReceipt{}, &StoreError{Code: CodeReceiptExpired}
		}
		return CommandReceipt{}, &StoreError{Code: CodeReceiptNotFound}
	}
	return receipt, err
}

func authorizeAdapterRead(ctx context.Context, tx *sql.Tx, adapterID string, credential AdapterCredential) error {
	if !adapterIDPattern.MatchString(adapterID) {
		return &StoreError{Code: CodeAdapterInvalid}
	}
	digest := sha256.Sum256(credential[:])
	var active int
	var storedDigest []byte
	err := tx.QueryRowContext(ctx, `select active, credential_hash from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&active, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (active != 1 || len(storedDigest) != sha256.Size || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1) {
		return &StoreError{Code: CodeAdapterUnauthorized}
	}
	return err
}

// AuthorizeAdapter is only for establishing a marker-only doorbell connection.
// Data reads and command admission remain credential-bound in their own transactions.
func (s *Store) AuthorizeAdapter(ctx context.Context, adapterID string, credential AdapterCredential) error {
	return s.WithAuthorizedAdapter(ctx, adapterID, credential, func() error { return nil })
}

// WithAuthorizedAdapter runs one nonblocking local callback while the
// credential-bound read transaction and credential-generation lock are held.
// Doorbell subscription uses it to make authorization and replacement atomic
// against rotation and deactivation.
func (s *Store) WithAuthorizedAdapter(ctx context.Context, adapterID string, credential AdapterCredential, callback func() error) error {
	if callback == nil {
		return errors.New("authorized adapter callback is required")
	}
	s.adapterAuthorizationMu.RLock()
	defer s.adapterAuthorizationMu.RUnlock()
	db, err := s.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := authorizeAdapterRead(ctx, tx, adapterID, credential); err != nil {
		return err
	}
	if err := callback(); err != nil {
		return err
	}
	return tx.Commit()
}

// AuthorizeAdapterMarker holds credential authority stable until release. The
// adapter endpoint uses it only around one deadline-bounded marker write.
func (s *Store) AuthorizeAdapterMarker(ctx context.Context, adapterID string, credential AdapterCredential) (func(), error) {
	s.adapterAuthorizationMu.RLock()
	if err := s.authorizeAdapter(ctx, adapterID, credential); err != nil {
		s.adapterAuthorizationMu.RUnlock()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(s.adapterAuthorizationMu.RUnlock) }, nil
}

func (s *Store) authorizeAdapter(ctx context.Context, adapterID string, credential AdapterCredential) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := authorizeAdapterRead(ctx, tx, adapterID, credential); err != nil {
		return err
	}
	return tx.Commit()
}

type receiptQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func queryReceipt(ctx context.Context, query receiptQuerier, adapterID, commandID string) (CommandReceipt, error) {
	return scanReceipt(query.QueryRowContext(ctx, `select adapter_id, command_id, receipt_seq, fingerprint, enrollment_id, state, admitted_at, settled_at, rejection_code, result_device_id, result_label, result_revision from enrollment_command_receipts where adapter_id = ? and command_id = ?`, adapterID, commandID))
}

func scanReceipt(scanner interface{ Scan(...any) error }) (CommandReceipt, error) {
	var receipt CommandReceipt
	var fingerprint []byte
	var admitted int64
	var settled sql.NullInt64
	var rejection, resultDevice, resultLabel sql.NullString
	var resultRevision sql.NullInt64
	err := scanner.Scan(&receipt.AdapterID, &receipt.CommandID, &receipt.ReceiptSeq, &fingerprint, &receipt.EnrollmentID, &receipt.State, &admitted, &settled, &rejection, &resultDevice, &resultLabel, &resultRevision)
	if err != nil {
		return CommandReceipt{}, err
	}
	copy(receipt.Fingerprint[:], fingerprint)
	receipt.AdmittedAt = time.Unix(admitted, 0).UTC()
	if settled.Valid {
		value := time.Unix(settled.Int64, 0).UTC()
		receipt.SettledAt = &value
	}
	receipt.RejectionCode = RejectionCode(rejection.String)
	if resultDevice.Valid {
		receipt.Result = &ApprovalResult{EnrollmentID: receipt.EnrollmentID, DeviceID: resultDevice.String, Label: resultLabel.String, Revision: resultRevision.Int64}
	}
	return receipt, nil
}

// ApproveAdapterCommand executes only an already admitted exact command.
func (s *Store) ApproveAdapterCommand(ctx context.Context, adapterID, commandID string, now time.Time) (CommandReceipt, error) {
	if !adapterIDPattern.MatchString(adapterID) {
		return CommandReceipt{}, &StoreError{Code: CodeAdapterInvalid}
	}
	if _, err := validateUUIDv7(commandID); err != nil {
		return CommandReceipt{}, &StoreError{Code: CodeCommandInvalid}
	}
	if err := s.SettleExpired(ctx, now); err != nil {
		return CommandReceipt{}, err
	}
	db, err := s.db()
	if err != nil {
		return CommandReceipt{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CommandReceipt{}, err
	}
	defer tx.Rollback()
	receipt, err := queryReceipt(ctx, tx, adapterID, commandID)
	if errors.Is(err, sql.ErrNoRows) {
		return CommandReceipt{}, &StoreError{Code: CodeReceiptNotFound}
	}
	if err != nil {
		return CommandReceipt{}, err
	}
	if receipt.State != ReceiptAdmitted {
		return receipt, tx.Commit()
	}
	var deviceID, deviceKeyValue, label, labelKey string
	err = tx.QueryRowContext(ctx, `select device_id, device_key, label, label_key from pending_enrollments where enrollment_id = ?`, receipt.EnrollmentID).Scan(&deviceID, &deviceKeyValue, &label, &labelKey)
	if errors.Is(err, sql.ErrNoRows) {
		code, codeErr := missingPendingRejection(ctx, tx, receipt.EnrollmentID)
		if codeErr != nil {
			return CommandReceipt{}, codeErr
		}
		if err := rejectAdmittedApprovalCommands(ctx, tx, receipt.EnrollmentID, code, now, "", ""); err != nil {
			return CommandReceipt{}, err
		}
		if err := tx.Commit(); err != nil {
			return CommandReceipt{}, err
		}
		return s.queryCommandInternal(ctx, adapterID, commandID)
	}
	if err != nil {
		return CommandReceipt{}, err
	}
	var memberCount int
	if err := tx.QueryRowContext(ctx, `select count(*) from members where revoked_at is null`).Scan(&memberCount); err != nil {
		return CommandReceipt{}, err
	}
	if memberCount >= MaxMembers {
		return s.rejectExecutingCommand(ctx, tx, receipt, RejectionMemberCapacity, now)
	}
	deviceKey, err := identity.ParseID(deviceKeyValue)
	if err != nil || len(deviceKey) != ed25519.PublicKeySize {
		return s.rejectExecutingCommand(ctx, tx, receipt, RejectionInvalidEnrollmentKey, now)
	}
	credential, err := s.authority.Issue(deviceKey, label, 1, now)
	if err != nil {
		return CommandReceipt{}, err
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return CommandReceipt{}, err
	}
	now = secondTime(now)
	if _, err := tx.ExecContext(ctx, `insert into members(device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) values (?, ?, ?, ?, 1, ?, ?, ?)`, deviceID, deviceKeyValue, label, labelKey, string(credentialJSON), now.Unix(), receipt.EnrollmentID); err != nil {
		return CommandReceipt{}, fmt.Errorf("create adapter-approved member: %w", err)
	}
	if result, err := tx.ExecContext(ctx, `delete from pending_enrollments where enrollment_id = ?`, receipt.EnrollmentID); err != nil {
		return CommandReceipt{}, err
	} else if changed, _ := result.RowsAffected(); changed != 1 {
		return CommandReceipt{}, errors.New("pending enrollment changed during approval")
	}
	if err := insertFact(ctx, tx, FactMemberApproved, receipt.EnrollmentID, deviceID, label, now, 0, 1); err != nil {
		return CommandReceipt{}, err
	}
	if err := insertAuditActor(ctx, tx, now, "adapter", "", adapterID, "member.approved", deviceID, label, 1); err != nil {
		return CommandReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, `update enrollment_command_receipts set state = ?, settled_at = ?, result_device_id = ?, result_label = ?, result_revision = 1 where adapter_id = ? and command_id = ? and state = ?`, ReceiptCommitted, now.Unix(), deviceID, label, adapterID, commandID, ReceiptAdmitted)
	if err != nil {
		return CommandReceipt{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return CommandReceipt{}, errors.New("adapter command changed during approval")
	}
	if err := rejectAdmittedApprovalCommands(ctx, tx, receipt.EnrollmentID, RejectionSettledElsewhere, now, adapterID, commandID); err != nil {
		return CommandReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return CommandReceipt{}, err
	}
	s.notifyFacts()
	return s.queryCommandInternal(ctx, adapterID, commandID)
}

func (s *Store) rejectExecutingCommand(ctx context.Context, tx *sql.Tx, receipt CommandReceipt, code RejectionCode, now time.Time) (CommandReceipt, error) {
	if !validRejectionCode(code) {
		return CommandReceipt{}, errors.New("invalid command rejection code")
	}
	result, err := tx.ExecContext(ctx, `update enrollment_command_receipts set state = ?, settled_at = ?, rejection_code = ? where adapter_id = ? and command_id = ? and state = ?`, ReceiptRejected, now.Unix(), code, receipt.AdapterID, receipt.CommandID, ReceiptAdmitted)
	if err != nil {
		return CommandReceipt{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return CommandReceipt{}, errors.New("adapter command changed during rejection")
	}
	if err := tx.Commit(); err != nil {
		return CommandReceipt{}, err
	}
	return s.queryCommandInternal(ctx, receipt.AdapterID, receipt.CommandID)
}

func missingPendingRejection(ctx context.Context, tx *sql.Tx, enrollmentID string) (RejectionCode, error) {
	var kind string
	err := tx.QueryRowContext(ctx, `select kind from enrollment_facts where enrollment_id = ? and kind in (?, ?) order by seq desc limit 1`, enrollmentID, FactMemberApproved, FactPendingExpired).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return RejectionNotPending, nil
	}
	if err != nil {
		return "", err
	}
	if kind == FactPendingExpired {
		return RejectionEnrollmentExpired, nil
	}
	return RejectionSettledElsewhere, nil
}

func rejectAdmittedApprovalCommands(ctx context.Context, tx *sql.Tx, enrollmentID string, code RejectionCode, now time.Time, exceptAdapterID, exceptCommandID string) error {
	if !validRejectionCode(code) {
		return errors.New("invalid command rejection code")
	}
	_, err := tx.ExecContext(ctx, `update enrollment_command_receipts set state = ?, settled_at = ?, rejection_code = ? where enrollment_id = ? and state = ? and not (adapter_id = ? and command_id = ?)`, ReceiptRejected, now.Unix(), code, enrollmentID, ReceiptAdmitted, exceptAdapterID, exceptCommandID)
	if err != nil {
		return fmt.Errorf("settle admitted approval commands: %w", err)
	}
	return nil
}

func (s *Store) AdmittedApprovalCommands(ctx context.Context, adapterID string, credential AdapterCredential, limit int) ([]CommandReceipt, error) {
	return s.admittedApprovalCommandsRead(ctx, adapterID, &credential, limit)
}

// admittedApprovalCommands is server-internal and returns all admitted commands.
func (s *Store) admittedApprovalCommands(ctx context.Context, limit int) ([]CommandReceipt, error) {
	return s.admittedApprovalCommandsRead(ctx, "", nil, limit)
}

func (s *Store) admittedApprovalCommandsRead(ctx context.Context, adapterID string, credential *AdapterCredential, limit int) ([]CommandReceipt, error) {
	if limit <= 0 || limit > MaxAdmittedReceipts {
		return nil, errors.New("invalid admitted command limit")
	}
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if credential != nil {
		if err := authorizeAdapterRead(ctx, tx, adapterID, *credential); err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(ctx, `select adapter_id, command_id, receipt_seq, fingerprint, enrollment_id, state, admitted_at, settled_at, rejection_code, result_device_id, result_label, result_revision from enrollment_command_receipts where state = ? and (? = '' or adapter_id = ?) order by receipt_seq limit ?`, ReceiptAdmitted, adapterID, adapterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CommandReceipt
	for rows.Next() {
		receipt, err := scanReceipt(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, receipt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) PruneReceipts(ctx context.Context, now time.Time) (int64, error) {
	db, err := s.db()
	if err != nil {
		return 0, err
	}
	result, err := db.ExecContext(ctx, `delete from enrollment_command_receipts where state <> ? and settled_at <= ?`, ReceiptAdmitted, now.Add(-30*24*time.Hour).Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func validateUUIDv7(value string) (time.Time, error) {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return time.Time{}, errors.New("command ID must be a canonical UUIDv7")
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != 16 || raw[6]>>4 != 7 || raw[8]&0xc0 != 0x80 {
		return time.Time{}, errors.New("command ID must be a canonical UUIDv7")
	}
	milliseconds := int64(raw[0])<<40 | int64(raw[1])<<32 | int64(raw[2])<<24 | int64(raw[3])<<16 | int64(raw[4])<<8 | int64(raw[5])
	return time.UnixMilli(milliseconds).UTC(), nil
}

func validEnrollmentID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func validRejectionCode(code RejectionCode) bool {
	switch code {
	case RejectionEnrollmentExpired, RejectionSettledElsewhere, RejectionNotPending, RejectionMemberCapacity, RejectionInvalidEnrollmentKey:
		return true
	default:
		return false
	}
}

func newAdapterCredential() (AdapterCredential, error) {
	var credential AdapterCredential
	if _, err := rand.Read(credential[:]); err != nil {
		return AdapterCredential{}, fmt.Errorf("generate adapter credential: %w", err)
	}
	return credential, nil
}

func secondTime(value time.Time) time.Time { return time.Unix(value.Unix(), 0).UTC() }
