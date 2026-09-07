package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

const (
	PendingLifetime        = 15 * time.Minute
	DefaultMaxPending      = 64
	MaxMembers             = 256
	DefaultMemberListLimit = 50
	MaxMemberListLimit     = 128
	DefaultAuditLimit      = 50
	MaxAuditLimit          = 128
)

var (
	labelPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	approvalCodePattern = regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}$`)
)

type Store struct {
	database                func() *sql.DB
	authority               *Authority
	maxPending              int
	random                  io.Reader
	adapterMutationTestHook func(string)
	factNotifications       chan<- struct{}
	adapterAuthorizationMu  sync.RWMutex
}

type StoreOption func(*Store)

func WithFactNotifications(notifications chan<- struct{}) StoreOption {
	return func(store *Store) { store.factNotifications = notifications }
}

func WithRandomReader(random io.Reader) StoreOption {
	return func(store *Store) {
		if random != nil {
			store.random = random
		}
	}
}

type Enrollment struct {
	State      string      `json:"state"`
	Code       string      `json:"code,omitempty"`
	ExpiresAt  time.Time   `json:"expires_at,omitempty"`
	Credential *Credential `json:"credential,omitempty"`
}

type Pending struct {
	Code      string    `json:"code"`
	DeviceID  string    `json:"device_id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Member struct {
	EnrollmentID string     `json:"-"`
	DeviceID     string     `json:"device_id"`
	Label        string     `json:"label"`
	Revision     int64      `json:"revision"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type AuditEvent struct {
	ID             int64     `json:"id"`
	OccurredAt     time.Time `json:"occurred_at"`
	ActorType      string    `json:"actor_type"`
	ActorDeviceID  string    `json:"actor_device_id,omitempty"`
	ActorID        string    `json:"actor_id,omitempty"`
	Action         string    `json:"action"`
	TargetDeviceID string    `json:"target_device_id,omitempty"`
	TargetLabel    string    `json:"target_label,omitempty"`
	TargetRevision *int64    `json:"target_revision,omitempty"`
	TargetInviteID string    `json:"target_invite_id,omitempty"`
}

type MemberPage struct {
	Members    []Member
	NextCursor string
}

func NewStore(db *sql.DB, authority *Authority, maxPending int, options ...StoreOption) *Store {
	return NewStoreProvider(func() *sql.DB { return db }, authority, maxPending, options...)
}

func NewStoreProvider(database func() *sql.DB, authority *Authority, maxPending int, options ...StoreOption) *Store {
	if maxPending <= 0 || maxPending > DefaultMaxPending {
		maxPending = DefaultMaxPending
	}
	store := &Store{database: database, authority: authority, maxPending: maxPending, random: rand.Reader}
	for _, option := range options {
		option(store)
	}
	return store
}

func (s *Store) notifyFacts() {
	if s.factNotifications == nil {
		return
	}
	select {
	case s.factNotifications <- struct{}{}:
	default:
	}
}

func ValidateLabel(label string) error {
	if !labelPattern.MatchString(label) {
		return errors.New("label must be 1-63 portable letters, digits, dots, underscores, or hyphens and start with a letter or digit")
	}
	return nil
}

func NormalizeApprovalCode(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !approvalCodePattern.MatchString(code) {
		return "", errors.New("approval code must use the form XXXX-XXXX")
	}
	return code, nil
}

func (s *Store) RequestEnrollment(ctx context.Context, deviceKey ed25519.PublicKey, label, sourceIP string, now time.Time) (Enrollment, error) {
	if len(deviceKey) != ed25519.PublicKeySize {
		return Enrollment{}, membershipError(CodeMembershipInvalid, "invalid enrollment device key")
	}
	if err := ValidateLabel(label); err != nil {
		return Enrollment{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	deviceID := identity.ID(deviceKey)
	labelKey := strings.ToLower(label)
	db, err := s.db()
	if err != nil {
		return Enrollment{}, err
	}
	if err := s.SettleExpired(ctx, now); err != nil {
		return Enrollment{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback()
	var memberLabel, credentialJSON string
	var revokedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `select label, credential, revoked_at from members where device_id = ?`, deviceID).Scan(&memberLabel, &credentialJSON, &revokedAt)
	if err == nil {
		if !strings.EqualFold(memberLabel, label) {
			return Enrollment{}, membershipError(CodeMembershipConflict, "device key is already bound to another label")
		}
		if revokedAt.Valid {
			return Enrollment{}, membershipError(CodeMembershipRevoked, "device membership is revoked")
		}
		var credential Credential
		if err := json.Unmarshal([]byte(credentialJSON), &credential); err != nil {
			return Enrollment{}, fmt.Errorf("decode stored credential: %w", err)
		}
		return Enrollment{State: "enrolled", Credential: &credential}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, fmt.Errorf("query member enrollment: %w", err)
	}
	var conflictingID string
	err = tx.QueryRowContext(ctx, `select device_id from members where label_key = ?`, labelKey).Scan(&conflictingID)
	if err == nil {
		return Enrollment{}, membershipError(CodeMembershipConflict, "label is already enrolled")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, fmt.Errorf("query member label: %w", err)
	}

	var code, pendingLabel string
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `select code, label, expires_at from pending_enrollments where device_id = ?`, deviceID).Scan(&code, &pendingLabel, &expiresAt)
	if err == nil {
		if !strings.EqualFold(pendingLabel, label) {
			return Enrollment{}, membershipError(CodeMembershipConflict, "device key already has a pending request for another label")
		}
		return Enrollment{State: "pending", Code: code, ExpiresAt: time.Unix(expiresAt, 0).UTC()}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, fmt.Errorf("query pending enrollment: %w", err)
	}
	err = tx.QueryRowContext(ctx, `select device_id from pending_enrollments where label_key = ?`, labelKey).Scan(&conflictingID)
	if err == nil {
		return Enrollment{}, membershipError(CodeMembershipConflict, "label already has a pending request")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, fmt.Errorf("query pending label: %w", err)
	}
	var reserved int
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from enrollment_invites where label_key = ?)`, labelKey).Scan(&reserved); err != nil {
		return Enrollment{}, fmt.Errorf("query invite label reservation: %w", err)
	}
	if reserved != 0 {
		return Enrollment{}, membershipError(CodeMembershipConflict, "label is reserved by an active invite")
	}
	var pendingCount int
	if err := tx.QueryRowContext(ctx, `select count(*) from pending_enrollments`).Scan(&pendingCount); err != nil {
		return Enrollment{}, fmt.Errorf("count pending enrollments: %w", err)
	}
	if pendingCount >= s.maxPending {
		return Enrollment{}, membershipError(CodeMembershipCapacity, "pending enrollment capacity reached")
	}
	code, err = generateCode()
	if err != nil {
		return Enrollment{}, err
	}
	expires := now.Add(PendingLifetime).Unix()
	if err := ensureFactAdmissionCapacity(ctx, tx); err != nil {
		return Enrollment{}, err
	}
	enrollmentID, err := newEnrollmentID()
	if err != nil {
		return Enrollment{}, err
	}
	_, err = tx.ExecContext(ctx, `insert into pending_enrollments (code, device_id, device_key, label, label_key, source_ip, created_at, expires_at, enrollment_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code, deviceID, identity.ID(deviceKey), label, labelKey, sourceIP, now.Unix(), expires, enrollmentID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("create pending enrollment: %w", err)
	}
	if err := insertAudit(ctx, tx, now, "device", deviceID, "enrollment.requested", deviceID, label, 0); err != nil {
		return Enrollment{}, err
	}
	if err := insertFact(ctx, tx, FactPendingAdmitted, enrollmentID, deviceID, label, now, expires, 0); err != nil {
		return Enrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit pending enrollment: %w", err)
	}
	s.notifyFacts()
	return Enrollment{State: "pending", Code: code, ExpiresAt: time.Unix(expires, 0).UTC()}, nil
}

func (s *Store) EnrollmentStatus(ctx context.Context, deviceKey ed25519.PublicKey, label string, now time.Time) (Enrollment, error) {
	if len(deviceKey) != ed25519.PublicKeySize {
		return Enrollment{}, membershipError(CodeMembershipInvalid, "invalid enrollment device key")
	}
	if err := ValidateLabel(label); err != nil {
		return Enrollment{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	db, err := s.db()
	if err != nil {
		return Enrollment{}, err
	}
	deviceID := identity.ID(deviceKey)
	if err := s.SettleExpired(ctx, now); err != nil {
		return Enrollment{}, err
	}
	var memberLabel, credentialJSON string
	var revokedAt sql.NullInt64
	err = db.QueryRowContext(ctx, `select label, credential, revoked_at from members where device_id = ?`, deviceID).Scan(&memberLabel, &credentialJSON, &revokedAt)
	if err == nil {
		if !strings.EqualFold(memberLabel, label) {
			return Enrollment{}, membershipError(CodeMembershipConflict, "device key is already bound to another label")
		}
		if revokedAt.Valid {
			return Enrollment{State: "revoked"}, nil
		}
		var credential Credential
		if err := json.Unmarshal([]byte(credentialJSON), &credential); err != nil {
			return Enrollment{}, fmt.Errorf("decode stored credential: %w", err)
		}
		return Enrollment{State: "enrolled", Credential: &credential}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, fmt.Errorf("query member enrollment status: %w", err)
	}
	var code, pendingLabel string
	var expiresAt int64
	err = db.QueryRowContext(ctx, `select code, label, expires_at from pending_enrollments where device_id = ?`, deviceID).Scan(&code, &pendingLabel, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expiresAt <= now.Unix()) {
		return Enrollment{State: "expired"}, nil
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("query pending enrollment status: %w", err)
	}
	if !strings.EqualFold(pendingLabel, label) {
		return Enrollment{}, membershipError(CodeMembershipConflict, "device key already has a pending request for another label")
	}
	return Enrollment{State: "pending", Code: code, ExpiresAt: time.Unix(expiresAt, 0).UTC()}, nil
}

func (s *Store) ListPending(ctx context.Context, now time.Time) ([]Pending, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	if err := s.SettleExpired(ctx, now); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `select code, device_id, label, created_at, expires_at from pending_enrollments order by created_at, code`)
	if err != nil {
		return nil, fmt.Errorf("list pending enrollments: %w", err)
	}
	defer rows.Close()
	var result []Pending
	for rows.Next() {
		var pending Pending
		var createdAt, expiresAt int64
		if err := rows.Scan(&pending.Code, &pending.DeviceID, &pending.Label, &createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan pending enrollment: %w", err)
		}
		pending.CreatedAt = time.Unix(createdAt, 0).UTC()
		pending.ExpiresAt = time.Unix(expiresAt, 0).UTC()
		result = append(result, pending)
	}
	return result, rows.Err()
}

// PendingCount reports unexpired requests without deleting expired rows.
func (s *Store) PendingCount(ctx context.Context, now time.Time) (uint64, error) {
	db, err := s.db()
	if err != nil {
		return 0, err
	}
	var count uint64
	err = db.QueryRowContext(ctx, `select count(*) from (select 1 from pending_enrollments where expires_at > ? limit ?)`, now.Unix(), s.maxPending+1).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending enrollments: %w", err)
	}
	return count, nil
}

func (s *Store) Approve(ctx context.Context, code, actorType, actorDeviceID string, now time.Time) (Member, error) {
	code, err := NormalizeApprovalCode(code)
	if err != nil {
		return Member{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	db, err := s.db()
	if err != nil {
		return Member{}, err
	}
	if err := s.SettleExpired(ctx, now); err != nil {
		return Member{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Member{}, fmt.Errorf("begin approval: %w", err)
	}
	defer tx.Rollback()
	if actorType == "member" {
		var active int
		if err := tx.QueryRowContext(ctx, `select count(*) from members where device_id = ? and revoked_at is null`, actorDeviceID).Scan(&active); err != nil {
			return Member{}, fmt.Errorf("verify approving member: %w", err)
		}
		if active != 1 {
			return Member{}, membershipError(CodeMembershipRevoked, "approving member is not active")
		}
	} else if actorType != "local" {
		return Member{}, membershipError(CodeMembershipInvalid, "invalid approval actor type")
	}
	var enrollmentID, deviceID, deviceKeyValue, label, labelKey string
	err = tx.QueryRowContext(ctx, `select enrollment_id, device_id, device_key, label, label_key from pending_enrollments where code = ?`, code).Scan(&enrollmentID, &deviceID, &deviceKeyValue, &label, &labelKey)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, membershipError(CodeMembershipNotFound, "pending enrollment not found or expired")
	}
	if err != nil {
		return Member{}, fmt.Errorf("query pending approval: %w", err)
	}
	var memberCount int
	if err := tx.QueryRowContext(ctx, `select count(*) from members where revoked_at is null`).Scan(&memberCount); err != nil {
		return Member{}, fmt.Errorf("count active members: %w", err)
	}
	if memberCount >= MaxMembers {
		return Member{}, membershipError(CodeMembershipCapacity, "member capacity reached")
	}
	deviceKey, err := identity.ParseID(deviceKeyValue)
	if err != nil {
		return Member{}, fmt.Errorf("decode pending device key: %w", err)
	}
	credential, err := s.authority.Issue(deviceKey, label, 1, now)
	if err != nil {
		return Member{}, err
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return Member{}, fmt.Errorf("encode membership credential: %w", err)
	}
	_, err = tx.ExecContext(ctx, `insert into members (device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) values (?, ?, ?, ?, 1, ?, ?, ?)`,
		deviceID, deviceKeyValue, label, labelKey, string(credentialJSON), now.Unix(), enrollmentID)
	if err != nil {
		return Member{}, fmt.Errorf("create member: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `delete from pending_enrollments where code = ?`, code); err != nil {
		return Member{}, fmt.Errorf("consume pending enrollment: %w", err)
	}
	if err := insertAudit(ctx, tx, now, actorType, actorDeviceID, "member.approved", deviceID, label, 1); err != nil {
		return Member{}, err
	}
	if err := insertFact(ctx, tx, FactMemberApproved, enrollmentID, deviceID, label, now, 0, 1); err != nil {
		return Member{}, err
	}
	if err := rejectAdmittedApprovalCommands(ctx, tx, enrollmentID, RejectionSettledElsewhere, now, "", ""); err != nil {
		return Member{}, err
	}
	if err := tx.Commit(); err != nil {
		return Member{}, fmt.Errorf("commit approval: %w", err)
	}
	s.notifyFacts()
	return Member{EnrollmentID: enrollmentID, DeviceID: deviceID, Label: label, Revision: 1, CreatedAt: now.UTC()}, nil
}

func (s *Store) Authenticate(ctx context.Context, credential Credential) (Member, error) {
	claims, err := VerifyCredential(credential, s.authority.PublicKey(), s.authority.ServerID())
	if err != nil {
		return Member{}, membershipError(CodeMembershipInvalid, "invalid membership credential")
	}
	var member Member
	var createdAt int64
	var revokedAt sql.NullInt64
	db, err := s.db()
	if err != nil {
		return Member{}, err
	}
	err = db.QueryRowContext(ctx, `select device_id, label, revision, created_at, revoked_at from members where device_id = ?`, claims.DeviceKey).
		Scan(&member.DeviceID, &member.Label, &member.Revision, &createdAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, membershipError(CodeMembershipNotFound, "membership not found")
	}
	if err != nil {
		return Member{}, fmt.Errorf("query membership: %w", err)
	}
	if revokedAt.Valid {
		return Member{}, membershipError(CodeMembershipRevoked, "membership is revoked")
	}
	if member.Label != claims.Label || member.Revision != claims.Revision {
		return Member{}, membershipError(CodeMembershipConflict, "membership credential is stale or mismatched")
	}
	member.CreatedAt = time.Unix(createdAt, 0).UTC()
	return member, nil
}

func (s *Store) ListMembers(ctx context.Context, limit int, cursor string, activeOnly bool) (MemberPage, error) {
	if limit <= 0 {
		limit = DefaultMemberListLimit
	}
	if limit > MaxMemberListLimit {
		return MemberPage{}, membershipError(CodeMembershipInvalid, fmt.Sprintf("member list limit must not exceed %d", MaxMemberListLimit))
	}
	cursorCreatedAt, cursorDeviceID, err := decodeMemberCursor(cursor)
	if err != nil {
		return MemberPage{}, err
	}
	db, err := s.db()
	if err != nil {
		return MemberPage{}, err
	}
	active := 0
	if activeOnly {
		active = 1
	}
	rows, err := db.QueryContext(ctx, `select device_id, label, revision, created_at, revoked_at from members where (? = 0 or revoked_at is null) and (? = '' or created_at < ? or (created_at = ? and device_id < ?)) order by created_at desc, device_id desc limit ?`,
		active, cursor, cursorCreatedAt, cursorCreatedAt, cursorDeviceID, limit+1)
	if err != nil {
		return MemberPage{}, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	result := make([]Member, 0, limit+1)
	for rows.Next() {
		var member Member
		var createdAt int64
		var revokedAt sql.NullInt64
		if err := rows.Scan(&member.DeviceID, &member.Label, &member.Revision, &createdAt, &revokedAt); err != nil {
			return MemberPage{}, fmt.Errorf("scan member: %w", err)
		}
		member.CreatedAt = time.Unix(createdAt, 0).UTC()
		if revokedAt.Valid {
			value := time.Unix(revokedAt.Int64, 0).UTC()
			member.RevokedAt = &value
		}
		result = append(result, member)
	}
	if err := rows.Err(); err != nil {
		return MemberPage{}, err
	}
	page := MemberPage{Members: result}
	if len(result) > limit {
		page.Members = result[:limit]
		last := page.Members[len(page.Members)-1]
		page.NextCursor = encodeMemberCursor(last.CreatedAt.Unix(), last.DeviceID)
	}
	return page, nil
}

func encodeMemberCursor(createdAt int64, deviceID string) string {
	value := strconv.FormatInt(createdAt, 10) + "\n" + deviceID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeMemberCursor(cursor string) (int64, string, error) {
	if cursor == "" {
		return 0, "", nil
	}
	if len(cursor) > 128 {
		return 0, "", membershipError(CodeMembershipInvalid, "invalid member list cursor")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != cursor {
		return 0, "", membershipError(CodeMembershipInvalid, "invalid member list cursor")
	}
	createdValue, deviceID, ok := strings.Cut(string(decoded), "\n")
	if !ok {
		return 0, "", membershipError(CodeMembershipInvalid, "invalid member list cursor")
	}
	createdAt, err := strconv.ParseInt(createdValue, 10, 64)
	if err != nil || createdAt < 0 {
		return 0, "", membershipError(CodeMembershipInvalid, "invalid member list cursor")
	}
	if _, err := identity.ParseID(deviceID); err != nil {
		return 0, "", membershipError(CodeMembershipInvalid, "invalid member list cursor")
	}
	return createdAt, deviceID, nil
}

func (s *Store) ListActiveMembers(ctx context.Context) ([]Member, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `select device_id, label, revision, created_at from members where revoked_at is null order by label_key, device_id limit ?`, MaxMembers+1)
	if err != nil {
		return nil, fmt.Errorf("list active members: %w", err)
	}
	defer rows.Close()
	result := make([]Member, 0)
	for rows.Next() {
		var member Member
		var createdAt int64
		if err := rows.Scan(&member.DeviceID, &member.Label, &member.Revision, &createdAt); err != nil {
			return nil, fmt.Errorf("scan active member: %w", err)
		}
		member.CreatedAt = time.Unix(createdAt, 0).UTC()
		result = append(result, member)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) > MaxMembers {
		return nil, errors.New("active member capacity exceeded")
	}
	return result, nil
}

func (s *Store) ActiveMember(ctx context.Context, deviceID string) (Member, error) {
	if _, err := identity.ParseID(deviceID); err != nil {
		return Member{}, membershipError(CodeMembershipInvalid, "device ID must be one complete enrolled device ID")
	}
	db, err := s.db()
	if err != nil {
		return Member{}, err
	}
	var member Member
	var createdAt int64
	var revokedAt sql.NullInt64
	err = db.QueryRowContext(ctx, `select device_id, label, revision, created_at, revoked_at from members where device_id = ?`, deviceID).
		Scan(&member.DeviceID, &member.Label, &member.Revision, &createdAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, membershipError(CodeMembershipNotFound, "active member not found for exact device ID")
	}
	if err != nil {
		return Member{}, fmt.Errorf("query active member: %w", err)
	}
	if revokedAt.Valid {
		return Member{}, membershipError(CodeMembershipRevoked, "member is already revoked")
	}
	member.CreatedAt = time.Unix(createdAt, 0).UTC()
	return member, nil
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	if limit > MaxAuditLimit {
		return nil, membershipError(CodeMembershipInvalid, fmt.Sprintf("audit limit must not exceed %d", MaxAuditLimit))
	}
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `select id, occurred_at, actor_type, coalesce(actor_device_id, ''), coalesce(actor_id, ''), action, coalesce(target_device_id, ''), coalesce(target_label, ''), target_revision, coalesce(target_invite_id, '') from audit_events order by occurred_at desc, id desc limit ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	result := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var occurredAt int64
		var revision sql.NullInt64
		if err := rows.Scan(&event.ID, &occurredAt, &event.ActorType, &event.ActorDeviceID, &event.ActorID, &event.Action, &event.TargetDeviceID, &event.TargetLabel, &revision, &event.TargetInviteID); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		event.OccurredAt = time.Unix(occurredAt, 0).UTC()
		if revision.Valid {
			value := revision.Int64
			event.TargetRevision = &value
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, deviceID string, expectedRevision int64, actorType, actorDeviceID string, now time.Time) (Member, error) {
	if actorType == "adapter" {
		return Member{}, membershipError(CodeMembershipInvalid, "adapter actors cannot revoke members")
	}
	if _, err := identity.ParseID(deviceID); err != nil {
		return Member{}, membershipError(CodeMembershipInvalid, "device ID must be one complete enrolled device ID")
	}
	if expectedRevision <= 0 {
		return Member{}, membershipError(CodeMembershipInvalid, "expected active member revision is required")
	}
	now = time.Unix(now.Unix(), 0).UTC()
	db, err := s.db()
	if err != nil {
		return Member{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Member{}, fmt.Errorf("begin revocation: %w", err)
	}
	defer tx.Rollback()
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return Member{}, err
	}
	var member Member
	var createdAt int64
	var revokedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `select enrollment_id, device_id, label, revision, created_at, revoked_at from members where device_id = ?`, deviceID).
		Scan(&member.EnrollmentID, &member.DeviceID, &member.Label, &member.Revision, &createdAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, membershipError(CodeMembershipNotFound, "member not found")
	}
	if err != nil {
		return Member{}, fmt.Errorf("query revocation member: %w", err)
	}
	if revokedAt.Valid {
		return Member{}, membershipError(CodeMembershipRevoked, "member is already revoked")
	}
	if member.Revision != expectedRevision {
		return Member{}, membershipError(CodeMembershipConflict, fmt.Sprintf("member revision changed from %d to %d; inspect the member and retry", expectedRevision, member.Revision))
	}
	member.Revision++
	result, err := tx.ExecContext(ctx, `update members set revision = ?, revoked_at = ? where device_id = ? and revision = ? and revoked_at is null`, member.Revision, now.Unix(), deviceID, expectedRevision)
	if err != nil {
		return Member{}, fmt.Errorf("revoke member: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return Member{}, fmt.Errorf("check revocation result: %w", err)
	}
	if updated != 1 {
		return Member{}, membershipError(CodeMembershipConflict, "member changed or was already revoked; inspect the member and retry")
	}
	if err := insertAudit(ctx, tx, now, actorType, actorDeviceID, "member.revoked", deviceID, member.Label, member.Revision); err != nil {
		return Member{}, err
	}
	if err := insertFact(ctx, tx, FactMemberRevoked, member.EnrollmentID, deviceID, member.Label, now, 0, member.Revision); err != nil {
		return Member{}, err
	}
	if err := revokeIssuerInvites(ctx, tx, deviceID, actorType, actorDeviceID, now); err != nil {
		return Member{}, err
	}
	if err := tx.Commit(); err != nil {
		return Member{}, fmt.Errorf("commit revocation: %w", err)
	}
	s.notifyFacts()
	member.CreatedAt = time.Unix(createdAt, 0).UTC()
	revoked := now.UTC()
	member.RevokedAt = &revoked
	return member, nil
}

func deleteExpired(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	rows, err := tx.QueryContext(ctx, `select enrollment_id, device_id, label from pending_enrollments where expires_at <= ? order by expires_at, enrollment_id`, now.Unix())
	if err != nil {
		return false, fmt.Errorf("query expired enrollments: %w", err)
	}
	type expiredPending struct{ enrollmentID, deviceID, label string }
	var expired []expiredPending
	for rows.Next() {
		var pending expiredPending
		if err := rows.Scan(&pending.enrollmentID, &pending.deviceID, &pending.label); err != nil {
			rows.Close()
			return false, err
		}
		expired = append(expired, pending)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, pending := range expired {
		if err := insertFact(ctx, tx, FactPendingExpired, pending.enrollmentID, pending.deviceID, pending.label, now, 0, 0); err != nil {
			return false, err
		}
		if err := rejectAdmittedApprovalCommands(ctx, tx, pending.enrollmentID, RejectionEnrollmentExpired, now, "", ""); err != nil {
			return false, err
		}
		result, err := tx.ExecContext(ctx, `delete from pending_enrollments where enrollment_id = ? and expires_at <= ?`, pending.enrollmentID, now.Unix())
		if err != nil {
			return false, fmt.Errorf("delete expired enrollment: %w", err)
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return false, errors.New("expired enrollment changed during settlement")
		}
	}
	return len(expired) != 0, nil
}

func (s *Store) SettleExpired(ctx context.Context, now time.Time) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := deleteExpired(ctx, tx, now)
	if err != nil {
		return err
	}
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit expired enrollments: %w", err)
	}
	if changed {
		s.notifyFacts()
	}
	return nil
}

func (s *Store) db() (*sql.DB, error) {
	if s.database == nil {
		return nil, errors.New("membership database provider is required")
	}
	db := s.database()
	if db == nil {
		return nil, errors.New("membership database is not ready")
	}
	return db, nil
}

func membershipError(code ErrorCode, message string) error {
	return &StoreError{Code: code, Message: message}
}

func insertAudit(ctx context.Context, tx *sql.Tx, now time.Time, actorType, actorDeviceID, action, targetDeviceID, targetLabel string, targetRevision int64) error {
	if actorType != "local" && actorType != "member" && actorType != "device" {
		return errors.New("invalid audit actor type")
	}
	return insertAuditActor(ctx, tx, now, actorType, actorDeviceID, "", action, targetDeviceID, targetLabel, targetRevision)
}

func insertAuditActor(ctx context.Context, tx *sql.Tx, now time.Time, actorType, actorDeviceID, actorID, action, targetDeviceID, targetLabel string, targetRevision int64) error {
	if actorType == "adapter" {
		if actorDeviceID != "" || !adapterIDPattern.MatchString(actorID) {
			return errors.New("invalid adapter audit actor")
		}
	} else if actorID != "" {
		return errors.New("non-adapter audit actor has adapter ID")
	}
	if _, err := tx.ExecContext(ctx, `insert into audit_events (occurred_at, actor_type, actor_device_id, actor_id, action, target_device_id, target_label, target_revision) values (?, ?, nullif(?, ''), nullif(?, ''), ?, ?, ?, nullif(?, 0))`,
		now.Unix(), actorType, actorDeviceID, actorID, action, targetDeviceID, targetLabel, targetRevision); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func generateCode() (string, error) {
	data := make([]byte, 5)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate enrollment code: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	return encoded[:4] + "-" + encoded[4:], nil
}
