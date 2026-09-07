package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/identity"
)

const (
	DefaultInviteLifetime           = 8 * time.Hour
	MinInviteLifetime               = time.Minute
	MaxInviteLifetime               = 7 * 24 * time.Hour
	MaxActiveInvites                = 64
	MaxMemberActiveInvites          = 16
	MaxMemberInviteCreatesPerMinute = 5
	InviteTokenLength               = 104
)

const (
	inviteServerDomain   = "px-enrollment-invite-server-v1\x00"
	inviteVerifierDomain = "px-enrollment-invite-verifier-v1\x00"
)

type InviteToken struct {
	ServerTag [16]byte
	InviteID  [16]byte
	Secret    [32]byte
}

type Invite struct {
	InviteID       string    `json:"invite_id"`
	Label          string    `json:"label"`
	IssuerType     string    `json:"issuer_type"`
	IssuerDeviceID string    `json:"issuer_device_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type InviteCreation struct {
	Invite
	Token string `json:"token"`
}

type InviteRedemption struct {
	Member     Member     `json:"member"`
	Credential Credential `json:"credential"`
}

func ParseInviteToken(value string) (InviteToken, error) {
	if len(value) != InviteTokenLength || value[:5] != "PXI1." || value[27] != '.' || value[60] != '.' {
		return InviteToken{}, errors.New("invalid enrollment invite token")
	}
	tagText, idText, secretText := value[5:27], value[28:60], value[61:]
	if strings.ToLower(idText) != idText {
		return InviteToken{}, errors.New("invalid enrollment invite token")
	}
	tag, err := base64.RawURLEncoding.DecodeString(tagText)
	if err != nil || len(tag) != 16 || base64.RawURLEncoding.EncodeToString(tag) != tagText {
		return InviteToken{}, errors.New("invalid enrollment invite token")
	}
	id, err := hex.DecodeString(idText)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != idText {
		return InviteToken{}, errors.New("invalid enrollment invite token")
	}
	secret, err := base64.RawURLEncoding.DecodeString(secretText)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != secretText {
		return InviteToken{}, errors.New("invalid enrollment invite token")
	}
	var token InviteToken
	copy(token.ServerTag[:], tag)
	copy(token.InviteID[:], id)
	copy(token.Secret[:], secret)
	return token, nil
}

func formatInviteToken(token InviteToken) string {
	return "PXI1." + base64.RawURLEncoding.EncodeToString(token.ServerTag[:]) + "." + hex.EncodeToString(token.InviteID[:]) + "." + base64.RawURLEncoding.EncodeToString(token.Secret[:])
}

func InviteServerTag(serverID string) [16]byte {
	digest := sha256.Sum256(append([]byte(inviteServerDomain), []byte(serverID)...))
	var tag [16]byte
	copy(tag[:], digest[:16])
	return tag
}

func InviteVerifier(serverID, label, labelKey string, inviteID [16]byte, secret [32]byte) [32]byte {
	transcript := make([]byte, 0, len(inviteVerifierDomain)+len(serverID)+len(label)+len(labelKey)+96)
	transcript = append(transcript, inviteVerifierDomain...)
	transcript = appendInviteField(transcript, []byte(serverID))
	transcript = appendInviteField(transcript, []byte(label))
	transcript = appendInviteField(transcript, []byte(labelKey))
	transcript = appendInviteField(transcript, inviteID[:])
	transcript = appendInviteField(transcript, secret[:])
	return sha256.Sum256(transcript)
}

func appendInviteField(dst, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func (s *Store) CreateInvite(ctx context.Context, label string, lifetime time.Duration, issuerType, issuerDeviceID string, now time.Time) (InviteCreation, error) {
	if err := ValidateLabel(label); err != nil {
		return InviteCreation{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	if lifetime == 0 {
		lifetime = DefaultInviteLifetime
	}
	if lifetime < MinInviteLifetime || lifetime > MaxInviteLifetime || lifetime%time.Second != 0 {
		return InviteCreation{}, membershipError(CodeMembershipInvalid, "invite lifetime must be whole seconds from 1 minute through 7 days")
	}
	if err := validateInviteActor(issuerType, issuerDeviceID); err != nil {
		return InviteCreation{}, err
	}
	token, verifier, err := s.generateInvite(label)
	if err != nil {
		return InviteCreation{}, err
	}
	now = secondTime(now)
	invite := Invite{
		InviteID: hex.EncodeToString(token.InviteID[:]), Label: label,
		IssuerType: issuerType, IssuerDeviceID: issuerDeviceID,
		CreatedAt: now, ExpiresAt: now.Add(lifetime),
	}
	db, err := s.db()
	if err != nil {
		return InviteCreation{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return InviteCreation{}, fmt.Errorf("begin invite creation: %w", err)
	}
	defer tx.Rollback()
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return InviteCreation{}, err
	}
	if err := authorizeInviteActor(ctx, tx, issuerType, issuerDeviceID); err != nil {
		return InviteCreation{}, err
	}
	labelKey := strings.ToLower(label)
	available, err := inviteLabelAvailable(ctx, tx, labelKey)
	if err != nil {
		return InviteCreation{}, err
	}
	if !available {
		return InviteCreation{}, &StoreError{Code: CodeInviteLabelUnavailable, Message: "invite label is unavailable"}
	}
	var globalCount int
	if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_invites`).Scan(&globalCount); err != nil {
		return InviteCreation{}, err
	}
	if globalCount >= MaxActiveInvites {
		return InviteCreation{}, &StoreError{Code: CodeInviteCapacity, Message: "invite capacity reached"}
	}
	if issuerType == "member" {
		var active, recent int
		if err := tx.QueryRowContext(ctx, `select count(*) from enrollment_invites where issuer_device_id = ?`, issuerDeviceID).Scan(&active); err != nil {
			return InviteCreation{}, err
		}
		if err := tx.QueryRowContext(ctx, `select count(*) from audit_events where action = 'invite.created' and actor_type = 'member' and actor_device_id = ? and occurred_at > ?`, issuerDeviceID, now.Add(-time.Minute).Unix()).Scan(&recent); err != nil {
			return InviteCreation{}, err
		}
		if active >= MaxMemberActiveInvites || recent >= MaxMemberInviteCreatesPerMinute {
			return InviteCreation{}, &StoreError{Code: CodeInviteCapacity, Message: "invite capacity reached"}
		}
	}
	if _, err := tx.ExecContext(ctx, `insert into enrollment_invites(invite_id, verifier, label, label_key, issuer_type, issuer_device_id, created_at, expires_at) values (?, ?, ?, ?, ?, nullif(?, ''), ?, ?)`, invite.InviteID, verifier[:], label, labelKey, issuerType, issuerDeviceID, now.Unix(), invite.ExpiresAt.Unix()); err != nil {
		return InviteCreation{}, fmt.Errorf("create invite: %w", err)
	}
	if err := insertInviteAudit(ctx, tx, now, issuerType, issuerDeviceID, "invite.created", invite.InviteID, label, "", 0); err != nil {
		return InviteCreation{}, err
	}
	if err := tx.Commit(); err != nil {
		return InviteCreation{}, fmt.Errorf("commit invite creation: %w", err)
	}
	return InviteCreation{Invite: invite, Token: formatInviteToken(token)}, nil
}

func (s *Store) ListInvites(ctx context.Context, actorType, actorDeviceID string, now time.Time) ([]Invite, error) {
	if err := validateInviteActor(actorType, actorDeviceID); err != nil {
		return nil, err
	}
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now = secondTime(now)
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return nil, err
	}
	if err := authorizeInviteActor(ctx, tx, actorType, actorDeviceID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `select invite_id, label, issuer_type, coalesce(issuer_device_id, ''), created_at, expires_at from enrollment_invites order by created_at desc, invite_id desc limit ?`, MaxActiveInvites+1)
	if err != nil {
		return nil, err
	}
	invites := make([]Invite, 0)
	for rows.Next() {
		invite, err := scanInvite(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		invites = append(invites, invite)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(invites) > MaxActiveInvites {
		return nil, errors.New("active invite capacity exceeded")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return invites, nil
}

func (s *Store) RevokeInvite(ctx context.Context, inviteID, actorType, actorDeviceID string, now time.Time) (Invite, error) {
	if err := ValidateInviteID(inviteID); err != nil {
		return Invite{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	if err := validateInviteActor(actorType, actorDeviceID); err != nil {
		return Invite{}, err
	}
	db, err := s.db()
	if err != nil {
		return Invite{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer tx.Rollback()
	now = secondTime(now)
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return Invite{}, err
	}
	if err := authorizeInviteActor(ctx, tx, actorType, actorDeviceID); err != nil {
		return Invite{}, err
	}
	invite, err := queryInvite(ctx, tx, inviteID)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, inviteUnavailable()
	}
	if err != nil {
		return Invite{}, err
	}
	if _, err := tx.ExecContext(ctx, `delete from enrollment_invites where invite_id = ?`, inviteID); err != nil {
		return Invite{}, err
	}
	if err := insertInviteAudit(ctx, tx, now, actorType, actorDeviceID, "invite.revoked", inviteID, invite.Label, "", 0); err != nil {
		return Invite{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invite{}, err
	}
	return invite, nil
}

func (s *Store) RedeemInvite(ctx context.Context, tokenText string, deviceKey ed25519.PublicKey, label string, now time.Time) (InviteRedemption, error) {
	token, err := ParseInviteToken(tokenText)
	if err != nil {
		return InviteRedemption{}, membershipError(CodeMembershipInvalid, "invalid enrollment invite token")
	}
	if len(deviceKey) != ed25519.PublicKeySize {
		return InviteRedemption{}, membershipError(CodeMembershipInvalid, "invalid enrollment device key")
	}
	if err := ValidateLabel(label); err != nil {
		return InviteRedemption{}, membershipError(CodeMembershipInvalid, err.Error())
	}
	now = secondTime(now)
	db, err := s.db()
	if err != nil {
		return InviteRedemption{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return InviteRedemption{}, err
	}
	defer tx.Rollback()
	if _, err := deleteExpiredInvites(ctx, tx, now); err != nil {
		return InviteRedemption{}, err
	}
	inviteID := hex.EncodeToString(token.InviteID[:])
	var storedLabel, labelKey string
	var verifier []byte
	err = tx.QueryRowContext(ctx, `select label, label_key, verifier from enrollment_invites where invite_id = ?`, inviteID).Scan(&storedLabel, &labelKey, &verifier)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return InviteRedemption{}, err
		}
		return InviteRedemption{}, inviteUnavailable()
	}
	if err != nil {
		return InviteRedemption{}, err
	}
	wantTag := InviteServerTag(s.authority.ServerID())
	wantVerifier := InviteVerifier(s.authority.ServerID(), storedLabel, labelKey, token.InviteID, token.Secret)
	var providedLabel, invitedLabel [63]byte
	copy(providedLabel[:], label)
	copy(invitedLabel[:], storedLabel)
	labelContentMatch := subtle.ConstantTimeCompare(providedLabel[:], invitedLabel[:])
	labelLengthMatch := subtle.ConstantTimeEq(int32(len(label)), int32(len(storedLabel)))
	labelMatch := labelContentMatch & labelLengthMatch
	serverTagMatch := subtle.ConstantTimeCompare(token.ServerTag[:], wantTag[:])
	verifierMatch := subtle.ConstantTimeCompare(verifier, wantVerifier[:])
	if labelMatch&serverTagMatch&verifierMatch != 1 {
		if err := tx.Commit(); err != nil {
			return InviteRedemption{}, err
		}
		return InviteRedemption{}, inviteUnavailable()
	}
	deviceID := identity.ID(deviceKey)
	var conflict int
	if err := tx.QueryRowContext(ctx, `select exists(select 1 from members where device_id = ? or label_key = ?) or exists(select 1 from pending_enrollments where device_id = ? or label_key = ?)`, deviceID, labelKey, deviceID, labelKey).Scan(&conflict); err != nil {
		return InviteRedemption{}, err
	}
	if conflict != 0 {
		if err := tx.Commit(); err != nil {
			return InviteRedemption{}, err
		}
		return InviteRedemption{}, inviteUnavailable()
	}
	var memberCount int
	if err := tx.QueryRowContext(ctx, `select count(*) from members where revoked_at is null`).Scan(&memberCount); err != nil {
		return InviteRedemption{}, err
	}
	if memberCount >= MaxMembers {
		if err := tx.Commit(); err != nil {
			return InviteRedemption{}, err
		}
		return InviteRedemption{}, &StoreError{Code: CodeEnrollmentUnavailable, Message: "enrollment is unavailable"}
	}
	if err := ensureFactMemberCapacity(ctx, tx); err != nil {
		if HasCode(err, CodeFactCapacity) {
			if commitErr := tx.Commit(); commitErr != nil {
				return InviteRedemption{}, commitErr
			}
			return InviteRedemption{}, &StoreError{Code: CodeEnrollmentUnavailable, Message: "enrollment is unavailable"}
		}
		return InviteRedemption{}, err
	}
	credential, err := s.authority.Issue(deviceKey, label, 1, now)
	if err != nil {
		return InviteRedemption{}, err
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return InviteRedemption{}, err
	}
	enrollmentID, err := s.newEnrollmentID()
	if err != nil {
		return InviteRedemption{}, err
	}
	if _, err := tx.ExecContext(ctx, `insert into members(device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) values (?, ?, ?, ?, 1, ?, ?, ?)`, deviceID, identity.ID(deviceKey), label, labelKey, string(credentialJSON), now.Unix(), enrollmentID); err != nil {
		return InviteRedemption{}, fmt.Errorf("create invited member: %w", err)
	}
	result, err := tx.ExecContext(ctx, `delete from enrollment_invites where invite_id = ?`, inviteID)
	if err != nil {
		return InviteRedemption{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return InviteRedemption{}, inviteUnavailable()
	}
	if err := insertInviteAudit(ctx, tx, now, "device", deviceID, "invite.redeemed", inviteID, label, deviceID, 1); err != nil {
		return InviteRedemption{}, err
	}
	if err := tx.Commit(); err != nil {
		return InviteRedemption{}, err
	}
	member := Member{EnrollmentID: enrollmentID, DeviceID: deviceID, Label: label, Revision: 1, CreatedAt: now}
	return InviteRedemption{Member: member, Credential: credential}, nil
}

func (s *Store) generateInvite(label string) (InviteToken, [32]byte, error) {
	var token InviteToken
	token.ServerTag = InviteServerTag(s.authority.ServerID())
	if _, err := io.ReadFull(s.random, token.InviteID[:]); err != nil {
		return InviteToken{}, [32]byte{}, fmt.Errorf("generate invite ID: %w", err)
	}
	if _, err := io.ReadFull(s.random, token.Secret[:]); err != nil {
		return InviteToken{}, [32]byte{}, fmt.Errorf("generate invite secret: %w", err)
	}
	labelKey := strings.ToLower(label)
	return token, InviteVerifier(s.authority.ServerID(), label, labelKey, token.InviteID, token.Secret), nil
}

func (s *Store) newEnrollmentID() (string, error) {
	data := make([]byte, 16)
	if _, err := io.ReadFull(s.random, data); err != nil {
		return "", fmt.Errorf("generate enrollment ID: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func validateInviteActor(actorType, actorDeviceID string) error {
	if actorType == "local" && actorDeviceID == "" {
		return nil
	}
	if actorType == "member" {
		if _, err := identity.ParseID(actorDeviceID); err == nil {
			return nil
		}
	}
	return membershipError(CodeMembershipInvalid, "invalid invite actor")
}

func authorizeInviteActor(ctx context.Context, tx *sql.Tx, actorType, actorDeviceID string) error {
	if actorType == "local" {
		return nil
	}
	var active int
	if err := tx.QueryRowContext(ctx, `select count(*) from members where device_id = ? and revoked_at is null`, actorDeviceID).Scan(&active); err != nil {
		return err
	}
	if active != 1 {
		return membershipError(CodeMembershipRevoked, "invite actor is not an active member")
	}
	return nil
}

func inviteLabelAvailable(ctx context.Context, tx *sql.Tx, labelKey string) (bool, error) {
	var unavailable int
	err := tx.QueryRowContext(ctx, `select exists(select 1 from members where label_key = ?) or exists(select 1 from pending_enrollments where label_key = ?) or exists(select 1 from enrollment_invites where label_key = ?)`, labelKey, labelKey, labelKey).Scan(&unavailable)
	return unavailable == 0, err
}

// ValidateInviteID requires the canonical public representation used by invite
// administration routes and commands.
func ValidateInviteID(inviteID string) error {
	if len(inviteID) != 32 || strings.ToLower(inviteID) != inviteID {
		return errors.New("invalid invite ID")
	}
	decoded, err := hex.DecodeString(inviteID)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid invite ID")
	}
	return nil
}

func queryInvite(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, inviteID string,
) (Invite, error) {
	return scanInvite(query.QueryRowContext(ctx, `select invite_id, label, issuer_type, coalesce(issuer_device_id, ''), created_at, expires_at from enrollment_invites where invite_id = ?`, inviteID))
}

func scanInvite(scanner interface{ Scan(...any) error }) (Invite, error) {
	var invite Invite
	var createdAt, expiresAt int64
	if err := scanner.Scan(&invite.InviteID, &invite.Label, &invite.IssuerType, &invite.IssuerDeviceID, &createdAt, &expiresAt); err != nil {
		return Invite{}, err
	}
	invite.CreatedAt = time.Unix(createdAt, 0).UTC()
	invite.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return invite, nil
}

func deleteExpiredInvites(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	rows, err := tx.QueryContext(ctx, `select invite_id, label from enrollment_invites where expires_at <= ? order by expires_at, invite_id`, now.Unix())
	if err != nil {
		return false, err
	}
	type expiredInvite struct{ id, label string }
	var expired []expiredInvite
	for rows.Next() {
		var invite expiredInvite
		if err := rows.Scan(&invite.id, &invite.label); err != nil {
			rows.Close()
			return false, err
		}
		expired = append(expired, invite)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, invite := range expired {
		result, err := tx.ExecContext(ctx, `delete from enrollment_invites where invite_id = ? and expires_at <= ?`, invite.id, now.Unix())
		if err != nil {
			return false, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return false, errors.New("expired invite changed during settlement")
		}
		if err := insertInviteAudit(ctx, tx, now, "system", "", "invite.expired", invite.id, invite.label, "", 0); err != nil {
			return false, err
		}
	}
	return len(expired) != 0, nil
}

func revokeIssuerInvites(ctx context.Context, tx *sql.Tx, issuerDeviceID, actorType, actorDeviceID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `select invite_id, label from enrollment_invites where issuer_device_id = ? order by created_at, invite_id`, issuerDeviceID)
	if err != nil {
		return err
	}
	var invites []struct{ id, label string }
	for rows.Next() {
		var invite struct{ id, label string }
		if err := rows.Scan(&invite.id, &invite.label); err != nil {
			rows.Close()
			return err
		}
		invites = append(invites, invite)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, invite := range invites {
		if _, err := tx.ExecContext(ctx, `delete from enrollment_invites where invite_id = ?`, invite.id); err != nil {
			return err
		}
		if err := insertInviteAudit(ctx, tx, now, actorType, actorDeviceID, "invite.revoked", invite.id, invite.label, "", 0); err != nil {
			return err
		}
	}
	return nil
}

func insertInviteAudit(ctx context.Context, tx *sql.Tx, now time.Time, actorType, actorDeviceID, action, inviteID, label, targetDeviceID string, revision int64) error {
	if actorType != "local" && actorType != "member" && actorType != "device" && actorType != "system" {
		return errors.New("invalid invite audit actor")
	}
	if _, err := tx.ExecContext(ctx, `insert into audit_events(occurred_at, actor_type, actor_device_id, action, target_device_id, target_label, target_revision, target_invite_id) values (?, ?, nullif(?, ''), ?, nullif(?, ''), ?, nullif(?, 0), ?)`, now.Unix(), actorType, actorDeviceID, action, targetDeviceID, label, revision, inviteID); err != nil {
		return fmt.Errorf("record invite audit event: %w", err)
	}
	return nil
}

func inviteUnavailable() error {
	return &StoreError{Code: CodeInviteUnavailable, Message: "invite is invalid, unavailable, expired, revoked, used, or does not match this enrollment"}
}
