package membership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/identity"
)

func TestInviteCanonicalTokenAndVerifierVectors(t *testing.T) {
	serverID := "server-id"
	label := "Hal"
	var inviteID [16]byte
	var secret [32]byte
	for index := range inviteID {
		inviteID[index] = byte(index)
	}
	for index := range secret {
		secret[index] = byte(index + 16)
	}
	wantToken := "PXI1.rh6byqCJAHY_6BGAarjaNA.000102030405060708090a0b0c0d0e0f.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
	token := InviteToken{ServerTag: InviteServerTag(serverID), InviteID: inviteID, Secret: secret}
	if got := formatInviteToken(token); got != wantToken || len(got) != InviteTokenLength {
		t.Fatalf("token = %q (%d), want %q (%d)", got, len(got), wantToken, len(wantToken))
	}
	parsed, err := ParseInviteToken(wantToken)
	if err != nil || parsed != token {
		t.Fatalf("parsed token = %+v, %v", parsed, err)
	}
	verifier := InviteVerifier(serverID, label, "hal", inviteID, secret)
	if got := hex.EncodeToString(verifier[:]); got != "4fcfa3dbb02eb012a479732f0b5041785fc2548cc546de40c7e7c33e44b404f8" {
		t.Fatalf("verifier = %s", got)
	}
	if verifier == InviteVerifier(serverID, "hal", "hal", inviteID, secret) {
		t.Fatal("verifier did not bind exact label casing")
	}

	invalid := []string{
		"", " " + wantToken, wantToken + "\n", strings.ToLower(wantToken[:4]) + wantToken[4:],
		wantToken[:28] + strings.ToUpper(wantToken[28:60]) + wantToken[60:],
		wantToken[:27] + "_" + wantToken[28:], wantToken[:60] + "=" + wantToken[61:],
		wantToken[:len(wantToken)-1], wantToken + "A",
	}
	for _, value := range invalid {
		if _, err := ParseInviteToken(value); err == nil {
			t.Fatalf("invalid token accepted: %q", value)
		}
	}
}

func TestValidateInviteID(t *testing.T) {
	if err := ValidateInviteID("000102030405060708090a0b0c0d0e0f"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", strings.Repeat("0", 31), strings.Repeat("0", 33), strings.Repeat("A", 32), strings.Repeat("z", 32)} {
		if err := ValidateInviteID(value); err == nil {
			t.Fatalf("invalid invite ID accepted: %q", value)
		}
	}
}

func TestInviteCreateListRedeemAuditAndRedaction(t *testing.T) {
	base, db := newTestStore(t, DefaultMaxPending)
	randomBytes := make([]byte, 64)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	store := NewStore(db, base.authority, DefaultMaxPending, WithRandomReader(bytes.NewReader(randomBytes)))
	now := time.Unix(1_700_000_000, 987_000_000)
	created, err := store.CreateInvite(context.Background(), "Hal", 0, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Token) != InviteTokenLength || created.Invite.CreatedAt.Nanosecond() != 0 || created.Invite.ExpiresAt.Sub(created.Invite.CreatedAt) != DefaultInviteLifetime {
		t.Fatalf("created invite = %+v token length=%d", created.Invite, len(created.Token))
	}
	parsed, err := ParseInviteToken(created.Token)
	if err != nil || created.Invite.InviteID != hex.EncodeToString(parsed.InviteID[:]) {
		t.Fatalf("created token invalid: parse_error=%v id_matches=%t token_length=%d", err, created.Invite.InviteID == hex.EncodeToString(parsed.InviteID[:]), len(created.Token))
	}
	var storedVerifier []byte
	if err := db.QueryRow(`select verifier from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&storedVerifier); err != nil {
		t.Fatal(err)
	}
	wantVerifier := InviteVerifier(store.authority.ServerID(), "Hal", "hal", parsed.InviteID, parsed.Secret)
	if !bytes.Equal(storedVerifier, wantVerifier[:]) {
		t.Fatal("stored verifier does not match canonical transcript")
	}
	if bytes.Contains(storedVerifier, parsed.Secret[:]) {
		t.Fatal("stored verifier contains plaintext secret")
	}

	pendingKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), pendingKey, "hal", "192.0.2.1", now); !HasCode(err, CodeMembershipConflict) {
		t.Fatalf("reserved pending label error = %v", err)
	}
	listed, err := store.ListInvites(context.Background(), "local", "", now)
	if err != nil || len(listed) != 1 || listed[0] != created.Invite {
		t.Fatalf("listed invites = %+v, %v", listed, err)
	}
	encoded, _ := json.Marshal(listed)
	for _, forbidden := range []string{created.Token, hex.EncodeToString(parsed.Secret[:]), "verifier", "token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("invite metadata contains %q: %s", forbidden, encoded)
		}
	}

	joiningKey, _, _ := ed25519.GenerateKey(rand.Reader)
	var unavailableErrors []string
	for name, unusable := range map[string]string{
		"wrong label":  created.Token,
		"wrong secret": mutateInviteToken(t, created.Token, func(token *InviteToken) { token.Secret[0] ^= 1 }),
		"wrong server": mutateInviteToken(t, created.Token, func(token *InviteToken) { token.ServerTag[0] ^= 1 }),
	} {
		label := "Hal"
		if name == "wrong label" {
			label = "hal"
		}
		if _, err := store.RedeemInvite(context.Background(), unusable, joiningKey, label, now); !HasCode(err, CodeInviteUnavailable) || err.Error() != inviteUnavailable().Error() {
			t.Fatalf("%s error = %v", name, err)
		} else {
			unavailableErrors = append(unavailableErrors, err.Error())
		}
	}
	if _, err := store.RedeemInvite(context.Background(), "invalid", joiningKey, "Hal", now); err == nil {
		t.Fatal("malformed token succeeded")
	} else {
		unavailableErrors = append(unavailableErrors, err.Error())
	}
	redemption, err := store.RedeemInvite(context.Background(), created.Token, joiningKey, "Hal", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if redemption.Member.Label != "Hal" || redemption.Member.Revision != 1 || redemption.Credential.Claims.DeviceKey != redemption.Member.DeviceID {
		t.Fatalf("redemption = %+v", redemption)
	}
	if _, err := store.Authenticate(context.Background(), redemption.Credential); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemInvite(context.Background(), created.Token, joiningKey, "Hal", now); !HasCode(err, CodeInviteUnavailable) {
		t.Fatalf("replay error = %v", err)
	}
	page, err := store.replayFacts(context.Background(), 0, 0, 10)
	if err != nil || len(page.Facts) != 0 {
		t.Fatalf("invite facts = %+v, %v", page.Facts, err)
	}
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("audit = %+v, %v", events, err)
	}
	if events[0].Action != "invite.redeemed" || events[0].ActorType != "device" || events[0].ActorDeviceID != redemption.Member.DeviceID || events[0].TargetInviteID != created.Invite.InviteID || events[0].TargetDeviceID != redemption.Member.DeviceID || events[0].TargetRevision == nil || *events[0].TargetRevision != 1 {
		t.Fatalf("redemption audit = %+v", events[0])
	}
	if events[1].Action != "invite.created" || events[1].ActorType != "local" || events[1].TargetInviteID != created.Invite.InviteID || events[1].TargetDeviceID != "" || events[1].TargetRevision != nil {
		t.Fatalf("creation audit = %+v", events[1])
	}
	auditJSON, _ := json.Marshal(events)
	errorJSON, _ := json.Marshal(unavailableErrors)
	serialized := append(append(encoded, auditJSON...), errorJSON...)
	for _, forbidden := range []string{created.Token, base64.RawURLEncoding.EncodeToString(parsed.Secret[:]), hex.EncodeToString(parsed.Secret[:]), hex.EncodeToString(storedVerifier)} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("serialized list, audit, or errors contain secret material %q: %s", forbidden, serialized)
		}
	}
	assertVerifierConfinement(t, db)
	var retainedVerifier int
	if err := db.QueryRow(`select count(*) from enrollment_invites where verifier = ?`, storedVerifier).Scan(&retainedVerifier); err != nil || retainedVerifier != 0 {
		t.Fatalf("terminal verifier rows = %d, %v", retainedVerifier, err)
	}
	if _, err := store.Revoke(context.Background(), redemption.Member.DeviceID, 1, "local", "", now.Add(2*time.Second)); err != nil {
		t.Fatalf("revoke invite-created member: %v", err)
	}
	page, err = store.replayFacts(context.Background(), 0, 0, 10)
	if err != nil || len(page.Facts) != 1 || page.Facts[0].Kind != FactMemberRevoked {
		t.Fatalf("invite member revocation facts = %+v, %v", page.Facts, err)
	}
}

func TestInviteExpiryIsLazyAuditedWithoutFactNotification(t *testing.T) {
	base, db := newTestStore(t, DefaultMaxPending)
	notifications := make(chan struct{}, 1)
	store := NewStore(db, base.authority, DefaultMaxPending, WithFactNotifications(notifications))
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "expires", time.Minute, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RedeemInvite(context.Background(), created.Token, key, "expires", now.Add(time.Minute)); !HasCode(err, CodeInviteUnavailable) {
		t.Fatalf("expired redemption error = %v", err)
	}
	select {
	case <-notifications:
		t.Fatal("invite expiry emitted fact notification")
	default:
	}
	var invites, expiryAudits, facts int
	db.QueryRow(`select count(*) from enrollment_invites`).Scan(&invites)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.expired' and actor_type = 'system' and actor_device_id is null and actor_id is null`).Scan(&expiryAudits)
	db.QueryRow(`select count(*) from enrollment_facts`).Scan(&facts)
	if invites != 0 || expiryAudits != 1 || facts != 0 {
		t.Fatalf("expiry state invites=%d audits=%d facts=%d", invites, expiryAudits, facts)
	}
}

func TestInviteLifetimeGlobalCapacityAndRevocation(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	for _, lifetime := range []time.Duration{-time.Second, time.Second, time.Minute - time.Second, time.Minute + time.Nanosecond, MaxInviteLifetime + time.Second} {
		if _, err := store.CreateInvite(context.Background(), "invalid-lifetime", lifetime, "local", "", now); !HasCode(err, CodeMembershipInvalid) {
			t.Fatalf("lifetime %s error = %v", lifetime, err)
		}
	}
	for index := range MaxActiveInvites {
		lifetime := MinInviteLifetime
		if index == MaxActiveInvites-1 {
			lifetime = MaxInviteLifetime
		}
		if _, err := store.CreateInvite(context.Background(), fmt.Sprintf("global-%02d", index), lifetime, "local", "", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateInvite(context.Background(), "global-overflow", time.Hour, "local", "", now); !HasCode(err, CodeInviteCapacity) {
		t.Fatalf("global invite capacity error = %v", err)
	}
	listed, err := store.ListInvites(context.Background(), "local", "", now)
	if err != nil || len(listed) != MaxActiveInvites {
		t.Fatalf("global invite list length = %d, %v", len(listed), err)
	}
	for index := 1; index < len(listed); index++ {
		if listed[index-1].CreatedAt.Before(listed[index].CreatedAt) || listed[index-1].CreatedAt.Equal(listed[index].CreatedAt) && listed[index-1].InviteID <= listed[index].InviteID {
			t.Fatalf("invite list is not descending at %d: %+v", index, listed[index-1:index+1])
		}
	}
	revoked, err := store.RevokeInvite(context.Background(), listed[0].InviteID, "local", "", now)
	if err != nil || revoked.InviteID != listed[0].InviteID {
		t.Fatalf("revoked invite = %+v, %v", revoked, err)
	}
	if _, err := store.RevokeInvite(context.Background(), listed[0].InviteID, "local", "", now); !HasCode(err, CodeInviteUnavailable) {
		t.Fatalf("repeated revoke error = %v", err)
	}
	if _, err := store.CreateInvite(context.Background(), "global-replacement", time.Hour, "local", "", now); err != nil {
		t.Fatalf("replacement after revoke: %v", err)
	}
}

func TestInviteMemberAndPendingConflictIsUniformAndNonConsuming(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "conflict-target", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	pendingKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), pendingKey, "other-pending", "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemInvite(context.Background(), created.Token, pendingKey, "conflict-target", now); !HasCode(err, CodeInviteUnavailable) || err.Error() != inviteUnavailable().Error() {
		t.Fatalf("pending key conflict error = %v", err)
	}
	member := createTestMember(t, store, "other-member", now)
	memberKey, err := identity.ParseID(member.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemInvite(context.Background(), created.Token, memberKey, "conflict-target", now); !HasCode(err, CodeInviteUnavailable) || err.Error() != inviteUnavailable().Error() {
		t.Fatalf("member key conflict error = %v", err)
	}
	var active int
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&active)
	if active != 1 {
		t.Fatal("key conflict consumed invite")
	}
}

func TestInviteRedeemRevokeRaceHasOneTerminalMutation(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "race-invite", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	ready, start := raceBarrier(2)
	errs := make(chan error, 2)
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.RedeemInvite(context.Background(), created.Token, key, "race-invite", now)
		errs <- err
	}()
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.RevokeInvite(context.Background(), created.Invite.InviteID, "local", "", now)
		errs <- err
	}()
	releaseRace(ready, start, 2)
	successes := 0
	for range 2 {
		err := <-errs
		if err == nil {
			successes++
		} else if !HasCode(err, CodeInviteUnavailable) {
			t.Fatalf("race error = %v", err)
		}
	}
	var terminals, active int
	db.QueryRow(`select count(*) from audit_events where target_invite_id = ? and action in ('invite.redeemed', 'invite.revoked')`, created.Invite.InviteID).Scan(&terminals)
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&active)
	if successes != 1 || terminals != 1 || active != 0 {
		t.Fatalf("race successes=%d terminals=%d active=%d", successes, terminals, active)
	}
}

func TestInviteConcurrentRedemptionsAreSingleUse(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "double-redeem", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]ed25519.PublicKey, 2)
	for index := range keys {
		keys[index], _, _ = ed25519.GenerateKey(rand.Reader)
	}
	ready, start := raceBarrier(2)
	errs := make(chan error, 2)
	for _, key := range keys {
		go func() {
			ready <- struct{}{}
			<-start
			_, err := store.RedeemInvite(context.Background(), created.Token, key, "double-redeem", now)
			errs <- err
		}()
	}
	releaseRace(ready, start, 2)
	successes, unavailable := 0, 0
	for range 2 {
		err := <-errs
		if err == nil {
			successes++
		} else if HasCode(err, CodeInviteUnavailable) {
			unavailable++
		} else {
			t.Fatalf("redeem race error = %v", err)
		}
	}
	var members, audits, active int
	db.QueryRow(`select count(*) from members where label = 'double-redeem'`).Scan(&members)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.redeemed' and target_invite_id = ?`, created.Invite.InviteID).Scan(&audits)
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&active)
	if successes != 1 || unavailable != 1 || members != 1 || audits != 1 || active != 0 {
		t.Fatalf("redeem race successes=%d unavailable=%d members=%d audits=%d active=%d", successes, unavailable, members, audits, active)
	}
}

func TestInviteCreatePendingLabelRaceReservesExactlyOneAuthority(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	ready, start := raceBarrier(2)
	createResults := make(chan error, 1)
	pendingResults := make(chan error, 1)
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.CreateInvite(context.Background(), "label-race", time.Hour, "local", "", now)
		createResults <- err
	}()
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.RequestEnrollment(context.Background(), key, "label-race", "192.0.2.1", now)
		pendingResults <- err
	}()
	releaseRace(ready, start, 2)
	createErr, pendingErr := <-createResults, <-pendingResults
	if (createErr == nil) == (pendingErr == nil) {
		t.Fatalf("label race create=%v pending=%v", createErr, pendingErr)
	}
	if createErr != nil && !HasCode(createErr, CodeInviteLabelUnavailable) {
		t.Fatalf("create label race error = %v", createErr)
	}
	if pendingErr != nil && !HasCode(pendingErr, CodeMembershipConflict) {
		t.Fatalf("pending label race error = %v", pendingErr)
	}
	var invites, pending int
	db.QueryRow(`select count(*) from enrollment_invites where label_key = 'label-race'`).Scan(&invites)
	db.QueryRow(`select count(*) from pending_enrollments where label_key = 'label-race'`).Scan(&pending)
	if invites+pending != 1 {
		t.Fatalf("label race invites=%d pending=%d", invites, pending)
	}
}

func TestInviteIssuerRevocationRedemptionRaceHasLegalAtomicOutcome(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	issuer := createTestMember(t, store, "race-issuer", now)
	created, err := store.CreateInvite(context.Background(), "race-child", time.Hour, "member", issuer.DeviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	ready, start := raceBarrier(2)
	revokeResults := make(chan error, 1)
	redeemResults := make(chan error, 1)
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.Revoke(context.Background(), issuer.DeviceID, issuer.Revision, "local", "", now)
		revokeResults <- err
	}()
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.RedeemInvite(context.Background(), created.Token, key, "race-child", now)
		redeemResults <- err
	}()
	releaseRace(ready, start, 2)
	if err := <-revokeResults; err != nil {
		t.Fatalf("issuer revocation race error = %v", err)
	}
	redeemErr := <-redeemResults
	if redeemErr != nil && !HasCode(redeemErr, CodeInviteUnavailable) {
		t.Fatalf("issuer redemption race error = %v", redeemErr)
	}
	var issuerActive, invites, children, redeemedAudits, revokedAudits int
	db.QueryRow(`select count(*) from members where device_id = ? and revoked_at is null`, issuer.DeviceID).Scan(&issuerActive)
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&invites)
	db.QueryRow(`select count(*) from members where label = 'race-child' and revoked_at is null`).Scan(&children)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.redeemed' and target_invite_id = ?`, created.Invite.InviteID).Scan(&redeemedAudits)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.revoked' and target_invite_id = ?`, created.Invite.InviteID).Scan(&revokedAudits)
	if issuerActive != 0 || invites != 0 || redeemedAudits+revokedAudits != 1 {
		t.Fatalf("issuer race issuer=%d invites=%d children=%d redeemed=%d revoked=%d", issuerActive, invites, children, redeemedAudits, revokedAudits)
	}
	if redeemErr == nil && (children != 1 || redeemedAudits != 1) {
		t.Fatalf("successful race redemption children=%d redeemed=%d revoked=%d", children, redeemedAudits, revokedAudits)
	}
	if redeemErr != nil && (children != 0 || revokedAudits != 1) {
		t.Fatalf("cascaded race redemption children=%d redeemed=%d revoked=%d", children, redeemedAudits, revokedAudits)
	}
}

func TestInviteRedemptionAuditFailureRollsBackAuthority(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, _ := store.CreateInvite(context.Background(), "rollback-invite", time.Hour, "local", "", now)
	if _, err := db.Exec(`create trigger test_invite_redeem_audit_failure before insert on audit_events when new.action = 'invite.redeemed' begin select raise(abort, 'injected invite audit failure'); end`); err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RedeemInvite(context.Background(), created.Token, key, "rollback-invite", now); err == nil {
		t.Fatal("redemption succeeded through audit failure")
	}
	var invites, members, audits int
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&invites)
	db.QueryRow(`select count(*) from members where label = 'rollback-invite'`).Scan(&members)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.redeemed'`).Scan(&audits)
	if invites != 1 || members != 0 || audits != 0 {
		t.Fatalf("rollback invites=%d members=%d audits=%d", invites, members, audits)
	}
}

func TestInviteCreationAuditFailureReturnsNoTokenOrAuthority(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	if _, err := db.Exec(`create trigger test_invite_create_audit_failure before insert on audit_events when new.action = 'invite.created' begin select raise(abort, 'injected invite create failure'); end`); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateInvite(context.Background(), "create-rollback", time.Hour, "local", "", time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatal("invite creation succeeded through audit failure")
	}
	if created != (InviteCreation{}) {
		t.Fatalf("failed creation returned sensitive output: metadata_present=%t token_length=%d", created.Invite != (Invite{}), len(created.Token))
	}
	var invites, audits int
	db.QueryRow(`select count(*) from enrollment_invites`).Scan(&invites)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.created'`).Scan(&audits)
	if invites != 0 || audits != 0 {
		t.Fatalf("creation rollback invites=%d audits=%d", invites, audits)
	}
}

func TestInviteIssuerLimitsRateAndRevocationCascade(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	issuer := createTestMember(t, store, "issuer", now)
	for index := range MaxMemberInviteCreatesPerMinute {
		created, err := store.CreateInvite(context.Background(), fmt.Sprintf("rate-%d", index), time.Hour, "member", issuer.DeviceID, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RevokeInvite(context.Background(), created.Invite.InviteID, "local", "", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateInvite(context.Background(), "rate-blocked", time.Hour, "member", issuer.DeviceID, now); !HasCode(err, CodeInviteCapacity) {
		t.Fatalf("member invite rate error = %v", err)
	}

	var child InviteRedemption
	for index := range MaxMemberActiveInvites {
		at := now.Add(time.Duration(index+1) * time.Minute)
		created, err := store.CreateInvite(context.Background(), fmt.Sprintf("active-%02d", index), time.Hour, "member", issuer.DeviceID, at)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			key, _, _ := ed25519.GenerateKey(rand.Reader)
			child, err = store.RedeemInvite(context.Background(), created.Token, key, created.Invite.Label, at)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	created, err := store.CreateInvite(context.Background(), "active-last", time.Hour, "member", issuer.DeviceID, now.Add(18*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateInvite(context.Background(), "active-overflow", time.Hour, "member", issuer.DeviceID, now.Add(20*time.Minute)); !HasCode(err, CodeInviteCapacity) {
		t.Fatalf("member active cap error = %v", err)
	}
	if _, err := store.Revoke(context.Background(), issuer.DeviceID, issuer.Revision, "local", "", now.Add(21*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var active, cascades, childActive int
	db.QueryRow(`select count(*) from enrollment_invites where issuer_device_id = ?`, issuer.DeviceID).Scan(&active)
	db.QueryRow(`select count(*) from audit_events where action = 'invite.revoked' and actor_type = 'local' and occurred_at = ?`, now.Add(21*time.Minute).Unix()).Scan(&cascades)
	db.QueryRow(`select count(*) from members where device_id = ? and revoked_at is null`, child.Member.DeviceID).Scan(&childActive)
	if active != 0 || cascades != MaxMemberActiveInvites || childActive != 1 {
		t.Fatalf("cascade active=%d audits=%d child_active=%d last=%s", active, cascades, childActive, created.Invite.InviteID)
	}
}

func TestInviteIssuerCascadeFailureRollsBackMemberAndInvites(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	issuer := createTestMember(t, store, "cascade-rollback", now)
	created, err := store.CreateInvite(context.Background(), "cascade-child", time.Hour, "member", issuer.DeviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create trigger test_cascade_audit_failure before insert on audit_events when new.action = 'invite.revoked' begin select raise(abort, 'injected cascade failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), issuer.DeviceID, issuer.Revision, "local", "", now); err == nil {
		t.Fatal("issuer revocation succeeded through cascade audit failure")
	}
	var memberActive, inviteActive, revokeFacts int
	db.QueryRow(`select count(*) from members where device_id = ? and revoked_at is null and revision = 1`, issuer.DeviceID).Scan(&memberActive)
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&inviteActive)
	db.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind = ?`, issuer.EnrollmentID, FactMemberRevoked).Scan(&revokeFacts)
	if memberActive != 1 || inviteActive != 1 || revokeFacts != 0 {
		t.Fatalf("cascade rollback member=%d invite=%d facts=%d", memberActive, inviteActive, revokeFacts)
	}
}

func TestInviteCapacityFailureLeavesInviteActive(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "capacity-invite", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), key, "protected-prefix", "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`with recursive n(x) as (values(1) union all select x + 1 from n where x < ?) insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at) select ?, printf('%032x', x + 1000), ?, printf('device-%d', x), printf('label-%d', x), ? from n`, MaxFactRows-3, FactPendingAdmitted, now.Unix(), now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	joiningKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RedeemInvite(context.Background(), created.Token, joiningKey, "capacity-invite", now); !HasCode(err, CodeEnrollmentUnavailable) {
		t.Fatalf("fact capacity error = %v", err)
	}
	var active, members int
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&active)
	db.QueryRow(`select count(*) from members where label = 'capacity-invite'`).Scan(&members)
	if active != 1 || members != 0 {
		t.Fatalf("capacity state active=%d members=%d", active, members)
	}
}

func TestInviteMemberCapacityLeavesInviteActive(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "member-capacity", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`with recursive n(x) as (values(1) union all select x + 1 from n where x < ?) insert into members(device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) select printf('capacity-device-%03d', x), printf('capacity-key-%03d', x), printf('capacity-member-%03d', x), printf('capacity-member-%03d', x), 1, '{}', 1, printf('%032x', x + 2000) from n`, MaxMembers)
	if err != nil {
		t.Fatal(err)
	}
	joiningKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RedeemInvite(context.Background(), created.Token, joiningKey, "member-capacity", now); !HasCode(err, CodeEnrollmentUnavailable) {
		t.Fatalf("member capacity error = %v", err)
	}
	var active, members int
	db.QueryRow(`select count(*) from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&active)
	db.QueryRow(`select count(*) from members where label = 'member-capacity'`).Scan(&members)
	if active != 1 || members != 0 {
		t.Fatalf("member capacity state active=%d members=%d", active, members)
	}
}

func TestInviteExpiryRedemptionRaceSettlesOnce(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "expiry-race-invite", time.Minute, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	joiningKey, _, _ := ed25519.GenerateKey(rand.Reader)
	ready, start := raceBarrier(2)
	errs := make(chan error, 2)
	go func() {
		ready <- struct{}{}
		<-start
		_, err := store.RedeemInvite(context.Background(), created.Token, joiningKey, "expiry-race-invite", now.Add(time.Minute))
		errs <- err
	}()
	go func() {
		ready <- struct{}{}
		<-start
		errs <- store.SettleExpired(context.Background(), now.Add(time.Minute))
	}()
	releaseRace(ready, start, 2)
	for range 2 {
		if err := <-errs; err != nil && !HasCode(err, CodeInviteUnavailable) {
			t.Fatalf("expiry race error = %v", err)
		}
	}
	var expiryAudits, members int
	db.QueryRow(`select count(*) from audit_events where action = 'invite.expired' and target_invite_id = ?`, created.Invite.InviteID).Scan(&expiryAudits)
	db.QueryRow(`select count(*) from members where label = 'expiry-race-invite'`).Scan(&members)
	if expiryAudits != 1 || members != 0 {
		t.Fatalf("expiry race audits=%d members=%d", expiryAudits, members)
	}
}

func TestInvitePersistsAcrossRestartWithoutPlaintext(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "authority.key")
	publicPath := filepath.Join(dir, "server.pub")
	if err := Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	cfg, err := database.Config(database.KindServer, path)
	if err != nil {
		t.Fatal(err)
	}
	first := sqlite.New(cfg)
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store := NewStore(first.DB(), authority, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	created, err := store.CreateInvite(context.Background(), "restart-invite", time.Hour, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInviteToken(created.Token)
	if err != nil {
		t.Fatal(err)
	}
	assertVerifierConfinement(t, first.DB())
	assertInvitePlaintextAbsent(t, path, created.Token, parsed.Secret[:])
	if err := first.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := sqlite.New(cfg)
	if err := second.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Stop(context.Background()) })
	restarted := NewStore(second.DB(), authority, DefaultMaxPending)
	listed, err := restarted.ListInvites(context.Background(), "local", "", now)
	if err != nil || len(listed) != 1 || listed[0].InviteID != created.Invite.InviteID {
		t.Fatalf("restart list = %+v, %v", listed, err)
	}
	assertVerifierConfinement(t, second.DB())
	assertInvitePlaintextAbsent(t, path, created.Token, parsed.Secret[:])
	var verifier []byte
	if err := second.DB().QueryRow(`select verifier from enrollment_invites where invite_id = ?`, created.Invite.InviteID).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := restarted.RedeemInvite(context.Background(), created.Token, key, "restart-invite", now); err != nil {
		t.Fatal(err)
	}
	assertInvitePlaintextAbsent(t, path, created.Token, parsed.Secret[:])
	var retained int
	if err := second.DB().QueryRow(`select count(*) from enrollment_invites where verifier = ?`, verifier).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("logically deleted verifier rows = %d, %v", retained, err)
	}
}

func mutateInviteToken(t *testing.T, value string, mutate func(*InviteToken)) string {
	t.Helper()
	token, err := ParseInviteToken(value)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&token)
	return formatInviteToken(token)
}

func createTestMember(t *testing.T, store *Store, label string, now time.Time) Member {
	t.Helper()
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := store.RequestEnrollment(context.Background(), key, label, "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func raceBarrier(count int) (chan struct{}, chan struct{}) {
	return make(chan struct{}, count), make(chan struct{})
}

func releaseRace(ready chan struct{}, start chan struct{}, count int) {
	for range count {
		<-ready
	}
	close(start)
}

func assertInvitePlaintextAbsent(t *testing.T, databasePath, token string, rawSecret []byte) {
	t.Helper()
	encodedSecret := base64.RawURLEncoding.EncodeToString(rawSecret)
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		contents, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for name, forbidden := range map[string][]byte{
			"complete token": []byte(token),
			"encoded secret": []byte(encodedSecret),
			"raw secret":     rawSecret,
		} {
			if bytes.Contains(contents, forbidden) {
				t.Fatalf("%s contains invite %s", filepath.Base(path), name)
			}
		}
	}
}

func assertVerifierConfinement(t *testing.T, db interface {
	Query(string, ...any) (*sql.Rows, error)
},
) {
	t.Helper()
	rows, err := db.Query(`select m.name from sqlite_schema m join pragma_table_info(m.name) p where m.type = 'table' and p.name = 'verifier'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || tables[0] != "enrollment_invites" {
		t.Fatalf("verifier columns = %v", tables)
	}
}
