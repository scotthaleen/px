package membership

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/identity"
)

func TestEnrollmentApprovalAuthenticationAndRevocation(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	pending, err := store.RequestEnrollment(context.Background(), publicKey, "vm-1", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != "pending" || pending.Code == "" {
		t.Fatalf("pending = %+v", pending)
	}
	status, err := store.EnrollmentStatus(context.Background(), publicKey, "vm-1", now)
	if err != nil || status.State != "pending" || status.Code != pending.Code {
		t.Fatalf("pending status = %+v, %v", status, err)
	}
	repeated, err := store.RequestEnrollment(context.Background(), publicKey, "vm-1", "192.0.2.1", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Code != pending.Code {
		t.Fatalf("repeated code = %q, want %q", repeated.Code, pending.Code)
	}
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if member.Label != "vm-1" || member.Revision != 1 {
		t.Fatalf("member = %+v", member)
	}
	if pending, err := store.ListPending(context.Background(), now.Add(2*time.Minute)); err != nil || len(pending) != 0 {
		t.Fatalf("pending after approval = %+v, %v", pending, err)
	}
	enrolled, err := store.RequestEnrollment(context.Background(), publicKey, "vm-1", "192.0.2.1", now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.State != "enrolled" || enrolled.Credential == nil {
		t.Fatalf("enrolled = %+v", enrolled)
	}
	status, err = store.EnrollmentStatus(context.Background(), publicKey, "vm-1", now.Add(3*time.Minute))
	if err != nil || status.State != "enrolled" || status.Credential == nil {
		t.Fatalf("enrolled status = %+v, %v", status, err)
	}
	authenticated, err := store.Authenticate(context.Background(), *enrolled.Credential)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.DeviceID != member.DeviceID {
		t.Fatalf("authenticated = %+v", authenticated)
	}
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(context.Background(), *enrolled.Credential); err == nil {
		t.Fatal("revoked credential authenticated")
	}
	status, err = store.EnrollmentStatus(context.Background(), publicKey, "vm-1", now.Add(4*time.Minute))
	if err != nil || status.State != "revoked" || status.Credential != nil {
		t.Fatalf("revoked status = %+v, %v", status, err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPending, err := store.RequestEnrollment(context.Background(), otherKey, "other", "192.0.2.2", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(context.Background(), otherPending.Code, "member", member.DeviceID, now.Add(5*time.Minute)); err == nil {
		t.Fatal("revoked member approved an enrollment")
	}
	var auditCount int
	if err := db.QueryRow(`select count(*) from audit_events`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 4 {
		t.Fatalf("audit count = %d, want 4", auditCount)
	}
}

func TestPendingCountIsBoundedAndNonMutating(t *testing.T) {
	store, db := newTestStore(t, 2)
	now := time.Unix(1_700_000_000, 0)
	for index := range 2 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.RequestEnrollment(context.Background(), publicKey, fmt.Sprintf("count-%d", index), "192.0.2.1", now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := store.PendingCount(context.Background(), now); err != nil || count != 2 {
		t.Fatalf("pending count = %d, %v", count, err)
	}
	if count, err := store.PendingCount(context.Background(), now.Add(PendingLifetime+time.Minute)); err != nil || count != 0 {
		t.Fatalf("expired pending count = %d, %v", count, err)
	}
	var rows int
	if err := db.QueryRow(`select count(*) from pending_enrollments`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("stored pending rows = %d, %v", rows, err)
	}
}

func TestAuditListIsBoundedNewestFirstAndRedacted(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	pending, err := store.RequestEnrollment(context.Background(), publicKey, "audited", "192.0.2.44", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListAudit(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Action != "member.revoked" || events[1].Action != "member.approved" || events[0].ID <= events[1].ID {
		t.Fatalf("audit events = %+v", events)
	}
	if events[0].OccurredAt.Location() != time.UTC || events[0].TargetRevision == nil || *events[0].TargetRevision != 2 {
		t.Fatalf("revocation audit = %+v", events[0])
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"192.0.2.44", "credential", "device_key", "nonce", "source_ip", "request_body", "signaling"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit output contains %q: %s", forbidden, encoded)
		}
	}
	if _, err := store.ListAudit(context.Background(), MaxAuditLimit+1); err == nil {
		t.Fatal("oversized audit limit succeeded")
	}
}

func TestMemberListIsBoundedNewestFirstWithStableTieBreak(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	deviceIDs := make([]string, 0, 3)
	created := make(map[string]Member)
	for index := range 3 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := store.RequestEnrollment(context.Background(), publicKey, fmt.Sprintf("member-%d", index), "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
		if err != nil {
			t.Fatal(err)
		}
		deviceIDs = append(deviceIDs, member.DeviceID)
		created[member.DeviceID] = member
	}
	slices.Sort(deviceIDs)
	slices.Reverse(deviceIDs)
	page, err := store.ListMembers(context.Background(), 2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	members := page.Members
	if len(members) != 2 || members[0].DeviceID != deviceIDs[0] || members[1].DeviceID != deviceIDs[1] {
		t.Fatalf("members = %+v, want device IDs %v", members, deviceIDs[:2])
	}
	if page.NextCursor == "" {
		t.Fatal("first member page has no continuation cursor")
	}
	if _, err := store.ListMembers(context.Background(), MaxMemberListLimit+1, "", false); err == nil {
		t.Fatal("oversized member list limit succeeded")
	}
	toRevoke := created[deviceIDs[0]]
	if _, err := store.Revoke(context.Background(), toRevoke.DeviceID, toRevoke.Revision, "local", "", now); err != nil {
		t.Fatal(err)
	}
	page, err = store.ListMembers(context.Background(), 3, "", false)
	if err != nil {
		t.Fatal(err)
	}
	members = page.Members
	foundRevoked := false
	for _, member := range members {
		if member.DeviceID == toRevoke.DeviceID && member.RevokedAt != nil {
			foundRevoked = true
		}
	}
	if !foundRevoked {
		t.Fatalf("historical revoked member missing: %+v", members)
	}
}

func TestActiveMemberPaginationSurvivesHistoricalChurn(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	want := make(map[string]bool, 200)
	for index := range 200 {
		deviceID := insertMemberRow(t, db, fmt.Sprintf("active-%03d", index), int64(1_000+index), false)
		want[deviceID] = true
	}

	seen := make(map[string]bool, len(want))
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		page, err := store.ListMembers(context.Background(), 64, cursor, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range page.Members {
			if !want[member.DeviceID] || seen[member.DeviceID] || member.RevokedAt != nil {
				t.Fatalf("unexpected active page member = %+v", member)
			}
			seen[member.DeviceID] = true
		}
		if pageNumber == 0 {
			insertMemberRow(t, db, "new-revoked-history", 10_000, true)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(want) {
		t.Fatalf("active members reached = %d, want %d", len(seen), len(want))
	}
	if _, err := store.ListMembers(context.Background(), 10, "not-a-cursor", false); err == nil {
		t.Fatal("invalid member cursor succeeded")
	}
}

func insertMemberRow(t *testing.T, db *sql.DB, label string, createdAt int64, revoked bool) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := identity.ID(publicKey)
	enrollmentID, err := newEnrollmentID()
	if err != nil {
		t.Fatal(err)
	}
	var revokedAt any
	if revoked {
		revokedAt = createdAt + 1
	}
	if _, err := db.Exec(`insert into members (device_id, device_key, label, label_key, revision, credential, created_at, revoked_at, enrollment_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID, deviceID, label, strings.ToLower(label), 1, `{}`, createdAt, revokedAt, enrollmentID); err != nil {
		t.Fatal(err)
	}
	return deviceID
}

func TestConcurrentAndStaleRevocationWritesOneAuditEvent(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	pending, err := store.RequestEnrollment(context.Background(), publicKey, "race-revoke", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision+1, "local", "", now); err == nil || !strings.Contains(err.Error(), "revision changed") {
		t.Fatalf("stale revocation error = %v", err)
	}

	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful revocations = %d, want 1", successes)
	}
	var audits int
	if err := db.QueryRow(`select count(*) from audit_events where action = ?`, "member.revoked").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("revocation audits = %d, want 1", audits)
	}
}

func TestEnrollmentConflictsCapacityAndExpiry(t *testing.T) {
	store, _ := newTestStore(t, 1)
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	first, err := store.RequestEnrollment(context.Background(), publicA, "first", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), publicB, "second", "192.0.2.2", now); err == nil {
		t.Fatal("pending capacity was not enforced")
	}
	if _, err := store.RequestEnrollment(context.Background(), publicB, "first", "192.0.2.2", now); err == nil {
		t.Fatal("duplicate pending label was accepted")
	}
	if _, err := store.RequestEnrollment(context.Background(), publicA, "other", "192.0.2.1", now); err == nil {
		t.Fatal("pending key relabel was accepted")
	}
	if _, err := store.Approve(context.Background(), first.Code, "local", "", now.Add(PendingLifetime)); err == nil {
		t.Fatal("expired code was approved")
	}
	if _, err := store.RequestEnrollment(context.Background(), publicB, "second", "192.0.2.2", now.Add(PendingLifetime)); err != nil {
		t.Fatalf("expired request did not release capacity: %v", err)
	}
}

func TestApprovalRaceIsSingleUse(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	pending, err := store.RequestEnrollment(context.Background(), publicKey, "race", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Approve(context.Background(), pending.Code, "local", "", now.Add(time.Minute))
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful approvals = %d, want 1", successes)
	}
}

func TestCredentialRejectsTamperAndWrongAuthority(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.authority.Issue(publicKey, "device", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := credential
	tampered.Claims.Label = "attacker"
	if _, err := VerifyCredential(tampered, store.authority.PublicKey(), store.authority.ServerID()); err == nil {
		t.Fatal("tampered credential verified")
	}
	other, _ := newTestStore(t, DefaultMaxPending)
	if _, err := VerifyCredential(credential, other.authority.PublicKey(), other.authority.ServerID()); err == nil {
		t.Fatal("credential verified under another authority")
	}
	encoded, err := json.Marshal(credential)
	if err != nil || len(encoded) > 2048 {
		t.Fatalf("credential encoding length = %d, err = %v", len(encoded), err)
	}
}

func TestNormalizeApprovalCode(t *testing.T) {
	code, err := NormalizeApprovalCode("  abcd-2345 ")
	if err != nil || code != "ABCD-2345" {
		t.Fatalf("normalized code = %q, %v", code, err)
	}
	for _, invalid := range []string{"", "ABCD2345", "ABC1-2345", "ABCD-234"} {
		if _, err := NormalizeApprovalCode(invalid); err == nil {
			t.Fatalf("invalid code %q accepted", invalid)
		}
	}
}

func newTestStore(t *testing.T, maxPending int) (*Store, *sql.DB) {
	t.Helper()
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
	cfg, err := database.Config(database.KindServer, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := databaseStore.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return NewStore(databaseStore.DB(), authority, maxPending), databaseStore.DB()
}
