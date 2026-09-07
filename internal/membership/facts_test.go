package membership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrollmentFactsLifecycleReplayAndSnapshot(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)
	pendingA, err := store.RequestEnrollment(context.Background(), keyA, "fact-a", "192.0.2.10", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), keyB, "fact-b", "192.0.2.11", now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.currentPendingSnapshot(context.Background(), now)
	if err != nil || len(snapshot.Pending) != 2 || snapshot.HighWater != 2 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	encoded, _ := json.Marshal(snapshot)
	for _, secret := range []string{pendingA.Code, "192.0.2.10", "source_ip", "device_key", "credential"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("snapshot leaked %q: %s", secret, encoded)
		}
	}
	member, err := store.Approve(context.Background(), pendingA.Code, "local", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), member.DeviceID, 1, "local", "", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.SettleExpired(context.Background(), now.Add(PendingLifetime)); err != nil {
		t.Fatal(err)
	}
	page, err := store.replayFacts(context.Background(), 0, 0, MaxFactPage)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{FactPendingAdmitted, FactPendingAdmitted, FactMemberApproved, FactMemberRevoked, FactPendingExpired}
	if len(page.Facts) != len(want) {
		t.Fatalf("facts = %+v", page.Facts)
	}
	for index, kind := range want {
		if page.Facts[index].Kind != kind || page.Facts[index].Seq != int64(index+1) {
			t.Fatalf("fact %d = %+v", index, page.Facts[index])
		}
	}
	if _, err := store.replayFacts(context.Background(), 0, page.HighWater+1, 1); !HasCode(err, CodeFactReplayInvalid) {
		t.Fatal("future replay high-water succeeded")
	}
	if _, err := store.replayFacts(context.Background(), 0, 0, MaxFactPage+1); !HasCode(err, CodeFactReplayInvalid) {
		t.Fatal("oversized fact page succeeded")
	}
}

func TestFactFailureRollsBackAuthority(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	if _, err := db.Exec(`create trigger test_fact_failure before insert on enrollment_facts begin select raise(abort, 'injected fact failure'); end`); err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), key, "rollback", "192.0.2.1", time.Now()); err == nil {
		t.Fatal("request succeeded through injected fact failure")
	}
	for _, table := range []string{"pending_enrollments", "audit_events", "enrollment_facts"} {
		var count int
		if err := db.QueryRow(`select count(*) from ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows = %d, %v", table, count, err)
		}
	}
}

func TestLifecycleFactDuplicatesAndInvalidOrderingAreRejected(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, err := store.RequestEnrollment(context.Background(), key, "fact-order", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	var enrollmentID, deviceID, label string
	if err := db.QueryRow(`select enrollment_id, device_id, label from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID, &deviceID, &label); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at) values (?, ?, ?, ?, ?, ?)`, FactPendingAdmitted, enrollmentID, now.Unix(), deviceID, label, now.Add(PendingLifetime).Unix()); err == nil {
		t.Fatal("duplicate pending-admitted fact succeeded")
	}
	if _, err := db.Exec(`insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, member_revision) values (?, ?, ?, ?, ?, 2)`, FactMemberRevoked, enrollmentID, now.Unix(), deviceID, label); err == nil {
		t.Fatal("revocation before approval succeeded")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertFact(context.Background(), tx, FactPendingAdmitted, enrollmentID, deviceID, label, now, now.Add(PendingLifetime).Unix(), 0); err == nil {
		t.Fatal("store duplicate fact insertion succeeded")
	}
	if err := insertFact(context.Background(), tx, FactMemberRevoked, enrollmentID, deviceID, label, now, 0, 2); err == nil {
		t.Fatal("store invalid fact ordering succeeded")
	}
}

func TestApprovalFactFailureRollsBackMemberAuditAndPending(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, err := store.RequestEnrollment(context.Background(), key, "approval-rollback", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create trigger test_approval_fact_failure before insert on enrollment_facts when new.kind = 'enrollment.member_approved' begin select raise(abort, 'injected approval fact failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err == nil {
		t.Fatal("approval succeeded through injected fact failure")
	}
	var pendingRows, members, approvalAudits int
	db.QueryRow(`select count(*) from pending_enrollments where code = ?`, pending.Code).Scan(&pendingRows)
	db.QueryRow(`select count(*) from members`).Scan(&members)
	db.QueryRow(`select count(*) from audit_events where action = 'member.approved'`).Scan(&approvalAudits)
	if pendingRows != 1 || members != 0 || approvalAudits != 0 {
		t.Fatalf("rollback pending=%d members=%d audits=%d", pendingRows, members, approvalAudits)
	}
}

func TestLocalApprovalReceiptSettlementFailureRollsBackTerminalState(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "local-fault", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "local-fault", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandID := uuidV7ForTest(now, 1)
	store.AdmitApprovalCommand(context.Background(), "local-fault", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)
	if _, err := db.Exec(`create trigger test_receipt_settlement_failure before update on enrollment_command_receipts begin select raise(abort, 'injected receipt failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err == nil {
		t.Fatal("local approval succeeded through receipt failure")
	}
	receipt, err := store.queryCommandInternal(context.Background(), "local-fault", commandID)
	if err != nil || receipt.State != ReceiptAdmitted {
		t.Fatalf("receipt after rollback = %+v, %v", receipt, err)
	}
	var pendingRows, members, approvals int
	db.QueryRow(`select count(*) from pending_enrollments where enrollment_id = ?`, enrollmentID).Scan(&pendingRows)
	db.QueryRow(`select count(*) from members where enrollment_id = ?`, enrollmentID).Scan(&members)
	db.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind = ?`, enrollmentID, FactMemberApproved).Scan(&approvals)
	if pendingRows != 1 || members != 0 || approvals != 0 {
		t.Fatalf("terminal rollback pending=%d members=%d approvals=%d", pendingRows, members, approvals)
	}
}

func TestConcurrentExpirySettlesOnce(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), key, "expire-race", "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- store.SettleExpired(context.Background(), now.Add(PendingLifetime))
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow(`select count(*) from enrollment_facts where kind = ?`, FactPendingExpired).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expiry facts = %d, %v", count, err)
	}
}

func TestExpiredApprovalCommitsCleanupBeforeNotFound(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, err := store.RequestEnrollment(context.Background(), key, "expired-approve", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now.Add(PendingLifetime)); err == nil {
		t.Fatal("expired approval succeeded")
	}
	var pendingRows, expiryFacts int
	db.QueryRow(`select count(*) from pending_enrollments where code = ?`, pending.Code).Scan(&pendingRows)
	db.QueryRow(`select count(*) from enrollment_facts where kind = ?`, FactPendingExpired).Scan(&expiryFacts)
	if pendingRows != 0 || expiryFacts != 1 {
		t.Fatalf("expired approval cleanup pending=%d facts=%d", pendingRows, expiryFacts)
	}
}

func TestAdapterAdmissionReplayConflictAndHighWater(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0).UTC()
	credential := provisionAdapter(t, store, "adapter.one", now)
	first := uuidV7ForTest(now, 1)
	receipt, err := store.AdmitApprovalCommand(context.Background(), "adapter.one", credential, ApprovalCommand{CommandID: first, EnrollmentID: strings.Repeat("a", 32)}, now)
	if err != nil || receipt.State != ReceiptAdmitted {
		t.Fatalf("admit = %+v, %v", receipt, err)
	}
	replayed, err := store.AdmitApprovalCommand(context.Background(), "adapter.one", credential, ApprovalCommand{CommandID: first, EnrollmentID: strings.Repeat("a", 32)}, now.Add(40*24*time.Hour))
	if err != nil || replayed.ReceiptSeq != receipt.ReceiptSeq {
		t.Fatalf("exact old replay = %+v, %v", replayed, err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "adapter.one", credential, ApprovalCommand{CommandID: first, EnrollmentID: "malformed changed payload"}, now); !HasCode(err, CodeRequestConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	older := uuidV7ForTest(now.Add(-time.Millisecond), 9)
	if _, err := store.AdmitApprovalCommand(context.Background(), "adapter.one", credential, ApprovalCommand{CommandID: older, EnrollmentID: strings.Repeat("a", 32)}, now); !HasCode(err, CodeReceiptExpired) {
		t.Fatalf("older error = %v", err)
	}
	future := uuidV7ForTest(now.Add(5*time.Minute+time.Millisecond), 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "adapter.one", credential, ApprovalCommand{CommandID: future, EnrollmentID: strings.Repeat("a", 32)}, now); !HasCode(err, CodeCommandTimeInvalid) {
		t.Fatalf("future error = %v", err)
	}
	if _, err := validateUUIDv7(strings.ToUpper(first)); err == nil {
		t.Fatal("noncanonical UUID succeeded")
	}
	wrongVersion := first[:14] + "6" + first[15:]
	wrongVariant := first[:19] + "0" + first[20:]
	for _, invalid := range []string{wrongVersion, wrongVariant, strings.Replace(first, "-", "", 1)} {
		if _, err := validateUUIDv7(invalid); err == nil {
			t.Fatalf("invalid UUIDv7 %q succeeded", invalid)
		}
	}
	if ApprovalCommandFingerprint(ApprovalCommand{CommandID: first, EnrollmentID: "a"}) == ApprovalCommandFingerprint(ApprovalCommand{CommandID: first, EnrollmentID: "aa"}) {
		t.Fatal("length-delimited fingerprints collided")
	}
}

func TestAdapterAuthorityPreservesHighWaterAcrossChanges(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	first := provisionAdapter(t, store, "stable", now)
	commandID := uuidV7ForTest(now, 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "stable", first, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("c", 32)}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetAdapterActive(context.Background(), "stable", false, now); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.RotateAdapterCredential(context.Background(), "stable", now)
	if err != nil {
		t.Fatal(err)
	}
	next := uuidV7ForTest(now.Add(time.Millisecond), 2)
	if _, err := store.AdmitApprovalCommand(context.Background(), "stable", rotated.Credential, ApprovalCommand{CommandID: next, EnrollmentID: strings.Repeat("c", 32)}, now); !HasCode(err, CodeAdapterUnauthorized) {
		t.Fatalf("inactive adapter admission = %v", err)
	}
	authority, err := store.SetAdapterActive(context.Background(), "stable", true, now)
	if err != nil || authority.LastCommandID != commandID {
		t.Fatalf("authority = %+v, %v", authority, err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "stable", first, ApprovalCommand{CommandID: next, EnrollmentID: strings.Repeat("c", 32)}, now); !HasCode(err, CodeAdapterUnauthorized) {
		t.Fatalf("rotated credential admission = %v", err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "stable", rotated.Credential, ApprovalCommand{CommandID: next, EnrollmentID: strings.Repeat("c", 32)}, now); err != nil {
		t.Fatalf("new credential admission = %v", err)
	}
	encoded, _ := json.Marshal(authority)
	if strings.Contains(strings.ToLower(string(encoded)), "credential") || strings.Contains(strings.ToLower(string(encoded)), "hash") {
		t.Fatalf("authority status leaks verifier: %s", encoded)
	}
	var stored []byte
	if err := db.QueryRow(`select credential_hash from enrollment_adapters where adapter_id = 'stable'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(rotated.Credential[:])
	if !bytes.Equal(stored, wantDigest[:]) || bytes.Equal(stored, rotated.Credential[:]) {
		t.Fatal("adapter credential was not stored only as its verifier")
	}
}

func TestRotateAdapterCredentialRollsBackWhenPostUpdateStatusReadFails(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	provisioning, err := store.ProvisionAdapter(context.Background(), "rotate-read-fault", now)
	if err != nil {
		t.Fatal(err)
	}
	before := adapterVerifier(t, db, "rotate-read-fault")
	if _, err := db.Exec(`create trigger test_rotate_status_read_failure after update of credential_hash on enrollment_adapters begin update enrollment_adapters set created_at = 'invalid' where adapter_id = new.adapter_id; end`); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.RotateAdapterCredential(context.Background(), "rotate-read-fault", now.Add(time.Second))
	if err == nil {
		t.Fatal("rotation succeeded after status read corruption")
	}
	if rotated != (AdapterProvisioning{}) {
		t.Fatalf("failed rotation returned credential: %+v", rotated)
	}
	after := adapterVerifier(t, db, "rotate-read-fault")
	if before != after {
		t.Fatal("failed status read committed rotated verifier")
	}
	digest := sha256.Sum256(provisioning.Credential[:])
	if before != digest {
		t.Fatal("stored initial verifier did not match one-time credential")
	}
}

func TestRotateAdapterCredentialCancellationBeforeCommitRollsBack(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	if _, err := store.ProvisionAdapter(context.Background(), "rotate-cancel", now); err != nil {
		t.Fatal(err)
	}
	before := adapterVerifier(t, db, "rotate-cancel")
	ctx, cancel := context.WithCancel(context.Background())
	store.adapterMutationTestHook = func(stage string) {
		if stage == "rotate_before_commit" {
			cancel()
		}
	}
	t.Cleanup(func() { store.adapterMutationTestHook = nil })
	rotated, err := store.RotateAdapterCredential(ctx, "rotate-cancel", now.Add(time.Second))
	if err == nil {
		t.Fatal("canceled rotation committed")
	}
	if rotated != (AdapterProvisioning{}) {
		t.Fatalf("canceled rotation returned credential: %+v", rotated)
	}
	if after := adapterVerifier(t, db, "rotate-cancel"); before != after {
		t.Fatal("canceled rotation committed verifier")
	}
}

func TestProvisionAdapterCancellationBeforeCommitReturnsNoCredentialOrRow(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	ctx, cancel := context.WithCancel(context.Background())
	store.adapterMutationTestHook = func(stage string) {
		if stage == "provision_before_commit" {
			cancel()
		}
	}
	t.Cleanup(func() { store.adapterMutationTestHook = nil })
	provisioning, err := store.ProvisionAdapter(ctx, "provision-cancel", time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatal("canceled provisioning committed")
	}
	if provisioning != (AdapterProvisioning{}) {
		t.Fatalf("canceled provisioning returned credential: %+v", provisioning)
	}
	var rows int
	if err := db.QueryRow(`select count(*) from enrollment_adapters where adapter_id = 'provision-cancel'`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("canceled provisioning rows = %d, %v", rows, err)
	}
}

func adapterVerifier(t *testing.T, db *sql.DB, adapterID string) [32]byte {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`select credential_hash from enrollment_adapters where adapter_id = ?`, adapterID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	if len(raw) != len(digest) {
		t.Fatalf("adapter verifier length = %d", len(raw))
	}
	copy(digest[:], raw)
	return digest
}

func TestAdapterReadAuthorizationTracksActiveCredential(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "reader", now)
	otherCredential := provisionAdapter(t, store, "other-reader", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "authorized-read", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandID := uuidV7ForTest(now, 1)
	store.AdmitApprovalCommand(context.Background(), "reader", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)
	store.AdmitApprovalCommand(context.Background(), "other-reader", otherCredential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)

	assertUnauthorized := func(name string, call func() error) {
		t.Helper()
		if err := call(); !HasCode(err, CodeAdapterUnauthorized) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	assertUnauthorized("query wrong credential", func() error {
		_, err := store.QueryCommand(context.Background(), "reader", otherCredential, commandID)
		return err
	})
	assertUnauthorized("replay wrong credential", func() error {
		_, err := store.ReplayFacts(context.Background(), "reader", otherCredential, 0, 0, 10)
		return err
	})
	assertUnauthorized("snapshot wrong credential", func() error {
		_, err := store.CurrentPendingSnapshot(context.Background(), "reader", otherCredential, now)
		return err
	})
	assertUnauthorized("recovery wrong credential", func() error {
		_, err := store.AdmittedApprovalCommands(context.Background(), "reader", otherCredential, 10)
		return err
	})
	if receipt, err := store.QueryCommand(context.Background(), "reader", credential, commandID); err != nil || receipt.State != ReceiptAdmitted {
		t.Fatalf("authorized query = %+v, %v", receipt, err)
	}
	if page, err := store.ReplayFacts(context.Background(), "reader", credential, 0, 0, 10); err != nil || len(page.Facts) != 1 {
		t.Fatalf("authorized replay = %+v, %v", page, err)
	}
	if snapshot, err := store.CurrentPendingSnapshot(context.Background(), "reader", credential, now); err != nil || len(snapshot.Pending) != 1 {
		t.Fatalf("authorized snapshot = %+v, %v", snapshot, err)
	}
	if admitted, err := store.AdmittedApprovalCommands(context.Background(), "reader", credential, 10); err != nil || len(admitted) != 1 || admitted[0].AdapterID != "reader" {
		t.Fatalf("authorized recovery = %+v, %v", admitted, err)
	}
	if _, err := store.SetAdapterActive(context.Background(), "reader", false, now); err != nil {
		t.Fatal(err)
	}
	assertUnauthorized("query inactive", func() error {
		_, err := store.QueryCommand(context.Background(), "reader", credential, commandID)
		return err
	})
	if _, err := store.SetAdapterActive(context.Background(), "reader", true, now); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.RotateAdapterCredential(context.Background(), "reader", now)
	if err != nil {
		t.Fatal(err)
	}
	assertUnauthorized("query rotated credential", func() error {
		_, err := store.QueryCommand(context.Background(), "reader", credential, commandID)
		return err
	})
	if _, err := store.QueryCommand(context.Background(), "reader", rotated.Credential, commandID); err != nil {
		t.Fatalf("rotated credential query = %v", err)
	}
}

func TestAdapterReadAuthorizationRotationAndDeactivationRace(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "read-race", now)
	for iteration := range 20 {
		start := make(chan struct{})
		readResult := make(chan error, 1)
		rotateResult := make(chan AdapterProvisioning, 1)
		rotateError := make(chan error, 1)
		go func(current AdapterCredential) {
			<-start
			_, err := store.ReplayFacts(context.Background(), "read-race", current, 0, 0, 1)
			readResult <- err
		}(credential)
		go func() {
			<-start
			rotated, err := store.RotateAdapterCredential(context.Background(), "read-race", now.Add(time.Duration(iteration)*time.Second))
			rotateResult <- rotated
			rotateError <- err
		}()
		close(start)
		readErr := <-readResult
		rotated := <-rotateResult
		if err := <-rotateError; err != nil {
			t.Fatal(err)
		}
		if readErr != nil && !HasCode(readErr, CodeAdapterUnauthorized) {
			t.Fatalf("rotation race read error = %v", readErr)
		}
		credential = rotated.Credential
	}
	start := make(chan struct{})
	readResult := make(chan error, 1)
	deactivateResult := make(chan error, 1)
	go func() {
		<-start
		_, err := store.CurrentPendingSnapshot(context.Background(), "read-race", credential, now)
		readResult <- err
	}()
	go func() {
		<-start
		_, err := store.SetAdapterActive(context.Background(), "read-race", false, now)
		deactivateResult <- err
	}()
	close(start)
	readErr := <-readResult
	if err := <-deactivateResult; err != nil {
		t.Fatal(err)
	}
	if readErr != nil && !HasCode(readErr, CodeAdapterUnauthorized) {
		t.Fatalf("deactivation race read error = %v", readErr)
	}
	if _, err := store.CurrentPendingSnapshot(context.Background(), "read-race", credential, now); !HasCode(err, CodeAdapterUnauthorized) {
		t.Fatalf("post-deactivation read = %v", err)
	}
}

func TestAdapterMarkerAuthorizationLeaseOrdersCredentialRotation(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "marker-lease", now)
	release, err := store.AuthorizeAdapterMarker(context.Background(), "marker-lease", credential)
	if err != nil {
		t.Fatal(err)
	}
	rotated := make(chan AdapterProvisioning, 1)
	rotationError := make(chan error, 1)
	go func() {
		result, rotateErr := store.RotateAdapterCredential(context.Background(), "marker-lease", now.Add(time.Second))
		rotated <- result
		rotationError <- rotateErr
	}()
	select {
	case err := <-rotationError:
		t.Fatalf("rotation completed while marker lease was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	result := <-rotated
	if err := <-rotationError; err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeAdapter(context.Background(), "marker-lease", credential); !HasCode(err, CodeAdapterUnauthorized) {
		t.Fatalf("old credential after ordered rotation = %v", err)
	}
	if err := store.AuthorizeAdapter(context.Background(), "marker-lease", result.Credential); err != nil {
		t.Fatalf("new credential after ordered rotation = %v", err)
	}
}

func TestFactNotificationsArePostCommitAndNonblocking(t *testing.T) {
	base, db := newTestStore(t, DefaultMaxPending)
	notifications := make(chan struct{}, 1)
	store := NewStore(db, base.authority, DefaultMaxPending, WithFactNotifications(notifications))
	if _, err := db.Exec(`create trigger reject_test_fact before insert on enrollment_facts begin select raise(abort, 'test rollback'); end`); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), publicKey, "rollback-notify", "192.0.2.1", time.Now()); err == nil {
		t.Fatal("fact insertion unexpectedly committed")
	}
	select {
	case <-notifications:
		t.Fatal("rollback emitted a fact notification")
	default:
	}
	if _, err := db.Exec(`drop trigger reject_test_fact`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), publicKey, "rollback-notify", "192.0.2.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notifications:
	default:
		t.Fatal("commit did not emit a fact notification")
	}
	notifications <- struct{}{}
	secondKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, requestErr := store.RequestEnrollment(context.Background(), secondKey, "full-notify", "192.0.2.2", time.Now())
		done <- requestErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("full notification channel blocked enrollment commit")
	}
}

func TestAdapterAndPerAdapterCommandCapacity(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	var credential AdapterCredential
	for index := range MaxAdapters {
		provisioning, err := store.ProvisionAdapter(context.Background(), fmt.Sprintf("cap-%02d", index), now)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			credential = provisioning.Credential
		}
	}
	if _, err := store.ProvisionAdapter(context.Background(), "overflow", now); !HasCode(err, CodeAdapterCapacity) {
		t.Fatalf("adapter capacity error = %v", err)
	}
	enrollmentID := strings.Repeat("d", 32)
	var last string
	for index := range MaxAdmittedReceiptsPerAdapter {
		last = uuidV7ForTest(now.Add(time.Duration(index)*time.Millisecond), byte(index))
		if _, err := store.AdmitApprovalCommand(context.Background(), "cap-00", credential, ApprovalCommand{CommandID: last, EnrollmentID: enrollmentID}, now.Add(time.Duration(index)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	blocked := uuidV7ForTest(now.Add(MaxAdmittedReceiptsPerAdapter*time.Millisecond), 65)
	if _, err := store.AdmitApprovalCommand(context.Background(), "cap-00", credential, ApprovalCommand{CommandID: blocked, EnrollmentID: enrollmentID}, now.Add(MaxAdmittedReceiptsPerAdapter*time.Millisecond)); !HasCode(err, CodeCommandCapacity) {
		t.Fatalf("command capacity error = %v", err)
	}
	authority, _ := store.Adapter(context.Background(), "cap-00")
	if authority.LastCommandID != last {
		t.Fatalf("capacity consumed command ID: %q", authority.LastCommandID)
	}
	if _, err := store.ApproveAdapterCommand(context.Background(), "cap-00", last, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "cap-00", credential, ApprovalCommand{CommandID: blocked, EnrollmentID: enrollmentID}, now.Add(MaxAdmittedReceiptsPerAdapter*time.Millisecond)); err != nil {
		t.Fatalf("unconsumed command ID was not admissible: %v", err)
	}
}

func TestConcurrentExactCommandAdmissionIsSingleReceipt(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "concurrent", now)
	commandID := uuidV7ForTest(now, 1)
	var wait sync.WaitGroup
	results := make(chan CommandReceipt, 2)
	errs := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := store.AdmitApprovalCommand(context.Background(), "concurrent", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("e", 32)}, now)
			results <- receipt
			errs <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var seq int64
	for receipt := range results {
		if seq != 0 && receipt.ReceiptSeq != seq {
			t.Fatalf("receipt sequences differ: %d and %d", seq, receipt.ReceiptSeq)
		}
		seq = receipt.ReceiptSeq
	}
	var count int
	db.QueryRow(`select count(*) from enrollment_command_receipts`).Scan(&count)
	if count != 1 {
		t.Fatalf("receipt rows = %d", count)
	}
}

func TestConcurrentDistinctAdmissionPreservesMonotonicHighWater(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "ordered", now)
	low := uuidV7ForTest(now, 1)
	high := uuidV7ForTest(now, 2)
	start := make(chan struct{})
	results := make(chan struct {
		id  string
		err error
	}, 2)
	for _, commandID := range []string{low, high} {
		go func() {
			<-start
			_, err := store.AdmitApprovalCommand(context.Background(), "ordered", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("a", 32)}, now)
			results <- struct {
				id  string
				err error
			}{commandID, err}
		}()
	}
	close(start)
	for range 2 {
		result := <-results
		if result.id == high && result.err != nil {
			t.Fatalf("high command failed: %v", result.err)
		}
		if result.id == low && result.err != nil && !HasCode(result.err, CodeReceiptExpired) {
			t.Fatalf("low command error = %v", result.err)
		}
	}
	authority, err := store.Adapter(context.Background(), "ordered")
	if err != nil || authority.LastCommandID != high {
		t.Fatalf("ordered authority = %+v, %v", authority, err)
	}
}

func TestSkippedIDsExpireAndAdaptersFenceIndependently(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credentialA := provisionAdapter(t, store, "independent-a", now)
	credentialB := provisionAdapter(t, store, "independent-b", now)
	first := uuidV7ForTest(now, 1)
	skipped := uuidV7ForTest(now, 2)
	later := uuidV7ForTest(now, 3)
	for _, commandID := range []string{first, later} {
		if _, err := store.AdmitApprovalCommand(context.Background(), "independent-a", credentialA, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("b", 32)}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "independent-a", credentialA, ApprovalCommand{CommandID: skipped, EnrollmentID: strings.Repeat("b", 32)}, now); !HasCode(err, CodeReceiptExpired) {
		t.Fatalf("skipped ID error = %v", err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "independent-b", credentialB, ApprovalCommand{CommandID: first, EnrollmentID: strings.Repeat("b", 32)}, now); err != nil {
		t.Fatalf("independent adapter reused ID: %v", err)
	}
}

func TestAdmissionRejectsWallClockRollbackAndStaleFreshID(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "clock", now)
	first := uuidV7ForTest(now, 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "clock", credential, ApprovalCommand{CommandID: first, EnrollmentID: strings.Repeat("c", 32)}, now); err != nil {
		t.Fatal(err)
	}
	afterRollback := uuidV7ForTest(now.Add(time.Millisecond), 2)
	if _, err := store.AdmitApprovalCommand(context.Background(), "clock", credential, ApprovalCommand{CommandID: afterRollback, EnrollmentID: strings.Repeat("c", 32)}, now.Add(-10*time.Minute)); !HasCode(err, CodeCommandTimeInvalid) {
		t.Fatalf("wall rollback error = %v", err)
	}
	staleCredential := provisionAdapter(t, store, "stale", now)
	stale := uuidV7ForTest(now.Add(-31*24*time.Hour), 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "stale", staleCredential, ApprovalCommand{CommandID: stale, EnrollmentID: strings.Repeat("d", 32)}, now); !HasCode(err, CodeReceiptExpired) {
		t.Fatalf("stale fresh ID error = %v", err)
	}
}

func TestReceiptPressurePrunesOldestSettled(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "pressure", now)
	if _, err := db.Exec(`insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at) values ('pressure', 'protected-admitted', zeroblob(32), 1, ?, ?, ?, 1)`, ApprovalCommandAction, strings.Repeat("e", 32), ReceiptAdmitted); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`with recursive n(x) as (values(1) union all select x + 1 from n where x < ?) insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at, settled_at, rejection_code) select 'pressure', printf('settled-%05d', x), zeroblob(32), 1, ?, printf('%032x', x), ?, 1, 2, ? from n`, MaxReceipts-1, ApprovalCommandAction, ReceiptRejected, RejectionSettledElsewhere)
	if err != nil {
		t.Fatal(err)
	}
	commandID := uuidV7ForTest(now, 1)
	receipt, err := store.AdmitApprovalCommand(context.Background(), "pressure", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("f", 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	var total, admitted, oldestSettled int
	db.QueryRow(`select count(*) from enrollment_command_receipts`).Scan(&total)
	db.QueryRow(`select count(*) from enrollment_command_receipts where receipt_seq = 1 and state = ?`, ReceiptAdmitted).Scan(&admitted)
	db.QueryRow(`select count(*) from enrollment_command_receipts where receipt_seq = 2`).Scan(&oldestSettled)
	if total != MaxReceipts || admitted != 1 || oldestSettled != 0 || receipt.ReceiptSeq <= MaxReceipts {
		t.Fatalf("pressure total=%d admitted=%d oldest_settled=%d receipt=%+v", total, admitted, oldestSettled, receipt)
	}
}

func TestPrunedReceiptIdentityCannotBeReadmitted(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "pruned", now)
	commandID := uuidV7ForTest(now, 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "pruned", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("f", 32)}, now); err != nil {
		t.Fatal(err)
	}
	settled, err := store.ApproveAdapterCommand(context.Background(), "pruned", commandID, now)
	if err != nil {
		t.Fatal(err)
	}
	if settled.State != ReceiptRejected || settled.RejectionCode != RejectionNotPending {
		t.Fatalf("missing pending settlement = %+v", settled)
	}
	if removed, err := store.PruneReceipts(context.Background(), now.Add(31*24*time.Hour)); err != nil || removed != 1 {
		t.Fatalf("pruned receipts = %d, %v", removed, err)
	}
	if _, err := store.queryCommandInternal(context.Background(), "pruned", commandID); !HasCode(err, CodeReceiptExpired) {
		t.Fatalf("query pruned result = %v", err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "pruned", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("f", 32)}, now); !HasCode(err, CodeReceiptExpired) {
		t.Fatalf("readmit pruned identity = %v", err)
	}
}

func TestGlobalAdmittedReceiptCapacityDoesNotConsumeID(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	var credential AdapterCredential
	for index := range 17 {
		provisioning, err := store.ProvisionAdapter(context.Background(), fmt.Sprintf("global-%02d", index), now)
		if err != nil {
			t.Fatal(err)
		}
		if index == 16 {
			credential = provisioning.Credential
		}
	}
	_, err := db.Exec(`with recursive n(x) as (values(0) union all select x + 1 from n where x < ?) insert into enrollment_command_receipts(adapter_id, command_id, fingerprint, schema_version, action, enrollment_id, state, admitted_at) select printf('global-%02d', x / 64), printf('admitted-%04d', x), zeroblob(32), 1, ?, printf('%032x', x), ?, 1 from n`, MaxAdmittedReceipts-1, ApprovalCommandAction, ReceiptAdmitted)
	if err != nil {
		t.Fatal(err)
	}
	commandID := uuidV7ForTest(now, 1)
	if _, err := store.AdmitApprovalCommand(context.Background(), "global-16", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: strings.Repeat("1", 32)}, now); !HasCode(err, CodeCommandCapacity) {
		t.Fatalf("global command capacity error = %v", err)
	}
	authority, _ := store.Adapter(context.Background(), "global-16")
	if authority.LastCommandID != "" {
		t.Fatalf("global capacity consumed ID %q", authority.LastCommandID)
	}
}

func TestProtectedFactPrefixBlocksAdmissionButNotSettlement(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), keyA, "protected", "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`with recursive n(x) as (values(1) union all select x + 1 from n where x < ?) insert into enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at) select ?, printf('%032x', x), ?, printf('device-%d', x), printf('label-%d', x), ? from n`, MaxFactRows-3, FactPendingAdmitted, now.Unix(), now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), keyB, "blocked", "192.0.2.2", now); !HasCode(err, CodeFactCapacity) {
		t.Fatalf("protected-prefix capacity error = %v", err)
	}
	if err := store.SettleExpired(context.Background(), now.Add(PendingLifetime)); err != nil {
		t.Fatalf("reserved expiry settlement failed: %v", err)
	}
	if _, err := store.RequestEnrollment(context.Background(), keyB, "unblocked", "192.0.2.2", now.Add(PendingLifetime)); err != nil {
		t.Fatalf("admission after settlement failed: %v", err)
	}
	var floor int64
	db.QueryRow(`select replay_floor from enrollment_fact_metadata`).Scan(&floor)
	if floor == 0 {
		t.Fatal("pressure pruning did not advance the replay floor")
	}
	if _, err := store.replayFacts(context.Background(), 0, 0, 1); !HasCode(err, CodeCursorExpired) {
		t.Fatalf("pruned cursor error = %v", err)
	}
}

func TestApprovalTransfersPendingReservationAndRevocationConsumesMemberReserve(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	_, err := db.Exec(`with recursive n(x) as (values(1) union all select x + 1 from n where x < ?) insert into members(device_id, device_key, label, label_key, revision, credential, created_at, enrollment_id) select printf('device-%03d', x), printf('key-%03d', x), printf('member-%03d', x), printf('member-%03d', x), 1, '{}', 1, printf('%032x', x) from n`, MaxMembers-1)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, err := store.RequestEnrollment(context.Background(), key, "reserved-member", "192.0.2.1", now)
	if err != nil {
		t.Fatal(err)
	}
	assertOccupancy := func(want int) {
		t.Helper()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		got, err := factOccupancy(context.Background(), tx)
		if err != nil || got != want {
			t.Fatalf("fact occupancy = %d, %v, want %d", got, err, want)
		}
	}
	assertOccupancy(MaxMembers - 1 + 3)
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	assertOccupancy(MaxMembers - 1 + 3)
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now); err != nil {
		t.Fatal(err)
	}
	assertOccupancy(MaxMembers - 1 + 3)
}

func TestFactFloorUpdateFailureRollsBackPrefixDeletion(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "floor-rollback", "192.0.2.1", now)
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create trigger test_floor_failure before update on enrollment_fact_metadata begin select raise(abort, 'injected floor failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PruneFacts(context.Background(), now.Add(31*24*time.Hour)); err == nil {
		t.Fatal("fact prune succeeded through floor failure")
	}
	var facts, floor int
	db.QueryRow(`select count(*) from enrollment_facts`).Scan(&facts)
	db.QueryRow(`select replay_floor from enrollment_fact_metadata`).Scan(&floor)
	if facts != 2 || floor != 0 {
		t.Fatalf("floor rollback facts=%d floor=%d", facts, floor)
	}
}

func TestFactTraversalHighWaterExcludesConcurrentAppend(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := store.RequestEnrollment(context.Background(), keyA, "page-a", "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	first, err := store.replayFacts(context.Background(), 0, 0, 1)
	if err != nil || first.HighWater != 1 {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	if _, err := store.RequestEnrollment(context.Background(), keyB, "page-b", "192.0.2.2", now); err != nil {
		t.Fatal(err)
	}
	continued, err := store.replayFacts(context.Background(), 1, first.HighWater, 1)
	if err != nil || len(continued.Facts) != 0 || continued.HighWater != 1 {
		t.Fatalf("continued page = %+v, %v", continued, err)
	}
	next, err := store.replayFacts(context.Background(), 1, 0, 1)
	if err != nil || len(next.Facts) != 1 || next.Facts[0].Seq != 2 {
		t.Fatalf("next traversal = %+v, %v", next, err)
	}
}

func TestSQLiteReadSnapshotSerializesConcurrentAppendAndPrune(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), keyA, "snapshot-a", "192.0.2.1", now)
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var floor, highWater int64
	tx.QueryRow(`select replay_floor from enrollment_fact_metadata`).Scan(&floor)
	tx.QueryRow(`select max(seq) from enrollment_facts`).Scan(&highWater)
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)
	appendDone := make(chan error, 1)
	go func() {
		_, err := store.RequestEnrollment(context.Background(), keyB, "snapshot-b", "192.0.2.2", now)
		appendDone <- err
	}()
	var visible int
	if err := tx.QueryRow(`select count(*) from enrollment_facts where seq > ? and seq <= ?`, floor, highWater).Scan(&visible); err != nil || visible != 2 {
		t.Fatalf("snapshot facts = %d, %v", visible, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-appendDone; err != nil {
		t.Fatal(err)
	}
	page, err := store.replayFacts(context.Background(), highWater, 0, 10)
	if err != nil || len(page.Facts) != 1 {
		t.Fatalf("post-snapshot append = %+v, %v", page, err)
	}
	pruneDone := make(chan error, 1)
	readTx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := store.PruneFacts(context.Background(), now.Add(31*24*time.Hour))
		pruneDone <- err
	}()
	if err := readTx.QueryRow(`select count(*) from enrollment_facts where seq <= ?`, highWater).Scan(&visible); err != nil || visible != 2 {
		t.Fatalf("pre-prune snapshot facts = %d, %v", visible, err)
	}
	if err := readTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-pruneDone; err != nil {
		t.Fatal(err)
	}
	if _, err := store.replayFacts(context.Background(), 0, 0, 1); !HasCode(err, CodeCursorExpired) {
		t.Fatalf("post-prune cursor = %v", err)
	}
}

func TestReplayFactsConcurrentAppendAndPruneIsConsistentOrExpired(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "replay-race", now)
	for index := range 8 {
		key, _, _ := ed25519.GenerateKey(rand.Reader)
		pending, err := store.RequestEnrollment(context.Background(), key, fmt.Sprintf("resolved-%d", index), "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
			t.Fatal(err)
		}
	}
	for iteration := range 12 {
		var cursor int64
		if err := db.QueryRow(`select replay_floor from enrollment_fact_metadata`).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		type replayResult struct {
			page FactPage
			err  error
		}
		replayDone := make(chan replayResult, 1)
		appendDone := make(chan error, 1)
		pruneDone := make(chan error, 1)
		start := make(chan struct{})
		go func() {
			<-start
			page, err := store.ReplayFacts(context.Background(), "replay-race", credential, cursor, 0, 5)
			replayDone <- replayResult{page: page, err: err}
		}()
		go func() {
			<-start
			key, _, _ := ed25519.GenerateKey(rand.Reader)
			_, err := store.RequestEnrollment(context.Background(), key, fmt.Sprintf("concurrent-%d", iteration), "192.0.2.2", now.Add(time.Duration(iteration)*time.Second))
			appendDone <- err
		}()
		go func() {
			<-start
			_, err := store.PruneFacts(context.Background(), now.Add(31*24*time.Hour))
			pruneDone <- err
		}()
		close(start)
		result := <-replayDone
		if result.err != nil {
			if !HasCode(result.err, CodeCursorExpired) {
				t.Fatalf("replay race error = %v", result.err)
			}
		} else {
			expected := cursor + 1
			for _, fact := range result.page.Facts {
				if fact.Seq != expected || fact.Seq > result.page.HighWater {
					t.Fatalf("inconsistent replay page cursor=%d page=%+v", cursor, result.page)
				}
				expected++
			}
		}
		if err := <-appendDone; err != nil {
			t.Fatal(err)
		}
		if err := <-pruneDone; err != nil {
			t.Fatal(err)
		}
		if err := store.SettleExpired(context.Background(), now.Add(PendingLifetime+time.Duration(iteration)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PruneFacts(context.Background(), now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var floor int64
	if err := db.QueryRow(`select replay_floor from enrollment_fact_metadata`).Scan(&floor); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(`select seq from enrollment_facts order by seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	expected := floor + 1
	retained := 0
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			t.Fatal(err)
		}
		if seq != expected {
			t.Fatalf("interior replay gap after floor %d: got seq %d, want %d", floor, seq, expected)
		}
		expected++
		retained++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if floor == 0 {
		t.Fatal("concurrent pruning did not advance the replay floor")
	}
	if retained == 0 {
		var maxSeq int64
		if err := db.QueryRow(`select seq from sqlite_sequence where name = 'enrollment_facts'`).Scan(&maxSeq); err != nil || floor != maxSeq {
			t.Fatalf("empty retained prefix floor=%d max_seq=%d err=%v", floor, maxSeq, err)
		}
	}
}

func TestPendingSnapshotResumesAfterCapturedHighWater(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "snapshot-resume", "192.0.2.1", now)
	snapshot, err := store.currentPendingSnapshot(context.Background(), now)
	if err != nil || len(snapshot.Pending) != 1 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
		t.Fatal(err)
	}
	page, err := store.replayFacts(context.Background(), snapshot.HighWater, 0, 10)
	if err != nil || len(page.Facts) != 1 || page.Facts[0].Kind != FactMemberApproved {
		t.Fatalf("snapshot resume = %+v, %v", page, err)
	}
}

func TestApprovalExpiryRaceLeavesOneTerminalFactAndSettledReceipt(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "expiry-race", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "expiry-race", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandID := uuidV7ForTest(now, 1)
	store.AdmitApprovalCommand(context.Background(), "expiry-race", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		_, err := store.ApproveAdapterCommand(context.Background(), "expiry-race", commandID, now.Add(PendingLifetime-time.Second))
		errs <- err
	}()
	go func() {
		<-start
		errs <- store.SettleExpired(context.Background(), now.Add(PendingLifetime))
	}()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	receipt, err := store.queryCommandInternal(context.Background(), "expiry-race", commandID)
	if err != nil || receipt.State == ReceiptAdmitted {
		t.Fatalf("race receipt = %+v, %v", receipt, err)
	}
	var terminals int
	db.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind in (?, ?)`, enrollmentID, FactMemberApproved, FactPendingExpired).Scan(&terminals)
	if terminals != 1 {
		t.Fatalf("terminal facts = %d", terminals)
	}
}

func TestAdapterApprovalIsAtomicAndAttributed(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "approver", now)
	competingCredential := provisionAdapter(t, store, "competing", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, err := store.RequestEnrollment(context.Background(), key, "adapter-approved", "198.51.100.1", now)
	if err != nil {
		t.Fatal(err)
	}
	var enrollmentID string
	if err := db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID); err != nil {
		t.Fatal(err)
	}
	commandID := uuidV7ForTest(now, 1)
	competingCommandID := uuidV7ForTest(now, 2)
	if _, err := store.AdmitApprovalCommand(context.Background(), "approver", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdmitApprovalCommand(context.Background(), "competing", competingCredential, ApprovalCommand{CommandID: competingCommandID, EnrollmentID: enrollmentID}, now); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ApproveAdapterCommand(context.Background(), "approver", commandID, now)
	if err != nil || receipt.State != ReceiptCommitted || receipt.Result == nil {
		t.Fatalf("settled receipt = %+v, %v", receipt, err)
	}
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil || events[0].ActorType != "adapter" || events[0].ActorID != "approver" || events[0].ActorDeviceID != "" {
		t.Fatalf("adapter audit = %+v, %v", events, err)
	}
	var members, approvals int
	db.QueryRow(`select count(*) from members where enrollment_id = ?`, enrollmentID).Scan(&members)
	db.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind = ?`, enrollmentID, FactMemberApproved).Scan(&approvals)
	if members != 1 || approvals != 1 {
		t.Fatalf("members=%d approvals=%d", members, approvals)
	}
	competing, err := store.queryCommandInternal(context.Background(), "competing", competingCommandID)
	if err != nil || competing.State != ReceiptRejected || competing.RejectionCode != RejectionSettledElsewhere {
		t.Fatalf("competing receipt = %+v, %v", competing, err)
	}
	member := Member{DeviceID: receipt.Result.DeviceID, Revision: receipt.Result.Revision}
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if replay, err := store.ApproveAdapterCommand(context.Background(), "approver", commandID, now); err != nil || replay.ReceiptSeq != receipt.ReceiptSeq {
		t.Fatalf("settlement replay = %+v, %v", replay, err)
	} else if replay.Result.Revision != 1 || replay.Result.Label != "adapter-approved" {
		t.Fatalf("historical approval result changed after revocation: %+v", replay.Result)
	}
}

func TestAdapterApprovalFailureLeavesAdmittedAndPending(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "faulted", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "faulted", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandID := uuidV7ForTest(now, 1)
	store.AdmitApprovalCommand(context.Background(), "faulted", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)
	if _, err := db.Exec(`create trigger test_adapter_audit_failure before insert on audit_events when new.actor_type = 'adapter' begin select raise(abort, 'injected adapter audit failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveAdapterCommand(context.Background(), "faulted", commandID, now); err == nil {
		t.Fatal("adapter approval succeeded through audit failure")
	}
	receipt, err := store.queryCommandInternal(context.Background(), "faulted", commandID)
	if err != nil || receipt.State != ReceiptAdmitted {
		t.Fatalf("receipt after rollback = %+v, %v", receipt, err)
	}
	var pendingRows, members, approvals int
	db.QueryRow(`select count(*) from pending_enrollments where enrollment_id = ?`, enrollmentID).Scan(&pendingRows)
	db.QueryRow(`select count(*) from members where enrollment_id = ?`, enrollmentID).Scan(&members)
	db.QueryRow(`select count(*) from enrollment_facts where enrollment_id = ? and kind = ?`, enrollmentID, FactMemberApproved).Scan(&approvals)
	if pendingRows != 1 || members != 0 || approvals != 0 {
		t.Fatalf("rollback pending=%d members=%d approvals=%d", pendingRows, members, approvals)
	}
}

func TestRevocationFactFailureRollsBackAuthorityAndAudit(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "revoke-fault", "192.0.2.1", now)
	member, _ := store.Approve(context.Background(), pending.Code, "local", "", now)
	if _, err := db.Exec(`create trigger test_revocation_fact_failure before insert on enrollment_facts when new.kind = 'enrollment.member_revoked' begin select raise(abort, 'injected revocation fact failure'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), member.DeviceID, member.Revision, "local", "", now); err == nil {
		t.Fatal("revocation succeeded through fact failure")
	}
	var revision, revoked, audits int
	db.QueryRow(`select revision, revoked_at is not null from members where device_id = ?`, member.DeviceID).Scan(&revision, &revoked)
	db.QueryRow(`select count(*) from audit_events where action = 'member.revoked'`).Scan(&audits)
	if revision != 1 || revoked != 0 || audits != 0 {
		t.Fatalf("revocation rollback revision=%d revoked=%d audits=%d", revision, revoked, audits)
	}
}

func TestLocalApprovalRejectsAllAdmittedCommands(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credentialA := provisionAdapter(t, store, "recover-a", now)
	credentialB := provisionAdapter(t, store, "recover-b", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "recoverable", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandA := uuidV7ForTest(now, 1)
	commandB := uuidV7ForTest(now, 2)
	store.AdmitApprovalCommand(context.Background(), "recover-a", credentialA, ApprovalCommand{CommandID: commandA, EnrollmentID: enrollmentID}, now)
	store.AdmitApprovalCommand(context.Background(), "recover-b", credentialB, ApprovalCommand{CommandID: commandB, EnrollmentID: enrollmentID}, now)
	admitted, err := store.admittedApprovalCommands(context.Background(), 10)
	if err != nil || len(admitted) != 2 {
		t.Fatalf("admitted recovery = %+v, %v", admitted, err)
	}
	if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
		t.Fatal(err)
	}
	for _, key := range []struct{ adapterID, commandID string }{{"recover-a", commandA}, {"recover-b", commandB}} {
		receipt, err := store.queryCommandInternal(context.Background(), key.adapterID, key.commandID)
		if err != nil || receipt.State != ReceiptRejected || receipt.RejectionCode != RejectionSettledElsewhere || receipt.Result != nil {
			t.Fatalf("locally settled receipt = %+v, %v", receipt, err)
		}
	}
}

func TestExpiryRejectsAllAdmittedCommands(t *testing.T) {
	store, db := newTestStore(t, DefaultMaxPending)
	now := time.Unix(1_700_000_000, 0)
	credential := provisionAdapter(t, store, "expiry", now)
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	pending, _ := store.RequestEnrollment(context.Background(), key, "expires", "192.0.2.1", now)
	var enrollmentID string
	db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
	commandID := uuidV7ForTest(now, 1)
	store.AdmitApprovalCommand(context.Background(), "expiry", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now)
	if err := store.SettleExpired(context.Background(), now.Add(PendingLifetime)); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.queryCommandInternal(context.Background(), "expiry", commandID)
	if err != nil || receipt.State != ReceiptRejected || receipt.RejectionCode != RejectionEnrollmentExpired {
		t.Fatalf("expiry receipt = %+v, %v", receipt, err)
	}
}

func TestExecutionOfLateCommandUsesImmutableTerminalFactForRejection(t *testing.T) {
	for _, test := range []struct {
		name   string
		settle func(*Store, *sql.DB, Enrollment, string, time.Time) error
		want   RejectionCode
	}{
		{
			name: "approved elsewhere",
			settle: func(store *Store, _ *sql.DB, pending Enrollment, _ string, now time.Time) error {
				_, err := store.Approve(context.Background(), pending.Code, "local", "", now)
				return err
			},
			want: RejectionSettledElsewhere,
		},
		{
			name: "expired",
			settle: func(store *Store, _ *sql.DB, _ Enrollment, _ string, now time.Time) error {
				return store.SettleExpired(context.Background(), now.Add(PendingLifetime))
			},
			want: RejectionEnrollmentExpired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, db := newTestStore(t, DefaultMaxPending)
			now := time.Unix(1_700_000_000, 0)
			key, _, _ := ed25519.GenerateKey(rand.Reader)
			pending, _ := store.RequestEnrollment(context.Background(), key, "late-command", "192.0.2.1", now)
			var enrollmentID string
			db.QueryRow(`select enrollment_id from pending_enrollments where code = ?`, pending.Code).Scan(&enrollmentID)
			if err := test.settle(store, db, pending, enrollmentID, now); err != nil {
				t.Fatal(err)
			}
			credential := provisionAdapter(t, store, "late", now)
			commandID := uuidV7ForTest(now, 1)
			if _, err := store.AdmitApprovalCommand(context.Background(), "late", credential, ApprovalCommand{CommandID: commandID, EnrollmentID: enrollmentID}, now); err != nil {
				t.Fatal(err)
			}
			receipt, err := store.ApproveAdapterCommand(context.Background(), "late", commandID, now)
			if err != nil || receipt.State != ReceiptRejected || receipt.RejectionCode != test.want {
				t.Fatalf("late receipt = %+v, %v", receipt, err)
			}
		})
	}
}

func TestGenericRevocationRejectsAdapterActor(t *testing.T) {
	store, _ := newTestStore(t, DefaultMaxPending)
	if _, err := store.Revoke(context.Background(), strings.Repeat("a", 43), 1, "adapter", "adapter", time.Now()); err == nil || !strings.Contains(err.Error(), "cannot revoke") {
		t.Fatalf("adapter revocation error = %v", err)
	}
}

func TestFactAllocationConstants(t *testing.T) {
	if FactHistoryTarget+DefaultMaxPending*3+MaxMembers != MaxFactRows {
		t.Fatalf("fact allocation = %d + %d*3 + %d != %d", FactHistoryTarget, DefaultMaxPending, MaxMembers, MaxFactRows)
	}
}

func uuidV7ForTest(at time.Time, suffix byte) string {
	milliseconds := at.UnixMilli()
	raw := make([]byte, 16)
	for index := 5; index >= 0; index-- {
		raw[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	raw[6] = 0x70
	raw[8] = 0x80
	raw[15] = suffix
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func provisionAdapter(t *testing.T, store *Store, adapterID string, now time.Time) AdapterCredential {
	t.Helper()
	provisioning, err := store.ProvisionAdapter(context.Background(), adapterID, now)
	if err != nil {
		t.Fatal(err)
	}
	return provisioning.Credential
}
