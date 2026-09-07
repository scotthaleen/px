//go:build !windows

package put

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/transfer"
)

func TestExpiredSenderTombstonesRecoverSharedCapacity(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	for index := range 64 {
		manifest := storeManifest(fmt.Sprintf("%032x", index+1))
		lease, err := store.ReserveSender(t.Context(), manifest, "receiver", "/source")
		if err != nil {
			t.Fatalf("reserve %d: %v", index, err)
		}
		if err := store.MarkSenderCommitted(t.Context(), lease, "durability_confirmed"); err != nil {
			t.Fatal(err)
		}
		lease.Release()
	}
	created, expired := time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	if _, err := db.Exec(`update put_transfers set created_at=?,updated_at=?,expires_at=?,next_retry_at=? where direction='send'`, created, created, expired, created); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ReserveSender(t.Context(), storeManifest("ffffffffffffffffffffffffffffffff"), "receiver", "/source")
	if err != nil {
		t.Fatalf("expired tombstones retained capacity: %v", err)
	}
	lease.Release()
	var count int
	if err := db.QueryRow(`select count(*) from put_transfers where direction='send'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("sender rows=%d err=%v", count, err)
	}
}

func TestConcurrentSenderRetryClaimsAreExclusive(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("33333333333333333333333333333333")
	initial, err := store.ReserveSender(t.Context(), manifest, "receiver", "/source")
	if err != nil {
		t.Fatal(err)
	}
	initial.Release()
	start := make(chan struct{})
	type claimResult struct {
		lease *SenderLease
		err   error
	}
	results := make(chan claimResult, 2)
	for range 2 {
		go func() {
			<-start
			lease, err := store.ClaimSender(context.Background(), "home", manifest.ID)
			results <- claimResult{lease: lease, err: err}
		}()
	}
	close(start)
	var claimed, active int
	for range 2 {
		result := <-results
		if result.lease != nil {
			defer result.lease.Release()
		}
		if result.err == nil {
			claimed++
		} else if errors.Is(result.err, ErrActive) {
			active++
		} else {
			t.Fatalf("claim error=%v", result.err)
		}
	}
	if claimed != 1 || active != 1 {
		t.Fatalf("claimed=%d active=%d", claimed, active)
	}
}

func TestSenderRetryPersistsImmutableReplacementManifest(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("44444444444444444444444444444444")
	manifest.Mode = "replace"
	manifest.ExpectSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	initial, err := store.ReserveSender(t.Context(), manifest, "receiver", "/source")
	if err != nil {
		t.Fatal(err)
	}
	initial.Release()
	retry, err := store.ClaimSender(t.Context(), "home", manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Release()
	if retry.Record().Manifest != manifest {
		t.Fatalf("retry manifest=%+v want=%+v", retry.Record().Manifest, manifest)
	}
}

func TestCommittedSenderCannotBeClaimedForRetry(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("11111111111111111111111111111111")
	lease, err := store.ReserveSender(t.Context(), manifest, "receiver", "/source")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSenderCommitted(t.Context(), lease, "durability_confirmed"); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if _, err := store.ClaimSender(t.Context(), "home", manifest.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("committed retry claim error=%v", err)
	}
}

func TestInventoryExpiresSafeTombstonesAndFiltersExpiredRetry(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("22222222222222222222222222222222")
	lease, err := store.ReserveSender(t.Context(), manifest, "receiver", "/source")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	created, expired := time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	if _, err := db.Exec(`update put_transfers set created_at=?,updated_at=?,expires_at=?,next_retry_at=? where direction='send'`, created, created, expired, created); err != nil {
		t.Fatal(err)
	}
	ids, err := store.CompletionIDs(t.Context(), "home", "retry", "", "", 64)
	if err != nil || len(ids) != 0 {
		t.Fatalf("expired retry IDs=%v err=%v", ids, err)
	}
	items, err := store.Inventory(t.Context(), "home", 64)
	if err != nil || len(items) != 0 {
		t.Fatalf("expired inventory=%v err=%v", items, err)
	}
}

func TestCountsIncludeActiveReceiverAndRetryableSender(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	sender, err := store.ReserveSender(t.Context(), storeManifest("44444444444444444444444444444444"), "receiver", "/source")
	if err != nil {
		t.Fatal(err)
	}
	sender.Release()
	receiverManifest := storeManifest("55555555555555555555555555555555")
	receiverManifest.SenderID, receiverManifest.ReceiverID = "peer", "receiver"
	lease, err := store.ReserveReceiver(t.Context(), Record{Manifest: receiverManifest, PeerLabel: "peer"}, t.TempDir(), "unix1:0000000000000001:0000000000000001", ".px-55555555555555555555555555555555.put")
	if err != nil {
		t.Fatal(err)
	}
	active, retryable, err := store.Counts(t.Context(), "home")
	if err != nil || active != 1 || retryable != 1 {
		t.Fatalf("active=%d retryable=%d err=%v", active, retryable, err)
	}
	store.ReleaseReceiver(receiverManifest.ID, lease)
}

func TestPutAdmissionExpiresSafeTransferSenderRows(t *testing.T) {
	db := recoveryDatabase(t)
	resumeStore := transfer.NewResumeStore(func() *sql.DB { return db }, t.TempDir())
	store := NewStore(func() *sql.DB { return db })
	store.SetSharedSenderMaintenance(resumeStore.ExpireSenders)
	created, expired := time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	for index := range 64 {
		id := fmt.Sprintf("%064x", index+1)
		if _, err := db.Exec(`insert into transfer_resumes(direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,source_path,stdin_spool,state,created_at,updated_at,expires_at,manifest_version,visibility) values('send',?,'home','receiver','receiver','file',1,?,32768,8,'token',0,'/source',0,'transferring',?,?,?,3,'private')`, id, fmt.Sprintf("%064x", 1), created, created, expired); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := store.ReserveSender(t.Context(), storeManifest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "receiver", "/source")
	if err != nil {
		t.Fatalf("put admission remained blocked: %v", err)
	}
	lease.Release()
	var transferRows int
	if err := db.QueryRow(`select count(*) from transfer_resumes where direction='send'`).Scan(&transferRows); err != nil || transferRows != 0 {
		t.Fatalf("transfer sender rows=%d err=%v", transferRows, err)
	}
}

func TestReceiverBackupEvidencePersistsAndCountsTowardQuota(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("66666666666666666666666666666666")
	manifest.Mode = "replace"
	manifest.SenderID, manifest.ReceiverID = "peer", "receiver"
	identity := "unix1:0000000000000001:0000000000000002"
	record := Record{
		Manifest:       manifest,
		PeerLabel:      "peer",
		OldIdentity:    identity,
		OldMetadata:    "windowsmeta:test",
		OldUID:         1,
		OldGID:         1,
		OldMode:        0o600,
		BackupName:     ".px-" + manifest.ID + ".bak",
		BackupIdentity: identity,
		BackupSize:     4294967295,
	}
	lease, err := store.ReserveReceiver(t.Context(), record, t.TempDir(), identity, ".px-"+manifest.ID+".put")
	if err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(manifest.ID, lease)
	loaded, exists, err := store.Load(t.Context(), "receive", manifest.ID)
	if err != nil || !exists {
		t.Fatalf("load exists=%t err=%v", exists, err)
	}
	if loaded.BackupName != record.BackupName || loaded.BackupIdentity != record.BackupIdentity || loaded.BackupSize != record.BackupSize || loaded.BackupRemoved {
		t.Fatalf("backup evidence=%+v", loaded)
	}
	if _, err := db.Exec(`update put_transfers set state='committed',replaced=1,durability='durability_confirmed',stage_removed=1 where direction='receive' and transfer_id=?`, manifest.ID); err != nil {
		t.Fatal(err)
	}

	second := storeManifest("77777777777777777777777777777777")
	second.SenderID, second.ReceiverID = "peer", "receiver"
	if _, err := store.ReserveReceiver(t.Context(), Record{Manifest: second, PeerLabel: "peer"}, t.TempDir(), identity, ".px-"+second.ID+".put"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("backup bytes did not consume shared quota: %v", err)
	}
}

func TestReceiverBackupRemovalMustPrecedeParentSync(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	manifest := storeManifest("88888888888888888888888888888888")
	manifest.Mode = "replace"
	manifest.SenderID, manifest.ReceiverID = "peer", "receiver"
	identity := "unix1:0000000000000001:0000000000000002"
	record := Record{Manifest: manifest, PeerLabel: "peer", OldIdentity: identity, OldMetadata: "windowsmeta:test", OldUID: 1, OldGID: 1, OldMode: 0o600, BackupName: ".px-" + manifest.ID + ".bak", BackupIdentity: identity, BackupSize: 1}
	lease, err := store.ReserveReceiver(t.Context(), record, t.TempDir(), identity, ".px-"+manifest.ID+".put")
	if err != nil {
		t.Fatal(err)
	}
	defer store.ReleaseReceiver(manifest.ID, lease)
	if err := store.BeginCleanupNotAttempted(t.Context(), manifest.ID, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`update put_transfers set stage_removed=1,parent_synced=1 where direction='receive' and transfer_id=?`, manifest.ID); err == nil {
		t.Fatal("parent sync was recorded before backup removal")
	}
	if _, err := db.Exec(`update put_transfers set stage_removed=1,backup_removed=1 where direction='receive' and transfer_id=?`, manifest.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`update put_transfers set parent_synced=1 where direction='receive' and transfer_id=?`, manifest.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptCurrentIntentAndResolvedStoreSemantics(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	intentID := "99999999999999999999999999999999"
	resolvedID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	identity := "unix1:0000000000000001:0000000000000002"
	insertResolutionRecord(t, db, intentID, "accept_current_intent", identity, time.Time{})
	resolvedAt := time.Now().UTC()
	insertResolutionRecord(t, db, resolvedID, "resolved_accept_current", identity, resolvedAt)

	intent, exists, err := store.Load(t.Context(), "receive", intentID)
	if err != nil || !exists || intent.ResolutionDestinationIdentity != identity || !intent.ResolvedAt.IsZero() {
		t.Fatalf("intent=%+v exists=%t err=%v", intent, exists, err)
	}
	if _, err := db.Exec(`update put_transfers set lease_token=?,lease_expires_at=expires_at where transfer_id=?`, strings.Repeat("b", 64), intentID); err != nil {
		t.Fatal(err)
	}
	if err := store.Startup(t.Context()); err != nil {
		t.Fatal(err)
	}
	intent, exists, err = store.Load(t.Context(), "receive", intentID)
	if err != nil || !exists || intent.State != "accept_current_intent" || intent.ResolutionDestinationIdentity != identity {
		t.Fatalf("recovered intent=%+v exists=%t err=%v", intent, exists, err)
	}
	resolved, exists, err := store.Load(t.Context(), "receive", resolvedID)
	if err != nil || !exists || resolved.ResolutionDestinationIdentity != identity || resolved.ResolvedAt.Unix() != resolvedAt.Unix() {
		t.Fatalf("resolved=%+v exists=%t err=%v", resolved, exists, err)
	}
	blocking, err := store.HasBlocking(t.Context(), "home")
	if err != nil || !blocking {
		t.Fatalf("intent blocking=%t err=%v", blocking, err)
	}
	if _, err := store.Abandon(t.Context(), "home", intentID); !errors.Is(err, ErrNotAbandonable) {
		t.Fatalf("intent abandon error=%v", err)
	}
	if _, err := store.Abandon(t.Context(), "home", resolvedID); !errors.Is(err, ErrNotAbandonable) {
		t.Fatalf("resolved abandon error=%v", err)
	}
	ids, err := store.CompletionIDs(t.Context(), "home", "resolve", "", "", 64)
	if err != nil || len(ids) != 1 || ids[0] != intentID {
		t.Fatalf("resolve completion IDs=%v err=%v", ids, err)
	}
	created, expired := time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	if _, err := db.Exec(`update put_transfers set created_at=?,expires_at=? where transfer_id=?`, created, expired, intentID); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireSettled(t.Context(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(t.Context(), "receive", intentID); err != nil || !exists {
		t.Fatalf("expired intent exists=%t err=%v", exists, err)
	}
	if _, err := db.Exec(`delete from put_transfers where transfer_id=?`, intentID); err != nil {
		t.Fatal(err)
	}
	blocking, err = store.HasBlocking(t.Context(), "home")
	if err != nil || blocking {
		t.Fatalf("resolved blocking=%t err=%v", blocking, err)
	}

	if _, err := db.Exec(`update put_transfers set created_at=?,expires_at=? where transfer_id=?`, created, expired, resolvedID); err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireSettled(t.Context(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(t.Context(), "receive", resolvedID); err != nil || exists {
		t.Fatalf("expired resolved row exists=%t err=%v", exists, err)
	}
}

func TestResolvedAcceptCurrentReleasesReceiverQuota(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		size  int64
	}{
		{name: "bytes", count: 4, size: MaxFileBytes},
		{name: "rows", count: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			store := NewStore(func() *sql.DB { return db })
			identity := "unix1:0000000000000001:0000000000000002"
			for index := range test.count {
				id := fmt.Sprintf("%032x", index+1)
				insertOutcomeUnknownRecord(t, db, id, identity, test.size)
			}
			manifest := storeManifest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			manifest.SenderID, manifest.ReceiverID = "peer", "receiver"
			if _, err := store.ReserveReceiver(t.Context(), Record{Manifest: manifest, PeerLabel: "peer"}, t.TempDir(), identity, ".px-"+manifest.ID+".put"); !errors.Is(err, ErrCapacity) {
				t.Fatalf("unresolved rows did not consume %s quota: %v", test.name, err)
			}
			resolvedAt := time.Now().UTC().Unix()
			if _, err := db.Exec(`update put_transfers set state='accept_current_intent',resolution_destination_identity=? where transfer_id=?`, identity, fmt.Sprintf("%032x", 1)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`update put_transfers set state='resolved_accept_current',parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,stage_removed=0,parent_synced=0,resolved_at=? where transfer_id=?`, resolvedAt, fmt.Sprintf("%032x", 1)); err != nil {
				t.Fatal(err)
			}
			lease, err := store.ReserveReceiver(t.Context(), Record{Manifest: manifest, PeerLabel: "peer"}, t.TempDir(), identity, ".px-"+manifest.ID+".put")
			if err != nil {
				t.Fatalf("resolved row retained %s quota: %v", test.name, err)
			}
			store.ReleaseReceiver(manifest.ID, lease)
		})
	}
}

func insertOutcomeUnknownRecord(t *testing.T, db *sql.DB, id, identity string, size int64) {
	t.Helper()
	digest := fmt.Sprintf("%064x", 1)
	stageName := ".px-" + id + ".put"
	now := time.Now().UTC().Unix()
	if _, err := db.Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,stage_identity,state,acknowledged_bytes,created_at,updated_at,expires_at,next_retry_at) values('receive',?,'home','peer','receiver','peer','result','create',?, ?,32768,8,7,'/put',?,?,?,'outcome_unknown',?, ?,?,?,?)`, id, size, digest, identity, stageName, identity, size, now, now, now+int64(Lifetime/time.Second), now); err != nil {
		t.Fatal(err)
	}
}

func insertResolutionRecord(t *testing.T, db *sql.DB, id, state, identity string, resolvedAt time.Time) {
	t.Helper()
	insertOutcomeUnknownRecord(t, db, id, identity, 1)
	if _, err := db.Exec(`update put_transfers set state='accept_current_intent',resolution_destination_identity=? where transfer_id=?`, identity, id); err != nil {
		t.Fatal(err)
	}
	if state == "accept_current_intent" {
		return
	}
	if _, err := db.Exec(`update put_transfers set state='resolved_accept_current',parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,stage_removed=0,parent_synced=0,resolved_at=? where transfer_id=?`, resolvedAt.Unix(), id); err != nil {
		t.Fatal(err)
	}
}

func storeManifest(id string) Manifest {
	return Manifest{Version: protocolVersion, ID: id, Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: "result", Mode: "create", Size: 1, SHA256: fmt.Sprintf("%064x", 1), ChunkSize: ChunkSize, AckWindow: AckWindow, RootRevision: 7}
}
