package transfer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
)

func TestInterruptedTransferRestartsFromZeroAfterBothStoreRestarts(t *testing.T) {
	senderStore, senderDB, senderRoot := newResumeTestStore(t)
	receiverStore, receiverDB, receiverRoot := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "large.bin")
	content := []byte(strings.Repeat("resumable-transfer-data", 100_000))
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := t.TempDir()
	offered := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	broken := &failAfterChunks{Channel: sender, remaining: 10}
	received := make(chan error, 1)
	go func() {
		cfg := receiveConfig(receiverStore, inbox, nil)
		cfg.OfferedRoot = offered
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- err
	}()
	var events []ResumeEvent
	sendCfg := sendConfig(senderStore, source, func(event ResumeEvent) { events = append(events, event) })
	sendCfg.Visibility = VisibilityPublic
	_, sendErr := SendResumable(ctx, broken, sendCfg)
	if sendErr == nil {
		t.Fatal("interrupted send succeeded")
	}
	firstID := events[0].TransferID
	cancel()
	<-received
	receiverRecord, exists, err := receiverStore.load(context.Background(), "receive", firstID)
	if err != nil || !exists || receiverRecord.Offset != 0 {
		t.Fatalf("interrupted receiver state = %+v, exists=%t, err=%v", receiverRecord, exists, err)
	}

	senderStore = NewResumeStore(senderDB.DB, senderRoot)
	receiverStore = NewResumeStore(receiverDB.DB, receiverRoot)
	senderStore.SetObservationWriter(func(context.Context, TransferObservation) error { return nil }, func(context.Context, *sql.Tx, TransferObservation) error { return nil })
	receiverStore.SetObservationWriter(func(context.Context, TransferObservation) error { return nil }, func(context.Context, *sql.Tx, TransferObservation) error { return nil })
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sender, receiver = newMemoryPipe()
	received = make(chan error, 1)
	go func() {
		cfg := receiveConfig(receiverStore, inbox, nil)
		cfg.OfferedRoot = offered
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- err
	}()
	events = nil
	sendCfg = sendConfig(senderStore, source, func(event ResumeEvent) { events = append(events, event) })
	sendCfg.Visibility = VisibilityPublic
	result, err := SendResumable(ctx, sender, sendCfg)
	if err != nil || <-received != nil {
		t.Fatalf("resumed transfer: %v", err)
	}
	if result.Bytes != int64(len(content)) || events[0].TransferID != firstID || !hasResumeEvent(events, "resumed") {
		t.Fatalf("result = %+v, events = %+v", result, events)
	}
	actual, err := os.ReadFile(filepath.Join(offered, "large.bin"))
	if err != nil || string(actual) != string(content) {
		t.Fatalf("destination differs: %v", err)
	}
}

func TestSenderJournalFailurePrecedesCommitEventAckAndCleanup(t *testing.T) {
	senderStore, senderDB, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	journalErr := errors.New("journal unavailable")
	senderStore.SetObservationWriter(func(context.Context, TransferObservation) error { return journalErr }, func(context.Context, *sql.Tx, TransferObservation) error { return nil })
	source := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(source, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- err
	}()
	var events []ResumeEvent
	result, err := SendResumable(ctx, sender, sendConfig(senderStore, source, func(event ResumeEvent) { events = append(events, event) }))
	if !errors.Is(err, journalErr) || result.Name != "file.txt" || hasResumeEvent(events, "committed") {
		t.Fatalf("result=%+v events=%+v err=%v", result, events, err)
	}
	var rows int
	if err := senderDB.DB().QueryRow(`select count(*) from transfer_resumes where direction='send'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("sender recovery rows = %d, %v", rows, err)
	}
	cancel()
	<-received
}

func TestReceiverJournalFailureRollsBackPendingConfirmationTransition(t *testing.T) {
	store, db, _ := newResumeTestStore(t)
	journalErr := errors.New("journal unavailable")
	store.SetObservationWriter(func(context.Context, TransferObservation) error { return nil }, func(context.Context, *sql.Tx, TransferObservation) error { return journalErr })
	now := time.Now().UTC()
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("a", 64), Context: "home", SenderID: "sender", Name: "file", Visibility: VisibilityPrivate, Size: 1, SHA256: strings.Repeat("0", 64), ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}, Token: "token", PeerLabel: "sender", State: "committing", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := db.DB().Exec(`insert into transfer_resumes(direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at,manifest_version,visibility) values('receive',?,'home','sender','sender','file',1,?,32768,8,'token',1,'committing',?,?,?,3,'private')`, record.ID, record.SHA256, now.Unix(), now.Unix(), record.ExpiresAt.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := store.markCommittedRecord(context.Background(), record); !errors.Is(err, journalErr) {
		t.Fatalf("mark committed = %v", err)
	}
	var state string
	if err := db.DB().QueryRow(`select state from transfer_resumes where direction='receive' and transfer_id=?`, record.ID).Scan(&state); err != nil || state != "committing" {
		t.Fatalf("state = %q, %v", state, err)
	}
}

func TestReceiverJournalFailureWithholdsEventAckAndCleanup(t *testing.T) {
	senderStore, senderDB, _ := newResumeTestStore(t)
	receiverStore, receiverDB, _ := newResumeTestStore(t)
	journalErr := errors.New("journal unavailable")
	receiverStore.SetObservationWriter(func(context.Context, TransferObservation) error { return nil }, func(context.Context, *sql.Tx, TransferObservation) error { return journalErr })
	source := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(source, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	sender, receiver := newMemoryPipe()
	type receiveResult struct {
		events []ResumeEvent
		err    error
	}
	received := make(chan receiveResult, 1)
	go func() {
		var events []ResumeEvent
		cfg := receiveConfig(receiverStore, inbox, nil)
		cfg.Progress = func(event ResumeEvent) { events = append(events, event) }
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- receiveResult{events: events, err: err}
	}()
	var senderEvents []ResumeEvent
	result, sendErr := SendResumable(ctx, sender, sendConfig(senderStore, source, func(event ResumeEvent) { senderEvents = append(senderEvents, event) }))
	receiverResult := <-received
	if !errors.Is(receiverResult.err, journalErr) || hasResumeEvent(receiverResult.events, "committed") || hasResumeEvent(senderEvents, "committed") || result.Name != "" || sendErr == nil {
		t.Fatalf("receiver events=%+v err=%v sender events=%+v result=%+v err=%v", receiverResult.events, receiverResult.err, senderEvents, result, sendErr)
	}
	var receiverState string
	if err := receiverDB.DB().QueryRow(`select state from transfer_resumes where direction='receive'`).Scan(&receiverState); err != nil || receiverState != "committing" {
		t.Fatalf("receiver state = %q, %v", receiverState, err)
	}
	var senderRows int
	if err := senderDB.DB().QueryRow(`select count(*) from transfer_resumes where direction='send'`).Scan(&senderRows); err != nil || senderRows != 1 {
		t.Fatalf("sender rows = %d, %v", senderRows, err)
	}
	if _, err := os.Stat(filepath.Join(inbox, "home", "sender", "file.txt")); err != nil {
		t.Fatalf("published file missing after journal failure: %v", err)
	}
}

func TestCountsExcludeActiveAndExpiredRetryState(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	activeID := strings.Repeat("a", 64)
	retryID := strings.Repeat("b", 64)
	expiredID := strings.Repeat("c", 64)
	for _, value := range []struct {
		id      string
		expires time.Time
	}{
		{id: activeID, expires: now.Add(time.Hour)},
		{id: retryID, expires: now.Add(time.Hour)},
		{id: expiredID, expires: now.Add(-time.Hour)},
	} {
		if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('send',?,'home','peer-id','peer','file',1,'sha',1,1,'token',0,'transferring',?,?,?)`, value.id, now.Unix(), now.Unix(), value.expires.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	store.activeMu.Lock()
	store.active["send:"+activeID] = &activeResume{direction: "send", record: resumeRecord{resumeManifest: resumeManifest{ID: activeID, Context: "home"}, State: "transferring", ExpiresAt: now.Add(time.Hour)}}
	store.activeMu.Unlock()
	counts, err := store.Counts(context.Background(), "home", now)
	if err != nil || counts.Active != 1 || counts.Retryable != 1 {
		t.Fatalf("counts = %+v, %v", counts, err)
	}
	show, err := store.CompletionIDs(context.Background(), "home", "show", "", "", 64, now)
	if err != nil || !slices.Equal(show, []string{activeID, retryID}) {
		t.Fatalf("show completion = %v, %v", show, err)
	}
	retry, err := store.CompletionIDs(context.Background(), "home", "retry", "peer", "", 64, now)
	if err != nil || !slices.Equal(retry, []string{retryID}) {
		t.Fatalf("retry completion = %v, %v", retry, err)
	}
	cancel, err := store.CompletionIDs(context.Background(), "home", "cancel", "", "", 64, now)
	if err != nil || !slices.Equal(cancel, []string{activeID}) {
		t.Fatalf("cancel completion = %v, %v", cancel, err)
	}
	var expiredRows int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id=?`, expiredID).Scan(&expiredRows); err != nil || expiredRows != 1 {
		t.Fatalf("completion mutated expired row: count=%d err=%v", expiredRows, err)
	}
}

func TestCompletionAppliesEligibilityBeforeLimit(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	for index := 0; index < MaxInventoryLimit-1; index++ {
		id := fmt.Sprintf("%064x", index)
		if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('receive',?,'home','peer-id','peer','file',1,'sha',1,1,'token',0,'committed',?,?,?)`, id, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	eligible := strings.Repeat("f", 64)
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('send',?,'home','peer-id','peer','file',1,'sha',1,1,'token',0,'transferring',?,?,?)`, eligible, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	ids, err := store.CompletionIDs(context.Background(), "home", "retry", "peer", "", MaxInventoryLimit, now)
	if err != nil || !slices.Equal(ids, []string{eligible}) {
		t.Fatalf("retry completion = %v, %v", ids, err)
	}
	// Shared sender recovery admission now caps this table plus put rows at 64.
	for index := 0; index < MaxInventoryLimit-1; index++ {
		id := fmt.Sprintf("%064x", index)
		if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction,transfer_id,context_name,peer_device_id,peer_label,destination_name,source_size,source_sha256,chunk_size,ack_window,resume_token,acknowledged_bytes,state,created_at,updated_at,expires_at) values ('send',?,'home','peer-id','peer','file',1,'sha',1,1,'token',0,'transferring',?,?,?)`, id, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"show", "delete"} {
		ids, err := store.CompletionIDs(context.Background(), "home", action, "", "", MaxInventoryLimit, now)
		if err != nil || !slices.Equal(ids, []string{eligible}) {
			t.Fatalf("%s completion = %v, %v", action, ids, err)
		}
	}
}

func TestSendAdmissionExpiresSafePutSenderRows(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	created, expired := time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	for index := range MaxSendResumeStates {
		id := fmt.Sprintf("%032x", index+1)
		_, err := databaseStore.DB().Exec(`insert into put_transfers(direction,transfer_id,context_name,peer_device_id,local_device_id,peer_label,destination,mode,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,state,created_at,updated_at,expires_at,next_retry_at) values('send',?,'home','receiver','sender','receiver','result','create',1,?,32768,8,7,'/source','transferring',?,?,?,?)`, id, strings.Repeat("0", 64), created, created, expired, created)
		if err != nil {
			t.Fatal(err)
		}
	}
	store.SetSharedSenderMaintenance(func(ctx context.Context, now time.Time) error {
		_, err := databaseStore.DB().ExecContext(ctx, `delete from put_transfers where direction='send' and expires_at<=? and lease_token is null`, now.Unix())
		return err
	})
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("f", 64), Context: "home", ReceiverID: "receiver", Name: "result", Visibility: VisibilityPrivate, Size: 1, SHA256: strings.Repeat("0", 64), ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}, PeerLabel: "receiver", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.saveSend(t.Context(), record, "/source", false); err != nil {
		t.Fatalf("send admission remained blocked: %v", err)
	}
	var putRows int
	if err := databaseStore.DB().QueryRow(`select count(*) from put_transfers where direction='send'`).Scan(&putRows); err != nil || putRows != 0 {
		t.Fatalf("put sender rows=%d err=%v", putRows, err)
	}
}

func TestSharedSenderExpiryPreservesActiveTransfer(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("e", 64)
	insertResumeRecord(t, databaseStore, "send", id, "transferring", "/source", false, now.Add(-2*time.Hour), now.Add(-time.Hour))
	store.activeMu.Lock()
	store.active["send:"+id] = &activeResume{direction: "send", record: resumeRecord{resumeManifest: resumeManifest{ID: id}, State: "transferring"}}
	store.activeMu.Unlock()
	if err := store.ExpireSenders(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where direction='send' and transfer_id=?`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active sender rows=%d err=%v", count, err)
	}
}

func TestPublicTransferPublishesFlatAndHasDistinctIdentity(t *testing.T) {
	sourceRoot := t.TempDir()
	source := filepath.Join(sourceRoot, "source.bin")
	content := []byte("public-content")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	senderStore, _, _ := newResumeTestStore(t)
	privateCfg := sendConfig(senderStore, source, nil)
	privateCfg.Name = "artifact.bin"
	privateRecord, privateFile, err := prepareSend(context.Background(), privateCfg)
	if err != nil {
		t.Fatal(err)
	}
	privateFile.Close()
	publicCfg := privateCfg
	publicCfg.Visibility = VisibilityPublic
	publicRecord, publicFile, err := prepareSend(context.Background(), publicCfg)
	if err != nil {
		t.Fatal(err)
	}
	publicFile.Close()
	if privateRecord.ID == publicRecord.ID || privateRecord.Visibility != VisibilityPrivate || publicRecord.Visibility != VisibilityPublic {
		t.Fatalf("private = %+v, public = %+v", privateRecord.resumeManifest, publicRecord.resumeManifest)
	}

	receiverStore, _, _ := newResumeTestStore(t)
	inbox, offered := t.TempDir(), t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		cfg := receiveConfig(receiverStore, inbox, nil)
		cfg.OfferedRoot = offered
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- err
	}()
	if _, err := SendResumable(ctx, sender, publicCfg); err != nil || <-received != nil {
		t.Fatalf("public transfer failed: %v", err)
	}
	actual, err := os.ReadFile(filepath.Join(offered, "artifact.bin"))
	if err != nil || string(actual) != string(content) {
		t.Fatalf("public destination = %q, %v", actual, err)
	}
	if _, err := os.Stat(filepath.Join(inbox, "home", "sender", "artifact.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public transfer wrote inbox destination: %v", err)
	}
}

func TestPublicTransferRejectsExistingAndReservedDestination(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	senderStore, _, _ := newResumeTestStore(t)
	reserved := sendConfig(senderStore, source, nil)
	reserved.Name, reserved.Visibility = ".PX-internal", VisibilityPublic
	if _, file, err := prepareSend(context.Background(), reserved); err == nil {
		file.Close()
		t.Fatal("reserved public destination succeeded")
	}

	receiverStore, _, _ := newResumeTestStore(t)
	inbox, offered := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(offered, "Artifact.bin"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		cfg := receiveConfig(receiverStore, inbox, nil)
		cfg.OfferedRoot = offered
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- err
	}()
	cfg := sendConfig(senderStore, source, nil)
	cfg.Name, cfg.Visibility = "artifact.bin", VisibilityPublic
	if _, sendErr := SendResumable(ctx, sender, cfg); sendErr == nil || <-received == nil {
		t.Fatalf("existing public destination errors = %v", sendErr)
	}
	actual, err := os.ReadFile(filepath.Join(offered, "Artifact.bin"))
	if err != nil || string(actual) != "existing" {
		t.Fatalf("existing public destination changed: %q, %v", actual, err)
	}
}

func TestPrivateResumableTransferRejectsExistingDestination(t *testing.T) {
	for _, collision := range []string{"file", "symlink"} {
		t.Run(collision, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "source.bin")
			if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
			inbox := t.TempDir()
			directory := filepath.Join(inbox, "home", "sender")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "artifact.bin")
			target := destination
			if collision == "symlink" {
				target = filepath.Join(t.TempDir(), "target.bin")
			}
			if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			if collision == "symlink" {
				if err := os.Symlink(target, destination); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}

			senderStore, _, _ := newResumeTestStore(t)
			receiverStore, _, _ := newResumeTestStore(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sender, receiver := newMemoryPipe()
			received := make(chan error, 1)
			go func() {
				_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, inbox, nil))
				received <- err
			}()
			cfg := sendConfig(senderStore, source, nil)
			cfg.Name = "artifact.bin"
			_, sendErr := SendResumable(ctx, sender, cfg)
			if receiveErr := <-received; sendErr == nil || receiveErr == nil {
				t.Fatalf("existing private destination errors = %v, %v", sendErr, receiveErr)
			}
			actual, err := os.ReadFile(target)
			if err != nil || string(actual) != "existing" {
				t.Fatalf("existing destination changed: %q, %v", actual, err)
			}
			if collision == "symlink" {
				info, err := os.Lstat(destination)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("destination symlink changed: %v, %v", info, err)
				}
			}
		})
	}
}

func TestConcurrentPrivateResumableTransfersPublishOnlyOnce(t *testing.T) {
	receiverStore, _, _ := newResumeTestStore(t)
	inbox := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type outcome struct {
		content    string
		sendErr    error
		receiveErr error
	}
	outcomes := make(chan outcome, 2)
	start := make(chan struct{})
	type attempt struct {
		content string
		source  string
		store   *ResumeStore
	}
	attempts := make([]attempt, 0, 2)
	for _, content := range []string{"first", "second"} {
		source := filepath.Join(t.TempDir(), content+".bin")
		if err := os.WriteFile(source, []byte(strings.Repeat(content, 100_000)), 0o600); err != nil {
			t.Fatal(err)
		}
		store, _, _ := newResumeTestStore(t)
		attempts = append(attempts, attempt{content: content, source: source, store: store})
	}
	for _, attempt := range attempts {
		attempt := attempt
		go func() {
			sender, receiver := newMemoryPipe()
			received := make(chan error, 1)
			<-start
			go func() {
				_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, inbox, nil))
				received <- err
			}()
			cfg := sendConfig(attempt.store, attempt.source, nil)
			cfg.Name = "collision.bin"
			_, sendErr := SendResumable(ctx, sender, cfg)
			outcomes <- outcome{content: attempt.content, sendErr: sendErr, receiveErr: <-received}
		}()
	}
	close(start)

	succeeded := ""
	for range 2 {
		result := <-outcomes
		if result.sendErr == nil && result.receiveErr == nil {
			if succeeded != "" {
				t.Fatalf("both concurrent transfers published: %q and %q", succeeded, result.content)
			}
			succeeded = result.content
		}
	}
	if succeeded == "" {
		t.Fatal("neither concurrent transfer published")
	}
	actual, err := os.ReadFile(filepath.Join(inbox, "home", "sender", "collision.bin"))
	want := strings.Repeat(succeeded, 100_000)
	if err != nil || string(actual) != want {
		t.Fatalf("published destination differs: size %d, %v", len(actual), err)
	}
}

func TestRetryRejectsChangedSource(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte(strings.Repeat("a", ResumeChunkSize*10)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	broken := &failAfterChunks{Channel: sender, remaining: ResumeAckWindow + 1}
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- err
	}()
	var id string
	_, _ = SendResumable(ctx, broken, sendConfig(senderStore, source, func(event ResumeEvent) { id = event.TransferID }))
	cancel()
	<-received
	if err := os.WriteFile(source, []byte(strings.Repeat("b", ResumeChunkSize*10)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := SendResumable(context.Background(), &scriptedChannel{}, ResumeSendConfig{TransferID: id, Context: "home", SenderID: "sender-id", ReceiverID: "receiver-id", Store: senderStore})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("retry error = %v", err)
	}
}

func TestResumeRejectsStaleToken(t *testing.T) {
	senderStore, senderDB, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte(strings.Repeat("token-data", ResumeChunkSize)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	sender, receiver := newMemoryPipe()
	broken := &failAfterChunks{Channel: sender, remaining: ResumeAckWindow + 1}
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- err
	}()
	var id string
	_, _ = SendResumable(ctx, broken, sendConfig(senderStore, source, func(event ResumeEvent) { id = event.TransferID }))
	cancel()
	<-received
	if _, err := senderDB.DB().Exec(`update transfer_resumes set resume_token = 'stale-token' where direction = 'send' and transfer_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver = newMemoryPipe()
	received = make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- err
	}()
	_, sendErr := SendResumable(ctx, sender, sendConfig(senderStore, source, nil))
	if receiveErr := <-received; sendErr == nil || receiveErr == nil || !strings.Contains(sendErr.Error(), "stale") {
		t.Fatalf("send error = %v, receive error = %v", sendErr, receiveErr)
	}
}

func TestResumeRejectsDiskPressure(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), func(string) (uint64, error) { return 0, nil }))
		received <- err
	}()
	_, sendErr := SendResumable(ctx, sender, sendConfig(senderStore, source, nil))
	if receiveErr := <-received; sendErr == nil || receiveErr == nil || !strings.Contains(sendErr.Error(), "spool space") {
		t.Fatalf("send error = %v, receive error = %v", sendErr, receiveErr)
	}
}

func TestResumeRecoversLostCommitResponse(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte(strings.Repeat("commit-response", 10_000)), 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	sender, receiver := newMemoryPipe()
	lost := &failControlType{Channel: receiver, controlType: "committed"}
	type outcome struct {
		result Result
		err    error
	}
	receivedOutcome := make(chan outcome, 1)
	go func() {
		result, err := ReceiveResumable(ctx, lost, receiveConfig(receiverStore, inbox, nil))
		receivedOutcome <- outcome{result: result, err: err}
	}()
	if _, err := SendResumable(ctx, sender, sendConfig(senderStore, source, nil)); err == nil {
		t.Fatal("send succeeded despite lost commit response")
	}
	if received := <-receivedOutcome; received.err == nil || received.result.Bytes == 0 {
		t.Fatalf("receiver lost-commit outcome = %+v, %v", received.result, received.err)
	}
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver = newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, inbox, nil))
		received <- err
	}()
	result, err := SendResumable(ctx, sender, sendConfig(senderStore, source, nil))
	if err != nil || <-received != nil || result.Bytes == 0 {
		t.Fatalf("commit recovery result = %+v, %v", result, err)
	}
}

func TestResumeReconcilesDurablePublicCommitAfterRootRevisionRebind(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, receiverDB, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	content := []byte(strings.Repeat("commit-boundary", 10_000))
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sendCfg := sendConfig(senderStore, source, nil)
	sendCfg.Name, sendCfg.Visibility = "public.bin", VisibilityPublic
	record, file, err := prepareSend(context.Background(), sendCfg)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	record.Token, record.Offset = "resume-token", record.Size
	if err := senderStore.saveSend(context.Background(), record, source, false); err != nil {
		t.Fatal(err)
	}
	receiveRecord := record
	receiveRecord.PeerLabel, receiveRecord.State = "sender", "transferring"
	receiveRecord.OfferedRootRevision = 2
	if err := receiverStore.reserveReceive(context.Background(), receiveRecord); err != nil {
		t.Fatal(err)
	}
	if _, err := receiverDB.DB().Exec(`update transfer_resumes set state = 'committing', acknowledged_bytes = ? where direction = 'receive' and transfer_id = ?`, record.Size, record.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiverStore.partialPath(record.ID), content, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox, offered := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(offered, record.Name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	received := make(chan error, 1)
	go func() {
		cfg := receiveConfig(receiverStore, inbox, func(string) (uint64, error) { return 0, nil })
		cfg.OfferedRoot = offered
		cfg.OfferedRootRevision = 2
		_, err := ReceiveResumable(ctx, receiver, cfg)
		received <- err
	}()
	result, err := SendResumable(ctx, sender, sendCfg)
	if err != nil || <-received != nil || result.Bytes != int64(len(content)) {
		t.Fatalf("reconciled result = %+v, %v", result, err)
	}
	var count int
	if err := receiverDB.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'receive' and transfer_id = ?`, record.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("acknowledged receiver state count = %d, %v", count, err)
	}
	if _, err := os.Stat(receiverStore.partialPath(record.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciled partial remains: %v", err)
	}
}

func TestSendReportsCommitBeforeFinalAcknowledgement(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, _, _ := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte("committed"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	sender, receiver := newMemoryPipe()
	lostAck := &failControlType{Channel: sender, controlType: "ack"}
	type outcome struct {
		result Result
		err    error
	}
	received := make(chan outcome, 1)
	go func() {
		result, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- outcome{result: result, err: err}
	}()
	terminal := ResumeEvent{}
	result, err := SendResumable(ctx, lostAck, sendConfig(senderStore, source, func(event ResumeEvent) { terminal = event }))
	if err == nil || result.Bytes == 0 || terminal.State != "committed" {
		t.Fatalf("sender outcome = %+v, %v, event %+v", result, err, terminal)
	}
	receiverOutcome := <-received
	if receiverOutcome.err == nil || receiverOutcome.result.Bytes == 0 {
		t.Fatalf("receiver outcome = %+v, %v", receiverOutcome.result, receiverOutcome.err)
	}
}

func TestResumeRejectsCorruptChunkAndDeletesPartial(t *testing.T) {
	senderStore, _, _ := newResumeTestStore(t)
	receiverStore, databaseStore, root := newResumeTestStore(t)
	source := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(source, []byte(strings.Repeat("checksum", 20_000)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sender, receiver := newMemoryPipe()
	var once sync.Once
	corrupt := &mutateChannel{Channel: sender, mutate: func(message Message) Message {
		if !message.Text {
			once.Do(func() { message.Data[0] ^= 0xff })
		}
		return message
	}}
	received := make(chan error, 1)
	go func() {
		_, err := ReceiveResumable(ctx, receiver, receiveConfig(receiverStore, t.TempDir(), nil))
		received <- err
	}()
	_, sendErr := SendResumable(ctx, corrupt, sendConfig(senderStore, source, nil))
	if receiveErr := <-received; sendErr == nil || receiveErr == nil || !strings.Contains(sendErr.Error(), "checksum") {
		t.Fatalf("send error = %v, receive error = %v", sendErr, receiveErr)
	}
	var count int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'receive'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("receive resume count = %d, %v", count, err)
	}
	partials, err := filepath.Glob(filepath.Join(root, "*.part"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partials = %v, %v", partials, err)
	}
}

func TestResumeGCRemovesExpiredPartialAndStdinSpool(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	partial := filepath.Join(root, strings.Repeat("a", 64)+".part")
	spool := filepath.Join(root, ".stdin-test.spool")
	for _, path := range []string{partial, spool} {
		if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Add(-time.Hour).Unix()
	base := `insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at) values (?, ?, 'home', 'peer', 'peer', 'file', 7, ?, ?, ?, 'token', 0, ?, ?, 'transferring', ?, ?, ?)`
	if _, err := databaseStore.DB().Exec(base, "receive", strings.Repeat("a", 64), strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, nil, 0, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(base, "send", strings.Repeat("b", 64), strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, spool, 1, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{partial, spool} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired file remains: %s", path)
		}
	}
}

func TestResumeGCRetainsExpiredPublicPublicationEvidence(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	for index, state := range []string{"transferring", "committing", "committed_pending_confirmation", "committed"} {
		id := fmt.Sprintf("%064x", index+1)
		if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, ?, ?, 'token', 0, ?, ?, ?, ?, 3, 'public')`, id, strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, state, now.Add(-2*time.Hour).Unix(), now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var unresolved, committed int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'receive' and visibility = 'public' and state != 'committed'`).Scan(&unresolved); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'receive' and visibility = 'public' and state = 'committed'`).Scan(&committed); err != nil {
		t.Fatal(err)
	}
	if unresolved != 2 || committed != 0 {
		t.Fatalf("public receive rows after GC = unresolved %d, committed %d", unresolved, committed)
	}
}

func TestLegacyPrivateResumeStatePreservesV2ManifestIdentity(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	manifest := resumeManifest{Version: 2, Context: "home", SenderID: "sender-id", ReceiverID: "receiver-id", Name: "legacy.bin", Size: 7, SHA256: strings.Repeat("0", 64), ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}
	manifest.ID = manifestID(manifest)
	now := time.Now().Unix()
	_, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at) values ('send', ?, 'home', ?, 'receiver', ?, ?, ?, ?, ?, 'token', 0, '/source', 0, 'transferring', ?, ?, ?)`, manifest.ID, manifest.ReceiverID, manifest.Name, manifest.Size, manifest.SHA256, manifest.ChunkSize, manifest.AckWindow, now, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	record, exists, err := store.load(context.Background(), "send", manifest.ID)
	record.SenderID = manifest.SenderID
	if err != nil || !exists || record.Version != 2 || record.Visibility != "" || record.ID != manifestID(record.resumeManifest) {
		t.Fatalf("legacy record = %+v, exists %v, error %v", record, exists, err)
	}
}

func TestResumeStateBoundsAndManifestIdentity(t *testing.T) {
	store, _, _ := newResumeTestStore(t)
	store.quota = 1
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("a", 64), Context: "home", SenderID: "sender-id", ReceiverID: "receiver-id", Name: "file", Visibility: VisibilityPrivate, Size: 2, SHA256: strings.Repeat("0", 64), ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}, Token: "token", PeerLabel: "sender", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.reserveReceive(context.Background(), record); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("quota error = %v", err)
	}
	_, release, err := store.acquire(context.Background(), "receive", record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.acquire(context.Background(), "receive", record); err == nil {
		t.Fatal("duplicate active transfer succeeded")
	}
	release()
	manifest := record.resumeManifest
	manifest.ID = manifestID(manifest)
	if err := validateManifest(manifest, receiveConfig(store, t.TempDir(), nil)); err != nil {
		t.Fatal(err)
	}
	mismatched := receiveConfig(store, t.TempDir(), nil)
	mismatched.SenderID = "different-peer"
	if err := validateManifest(manifest, mismatched); err == nil {
		t.Fatal("mismatched authenticated peer was accepted")
	}
	tampered := manifest
	tampered.Visibility = VisibilityPublic
	if err := validateManifest(tampered, receiveConfig(store, t.TempDir(), nil)); err == nil {
		t.Fatal("visibility changed without changing transfer identity")
	}
	manifest.ChunkSize++
	manifest.ID = manifestID(manifest)
	if err := validateManifest(manifest, receiveConfig(store, t.TempDir(), nil)); err == nil {
		t.Fatal("incompatible chunk policy was accepted")
	}
	manifest.ChunkSize = ResumeChunkSize
	manifest.Visibility = "shared"
	manifest.ID = manifestID(manifest)
	if err := validateManifest(manifest, receiveConfig(store, t.TempDir(), nil)); err == nil {
		t.Fatal("unknown visibility was accepted")
	}
}

func TestReceiveResumeQuotaIncludesPendingConfirmationAndCapsStates(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	for index := 0; index < MaxResumeStates; index++ {
		state := "transferring"
		if index == MaxResumeStates-1 {
			state = "committed_pending_confirmation"
		}
		insertResumeRecord(t, databaseStore, "receive", fmt.Sprintf("%064x", index+1), state, "", false, now, now.Add(time.Hour))
	}
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("a", 64), Context: "home", SenderID: "sender-id", Name: "file", Visibility: VisibilityPrivate, Size: 1, SHA256: strings.Repeat("0", 64), ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}, Token: "token", PeerLabel: "sender", ExpiresAt: now.Add(time.Hour)}
	if err := store.reserveReceive(context.Background(), record); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("state bound error = %v", err)
	}
	if _, err := databaseStore.DB().Exec(`update transfer_resumes set state = 'committed' where transfer_id = ?`, fmt.Sprintf("%064x", MaxResumeStates)); err != nil {
		t.Fatal(err)
	}
	if err := store.reserveReceive(context.Background(), record); err != nil {
		t.Fatalf("confirmed state consumed quota: %v", err)
	}

	byteStore, byteDatabase, _ := newResumeTestStore(t)
	byteStore.quota = 21
	insertResumeRecord(t, byteDatabase, "receive", strings.Repeat("b", 64), "committed_pending_confirmation", "", false, now, now.Add(time.Hour))
	record.ID, record.Size = strings.Repeat("c", 64), 2
	if err := byteStore.reserveReceive(context.Background(), record); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("pending byte quota error = %v", err)
	}
	if _, err := byteDatabase.DB().Exec(`update transfer_resumes set state = 'committed'`); err != nil {
		t.Fatal(err)
	}
	if err := byteStore.reserveReceive(context.Background(), record); err != nil {
		t.Fatalf("confirmed bytes consumed quota: %v", err)
	}
}

func TestSendResumeAdmissionBoundsRowsAndRetainedSpools(t *testing.T) {
	now := time.Now().UTC()
	t.Run("row capacity and existing retry", func(t *testing.T) {
		store, databaseStore, _ := newResumeTestStore(t)
		for index := range MaxSendResumeStates {
			insertResumeRecord(t, databaseStore, "send", fmt.Sprintf("%064x", index+1), "transferring", "/source", false, now, now.Add(time.Hour))
		}
		record := sendResumeRecord(strings.Repeat("f", 64), 20, now)
		if err := store.saveSend(context.Background(), record, "/source", false); !errors.Is(err, ErrSendResumeCapacity) {
			t.Fatalf("send row capacity error = %v", err)
		}
		record.ID = fmt.Sprintf("%064x", 1)
		if err := store.saveSend(context.Background(), record, "/source", false); err != nil {
			t.Fatalf("existing send update at capacity: %v", err)
		}
	})

	t.Run("spool bytes and non-growing legacy state", func(t *testing.T) {
		store, databaseStore, root := newResumeTestStore(t)
		store.sendQuota = 10
		spool := filepath.Join(root, ".stdin-existing.spool")
		insertResumeRecord(t, databaseStore, "send", strings.Repeat("a", 64), "transferring", spool, true, now, now.Add(time.Hour))
		existing := sendResumeRecord(strings.Repeat("a", 64), 20, now)
		if err := store.saveSend(context.Background(), existing, spool, true); err != nil {
			t.Fatalf("non-growing legacy spool update: %v", err)
		}
		additional := sendResumeRecord(strings.Repeat("b", 64), 1, now)
		if err := store.saveSend(context.Background(), additional, filepath.Join(root, ".stdin-new.spool"), true); !errors.Is(err, ErrSendResumeCapacity) {
			t.Fatalf("send spool capacity error = %v", err)
		}
		if err := store.saveSend(context.Background(), additional, "/source", false); err != nil {
			t.Fatalf("non-spool state worsened legacy spool quota: %v", err)
		}
	})

	t.Run("spool ownership cannot be replaced", func(t *testing.T) {
		store, _, root := newResumeTestStore(t)
		oldSpool := filepath.Join(root, ".stdin-old.spool")
		newSpool := filepath.Join(root, ".stdin-new.spool")
		for _, path := range []string{oldSpool, newSpool} {
			if err := os.WriteFile(path, []byte("identical stdin"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg := sendConfig(store, oldSpool, nil)
		cfg.Name, cfg.StdinSpool = "stdin.bin", true
		record, file, err := prepareSend(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		if err := store.saveSend(context.Background(), record, oldSpool, true); err != nil {
			t.Fatal(err)
		}
		cfg.Source = newSpool
		if _, file, err := prepareSend(context.Background(), cfg); !errors.Is(err, ErrSendSpoolOwnership) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("replacement spool preparation error = %v", err)
		}
		if err := store.saveSend(context.Background(), record, newSpool, true); !errors.Is(err, ErrSendSpoolOwnership) {
			t.Fatalf("replacement spool persistence error = %v", err)
		}
		stored, exists, err := store.load(context.Background(), "send", record.ID)
		if err != nil || !exists || stored.SourcePath != oldSpool || !stored.StdinSpool {
			t.Fatalf("stored spool owner = %+v, %v, %v", stored, exists, err)
		}
	})
}

func TestCancelDoesNotWaitForTransferMaintenance(t *testing.T) {
	store, _, _ := newResumeTestStore(t)
	id := strings.Repeat("a", 64)
	operationContext, cancel := context.WithCancel(context.Background())
	store.activeMu.Lock()
	store.active["send:"+id] = &activeResume{
		direction: "send", cancel: cancel,
		record: resumeRecord{resumeManifest: resumeManifest{ID: id, Context: "home"}},
	}
	store.activeMu.Unlock()
	store.maintenanceMu.Lock()
	defer store.maintenanceMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- store.Cancel("home", id) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel waited for transfer maintenance")
	}
	select {
	case <-operationContext.Done():
	case <-time.After(time.Second):
		t.Fatal("active transfer was not canceled")
	}
}

func TestInventoryIsBoundedDeterministicAndRedacted(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	spool := filepath.Join(root, ".stdin-inventory.spool")
	if err := os.WriteFile(spool, []byte("private-spool-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", strings.Repeat("b", 64), "transferring", spool, true, now.Add(-time.Minute), now.Add(time.Hour))
	insertResumeRecord(t, databaseStore, "receive", strings.Repeat("a", 64), "committed_pending_confirmation", "", false, now.Add(-2*time.Minute), now.Add(time.Hour))
	insertResumeRecord(t, databaseStore, "receive", strings.Repeat("c", 64), "transferring", "", false, now.Add(-3*time.Minute), now.Add(-time.Second))
	if err := os.WriteFile(store.partialPath(strings.Repeat("c", 64)), []byte("expired"), 0o600); err != nil {
		t.Fatal(err)
	}

	inventory, err := store.List(context.Background(), "home", 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Version != InventoryVersion || len(inventory.Transfers) != 2 {
		t.Fatalf("inventory = %+v", inventory)
	}
	if inventory.Transfers[0].ID != strings.Repeat("b", 64) || inventory.Transfers[0].State != "retryable" || !inventory.Transfers[0].Retryable {
		t.Fatalf("first item = %+v", inventory.Transfers[0])
	}
	pending := inventory.Transfers[1]
	if pending.State != "pending_peer_confirmation" || !pending.LocalCommitted || pending.PeerConfirmation != "pending" {
		t.Fatalf("pending item = %+v", pending)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{spool, "private-spool-data", "resume-token", "source_sha256"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("inventory exposed %q: %s", secret, encoded)
		}
	}
	second, err := store.List(context.Background(), "home", 2, now)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, _ := json.Marshal(second)
	if string(encoded) != string(secondJSON) {
		t.Fatalf("inventory JSON changed:\n%s\n%s", encoded, secondJSON)
	}
	if _, err := os.Stat(store.partialPath(strings.Repeat("c", 64))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired partial remains: %v", err)
	}
}

func TestInventoryCancellationAndDestructiveDeletion(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("d", 64), Context: "home", ReceiverID: "peer-id", Name: "active.bin", Visibility: VisibilityPrivate, Size: 10}, PeerLabel: "peer", ExpiresAt: now.Add(time.Hour)}
	operationContext, release, err := store.acquire(context.Background(), "send", record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Cancel("home", record.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Cancel("home", record.ID); err != nil {
		t.Fatalf("concurrent-style repeated cancellation = %v", err)
	}
	select {
	case <-operationContext.Done():
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach operation context")
	}
	release()
	if err := store.Cancel("home", record.ID); !errors.Is(err, ErrTransferNotActive) {
		t.Fatalf("inactive cancellation = %v", err)
	}

	ordinary := filepath.Join(t.TempDir(), "ordinary-source")
	if err := os.WriteFile(ordinary, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", strings.Repeat("e", 64), "transferring", ordinary, false, now, now.Add(time.Hour))
	if _, err := store.Delete(context.Background(), "home", strings.Repeat("e", 64), now); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(ordinary); err != nil || string(content) != "preserve" {
		t.Fatalf("ordinary source changed: %q, %v", content, err)
	}
	spool := filepath.Join(root, ".stdin-delete.spool")
	if err := os.WriteFile(spool, []byte("discard"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", strings.Repeat("f", 64), "transferring", spool, true, now, now.Add(time.Hour))
	if _, err := store.Delete(context.Background(), "home", strings.Repeat("f", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdin spool remains: %v", err)
	}
}

func TestCanceledSendRetainsRetryStateAndStdinSpool(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	spool := filepath.Join(root, ".stdin-cancel.spool")
	if err := os.WriteFile(spool, []byte("retry me"), 0o600); err != nil {
		t.Fatal(err)
	}
	submitted := make(chan string, 1)
	done := make(chan error, 1)
	releaseOperation := make(chan struct{})
	go func() {
		cfg := sendConfig(store, spool, func(event ResumeEvent) {
			if event.State == "submitted" {
				submitted <- event.TransferID
			}
		})
		cfg.Name = "stdin.txt"
		cfg.StdinSpool = true
		_, err := SendResumable(context.Background(), cancelBlockingChannel{release: releaseOperation}, cfg)
		done <- err
	}()
	id := <-submitted
	cancels := make(chan error, 2)
	for range 2 {
		go func() { cancels <- store.Cancel("home", id) }()
	}
	var canceled int
	for range 2 {
		if err := <-cancels; err == nil {
			canceled++
		} else if !errors.Is(err, ErrTransferNotActive) {
			t.Fatalf("concurrent cancellation = %v", err)
		}
	}
	if canceled == 0 {
		t.Fatal("no concurrent cancellation succeeded")
	}
	close(releaseOperation)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled send error = %v", err)
	}
	var count int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where direction = 'send' and transfer_id = ?`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retained sender state count = %d, %v", count, err)
	}
	if content, err := os.ReadFile(spool); err != nil || string(content) != "retry me" {
		t.Fatalf("retained stdin spool = %q, %v", content, err)
	}
}

func TestGCQuarantinesInvalidArtifactWithoutFailing(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	id := strings.Repeat("9", 64)
	partial := store.partialPath(id)
	if err := os.Mkdir(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "blocker"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	insertResumeRecord(t, databaseStore, "receive", id, "transferring", "", false, now.Add(-time.Hour), now.Add(-time.Second))
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := databaseStore.DB().QueryRow(`select state from transfer_resumes where transfer_id = ?`, id).Scan(&state); err != nil || state != "corrupt" {
		t.Fatalf("quarantined state = %q, %v", state, err)
	}
}

func TestDeleteRefusesCommittingAndCommittedReceiverState(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	for index, state := range []string{"committing", "committed_pending_confirmation", "committed"} {
		id := strings.Repeat(string(rune('a'+index)), 64)
		insertResumeRecord(t, databaseStore, "receive", id, state, "", false, now, now.Add(time.Hour))
		if _, err := store.Delete(context.Background(), "home", id, now); !errors.Is(err, ErrTransferNotDeletable) {
			t.Fatalf("delete %s state = %v", state, err)
		}
		if state == "committed" {
			item, err := store.Show(context.Background(), "home", id, now)
			if err != nil || item.State != "confirmed" || item.PeerConfirmation != "confirmed" {
				t.Fatalf("legacy committed projection = %+v, %v", item, err)
			}
		}
		var count int
		if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id = ?`, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s state count = %d, %v", state, count, err)
		}
	}
}

func TestRetryLeaseExcludesDeleteAndGCUntilRelease(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("6", 64)
	spool := filepath.Join(root, ".stdin-lease.spool")
	if err := os.WriteFile(spool, []byte("leased"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", id, "transferring", spool, true, now, now.Add(time.Hour))
	lease, err := store.ClaimSend(context.Background(), id, "home", "peer", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(context.Background(), "home", id, now); !errors.Is(err, ErrTransferActive) {
		t.Fatalf("delete leased retry = %v", err)
	}
	if err := store.GC(context.Background(), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool); err != nil {
		t.Fatalf("GC removed leased spool: %v", err)
	}
	lease.Release()
	if err := store.GC(context.Background(), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released expired spool remains: %v", err)
	}
}

func TestRetryLeaseValidatesContextAndPeer(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("5", 64)
	insertResumeRecord(t, databaseStore, "send", id, "transferring", "/ordinary/source", false, now, now.Add(time.Hour))
	if _, err := store.ClaimSend(context.Background(), id, "other", "peer", now); !errors.Is(err, ErrTransferContextMismatch) {
		t.Fatalf("context mismatch = %v", err)
	}
	if _, err := store.ClaimSend(context.Background(), id, "home", "other-peer", now); !errors.Is(err, ErrTransferPeerMismatch) {
		t.Fatalf("peer mismatch = %v", err)
	}
	lease, err := store.ClaimSend(context.Background(), id, "home", "PEER", now)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
}

func TestDeleteRestoresArtifactWhenDatabaseDeleteFails(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("4", 64)
	spool := filepath.Join(root, ".stdin-rollback.spool")
	if err := os.WriteFile(spool, []byte("restore"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", id, "transferring", spool, true, now, now.Add(time.Hour))
	if _, err := databaseStore.DB().Exec(`create trigger fail_transfer_delete before delete on transfer_resumes when old.transfer_id = '` + id + `' begin select raise(abort, 'blocked'); end`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(context.Background(), "home", id, now); !errors.Is(err, ErrTransferCleanup) {
		t.Fatalf("failed delete = %v", err)
	}
	if content, err := os.ReadFile(spool); err != nil || string(content) != "restore" {
		t.Fatalf("restored spool = %q, %v", content, err)
	}
	var count int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id = ?`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored row count = %d, %v", count, err)
	}
}

func TestContextCleanupRestoresAllArtifactsWhenDatabaseDeleteFails(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	firstID, secondID := strings.Repeat("1", 64), strings.Repeat("2", 64)
	firstSpool := filepath.Join(root, ".stdin-context-first.spool")
	secondSpool := filepath.Join(root, ".stdin-context-second.spool")
	for _, path := range []string{firstSpool, secondSpool} {
		if err := os.WriteFile(path, []byte("restore"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	insertResumeRecord(t, databaseStore, "send", firstID, "transferring", firstSpool, true, now, now.Add(time.Hour))
	insertResumeRecord(t, databaseStore, "send", secondID, "transferring", secondSpool, true, now, now.Add(time.Hour))
	if _, err := databaseStore.DB().Exec(`create trigger fail_context_transfer_delete before delete on transfer_resumes when old.transfer_id = '` + secondID + `' begin select raise(abort, 'blocked'); end`); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveContext(context.Background(), "home"); err == nil {
		t.Fatalf("context cleanup = %v", err)
	}
	for _, path := range []string{firstSpool, secondSpool} {
		if content, err := os.ReadFile(path); err != nil || string(content) != "restore" {
			t.Fatalf("restored %s = %q, %v", filepath.Base(path), content, err)
		}
	}
	var count int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where context_name = 'home'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("context transfer rows = %d, %v", count, err)
	}
}

func TestPostCommitCleanupFailureRemainsDurablyQueued(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("8", 64)
	spool := filepath.Join(root, ".stdin-queued.spool")
	if err := os.WriteFile(spool, []byte("queued"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", id, "transferring", spool, true, now, now.Add(time.Hour))
	if _, err := databaseStore.DB().Exec(`create trigger fail_cleanup_marker_delete before delete on transfer_cleanup begin select raise(abort, 'blocked'); end`); err != nil {
		t.Fatal(err)
	}
	item, err := store.Delete(context.Background(), "home", id, now)
	if err != nil || !item.CleanupPending {
		t.Fatalf("post-commit cleanup = %+v, %v", item, err)
	}
	var rows, queued int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id = ?`, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("deleted rows = %d, %v", rows, err)
	}
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_cleanup`).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued cleanup = %d, %v", queued, err)
	}
	if _, err := databaseStore.DB().Exec(`drop trigger fail_cleanup_marker_delete`); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_cleanup`).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("drained cleanup = %d, %v", queued, err)
	}
}

func TestCorruptTransferIDIsQuarantinedWithoutBlockingValidGC(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	outside := filepath.Join(filepath.Dir(root), "outside.part")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', '../outside', 'home', 'peer', 'peer', 'file', 1, ?, ?, ?, 'token', 0, 'transferring', ?, ?, ?, 3, 'private')`, strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, now.Unix(), now.Unix(), now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	validID := strings.Repeat("7", 64)
	validSpool := filepath.Join(root, ".stdin-valid-gc.spool")
	if err := os.WriteFile(validSpool, []byte("valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", validID, "transferring", validSpool, true, now.Add(-time.Hour), now.Add(-time.Second))
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatalf("mixed GC = %v", err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "preserve" {
		t.Fatalf("outside file = %q, %v", content, err)
	}
	if _, err := os.Stat(validSpool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("valid expired spool remains: %v", err)
	}
	var state string
	if err := databaseStore.DB().QueryRow(`select state from transfer_resumes where transfer_id = '../outside'`).Scan(&state); err != nil || state != "corrupt" {
		t.Fatalf("corrupt row state = %q, %v", state, err)
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatalf("repeated GC = %v", err)
	}
}

func TestMalformedPublicPrepublicationRowIsDeletedButPublicationEvidenceBlocks(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	outside := filepath.Join(filepath.Dir(root), "prepublication.part")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	for index, state := range []string{"transferring", "committing", "committed_pending_confirmation"} {
		id := fmt.Sprintf("../malformed-%d", index)
		if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', ?, 'home', 'peer', 'peer', 'file', 1, ?, ?, ?, 'token', 0, ?, ?, ?, ?, 3, 'public')`, id, strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, state, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var prepublication int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id = '../malformed-0'`).Scan(&prepublication); err != nil || prepublication != 0 {
		t.Fatalf("prepublication malformed rows = %d, %v", prepublication, err)
	}
	var blockers int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes where transfer_id in ('../malformed-1', '../malformed-2') and state = 'corrupt'`).Scan(&blockers); err != nil || blockers != 2 {
		t.Fatalf("publication-bearing malformed blockers = %d, %v", blockers, err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "preserve" {
		t.Fatalf("outside artifact = %q, %v", content, err)
	}
}

func TestCorruptCleanupMarkersDoNotBlockHealthyGC(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	victim := filepath.Join(filepath.Dir(root), "outside.part")
	if err := os.WriteFile(victim, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	badID := strings.Repeat("1", 64)
	if _, err := databaseStore.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('receive', ?, '../outside.part', ?, 'intent', ?)`, badID, ".cleanup-"+strings.Repeat("a", 32), now.Unix()); err != nil {
		t.Fatal(err)
	}
	directoryID := strings.Repeat("8", 64)
	directoryStage := ".cleanup-" + strings.Repeat("d", 32)
	if err := os.Mkdir(filepath.Join(root, directoryStage), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('receive', ?, ?, ?, 'renamed', ?)`, directoryID, directoryID+".part", directoryStage, now.Unix()); err != nil {
		t.Fatal(err)
	}
	healthyID := strings.Repeat("2", 64)
	healthySpool := filepath.Join(root, ".stdin-healthy.spool")
	if err := os.WriteFile(healthySpool, []byte("healthy"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", healthyID, "transferring", healthySpool, true, now.Add(-time.Hour), now.Add(-time.Second))
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "preserve" {
		t.Fatalf("outside file = %q, %v", content, err)
	}
	if _, err := os.Stat(healthySpool); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("healthy spool remains: %v", err)
	}
	var markers int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_cleanup`).Scan(&markers); err != nil || markers != 0 {
		t.Fatalf("cleanup markers = %d, %v", markers, err)
	}
	if info, err := os.Stat(filepath.Join(root, directoryStage)); err != nil || !info.IsDir() {
		t.Fatalf("poisoned directory was modified: %v, %v", info, err)
	}
}

func TestCleanupMarkersCannotClaimAnotherTransferArtifact(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	ownerID, markerID := strings.Repeat("3", 64), strings.Repeat("4", 64)
	spool := filepath.Join(root, ".stdin-owned.spool")
	if err := os.WriteFile(spool, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", ownerID, "transferring", spool, true, now, now.Add(time.Hour))
	if _, err := databaseStore.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('send', ?, ?, ?, 'intent', ?)`, markerID, filepath.Base(spool), ".cleanup-"+strings.Repeat("b", 32), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(spool); err != nil || string(content) != "owned" {
		t.Fatalf("owned spool = %q, %v", content, err)
	}

	receiverMarkerID := strings.Repeat("5", 64)
	receiverOwnerID := strings.Repeat("6", 64)
	partial := filepath.Join(root, receiverOwnerID+".part")
	if err := os.WriteFile(partial, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('receive', ?, ?, ?, 'intent', ?)`, receiverMarkerID, receiverOwnerID+".part", ".cleanup-"+strings.Repeat("c", 32), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := store.GC(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(partial); err != nil || string(content) != "partial" {
		t.Fatalf("receiver partial = %q, %v", content, err)
	}
}

func TestContextRemovalCascadesCorruptMetadataWithoutTouchingUnknownPaths(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	outside := filepath.Join(filepath.Dir(root), "unknown.spool")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('receive', '../unknown', 'home', 'peer', 'peer', 'file', 1, ?, ?, ?, 'token', 0, 'corrupt', ?, ?, ?, 3, 'private')`, strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, now.Unix(), now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	insertResumeRecord(t, databaseStore, "send", strings.Repeat("7", 64), "corrupt", outside, true, now, now.Add(time.Hour))
	if err := store.RemoveContextWith(context.Background(), "home", func(tx *sql.Tx) error {
		_, err := tx.Exec(`delete from contexts where name = 'home'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "preserve" {
		t.Fatalf("unknown path = %q, %v", content, err)
	}
	var rows int
	if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("transfer rows = %d, %v", rows, err)
	}
}

func TestStartupGCRecoversCleanupCrashStates(t *testing.T) {
	for _, test := range []struct {
		name         string
		rename       bool
		deleteOwner  bool
		cascade      bool
		wantOriginal bool
	}{
		{name: "intent before rename", wantOriginal: true},
		{name: "renamed with owner", rename: true, wantOriginal: true},
		{name: "committed deletion", rename: true, deleteOwner: true},
		{name: "context cascade", rename: true, deleteOwner: true, cascade: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, databaseStore, root := newResumeTestStore(t)
			now := time.Now().UTC()
			id := strings.Repeat("d", 64)
			original := ".stdin-crash.spool"
			staged := ".cleanup-" + strings.Repeat("a", 32)
			path := filepath.Join(root, original)
			if err := os.WriteFile(path, []byte("recover"), 0o600); err != nil {
				t.Fatal(err)
			}
			insertResumeRecord(t, databaseStore, "send", id, "transferring", path, true, now, now.Add(time.Hour))
			if _, err := databaseStore.DB().Exec(`insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values ('send', ?, ?, ?, 'intent', ?)`, id, original, staged, now.Unix()); err != nil {
				t.Fatal(err)
			}
			if test.rename {
				if err := os.Rename(path, filepath.Join(root, staged)); err != nil {
					t.Fatal(err)
				}
			}
			if test.deleteOwner {
				statement, argument := `delete from transfer_resumes where direction = 'send' and transfer_id = ?`, id
				if test.cascade {
					statement, argument = `delete from contexts where name = ?`, "home"
				}
				if _, err := databaseStore.DB().Exec(statement, argument); err != nil {
					t.Fatal(err)
				}
			}
			restarted := NewResumeStore(databaseStore.DB, root)
			if err := restarted.GC(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			_, originalErr := os.Stat(path)
			if test.wantOriginal && originalErr != nil {
				t.Fatalf("original was not restored: %v", originalErr)
			}
			if !test.wantOriginal && !errors.Is(originalErr, os.ErrNotExist) {
				t.Fatalf("ownerless original remains: %v", originalErr)
			}
			if _, err := os.Stat(filepath.Join(root, staged)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staged artifact remains: %v", err)
			}
			var markers int
			if err := databaseStore.DB().QueryRow(`select count(*) from transfer_cleanup`).Scan(&markers); err != nil || markers != 0 {
				t.Fatalf("cleanup markers = %d, %v", markers, err)
			}
		})
	}
}

func TestSharedSpoolOwnershipCannotDeleteAnotherRow(t *testing.T) {
	store, databaseStore, root := newResumeTestStore(t)
	now := time.Now().UTC()
	spool := filepath.Join(root, ".stdin-shared.spool")
	if err := os.WriteFile(spool, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstID, secondID := strings.Repeat("e", 64), strings.Repeat("f", 64)
	insertResumeRecord(t, databaseStore, "send", firstID, "transferring", spool, true, now, now.Add(time.Hour))
	insertResumeRecord(t, databaseStore, "send", secondID, "transferring", spool, true, now, now.Add(time.Hour))
	lease, err := store.ClaimSend(context.Background(), secondID, "home", "peer", now)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err := store.Delete(context.Background(), "home", firstID, now); !errors.Is(err, ErrCorruptTransferState) {
		t.Fatalf("shared spool delete = %v", err)
	}
	if content, err := os.ReadFile(spool); err != nil || string(content) != "shared" {
		t.Fatalf("shared spool = %q, %v", content, err)
	}
}

func TestActiveInventoryTimestampsAreStableAndProgressDriven(t *testing.T) {
	store, _, _ := newResumeTestStore(t)
	created := time.Unix(1_700_000_000, 0).UTC()
	record := resumeRecord{resumeManifest: resumeManifest{Version: resumeVersion, ID: strings.Repeat("3", 64), Context: "home", ReceiverID: "peer", Name: "file", Visibility: VisibilityPrivate, Size: 100}, PeerLabel: "peer", CreatedAt: created, UpdatedAt: created, ExpiresAt: created.Add(time.Hour)}
	_, release, err := store.acquire(context.Background(), "send", record)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	first, err := store.List(context.Background(), "home", 1, created.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.List(context.Background(), "home", 1, created.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Transfers[0].CreatedAt != created || first.Transfers[0].UpdatedAt != created || first.Transfers[0] != second.Transfers[0] {
		t.Fatalf("active observations changed: %+v, %+v", first.Transfers[0], second.Transfers[0])
	}
	store.emitActive("send", nil, ResumeEvent{State: "transferring", TransferID: record.ID, Bytes: 50, Total: 100})
	updated, err := store.List(context.Background(), "home", 1, created.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Transfers[0].Bytes != 50 || !updated.Transfers[0].UpdatedAt.After(created) {
		t.Fatalf("progress inventory = %+v", updated.Transfers[0])
	}
	shown, err := store.Show(context.Background(), "home", record.ID, created.Add(3*time.Minute))
	if err != nil || shown != updated.Transfers[0] {
		t.Fatalf("active show = %+v, %v; list = %+v", shown, err, updated.Transfers[0])
	}
}

func TestActiveReceiverInventoryProjectsCommittingAndPendingConfirmation(t *testing.T) {
	store, databaseStore, _ := newResumeTestStore(t)
	now := time.Now().UTC()
	id := strings.Repeat("a", 64)
	insertResumeRecord(t, databaseStore, "receive", id, "transferring", "", false, now, now.Add(time.Hour))
	record, exists, err := store.load(context.Background(), "receive", id)
	if err != nil || !exists {
		t.Fatalf("load receiver = %+v, %v, %v", record, exists, err)
	}
	operationContext, release, err := store.acquire(context.Background(), "receive", record)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	assertProjection := func(wantState string, localCommitted bool, confirmation string) {
		t.Helper()
		results := make(chan InventoryItem, 8)
		errors := make(chan error, 8)
		for index := range 8 {
			go func() {
				if index%2 == 0 {
					item, err := store.Show(context.Background(), "home", id, time.Now())
					results <- item
					errors <- err
					return
				}
				inventory, err := store.List(context.Background(), "home", 1, time.Now())
				if err != nil || len(inventory.Transfers) != 1 {
					results <- InventoryItem{}
					errors <- err
					return
				}
				results <- inventory.Transfers[0]
				errors <- nil
			}()
		}
		for range 8 {
			item, err := <-results, <-errors
			if err != nil || item.State != wantState || item.LocalCommitted != localCommitted || item.PeerConfirmation != confirmation || item.Bytes != item.Total || item.Total != 20 || item.UpdatedAt.Before(now) {
				t.Fatalf("%s projection = %+v, %v", wantState, item, err)
			}
		}
	}

	if err := store.markCommitting(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	assertProjection("committing", false, "")
	if err := store.markCommitted(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	assertProjection("pending_peer_confirmation", true, "pending")
	if err := store.Cancel("home", id); err != nil {
		t.Fatalf("cancel pending receiver = %v", err)
	}
	select {
	case <-operationContext.Done():
	case <-time.After(time.Second):
		t.Fatal("pending receiver lost cancellation ownership")
	}
}

func TestTerminalCleanupSurvivesCanceledProtocolContext(t *testing.T) {
	for _, cancelSide := range []string{"send", "receive"} {
		t.Run(cancelSide, func(t *testing.T) {
			senderStore, senderDB, senderRoot := newResumeTestStore(t)
			receiverStore, receiverDB, _ := newResumeTestStore(t)
			spool := filepath.Join(senderRoot, ".stdin-terminal.spool")
			if err := os.WriteFile(spool, []byte("terminal cleanup"), 0o600); err != nil {
				t.Fatal(err)
			}
			sender, receiver := newMemoryPipe()
			senderCtx, cancelSender := context.WithCancel(context.Background())
			receiverCtx, cancelReceiver := context.WithCancel(context.Background())
			defer cancelSender()
			defer cancelReceiver()
			var senderChannel Channel = sender
			var receiverChannel Channel = receiver
			if cancelSide == "send" {
				senderChannel = &cancelOnControl{Channel: sender, controlType: "ack", cancel: cancelSender, onSend: true}
			} else {
				receiverChannel = &cancelOnControl{Channel: receiver, controlType: "ack", cancel: cancelReceiver}
			}
			received := make(chan error, 1)
			inbox := t.TempDir()
			receiverDone := make(chan struct{})
			go func() {
				defer close(receiverDone)
				_, err := ReceiveResumable(receiverCtx, receiverChannel, receiveConfig(receiverStore, inbox, nil))
				received <- err
			}()
			defer func() {
				cancelReceiver()
				<-receiverDone
			}()
			cfg := sendConfig(senderStore, spool, nil)
			cfg.Name, cfg.StdinSpool = "terminal.txt", true
			if _, err := SendResumable(senderCtx, senderChannel, cfg); err != nil {
				t.Fatalf("sender = %v", err)
			}
			if err := <-received; err != nil {
				t.Fatalf("receiver = %v", err)
			}
			if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("terminal spool remains: %v", err)
			}
			for role, databaseStore := range map[string]*sqlite.Store{"send": senderDB, "receive": receiverDB} {
				var count int
				if err := databaseStore.DB().QueryRow(`select count(*) from transfer_resumes`).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s terminal rows = %d, %v", role, count, err)
				}
			}
		})
	}
}

func insertResumeRecord(t *testing.T, databaseStore *sqlite.Store, direction, id, state, source string, spool bool, updatedAt, expiresAt time.Time) {
	t.Helper()
	spoolValue := 0
	if spool {
		spoolValue = 1
	}
	_, err := databaseStore.DB().Exec(`insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at, manifest_version, visibility) values (?, ?, 'home', 'peer-id', 'peer', 'artifact.bin', 20, ?, ?, ?, 'resume-token', 8, ?, ?, ?, ?, ?, ?, 3, 'private')`, direction, id, strings.Repeat("0", 64), ResumeChunkSize, ResumeAckWindow, source, spoolValue, state, updatedAt.Add(-time.Minute).Unix(), updatedAt.Unix(), expiresAt.Unix())
	if err != nil {
		t.Fatal(err)
	}
}

func sendResumeRecord(id string, size int64, now time.Time) resumeRecord {
	return resumeRecord{
		resumeManifest: resumeManifest{
			Version: resumeVersion, ID: id, Context: "home", SenderID: "sender-id", ReceiverID: "receiver-id",
			Name: "artifact.bin", Visibility: VisibilityPrivate, Size: size, SHA256: strings.Repeat("0", 64),
			ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow,
		},
		Token: "resume-token", PeerLabel: "peer", State: "transferring", ExpiresAt: now.Add(time.Hour),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

type failAfterChunks struct {
	Channel
	mu        sync.Mutex
	remaining int
}

type cancelBlockingChannel struct {
	release <-chan struct{}
}

type cancelOnControl struct {
	Channel
	controlType string
	cancel      context.CancelFunc
	onSend      bool
}

func (c *cancelOnControl) Send(ctx context.Context, message Message) error {
	err := c.Channel.Send(ctx, message)
	if err == nil && c.onSend && controlMessageType(message) == c.controlType {
		c.cancel()
	}
	return err
}

func (c *cancelOnControl) Receive(ctx context.Context) (Message, error) {
	message, err := c.Channel.Receive(ctx)
	if err == nil && !c.onSend && controlMessageType(message) == c.controlType {
		c.cancel()
	}
	return message, err
}

func controlMessageType(message Message) string {
	if !message.Text {
		return ""
	}
	var control resumeControl
	_ = json.Unmarshal(message.Data, &control)
	return control.Type
}

func (cancelBlockingChannel) Send(ctx context.Context, _ Message) error {
	return ctx.Err()
}

func (c cancelBlockingChannel) Receive(ctx context.Context) (Message, error) {
	<-ctx.Done()
	<-c.release
	return Message{}, ctx.Err()
}

type failControlType struct {
	Channel
	controlType string
	failed      bool
}

func (c *failControlType) Send(ctx context.Context, message Message) error {
	if message.Text && !c.failed {
		var value resumeControl
		if json.Unmarshal(message.Data, &value) == nil && value.Type == c.controlType {
			c.failed = true
			return errors.New("simulated response loss")
		}
	}
	return c.Channel.Send(ctx, message)
}

type mutateChannel struct {
	Channel
	mutate func(Message) Message
}

func (c *mutateChannel) Send(ctx context.Context, message Message) error {
	message.Data = append([]byte(nil), message.Data...)
	return c.Channel.Send(ctx, c.mutate(message))
}

func (c *failAfterChunks) Send(ctx context.Context, message Message) error {
	if !message.Text {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.remaining--
		if c.remaining < 0 {
			return errors.New("simulated disconnect")
		}
	}
	return c.Channel.Send(ctx, message)
}

func newResumeTestStore(t *testing.T) (*ResumeStore, *sqlite.Store, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := database.Config(database.KindAgent, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Stop(context.Background()) })
	now := time.Now().Unix()
	_, err = databaseStore.DB().Exec(`insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, state, enabled, offered_root, inbox_root, created_at, updated_at) values ('home', 'http://server', 'server', 'device', 'private', 'public', 'device', 'connected', 1, 'offered', 'inbox', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "transfers")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store := NewResumeStore(databaseStore.DB, root)
	store.SetObservationWriter(func(context.Context, TransferObservation) error { return nil }, func(context.Context, *sql.Tx, TransferObservation) error { return nil })
	return store, databaseStore, root
}

func sendConfig(store *ResumeStore, source string, progress func(ResumeEvent)) ResumeSendConfig {
	return ResumeSendConfig{Source: source, Context: "home", SenderID: "sender-id", ReceiverID: "receiver-id", PeerLabel: "receiver", Visibility: VisibilityPrivate, MaxFileBytes: DefaultMaxFileBytes, Store: store, Progress: progress}
}

func receiveConfig(store *ResumeStore, inbox string, space func(string) (uint64, error)) ResumeReceiveConfig {
	return ResumeReceiveConfig{InboxRoot: inbox, OfferedRoot: inbox, Context: "home", SenderID: "sender-id", SenderLabel: "sender", ReceiverID: "receiver-id", OfferedRootRevision: 1, MaxFileBytes: DefaultMaxFileBytes, Store: store, AvailableSpace: space}
}

func hasResumeEvent(events []ResumeEvent, state string) bool {
	for _, event := range events {
		if event.State == state {
			return true
		}
	}
	return false
}
