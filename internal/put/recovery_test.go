//go:build !windows

package put

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
)

type recoveryChannel struct{ send, receive chan Message }

type droppingChannel struct {
	recoveryChannel
	drop    string
	dropped *atomic.Bool
}

func (c droppingChannel) Send(ctx context.Context, message Message) error {
	if message.Text {
		var header struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(message.Data, &header) == nil && header.Type == c.drop {
			c.dropped.Store(true)
			close(c.send)
			close(c.receive)
			return nil
		}
	}
	return c.recoveryChannel.Send(ctx, message)
}

func (c recoveryChannel) Send(ctx context.Context, message Message) error {
	select {
	case c.send <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c recoveryChannel) Receive(ctx context.Context) (Message, error) {
	select {
	case message, ok := <-c.receive:
		if !ok {
			return Message{}, io.EOF
		}
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

func TestCommittedCleanupRecoversAtEveryDurableBoundary(t *testing.T) {
	for _, point := range []string{"after_stage_unlink", "after_stage_removed_record", "before_parent_sync", "after_parent_fsync", "after_parent_sync"} {
		t.Run(point, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("cleanup recovery"), 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewStore(func() *sql.DB { return db })
			fired := false
			store.fault = func(candidate string) error {
				if candidate == point && !fired {
					fired = true
					return errors.New("injected cleanup failure")
				}
				return nil
			}
			left, right := make(chan Message, 8), make(chan Message, 8)
			received := make(chan error, 1)
			go func() {
				_, err := Receive(t.Context(), recoveryChannel{send: right, receive: left}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
				received <- err
			}()
			result, err := Send(t.Context(), recoveryChannel{send: left, receive: right}, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store})
			if err != nil {
				t.Fatal(err)
			}
			if err := <-received; err != nil {
				t.Fatal(err)
			}
			if !fired {
				t.Fatalf("fault point %q did not run", point)
			}
			record, exists, err := store.Load(t.Context(), "receive", result.TransferID)
			if err != nil || !exists || record.State != "committed" || record.StageIdentity == "" {
				t.Fatalf("retained cleanup evidence=%+v exists=%t err=%v", record, exists, err)
			}
			store.fault = nil
			lease, err := store.ClaimReceiver(t.Context(), record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CleanupCommitted(t.Context(), record, lease); err != nil {
				t.Fatal(err)
			}
			store.ReleaseReceiver(record.ID, lease)
			record, exists, err = store.Load(t.Context(), "receive", result.TransferID)
			if err != nil || !exists || record.StageIdentity != "" || record.StageRemoved {
				t.Fatalf("cleanup did not settle=%+v exists=%t err=%v", record, exists, err)
			}
		})
	}
}

func TestStageIntentRecoversAcrossCreationBoundaries(t *testing.T) {
	for _, point := range []string{"after_stage_intent", "after_stage_create", "after_stage_attach"} {
		t.Run(point, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			store.fault = func(candidate string) error {
				if candidate == point {
					return errors.New("injected stage boundary failure")
				}
				return nil
			}
			manifest := recoveryManifest("result")
			err := startReceiverUntilFailure(t, store, root, manifest)
			if err == nil {
				t.Fatal("receiver unexpectedly reached ready")
			}
			record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
			if err != nil || !exists || record.StageName == "" || record.ParentIdentity == "" {
				t.Fatalf("durable intent=%+v exists=%t err=%v", record, exists, err)
			}
			switch point {
			case "after_stage_intent":
				if record.State != "stage_intent" || record.StageIdentity != "" {
					t.Fatalf("record=%+v", record)
				}
			case "after_stage_create":
				if record.State != "stage_intent" || record.StageIdentity != "" {
					t.Fatalf("record=%+v", record)
				}
				if _, err := os.Stat(filepath.Join(root, record.StageName)); err != nil {
					t.Fatal(err)
				}
			case "after_stage_attach":
				if record.State != "transferring" || record.StageIdentity == "" {
					t.Fatalf("record=%+v", record)
				}
			}
			store.fault = nil
			if _, err := store.Abandon(t.Context(), "home", manifest.ID); err != nil {
				t.Fatal(err)
			}
			if _, exists, err := store.Load(t.Context(), "receive", manifest.ID); err != nil || exists {
				t.Fatalf("intent survived cleanup: exists=%t err=%v", exists, err)
			}
		})
	}
}

func TestAdoptedStageIsTruncatedAndRewound(t *testing.T) {
	root := t.TempDir()
	parent, err := openDestinationParent(root, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{ParentPath: parent.path, ParentIdentity: parentDurableIdentity(parent), StageName: ".px-0123456789abcdef0123456789abcdef.put", State: "stage_intent"}
	stage, _, err := createOrOpenStage(parent, Manifest{}, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File.Write([]byte("untrusted old bytes")); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	parent, err = openDestinationParent(root, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	stage, adopted, err := createOrOpenStage(parent, Manifest{}, record)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	info, err := stage.File.Stat()
	if err != nil || !adopted || info.Size() != 0 {
		t.Fatalf("adopted=%t size=%d err=%v", adopted, info.Size(), err)
	}
	position, err := stage.File.Seek(0, io.SeekCurrent)
	if err != nil || position != 0 {
		t.Fatalf("position=%d err=%v", position, err)
	}
}

func TestStageRegistrationFailureRetainsCleanupEvidenceOnUncertainty(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	store.fault = func(point string) error {
		if point == "stage_registration" || point == "after_stage_unlink" {
			return errors.New("injected registration cleanup failure")
		}
		return nil
	}
	manifest := recoveryManifest("result")
	if err := startReceiverUntilFailure(t, store, root, manifest); err == nil {
		t.Fatal("registration failure was not surfaced")
	}
	record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
	if err != nil || !exists || record.State != "cleanup_not_attempted" || record.StageName == "" {
		t.Fatalf("cleanup evidence=%+v exists=%t err=%v", record, exists, err)
	}
	store.fault = nil
	if _, err := store.Abandon(t.Context(), "home", manifest.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAbandonInactiveReceiverCleansIdentityOwnedStage(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	sum := sha256.Sum256([]byte("x"))
	manifest := Manifest{Version: protocolVersion, Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: "result", Mode: "create", Size: 1, SHA256: hex.EncodeToString(sum[:]), ChunkSize: ChunkSize, AckWindow: AckWindow}
	manifest.ID = "0123456789abcdef0123456789abcdef"
	left, right := make(chan Message, 4), make(chan Message, 4)
	sender := recoveryChannel{send: left, receive: right}
	receiver := recoveryChannel{send: right, receive: left}
	ctx, cancel := context.WithCancel(t.Context())
	received := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	if prepared, err := receiveControl(ctx, sender); err != nil || prepared.Type != "prepared" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	if ready, err := receiveControl(ctx, sender); err != nil || ready.Type != "ready" {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	cancel()
	if err := <-received; !errors.Is(err, context.Canceled) {
		t.Fatalf("receive error=%v", err)
	}
	record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
	if err != nil || !exists || record.StageIdentity == "" {
		t.Fatalf("staged record=%+v exists=%t err=%v", record, exists, err)
	}
	stagePath := filepath.Join(root, record.StageName)
	if _, err := os.Stat(stagePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Abandon(t.Context(), "home", manifest.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage survived abandonment: %v", err)
	}
	if _, exists, err := store.Load(t.Context(), "receive", manifest.ID); err != nil || exists {
		t.Fatalf("receiver row survived abandonment: exists=%t err=%v", exists, err)
	}
}

func TestPrepublicationCleanupRecoversAtEveryDurableBoundary(t *testing.T) {
	for _, point := range []string{"after_stage_unlink", "after_stage_removed_record", "before_parent_sync", "after_parent_fsync", "after_parent_sync"} {
		t.Run(point, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			manifest := recoveryManifest("result")
			left, right := make(chan Message, 4), make(chan Message, 4)
			sender := recoveryChannel{send: left, receive: right}
			receiver := recoveryChannel{send: right, receive: left}
			ctx, cancel := context.WithCancel(t.Context())
			received := make(chan error, 1)
			go func() {
				_, err := Receive(ctx, receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
				received <- err
			}()
			if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
				t.Fatal(err)
			}
			if _, err := receiveControl(ctx, sender); err != nil {
				t.Fatal(err)
			}
			if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := receiveControl(ctx, sender); err != nil {
				t.Fatal(err)
			}
			cancel()
			<-received
			fired := false
			store.fault = func(candidate string) error {
				if candidate == point && !fired {
					fired = true
					return errors.New("injected prepublication cleanup failure")
				}
				return nil
			}
			if _, err := store.Abandon(t.Context(), "home", manifest.ID); err == nil {
				t.Fatal("cleanup fault was not surfaced")
			}
			record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
			if err != nil || !exists || record.State != "cleanup_not_attempted" {
				t.Fatalf("retained prepublication evidence=%+v exists=%t err=%v", record, exists, err)
			}
			store.fault = nil
			if _, err := store.Abandon(t.Context(), "home", manifest.ID); err != nil {
				t.Fatal(err)
			}
			if _, exists, err := store.Load(t.Context(), "receive", manifest.ID); err != nil || exists {
				t.Fatalf("cleanup did not settle: exists=%t err=%v", exists, err)
			}
		})
	}
}

func TestTerminalCleanupProofControlsSenderRetryRetention(t *testing.T) {
	points := []string{"", "after_stage_unlink", "after_stage_removed_record", "before_parent_sync", "after_parent_fsync", "after_parent_sync"}
	for _, point := range points {
		name := point
		if name == "" {
			name = "clean rejection"
		}
		t.Run(name, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewStore(func() *sql.DB { return db })
			mutated, faulted := false, false
			store.fault = func(candidate string) error {
				if candidate == "before_stage_verify" && !mutated {
					mutated = true
					var stageName string
					if err := db.QueryRow(`select stage_name from put_transfers where direction='receive'`).Scan(&stageName); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(root, stageName), []byte("y"), 0o600)
				}
				if point != "" && candidate == point && !faulted {
					faulted = true
					return errors.New("injected cleanup uncertainty")
				}
				return nil
			}
			left, right := make(chan Message, 8), make(chan Message, 8)
			received := make(chan error, 1)
			go func() {
				_, err := Receive(t.Context(), recoveryChannel{send: right, receive: left}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
				received <- err
			}()
			id := ""
			_, sendErr := Send(t.Context(), recoveryChannel{send: left, receive: right}, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store, Progress: func(event Event) {
				if event.TransferID != "" {
					id = event.TransferID
				}
			}})
			if sendErr == nil {
				t.Fatal("mutated stage was accepted")
			}
			if err := <-received; err == nil {
				t.Fatal("receiver accepted mutated stage")
			}
			_, senderExists, err := store.Load(t.Context(), "send", id)
			if err != nil {
				t.Fatal(err)
			}
			if point == "" && senderExists {
				t.Fatal("sender retained row after receiver proved clean rejection")
			}
			if point != "" && (!senderExists || !faulted || !strings.Contains(sendErr.Error(), "retry")) {
				t.Fatalf("senderExists=%t faulted=%t sendErr=%v", senderExists, faulted, sendErr)
			}
			receiverRecord, receiverExists, err := store.Load(t.Context(), "receive", id)
			if err != nil {
				t.Fatal(err)
			}
			if point == "" && receiverExists {
				t.Fatalf("clean receiver evidence remained: %+v", receiverRecord)
			}
			if point != "" && (!receiverExists || receiverRecord.State != "cleanup_not_attempted") {
				t.Fatalf("receiver evidence=%+v exists=%t", receiverRecord, receiverExists)
			}
			if _, err := os.Stat(filepath.Join(root, "result")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mutated stage published: %v", err)
			}
		})
	}
}

func TestTwoPeerRetryCompletesPendingReceiverCleanup(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(func() *sql.DB { return db })
	mutated, faulted := false, false
	store.fault = func(point string) error {
		if point == "before_stage_verify" && !mutated {
			mutated = true
			var stageName string
			if err := db.QueryRow(`select stage_name from put_transfers where direction='receive'`).Scan(&stageName); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, stageName), []byte("y"), 0o600)
		}
		if point == "before_parent_sync" && !faulted {
			faulted = true
			return errors.New("injected receiver cleanup failure")
		}
		return nil
	}
	left, right := make(chan Message, 8), make(chan Message, 8)
	received := make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), recoveryChannel{send: right, receive: left}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	id := ""
	_, sendErr := Send(t.Context(), recoveryChannel{send: left, receive: right}, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store, Progress: func(event Event) {
		if event.TransferID != "" {
			id = event.TransferID
		}
	}})
	if sendErr == nil || !strings.Contains(sendErr.Error(), "retry") {
		t.Fatalf("initial sender error=%v", sendErr)
	}
	if err := <-received; err == nil {
		t.Fatal("receiver cleanup failure was not surfaced")
	}
	assertStoredState(t, store, "send", id, "transferring")
	assertStoredState(t, store, "receive", id, "cleanup_not_attempted")

	store.fault = nil
	lease, err := store.ClaimSender(t.Context(), "home", id)
	if err != nil {
		t.Fatal(err)
	}
	left, right = make(chan Message, 4), make(chan Message, 4)
	received = make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), recoveryChannel{send: right, receive: left}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	result, retryErr := Send(t.Context(), recoveryChannel{send: left, receive: right}, SendConfig{Context: "home", ReceiverID: "receiver", Store: store, Lease: lease})
	lease.Release()
	if retryErr != nil || !result.Created {
		t.Fatalf("settled retry result=%+v error=%v", result, retryErr)
	}
	if err := <-received; err != nil {
		t.Fatalf("receiver retry error=%v", err)
	}
	assertStoredState(t, store, "send", id, "committed")
	assertStoredState(t, store, "receive", id, "committed")
}

func TestCancellationAfterPublicationIntentCleansWithoutPublishing(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	ctx, cancel := context.WithCancel(t.Context())
	store.fault = func(point string) error {
		if point == "before_native_publish" {
			cancel()
		}
		return nil
	}
	manifest := recoveryManifest("result")
	left, right := make(chan Message, 4), make(chan Message, 4)
	sender := recoveryChannel{send: left, receive: right}
	receiver := recoveryChannel{send: right, receive: left}
	received := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(ctx, sender); err != nil {
		t.Fatal(err)
	}
	if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(ctx, sender); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(ctx, Message{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(ctx, sender); err != nil {
		t.Fatal(err)
	}
	if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "complete", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-received; !errors.Is(err, context.Canceled) {
		t.Fatalf("receive error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "result")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination published after cancellation: %v", err)
	}
	if _, exists, err := store.Load(t.Context(), "receive", manifest.ID); err != nil || exists {
		t.Fatalf("cleanup state remained: exists=%t err=%v", exists, err)
	}
}

func TestReapParentSettlesPublicationIntentFromEvidenceWithoutRepublish(t *testing.T) {
	for _, test := range []struct {
		name, evidence, wantState string
	}{
		{name: "published identity", evidence: "published", wantState: "committed"},
		{name: "missing destination", evidence: "missing", wantState: "outcome_unknown"},
		{name: "conflicting destination", evidence: "conflict", wantState: "outcome_unknown"},
		{name: "ambiguous parent", evidence: "ambiguous", wantState: "outcome_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			record := createPublicationIntent(t, store, root)
			stagePath := filepath.Join(root, record.StageName)
			switch test.evidence {
			case "published":
				if err := os.Link(stagePath, filepath.Join(root, record.Destination)); err != nil {
					t.Fatal(err)
				}
			case "conflict":
				if err := os.WriteFile(filepath.Join(root, record.Destination), []byte("other"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "ambiguous":
				if err := os.Rename(root, root+"-moved"); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
				t.Fatal(err)
			}
			updated, exists, err := store.Load(t.Context(), "receive", record.ID)
			if err != nil || !exists || updated.State != test.wantState {
				t.Fatalf("record=%+v exists=%t err=%v", updated, exists, err)
			}
			if test.wantState == "committed" && updated.StageName != "" {
				t.Fatalf("committed cleanup evidence remained: %+v", updated)
			}
		})
	}
}

func TestReplacementPublicationRecoveryUsesIdentityEvidence(t *testing.T) {
	for _, test := range []struct {
		name, evidence, wantState string
	}{
		{name: "stage identity at destination", evidence: "published", wantState: "committed"},
		{name: "old identity and stage present", evidence: "not_published"},
		{name: "conflicting destination", evidence: "conflict", wantState: "outcome_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			record := createReplacementPublicationIntent(t, store, root, "")
			stagePath := filepath.Join(root, record.StageName)
			destinationPath := filepath.Join(root, record.Destination)
			switch test.evidence {
			case "published":
				if err := os.Rename(stagePath, destinationPath); err != nil {
					t.Fatal(err)
				}
			case "conflict":
				if err := os.Rename(destinationPath, destinationPath+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destinationPath, []byte("conflict"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
				t.Fatal(err)
			}
			updated, exists, err := store.Load(t.Context(), "receive", record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantState == "" {
				if exists {
					t.Fatalf("nonpublication cleanup retained record: %+v", updated)
				}
				content, readErr := os.ReadFile(destinationPath)
				if readErr != nil || string(content) != "old" {
					t.Fatalf("old destination=%q err=%v", content, readErr)
				}
				if _, statErr := os.Stat(stagePath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("nonpublished stage remains: %v", statErr)
				}
				return
			}
			if !exists || updated.State != test.wantState {
				t.Fatalf("record=%+v exists=%t", updated, exists)
			}
			if test.wantState == "committed" && (updated.Durability != "durability_unconfirmed" || updated.StageName != "") {
				t.Fatalf("recovered commit=%+v", updated)
			}
		})
	}
}

func TestReplacementOutcomeUnknownReconcilesFromLaterEvidenceWithoutRepublish(t *testing.T) {
	for _, test := range []struct {
		name      string
		published bool
	}{
		{name: "published evidence", published: true},
		{name: "not-published evidence"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			record := createReplacementPublicationIntent(t, store, root, "")
			stagePath := filepath.Join(root, record.StageName)
			destinationPath := filepath.Join(root, record.Destination)
			oldPath := destinationPath + ".old"
			if err := os.Rename(destinationPath, oldPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(destinationPath, []byte("conflict"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
				t.Fatal(err)
			}
			unknown, exists, err := store.Load(t.Context(), "receive", record.ID)
			if err != nil || !exists || unknown.State != "outcome_unknown" {
				t.Fatalf("unknown record=%+v exists=%t err=%v", unknown, exists, err)
			}
			if err := os.Remove(destinationPath); err != nil {
				t.Fatal(err)
			}
			if test.published {
				if err := os.Rename(stagePath, destinationPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(oldPath, destinationPath); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`update put_transfers set next_retry_at=created_at where direction='receive' and transfer_id=?`, record.ID); err != nil {
				t.Fatal(err)
			}
			if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
				t.Fatal(err)
			}
			settled, exists, err := store.Load(t.Context(), "receive", record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if test.published {
				if !exists || settled.State != "committed" || settled.StageName != "" {
					t.Fatalf("published settlement=%+v exists=%t", settled, exists)
				}
			} else if exists {
				t.Fatalf("not-published settlement retained row: %+v", settled)
			}
		})
	}
}

func TestAcceptCurrentResolutionResumesIntentAndCleansExactCreateStage(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	var events []ResolutionEvent
	store.SetResolved(func(event ResolutionEvent) { events = append(events, event) })
	record := createPublicationIntent(t, store, root)
	stagePath := filepath.Join(root, record.StageName)
	destinationPath := filepath.Join(root, record.Destination)
	if err := os.Link(stagePath, destinationPath); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimReceiver(t.Context(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkUnknown(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(record.ID, lease)
	store.fault = func(point string) error {
		if point == "after_accept_current_intent" {
			return errors.New("stop after accept-current intent")
		}
		return nil
	}
	if _, err := store.ResolveAcceptCurrent(t.Context(), "home", record.ID, root, 7); err == nil {
		t.Fatal("resolution unexpectedly completed past injected intent fault")
	}
	if len(events) != 0 {
		t.Fatalf("resolution event emitted before commit: %+v", events)
	}
	intent, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || intent.State != "accept_current_intent" || intent.ResolutionDestinationIdentity != record.StageIdentity {
		t.Fatalf("intent=%+v exists=%t err=%v", intent, exists, err)
	}
	if _, err := os.Stat(stagePath); err != nil {
		t.Fatalf("stage changed before resumable cleanup: %v", err)
	}
	store.fault = nil
	result, err := store.ResolveAcceptCurrent(t.Context(), "home", record.ID, root, 7)
	if err != nil || result.Version != ResolutionVersion || result.State != "resolved_accept_current" || result.Destination != record.Destination {
		t.Fatalf("resolution=%+v err=%v", result, err)
	}
	if len(events) != 1 || events[0].Version != ResolutionEventVersion || events[0].Type != "put.resolved_accept_current" || events[0].TransferID != record.ID || events[0].Context != "home" || events[0].At.IsZero() {
		t.Fatalf("resolution events=%+v", events)
	}
	resolved, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || resolved.State != "resolved_accept_current" || resolved.ResolutionDestinationIdentity != record.StageIdentity || resolved.StageName != "" || resolved.StageIdentity != "" || resolved.ParentPath != "" || resolved.ParentIdentity != "" || resolved.Durability != "" {
		t.Fatalf("resolved=%+v exists=%t err=%v", resolved, exists, err)
	}
	if _, err := os.Stat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact stage remains after resolution: %v", err)
	}
	if content, err := os.ReadFile(destinationPath); err != nil || string(content) != "x" {
		t.Fatalf("accepted destination=%q err=%v", content, err)
	}
	if blocking, err := store.HasBlocking(t.Context(), "home"); err != nil || blocking {
		t.Fatalf("resolved row blocking=%t err=%v", blocking, err)
	}
}

func TestAcceptCurrentResolutionRefusesChangedOwnedArtifactWithoutDeletion(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	record := createPublicationIntent(t, store, root)
	stagePath := filepath.Join(root, record.StageName)
	destinationPath := filepath.Join(root, record.Destination)
	if err := os.Link(stagePath, destinationPath); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimReceiver(t.Context(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkUnknown(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(record.ID, lease)
	ownedStage := stagePath + ".owned"
	if err := os.Rename(stagePath, ownedStage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagePath, []byte("unowned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveAcceptCurrent(t.Context(), "home", record.ID, root, 7); !errors.Is(err, ErrResolutionUnsafe) {
		t.Fatalf("resolution error=%v", err)
	}
	if content, err := os.ReadFile(destinationPath); err != nil || string(content) != "x" {
		t.Fatalf("destination changed=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(stagePath); err != nil || string(content) != "unowned" {
		t.Fatalf("unowned stage changed=%q err=%v", content, err)
	}
}

func TestReplacementSessionResumeClearsCommittedCleanupEvidence(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	record := createReplacementPublicationIntent(t, store, root, "")
	if err := os.Rename(filepath.Join(root, record.StageName), filepath.Join(root, record.Destination)); err != nil {
		t.Fatal(err)
	}
	left, right := make(chan Message, 4), make(chan Message, 4)
	sender := recoveryChannel{send: left, receive: right}
	receiver := recoveryChannel{send: right, receive: left}
	received := make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "offer", Manifest: &record.Manifest}); err != nil {
		t.Fatal(err)
	}
	prepared, err := receiveControl(t.Context(), sender)
	if err != nil || prepared.Type != "prepared" || prepared.ID != record.ID {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "start", ID: record.ID}); err != nil {
		t.Fatal(err)
	}
	committed, err := receiveControl(t.Context(), sender)
	if err != nil || committed.Type != "committed" || committed.ID != record.ID || !committed.Replaced || committed.Created {
		t.Fatalf("committed=%+v err=%v", committed, err)
	}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "result_ack", ID: record.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	updated, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || updated.State != "committed" || updated.StageName != "" || updated.StageIdentity != "" || updated.ParentPath != "" || updated.ParentIdentity != "" || updated.StageRemoved || updated.ParentSynced {
		t.Fatalf("resumed cleanup record=%+v exists=%t err=%v", updated, exists, err)
	}
	parent, err := openDestinationParent(root, record.Destination, false)
	if err != nil {
		t.Fatal(err)
	}
	destinationIntact, known := destinationHasIdentity(parent.Parent(), filepath.Base(record.Destination), record.StageIdentity)
	parent.Close()
	if !known || !destinationIntact {
		t.Fatal("session recovery changed the committed replacement")
	}
}

func TestReplacementCancellationAndCASMismatchCleanWithoutRename(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel bool
	}{
		{name: "cancellation", cancel: true},
		{name: "CAS mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			root := t.TempDir()
			store := NewStore(func() *sql.DB { return db })
			if err := os.WriteFile(filepath.Join(root, "result"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.cancel {
				store.fault = func(point string) error {
					if point == "before_native_publish" {
						cancel()
					}
					return nil
				}
			}
			manifest := recoveryManifest("result")
			manifest.Mode = "replace"
			digest := sha256.Sum256([]byte("old"))
			manifest.ExpectSHA256 = hex.EncodeToString(digest[:])
			if !test.cancel {
				manifest.ExpectSHA256 = strings.Repeat("0", 64)
			}
			left, right := make(chan Message, 4), make(chan Message, 4)
			sender := recoveryChannel{send: left, receive: right}
			receiver := recoveryChannel{send: right, receive: left}
			received := make(chan error, 1)
			go func() {
				_, err := Receive(ctx, receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
				received <- err
			}()
			if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
				t.Fatal(err)
			}
			if _, err := receiveControl(ctx, sender); err != nil {
				t.Fatal(err)
			}
			if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := receiveControl(ctx, sender); err != nil {
				t.Fatal(err)
			}
			if err := sender.Send(ctx, Message{Data: []byte("x")}); err != nil {
				t.Fatal(err)
			}
			if _, err := receiveControl(ctx, sender); err != nil {
				t.Fatal(err)
			}
			if err := sendControl(ctx, sender, control{Version: protocolVersion, Type: "complete", ID: manifest.ID}); err != nil {
				t.Fatal(err)
			}
			if !test.cancel {
				terminal, err := receiveControl(t.Context(), sender)
				if err != nil || (terminal.Type != "error" && terminal.Type != "retryable_error") || terminal.ID != manifest.ID {
					t.Fatalf("terminal=%+v err=%v", terminal, err)
				}
				if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "result_ack", ID: manifest.ID}); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-received; err == nil {
				t.Fatal("replacement unexpectedly succeeded")
			}
			content, err := os.ReadFile(filepath.Join(root, "result"))
			if err != nil || string(content) != "old" {
				t.Fatalf("destination=%q err=%v", content, err)
			}
			if _, exists, err := store.Load(t.Context(), "receive", manifest.ID); err != nil || exists {
				t.Fatalf("cleanup record exists=%t err=%v", exists, err)
			}
			stages, err := filepath.Glob(filepath.Join(root, ".px-*.put"))
			if err != nil || len(stages) != 0 {
				t.Fatalf("stages=%v err=%v", stages, err)
			}
		})
	}
}

func TestReplacementCommittedCleanupRetriesAfterFault(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	record := createReplacementPublicationIntent(t, store, root, "")
	if err := os.Rename(filepath.Join(root, record.StageName), filepath.Join(root, record.Destination)); err != nil {
		t.Fatal(err)
	}
	store.fault = func(point string) error {
		if point == "after_stage_removed_record" {
			return errors.New("injected replacement cleanup failure")
		}
		return nil
	}
	if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
		t.Fatal(err)
	}
	updated, exists, err := store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || updated.State != "committed" || updated.StageName == "" || !updated.StageRemoved {
		t.Fatalf("faulted cleanup record=%+v exists=%t err=%v", updated, exists, err)
	}
	store.fault = nil
	if _, err := db.Exec(`update put_transfers set next_retry_at=created_at where direction='receive' and transfer_id=?`, record.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "different-current-id"); err != nil {
		t.Fatal(err)
	}
	updated, exists, err = store.Load(t.Context(), "receive", record.ID)
	if err != nil || !exists || updated.StageName != "" {
		t.Fatalf("retried cleanup record=%+v exists=%t err=%v", updated, exists, err)
	}
}

func TestCommittedReplacementCleanupSettlesAfterLaterReplacement(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	first := createReplacementPublicationIntent(t, store, root, "")
	if err := os.Rename(filepath.Join(root, first.StageName), filepath.Join(root, first.Destination)); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimReceiver(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReceiver(t.Context(), first.ID, lease, "durability_confirmed"); err != nil {
		t.Fatal(err)
	}
	first, exists, err := store.Load(t.Context(), "receive", first.ID)
	if err != nil || !exists || first.State != "committed" {
		t.Fatalf("first committed record=%+v exists=%t err=%v", first, exists, err)
	}
	store.fault = func(point string) error {
		if point == "after_stage_removed_record" {
			return errors.New("injected replacement cleanup failure")
		}
		return nil
	}
	if err := store.CleanupCommitted(t.Context(), first, lease); err == nil {
		t.Fatal("first post-commit cleanup unexpectedly succeeded")
	}
	store.ReleaseReceiver(first.ID, lease)
	first, exists, err = store.Load(t.Context(), "receive", first.ID)
	if err != nil || !exists || first.StageName == "" || !first.StageRemoved {
		t.Fatalf("first retained cleanup evidence=%+v exists=%t err=%v", first, exists, err)
	}

	store.fault = nil
	second := createReplacementPublicationIntent(t, store, root, "")
	if err := os.Rename(filepath.Join(root, second.StageName), filepath.Join(root, second.Destination)); err != nil {
		t.Fatal(err)
	}
	result, settled, err := reconcilePublication(second)
	if err != nil || !settled || !result.Replaced {
		t.Fatalf("second replacement result=%+v settled=%t err=%v", result, settled, err)
	}
	lease, err = store.ClaimReceiver(t.Context(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReceiver(t.Context(), second.ID, lease, "durability_confirmed"); err != nil {
		t.Fatal(err)
	}
	second.State = "committed"
	second.Durability = "durability_confirmed"
	if err := store.CleanupCommitted(t.Context(), second, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(second.ID, lease)
	keep := filepath.Join(root, "keep")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	lease, err = store.ClaimReceiver(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupCommitted(t.Context(), first, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(first.ID, lease)
	content, err := os.ReadFile(filepath.Join(root, first.Destination))
	if err != nil || string(content) != "x" {
		t.Fatalf("later replacement=%q err=%v", content, err)
	}
	parent, err := openDestinationParent(root, first.Destination, false)
	if err != nil {
		t.Fatal(err)
	}
	secondRemains, known := destinationHasIdentity(parent.Parent(), filepath.Base(first.Destination), second.StageIdentity)
	parent.Close()
	if !known || !secondRemains {
		t.Fatal("first cleanup changed the later replacement identity")
	}
	if content, err := os.ReadFile(keep); err != nil || string(content) != "keep" {
		t.Fatalf("unrelated artifact=%q err=%v", content, err)
	}
	first, exists, err = store.Load(t.Context(), "receive", first.ID)
	if err != nil || !exists || first.StageName != "" || first.StageIdentity != "" || first.StageRemoved || first.ParentSynced {
		t.Fatalf("first cleanup evidence=%+v exists=%t err=%v", first, exists, err)
	}
	var retained int
	if err := db.QueryRow(`select count(*) from put_transfers where direction='receive' and state='committed' and stage_identity is not null`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("retained capacity evidence=%d err=%v", retained, err)
	}
}

func createReplacementPublicationIntent(t *testing.T, store *Store, root, expected string) Record {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "result"), []byte("old"), 0o600); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	parent, err := openDestinationParent(root, "result", false)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := inspectReplacementDestination(parent, "result")
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	manifest := recoveryManifest("result")
	manifest.Mode = "replace"
	manifest.ExpectSHA256 = expected
	manifest.RootRevision = 7
	record := Record{Manifest: manifest, Direction: "receive", PeerLabel: "sender", ParentPath: parent.path, ParentIdentity: parentDurableIdentity(parent), StageName: ".px-" + manifest.ID + ".put", State: "stage_intent", OldIdentity: evidence.Identity, OldUID: evidence.UID, OldGID: evidence.GID, OldMode: evidence.Mode}
	lease, err := store.ReserveReceiver(t.Context(), record, record.ParentPath, record.ParentIdentity, record.StageName)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	stage, attached, err := createOrOpenStage(parent, manifest, record)
	if err != nil {
		store.ReleaseReceiver(record.ID, lease)
		parent.Close()
		t.Fatal(err)
	}
	if !attached {
		t.Fatal("replacement stage identity was not attached")
	}
	if err := store.AttachStage(t.Context(), record.ID, lease, stage.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := stage.File.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateOffset(t.Context(), record.ID, lease, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.PublicationIntent(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(record.ID, lease)
	record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
	if err != nil || !exists {
		t.Fatalf("replacement intent exists=%t err=%v", exists, err)
	}
	return record
}

func TestReapParentProcessesCleanupBeforeExpiryAndUsesHourlyThenDailyCadence(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	record := createPublicationIntent(t, store, root)
	lease, err := store.ClaimReceiver(t.Context(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCleanupNotAttempted(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(record.ID, lease)
	if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "other"); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(t.Context(), "receive", record.ID); err != nil || exists {
		t.Fatalf("due cleanup row remained: exists=%t err=%v", exists, err)
	}
	record = createPublicationIntent(t, store, root)
	lease, err = store.ClaimReceiver(t.Context(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCleanupNotAttempted(t.Context(), record.ID, lease); err != nil {
		t.Fatal(err)
	}
	store.ReleaseReceiver(record.ID, lease)
	store.fault = func(point string) error {
		if point == "before_parent_sync" {
			return errors.New("injected cleanup sync failure")
		}
		return nil
	}
	before := time.Now().UTC()
	if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "other"); err != nil {
		t.Fatal(err)
	}
	var nextRetry int64
	if err := db.QueryRow(`select next_retry_at from put_transfers where direction='receive' and transfer_id=?`, record.ID).Scan(&nextRetry); err != nil {
		t.Fatal(err)
	}
	if next := time.Unix(nextRetry, 0); next.Before(before.Add(50*time.Minute)) || next.After(before.Add(70*time.Minute)) {
		t.Fatalf("pre-expiry cleanup retry=%s", next)
	}
	store.fault = nil

	record = createPublicationIntent(t, store, root)
	created := time.Now().Add(-48 * time.Hour).Unix()
	expired := time.Now().Add(-24 * time.Hour).Unix()
	if _, err := db.Exec(`update put_transfers set created_at=?,updated_at=?,expires_at=?,next_retry_at=? where direction='receive' and transfer_id=?`, created, created, expired, created, record.ID); err != nil {
		t.Fatal(err)
	}
	before = time.Now().UTC()
	if err := store.ReapParent(t.Context(), record.ParentPath, record.ParentIdentity, "other"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`select next_retry_at from put_transfers where direction='receive' and transfer_id=?`, record.ID).Scan(&nextRetry); err != nil {
		t.Fatal(err)
	}
	if next := time.Unix(nextRetry, 0); next.Before(before.Add(23*time.Hour)) || next.After(before.Add(25*time.Hour)) {
		t.Fatalf("expired publication evidence retry=%s", next)
	}
}

func TestReapParentProcessesAtMostEightDueRecords(t *testing.T) {
	db := recoveryDatabase(t)
	root := t.TempDir()
	store := NewStore(func() *sql.DB { return db })
	parent, err := openDestinationParent(root, "result", true)
	if err != nil {
		t.Fatal(err)
	}
	parentPath := parent.path
	parentIdentity := parentDurableIdentity(parent)
	parent.Close()
	created := time.Now().Add(-2 * Lifetime).Unix()
	expired := time.Now().Add(-Lifetime).Unix()
	for index := range 9 {
		manifest := recoveryManifest("result")
		manifest.ID = fmt.Sprintf("%032x", index+1)
		manifest.RootRevision = 7
		stageName := fmt.Sprintf(".px-%032x.put", index+1)
		lease, err := store.ReserveReceiver(t.Context(), Record{Manifest: manifest, PeerLabel: "sender"}, parentPath, parentIdentity, stageName)
		if err != nil {
			t.Fatal(err)
		}
		store.ReleaseReceiver(manifest.ID, lease)
		if _, err := db.Exec(`update put_transfers set created_at=?,updated_at=?,expires_at=?,next_retry_at=? where direction='receive' and transfer_id=?`, created, created, expired, created, manifest.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReapParent(t.Context(), parentPath, parentIdentity, "other"); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := db.QueryRow(`select count(*) from put_transfers where direction='receive'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("remaining=%d err=%v", remaining, err)
	}
}

func createPublicationIntent(t *testing.T, store *Store, root string) Record {
	t.Helper()
	manifest := recoveryManifest("result")
	store.fault = func(point string) error {
		if point == "before_native_publish" {
			return errors.New("stop before native publish")
		}
		return nil
	}
	left, right := make(chan Message, 4), make(chan Message, 4)
	sender := recoveryChannel{send: left, receive: right}
	receiver := recoveryChannel{send: right, receive: left}
	received := make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(t.Context(), sender); err != nil {
		t.Fatal(err)
	}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(t.Context(), sender); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(t.Context(), Message{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(t.Context(), sender); err != nil {
		t.Fatal(err)
	}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "complete", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err == nil {
		t.Fatal("receiver unexpectedly published")
	}
	store.fault = nil
	record, exists, err := store.Load(t.Context(), "receive", manifest.ID)
	if err != nil || !exists || record.State != "publication_intent" {
		t.Fatalf("publication intent=%+v exists=%t err=%v", record, exists, err)
	}
	return record
}

func TestControlDecodeRejectsUnknownIrrelevantMissingAndMismatchedFields(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	tests := []string{
		`{"version":2,"type":"start","type":"ready","id":"` + id + `"}`,
		`{"version":2,"type":"start","id":"` + id + `","id":"` + id + `"}`,
		`{"version":2,"type":"offer","manifest":{"version":2,"id":"` + id + `","id":"` + id + `","context":"home","sender_id":"sender","receiver_id":"receiver","destination":"result","mode":"create","size":1,"sha256":"` + strings.Repeat("0", 64) + `","chunk_size":32768,"ack_window":8,"put_root_revision":0}}`,
		`{"version":2,"type":"offer","manifest":{"version":2,"id":"` + id + `","context":"home","context":"home","sender_id":"sender","receiver_id":"receiver","destination":"result","mode":"create","size":1,"sha256":"` + strings.Repeat("0", 64) + `","chunk_size":32768,"ack_window":8,"put_root_revision":0}}`,
		`{"version":2,"type":"offer","manifest":null,"id":""}`,
		`{"version":2,"type":"prepared","id":"` + id + `","put_root_revision":7,"bytes":0}`,
		`{"version":2,"type":"start","id":"` + id + `","bytes":0}`,
		`{"version":2,"type":"ready","id":"` + id + `","unknown":1}`,
		`{"version":2,"type":"ready","id":"` + id + `","offset":0}`,
		`{"version":2,"type":"complete","id":"` + id + `","bytes":0}`,
		`{"version":2,"type":"result_ack","id":"` + id + `","created":false}`,
		`{"version":2,"type":"ack","id":"` + id + `","offset":1,"bytes":0}`,
		`{"version":2,"type":"committed","id":"` + id + `","bytes":1,"created":true,"replaced":false,"durability":"durability_confirmed","put_root_revision":7,"offset":0}`,
		`{"version":2,"type":"prepared","id":"` + id + `"}`,
		`{"version":2,"type":"committed","id":"` + id + `","created":true,"replaced":false,"durability":"durability_confirmed","put_root_revision":7}`,
		`{"version":2,"type":"error","id":"` + id + `","error":"no","offset":0}`,
		`{"version":2,"type":"start","id":"` + id + `"} {}`,
	}
	for index, raw := range tests {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			messages := make(chan Message, 1)
			messages <- Message{Text: true, Data: []byte(raw)}
			if _, err := receiveControl(t.Context(), recoveryChannel{receive: messages}); err == nil {
				t.Fatalf("accepted %s", raw)
			}
		})
	}
}

func TestControlDecodeMapsAndRedactsStructuralErrors(t *testing.T) {
	const sensitive = "private-member-or-value"
	for _, raw := range []string{
		`{"version":2,"type":"offer","manifest":{"` + sensitive + `":"` + sensitive + `","` + sensitive + `":"other"}}`,
		`{"version":2,"type":"start","id":"0123456789abcdef0123456789abcdef"} "` + sensitive + `"`,
	} {
		messages := make(chan Message, 1)
		messages <- Message{Text: true, Data: []byte(raw)}
		_, err := receiveControl(t.Context(), recoveryChannel{receive: messages})
		if err == nil || err.Error() != "invalid put control message" || strings.Contains(err.Error(), sensitive) {
			t.Fatalf("receiveControl() error = %v", err)
		}
	}
}

func TestHandshakeLossBoundariesRetainOnlyRecoverableState(t *testing.T) {
	for _, test := range []struct {
		name, drop, senderState, receiverState string
	}{
		{name: "prepared", drop: "prepared"},
		{name: "start", drop: "start", senderState: "transferring"},
		{name: "ready", drop: "ready", senderState: "transferring", receiverState: "transferring"},
		{name: "committed", drop: "committed", senderState: "transferring", receiverState: "committed"},
		{name: "final ack", drop: "result_ack", senderState: "committed", receiverState: "committed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			store := NewStore(func() *sql.DB { return db })
			root := t.TempDir()
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			left, right := make(chan Message, 8), make(chan Message, 8)
			var dropped atomic.Bool
			senderBase := recoveryChannel{send: left, receive: right}
			receiverBase := recoveryChannel{send: right, receive: left}
			var sender Channel = senderBase
			var receiver Channel = receiverBase
			if test.drop == "start" || test.drop == "result_ack" {
				sender = droppingChannel{recoveryChannel: senderBase, drop: test.drop, dropped: &dropped}
			} else {
				receiver = droppingChannel{recoveryChannel: receiverBase, drop: test.drop, dropped: &dropped}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			received := make(chan error, 1)
			go func() {
				_, err := Receive(ctx, receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
				received <- err
			}()
			id := ""
			_, sendErr := Send(ctx, sender, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store, Progress: func(event Event) {
				if event.TransferID != "" {
					id = event.TransferID
				}
			}})
			receiveErr := <-received
			if !dropped.Load() {
				t.Fatalf("%s was not dropped", test.drop)
			}
			if test.drop == "result_ack" {
				if sendErr != nil || receiveErr == nil {
					t.Fatalf("final ack loss send=%v receive=%v", sendErr, receiveErr)
				}
			} else if sendErr == nil && receiveErr == nil {
				t.Fatal("loss unexpectedly succeeded")
			}
			assertStoredState(t, store, "send", id, test.senderState)
			assertStoredState(t, store, "receive", id, test.receiverState)
		})
	}
}

func TestTerminalDeliveryOutlivesDurableSettlement(t *testing.T) {
	if resultDeliveryTimeout <= settlementTimeout {
		t.Fatalf("result delivery timeout %v must exceed settlement timeout %v", resultDeliveryTimeout, settlementTimeout)
	}
}

func TestLostCommittedResultReplaysReceiverTombstoneOnRetry(t *testing.T) {
	db := recoveryDatabase(t)
	store := NewStore(func() *sql.DB { return db })
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	left, right := make(chan Message, 8), make(chan Message, 8)
	var dropped atomic.Bool
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	received := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, droppingChannel{recoveryChannel: recoveryChannel{send: right, receive: left}, drop: "committed", dropped: &dropped}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	id := ""
	_, _ = Send(ctx, recoveryChannel{send: left, receive: right}, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store, Progress: func(event Event) { id = event.TransferID }})
	<-received
	lease, err := store.ClaimSender(t.Context(), "home", id)
	if err != nil {
		t.Fatal(err)
	}
	left, right = make(chan Message, 4), make(chan Message, 4)
	received = make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), recoveryChannel{send: right, receive: left}, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		received <- err
	}()
	result, err := Send(t.Context(), recoveryChannel{send: left, receive: right}, SendConfig{Context: "home", ReceiverID: "receiver", Store: store, Lease: lease})
	lease.Release()
	if err != nil || result.TransferID != id {
		t.Fatalf("retry result=%+v err=%v", result, err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	assertStoredState(t, store, "send", id, "committed")
}

func assertStoredState(t *testing.T, store *Store, direction, id, state string) {
	t.Helper()
	record, exists, err := store.Load(t.Context(), direction, id)
	if state == "" {
		if err != nil || exists {
			t.Fatalf("%s state=%q exists=%t err=%v", direction, record.State, exists, err)
		}
		return
	}
	if err != nil || !exists || record.State != state {
		t.Fatalf("%s state=%q want=%q exists=%t err=%v", direction, record.State, state, exists, err)
	}
}

func recoveryManifest(destination string) Manifest {
	sum := sha256.Sum256([]byte("x"))
	id, _ := randomID(16)
	return Manifest{Version: protocolVersion, ID: id, Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: destination, Mode: "create", Size: 1, SHA256: hex.EncodeToString(sum[:]), ChunkSize: ChunkSize, AckWindow: AckWindow}
}

func startReceiverUntilFailure(t *testing.T, store *Store, root string, manifest Manifest) error {
	t.Helper()
	left, right := make(chan Message, 4), make(chan Message, 4)
	sender := recoveryChannel{send: left, receive: right}
	receiver := recoveryChannel{send: right, receive: left}
	result := make(chan error, 1)
	go func() {
		_, err := Receive(t.Context(), receiver, ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		result <- err
	}()
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		t.Fatal(err)
	}
	prepared, err := receiveControl(t.Context(), sender)
	if err != nil || prepared.Type != "prepared" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		return err
	case message := <-right:
		terminalMessages := make(chan Message, 1)
		terminalMessages <- message
		terminal, err := receiveControl(t.Context(), recoveryChannel{receive: terminalMessages})
		if err != nil || (terminal.Type != "error" && terminal.Type != "retryable_error") || terminal.ID != manifest.ID {
			t.Fatalf("terminal=%+v err=%v", terminal, err)
		}
		if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "result_ack", ID: manifest.ID}); err != nil {
			t.Fatal(err)
		}
		return <-result
	}
}

func recoveryDatabase(t *testing.T) *sql.DB {
	t.Helper()
	cfg, err := database.Config(database.KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	component := sqlite.New(cfg)
	if err := component.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = component.Stop(context.Background()) })
	db := component.DB()
	_, err = db.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,put_root,allow_put,put_root_revision,created_at,updated_at) values('home','https://px.example','server','receiver','private','public','receiver','connected',1,?,?,?,1,7,1,1)`, t.TempDir(), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}
