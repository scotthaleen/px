//go:build !windows

package put_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/put"
)

type memoryChannel struct{ send, receive chan put.Message }

func (c memoryChannel) Send(ctx context.Context, message put.Message) error {
	select {
	case c.send <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c memoryChannel) Receive(ctx context.Context) (put.Message, error) {
	select {
	case message := <-c.receive:
		return message, nil
	case <-ctx.Done():
		return put.Message{}, ctx.Err()
	}
}

func TestCreateOnlyPutPublishesAndPersistsIndependentRevision(t *testing.T) {
	db := putDatabase(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source")
	content := []byte(strings.Repeat("safe-put", 10000))
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	left, right := make(chan put.Message, 8), make(chan put.Message, 8)
	sender := memoryChannel{send: left, receive: right}
	receiver := memoryChannel{send: right, receive: left}
	store := put.NewStore(func() *sql.DB { return db })
	receiverResult := make(chan error, 1)
	go func() {
		result, err := put.Receive(t.Context(), receiver, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
		if err == nil && (!result.Created || !result.DurabilityConfirmed) {
			err = errors.New("receiver result did not confirm durable creation")
		}
		receiverResult <- err
	}()
	result, err := put.Send(t.Context(), sender, put.SendConfig{Source: source, Destination: "existing/result.bin", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-receiverResult; err != nil {
		t.Fatal(err)
	}
	if !result.Created || !result.DurabilityConfirmed || result.Destination != "existing/result.bin" {
		t.Fatalf("result=%+v", result)
	}
	got, err := os.ReadFile(filepath.Join(root, "existing", "result.bin"))
	if err != nil || string(got) != string(content) {
		t.Fatalf("destination mismatch: %v", err)
	}
	var revision int64
	if err := db.QueryRow(`select put_root_revision from put_transfers where direction='receive' and transfer_id=?`, result.TransferID).Scan(&revision); err != nil || revision != 7 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	var stageIdentity sql.NullString
	if err := db.QueryRow(`select stage_identity from put_transfers where direction='receive' and transfer_id=?`, result.TransferID).Scan(&stageIdentity); err != nil || stageIdentity.Valid {
		t.Fatalf("committed stage was not durably cleaned: identity=%q valid=%t err=%v", stageIdentity.String, stageIdentity.Valid, err)
	}
}

func TestPutCollisionAndSymlinkParentLeaveExistingStateUnchanged(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(existing, "result")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest("existing/result")
	store, _ := putStore(t)
	left, right := make(chan put.Message, 4), make(chan put.Message, 4)
	left <- put.Message{Text: true, Data: mustControlOffer(t, manifest)}
	left <- put.Message{Text: true, Data: mustControl(t, "start", manifest.ID)}
	left <- put.Message{Text: true, Data: mustControl(t, "result_ack", manifest.ID)}
	_, err := put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
	if err == nil {
		t.Fatal("collision accepted")
	}
	assertControlTypes(t, right, "prepared", "error")
	got, _ := os.ReadFile(destination)
	if string(got) != "original" {
		t.Fatalf("existing destination changed: %q", got)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	manifest = testManifest("link/result")
	left = make(chan put.Message, 4)
	right = make(chan put.Message, 4)
	left <- put.Message{Text: true, Data: mustControlOffer(t, manifest)}
	left <- put.Message{Text: true, Data: mustControl(t, "result_ack", manifest.ID)}
	_, err = put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store})
	if err == nil {
		t.Fatal("symlink parent accepted")
	}
	assertControlTypes(t, right, "error")
}

func TestPutRejectsCaseCollisionUnsafeAncestorAndNonCreateMode(t *testing.T) {
	t.Run("case collision", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "Result"), []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertOfferRejected(t, root, testManifest("result"), "prepared", "error")
	})
	t.Run("unsafe ancestor", func(t *testing.T) {
		root := t.TempDir()
		ancestor := filepath.Join(root, "unsafe")
		parent := filepath.Join(ancestor, "protected-final")
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		assertOfferRejected(t, root, testManifest("unsafe/protected-final/result"), "error")
	})
	t.Run("mode binding", func(t *testing.T) {
		manifest := testManifest("result")
		manifest.Mode = "replace"
		assertOfferRejected(t, t.TempDir(), manifest, "prepared", "error")
	})
}

func TestPutRejectsUppercaseTransferIDBeforePreparedOrReservation(t *testing.T) {
	manifest := testManifest("result")
	manifest.ID = strings.ToUpper(manifest.ID)
	store, db := putStore(t)
	left, right := make(chan put.Message, 1), make(chan put.Message, 1)
	left <- put.Message{Text: true, Data: mustControlOffer(t, manifest)}
	if _, err := put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: t.TempDir(), Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store}); err == nil {
		t.Fatal("uppercase transfer ID was admitted")
	}
	if len(right) != 0 {
		t.Fatal("uppercase transfer ID reached prepared admission")
	}
	var count int
	if err := db.QueryRow(`select count(*) from put_transfers where transfer_id=?`, manifest.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("uppercase transfer reservation count = %d, %v", count, err)
	}
}

func TestRepeatedIdenticalPutUsesFreshIDAndNormalCollision(t *testing.T) {
	db := putDatabase(t)
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("same content"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := put.NewStore(func() *sql.DB { return db })
	firstID, firstErr := runPut(t, store, root, source, "result", 7)
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	secondID, secondErr := runPut(t, store, root, source, "result", 7)
	if secondErr == nil {
		t.Fatal("identical second put did not collide")
	}
	if firstID == "" || secondID == "" || firstID == secondID {
		t.Fatalf("invocation IDs first=%q second=%q", firstID, secondID)
	}
	got, err := os.ReadFile(filepath.Join(root, "result"))
	if err != nil || string(got) != "same content" {
		t.Fatalf("destination changed: %q err=%v", got, err)
	}
}

func TestPutRootRevisionIsPinnedIndependentlyOfFreshID(t *testing.T) {
	db := putDatabase(t)
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("revision"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := put.NewStore(func() *sql.DB { return db })
	id, err := runPut(t, store, root, source, "first", 7)
	if err != nil {
		t.Fatal(err)
	}
	var revision int64
	if err := db.QueryRow(`select put_root_revision from put_transfers where direction='send' and transfer_id=?`, id).Scan(&revision); err != nil || revision != 7 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	secondID, err := runPut(t, store, root, source, "second", 8)
	if err != nil {
		t.Fatal(err)
	}
	if secondID == id {
		t.Fatal("revision-changing invocation reused transfer ID")
	}
	if err := db.QueryRow(`select put_root_revision from put_transfers where direction='send' and transfer_id=?`, secondID).Scan(&revision); err != nil || revision != 8 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
}

func TestCanonicalManifestVectorAndStrictDecode(t *testing.T) {
	manifest := testManifest("parent/file")
	data, err := put.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "66196bb3aba3fdd43848ad04812caadda3c7e5f0e34a578b5aab429c6816d260" {
		t.Fatalf("vector=%s payload=%s", got, data)
	}
}

func TestReplacementManifestRequiresCanonicalCAS(t *testing.T) {
	manifest := testManifest("result")
	manifest.ExpectSHA256 = strings.Repeat("a", 64)
	if _, err := put.CanonicalManifest(manifest); err == nil {
		t.Fatal("create manifest accepted CAS")
	}
	manifest.Mode = "replace"
	data, err := put.CanonicalManifest(manifest)
	if err != nil {
		t.Fatalf("replacement manifest rejected canonical CAS: %v", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "140affb47af03358dd35c5ad737bd7bf7ed3bd1ce0a7c9b653109c70c28adf0b" {
		t.Fatalf("replacement vector=%s payload=%s", got, data)
	}
	manifest.ExpectSHA256 = strings.Repeat("A", 64)
	if _, err := put.CanonicalManifest(manifest); err == nil {
		t.Fatal("replacement manifest accepted uppercase CAS")
	}
}

func testManifest(destination string) put.Manifest {
	manifest := put.Manifest{Version: 2, Context: "home", SenderID: "sender", ReceiverID: "receiver", Destination: destination, Mode: "create", Size: 1, SHA256: strings.Repeat("0", 64), ChunkSize: put.ChunkSize, AckWindow: put.AckWindow, RootRevision: 7}
	type identity struct {
		Version     int    `json:"version"`
		Context     string `json:"context"`
		SenderID    string `json:"sender_id"`
		ReceiverID  string `json:"receiver_id"`
		Destination string `json:"destination"`
		Mode        string `json:"mode"`
		Size        int64  `json:"size"`
		SHA256      string `json:"sha256"`
		ChunkSize   int    `json:"chunk_size"`
		AckWindow   int    `json:"ack_window"`
	}
	data, _ := json.Marshal(identity{manifest.Version, manifest.Context, manifest.SenderID, manifest.ReceiverID, manifest.Destination, manifest.Mode, manifest.Size, manifest.SHA256, manifest.ChunkSize, manifest.AckWindow})
	sum := sha256.Sum256(append([]byte("px-put-id-v2\x00"), data...))
	manifest.ID = hex.EncodeToString(sum[:16])
	return manifest
}

func mustControlOffer(t *testing.T, manifest put.Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"version": 2, "type": "offer", "manifest": manifest})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustControl(t *testing.T, kind, id string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"version": 2, "type": kind, "id": id})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runPut(t *testing.T, store *put.Store, root, source, destination string, revision int64) (string, error) {
	t.Helper()
	left, right := make(chan put.Message, 8), make(chan put.Message, 8)
	received := make(chan error, 1)
	go func() {
		_, err := put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: revision, Store: store})
		received <- err
	}()
	id := ""
	_, sendErr := put.Send(t.Context(), memoryChannel{send: left, receive: right}, put.SendConfig{Source: source, Destination: destination, Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store, Progress: func(event put.Event) {
		if event.TransferID != "" {
			id = event.TransferID
		}
	}})
	receiveErr := <-received
	return id, errors.Join(sendErr, receiveErr)
}

func assertOfferRejected(t *testing.T, root string, manifest put.Manifest, controlTypes ...string) {
	t.Helper()
	store, _ := putStore(t)
	left, right := make(chan put.Message, 4), make(chan put.Message, 4)
	left <- put.Message{Text: true, Data: mustControlOffer(t, manifest)}
	if len(controlTypes) > 0 && controlTypes[0] == "prepared" {
		left <- put.Message{Text: true, Data: mustControl(t, "start", manifest.ID)}
	}
	left <- put.Message{Text: true, Data: mustControl(t, "result_ack", manifest.ID)}
	if _, err := put.Receive(t.Context(), memoryChannel{send: right, receive: left}, put.ReceiveConfig{Root: root, Context: "home", SenderID: "sender", SenderLabel: "sender", ReceiverID: "receiver", RootRevision: 7, Store: store}); err == nil {
		t.Fatal("unsafe offer accepted")
	}
	assertControlTypes(t, right, controlTypes...)
}

func assertControlTypes(t *testing.T, messages chan put.Message, want ...string) {
	t.Helper()
	for index, wantType := range want {
		select {
		case message := <-messages:
			var value struct {
				Version int    `json:"version"`
				Type    string `json:"type"`
			}
			if !message.Text || json.Unmarshal(message.Data, &value) != nil || value.Version != 2 || value.Type != wantType {
				t.Fatalf("control %d = version %d type %q data %q, want v2 %q", index, value.Version, value.Type, message.Data, wantType)
			}
		default:
			t.Fatalf("missing control %d, want v2 %q", index, wantType)
		}
	}
	if len(messages) != 0 {
		t.Fatalf("received %d unexpected controls", len(messages))
	}
}

func putStore(t *testing.T) (*put.Store, *sql.DB) {
	t.Helper()
	db := putDatabase(t)
	return put.NewStore(func() *sql.DB { return db }), db
}

func putDatabase(t *testing.T) *sql.DB {
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
	now := int64(1)
	_, err = db.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,put_root,allow_put,put_root_revision,created_at,updated_at) values('home','https://px.example','server','receiver','private','public','receiver','connected',1,?,?,?,1,7,?,?)`, t.TempDir(), t.TempDir(), t.TempDir(), now, now)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
