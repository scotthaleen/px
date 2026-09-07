package recent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
)

func TestInsertIsIdempotentAndRejectsMetadataMismatch(t *testing.T) {
	store, db := testStore(t)
	value := testObservation("home", 1, time.Unix(100, 0).UTC())
	if err := store.Insert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	retry := value
	retry.ObservedAt = time.Unix(200, 0).UTC()
	if err := store.Insert(context.Background(), retry); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	values, err := store.List(context.Background(), "home", "", MaxLimit)
	if err != nil || len(values) != 1 || !values[0].ObservedAt.Equal(value.ObservedAt) {
		t.Fatalf("values = %+v, %v", values, err)
	}
	retry.Bytes++
	if err := store.Insert(context.Background(), retry); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatch = %v", err)
	}
	var count int
	if err := db.QueryRow(`select count(*) from recent_observations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count = %d, %v", count, err)
	}
}

func TestRetentionPrunesOnlyOnNewInsertion(t *testing.T) {
	store, db := testStore(t)
	now := time.Unix(4_000_000, 0).UTC()
	old := testObservation("home", 1, now.Add(-AgeEligibility-time.Second))
	if err := store.Insert(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	values, err := store.List(context.Background(), "home", "", MaxLimit)
	if err != nil || len(values) != 1 {
		t.Fatalf("quiet old rows = %+v, %v", values, err)
	}
	for index := 2; index <= MaxPerContext+2; index++ {
		if err := store.Insert(context.Background(), testObservation("home", index, now.Add(time.Duration(index)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(`select count(*) from recent_observations where context_name='home'`).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
	values, err = store.List(context.Background(), "home", "", MaxLimit)
	if err != nil || len(values) != MaxPerContext || values[0].TransferID != fmt.Sprintf("%064x", MaxPerContext+2) {
		t.Fatalf("pressure values = %d %+v, %v", len(values), values, err)
	}
}

func TestClearAndContextCascade(t *testing.T) {
	store, db := testStore(t)
	if err := store.Insert(context.Background(), testObservation("home", 1, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	count, err := store.Clear(context.Background(), "home")
	if err != nil || count != 1 {
		t.Fatalf("clear = %d, %v", count, err)
	}
	if err := store.Insert(context.Background(), testObservation("home", 2, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`delete from contexts where name='home'`); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.QueryRow(`select count(*) from recent_observations`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("cascade rows = %d, %v", rows, err)
	}
}

func TestGlobalPressurePrunesOldest(t *testing.T) {
	store, db := testStore(t)
	now := time.Now().UTC()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for contextIndex := range 64 {
		contextName := fmt.Sprintf("c%02d", contextIndex)
		if _, err := tx.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values(?,'http://server','server','device','private','public','device','connected',1,'offered','inbox',1,1)`, contextName); err != nil {
			t.Fatal(err)
		}
		for rowIndex := range 64 {
			id := fmt.Sprintf("%064x", contextIndex*64+rowIndex+1)
			if _, err := tx.Exec(`insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values(?,'send',?,'sender_observed_commit',?,'peer','file','private',1,?)`, contextName, id, strings.Repeat("A", 43), now.Unix()+int64(contextIndex*64+rowIndex)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := tx.Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values('new','http://server','server','device','private','public','device','connected',1,'offered','inbox',1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	value := testObservation("new", 5000, now.Add(5000*time.Second))
	if err := store.Insert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	var count, oldest int
	if err := db.QueryRow(`select count(*) from recent_observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`select count(*) from recent_observations where transfer_id=?`, fmt.Sprintf("%064x", 1)).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if count != MaxPerAgent || oldest != 0 {
		t.Fatalf("global rows = %d, oldest = %d", count, oldest)
	}
}

func TestDecodeStrictRejectsUnknownDuplicateTrailingAndBounds(t *testing.T) {
	const sensitive = "private-member-or-value"
	for _, test := range []struct {
		data   string
		output any
	}{
		{`{"version":1,"limit":1,"unknown":true}`, &request{}},
		{`{"version":1,"limit":1,"limit":2}`, &request{}},
		{`{"version":1,"description":"x","reporter":{"device_id":"` + sensitive + `","device_id":"other","label":"peer"},"observations":[]}`, &Snapshot{}},
		{`{"version":1,"limit":1} "` + sensitive + `"`, &request{}},
		{strings.Repeat("x", MaxMessageBytes+1), &request{}},
	} {
		err := DecodeStrict([]byte(test.data), test.output)
		if err == nil || err.Error() != "invalid recent observation message" || strings.Contains(err.Error(), sensitive) {
			t.Fatalf("accepted %q", test.data)
		}
	}
}

func TestMaximumSnapshotFitsWireBound(t *testing.T) {
	values := make([]Observation, MaxLimit)
	for index := range values {
		values[index] = testObservation(strings.Repeat("c", 63), index+1, time.Unix(int64(index+1), 0).UTC())
		values[index].PeerLabel = strings.Repeat("p", 63)
		values[index].Destination = strings.Repeat("n", 255)
	}
	snapshot := Snapshot{Version: Version, Description: Description, Reporter: Reporter{DeviceID: strings.Repeat("A", 43), Label: strings.Repeat("r", 63), Context: strings.Repeat("c", 63)}, Observations: values}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > MaxMessageBytes || ValidateSnapshot(snapshot, false) != nil {
		t.Fatalf("maximum snapshot bytes = %d, marshal=%v validate=%v", len(data), err, ValidateSnapshot(snapshot, false))
	}
}

func TestServeFiltersByAuthenticatedPeerAndOmitsContext(t *testing.T) {
	requestData, err := json.Marshal(request{Version: Version, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	ackData, err := json.Marshal(acknowledgement{Version: Version, Type: "ack"})
	if err != nil {
		t.Fatal(err)
	}
	channel := &scriptedChannel{receive: []Message{{Text: true, Data: requestData}, {Text: true, Data: ackData}}}
	peerID := strings.Repeat("A", 43)
	reporter := Reporter{DeviceID: strings.Repeat("B", 43), Label: "reporter"}
	calledPeer := ""
	err = Serve(context.Background(), channel, reporter, peerID, func(_ context.Context, peer string, limit int) ([]Observation, error) {
		calledPeer = peer
		if limit != 1 {
			t.Fatalf("limit = %d", limit)
		}
		return []Observation{testObservation("internal", 1, time.Now().UTC())}, nil
	})
	if err != nil || calledPeer != peerID {
		t.Fatalf("serve peer = %q, %v", calledPeer, err)
	}
	var snapshot Snapshot
	if err := DecodeStrict(channel.sent.Data, &snapshot); err != nil || snapshot.Reporter.Context != "" || len(snapshot.Observations) != 1 || snapshot.Observations[0].Context != "" || snapshot.Observations[0].Sequence != 0 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	if bytes.Contains(channel.sent.Data, []byte(`"sequence"`)) {
		t.Fatalf("remote snapshot leaked sequence: %s", channel.sent.Data)
	}
}

func TestServeFinalAcknowledgementDeadlineIsGeneric(t *testing.T) {
	requestData, err := json.Marshal(request{Version: Version, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	channel := &deadlineRecentChannel{request: Message{Text: true, Data: requestData}}
	peerID := strings.Repeat("A", 43)
	reporter := Reporter{DeviceID: strings.Repeat("B", 43), Label: "reporter"}
	err = ServeWithDeadline(context.Background(), channel, reporter, peerID, func(context.Context, string, int) ([]Observation, error) {
		return []Observation{testObservation("home", 1, time.Now().UTC())}, nil
	}, 5*time.Millisecond)
	if !errors.Is(err, ErrProtocolTimeout) || err.Error() != "recent request timed out" || !channel.sent {
		t.Fatalf("ack stall = %v, sent=%t", err, channel.sent)
	}
}

type deadlineRecentChannel struct {
	request Message
	reads   int
	sent    bool
}

func (c *deadlineRecentChannel) Send(context.Context, Message) error {
	c.sent = true
	return nil
}

func (c *deadlineRecentChannel) Receive(ctx context.Context) (Message, error) {
	c.reads++
	if c.reads == 1 {
		return c.request, nil
	}
	<-ctx.Done()
	return Message{}, ctx.Err()
}

func TestRequestBindsReporterRequesterLimitAndRedaction(t *testing.T) {
	reporter := Reporter{DeviceID: strings.Repeat("B", 43), Label: "reporter"}
	requesterID := strings.Repeat("A", 43)
	base := Snapshot{Version: Version, Description: Description, Reporter: reporter, Observations: []Observation{testObservation("", 1, time.Now().UTC())}}
	base.Observations[0].Sequence = 0
	base.Observations[0].PeerDeviceID = requesterID
	for _, test := range []struct {
		name    string
		mutate  func(*Snapshot)
		wantErr bool
	}{
		{name: "valid"},
		{name: "spoofed reporter identity", mutate: func(value *Snapshot) { value.Reporter.DeviceID = strings.Repeat("C", 43) }, wantErr: true},
		{name: "spoofed reporter label", mutate: func(value *Snapshot) { value.Reporter.Label = "other" }, wantErr: true},
		{name: "unrelated peer row", mutate: func(value *Snapshot) { value.Observations[0].PeerDeviceID = strings.Repeat("C", 43) }, wantErr: true},
		{name: "global sequence leak", mutate: func(value *Snapshot) { value.Observations[0].Sequence = 7 }, wantErr: true},
		{name: "over requested limit", mutate: func(value *Snapshot) { value.Observations = append(value.Observations, value.Observations[0]) }, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Observations = append([]Observation(nil), base.Observations...)
			if test.mutate != nil {
				test.mutate(&value)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			channel := &scriptedChannel{receive: []Message{{Text: true, Data: data}}}
			actual, err := Request(context.Background(), channel, 1, reporter, requesterID)
			if test.wantErr && err == nil || !test.wantErr && (err != nil || len(actual.Observations) != 1) {
				t.Fatalf("snapshot = %+v, error = %v", actual, err)
			}
		})
	}
}

type scriptedChannel struct {
	receive []Message
	index   int
	sent    Message
}

func (c *scriptedChannel) Send(_ context.Context, message Message) error {
	c.sent = message
	return nil
}

func (c *scriptedChannel) Receive(context.Context) (Message, error) {
	message := c.receive[c.index]
	c.index++
	return message, nil
}

func testStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	cfg, err := database.Config(database.KindAgent, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	dbStore := sqlite.New(cfg)
	if err := dbStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dbStore.Stop(context.Background()) })
	now := time.Now().Unix()
	if _, err := dbStore.DB().Exec(`insert into contexts(name,server_url,server_id,device_id,private_key_path,public_key_path,label,state,enabled,offered_root,inbox_root,created_at,updated_at) values('home','http://server','server','device','private','public','device','connected',1,'offered','inbox',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	return NewStore(dbStore.DB), dbStore.DB()
}

func testObservation(contextName string, index int, observed time.Time) Observation {
	return Observation{Context: contextName, Direction: "send", TransferID: fmt.Sprintf("%064x", index), Kind: "sender_observed_commit", PeerDeviceID: strings.Repeat("A", 43), PeerLabel: "peer", Destination: "file.txt", Visibility: "private", Bytes: 10, ObservedAt: observed}
}
