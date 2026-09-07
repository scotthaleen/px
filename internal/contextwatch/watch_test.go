package contextwatch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/localipc"
)

func TestSubscribeTransitionBarrier(t *testing.T) {
	for index := range 200 {
		hub := NewHub()
		peer := testPeer(index, "peer")
		start := make(chan struct{})
		var subscription *Subscription
		var subscribeErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			subscription, subscribeErr = hub.Subscribe("home")
		}()
		go func() {
			defer wait.Done()
			<-start
			hub.Connect("home", []Peer{peer})
		}()
		close(start)
		wait.Wait()
		if subscribeErr != nil {
			t.Fatal(subscribeErr)
		}
		initial := <-subscription.Events
		switch initial.Type {
		case ContextConnected:
			if len(initial.Peers) != 1 || initial.Peers[0] != peer {
				t.Fatalf("connected snapshot = %+v", initial)
			}
		case ContextDisconnected:
			connected := <-subscription.Events
			if connected.Type != ContextConnected || connected.Sequence <= initial.Sequence || len(connected.Peers) != 1 || connected.Peers[0] != peer {
				t.Fatalf("transition after snapshot = %+v, %+v", initial, connected)
			}
		default:
			t.Fatalf("initial type = %q", initial.Type)
		}
		subscription.Close()
	}
}

func TestProjectionOrderingDuplicatesReplacementAndReconnect(t *testing.T) {
	hub := NewHub()
	beta := testPeer(2, "beta")
	alpha := testPeer(1, "Alpha")
	hub.Connect("home", []Peer{beta, alpha})
	subscription, err := hub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	initial := <-subscription.Events
	if initial.Type != ContextConnected || !initial.Snapshot || len(initial.Peers) != 2 || initial.Peers[0] != alpha || initial.Peers[1] != beta {
		t.Fatalf("ordered baseline = %+v", initial)
	}
	hub.Join("home", alpha)
	select {
	case event := <-subscription.Events:
		t.Fatalf("duplicate join emitted %+v", event)
	default:
	}
	hub.Leave("home", testPeer(9, "unknown").DeviceID)
	select {
	case event := <-subscription.Events:
		t.Fatalf("unknown leave emitted %+v", event)
	default:
	}
	replacement := testPeer(3, "Alpha")
	hub.Join("home", replacement)
	offline, online := <-subscription.Events, <-subscription.Events
	if offline.Type != PeerOffline || *offline.Peer != alpha || online.Type != PeerOnline || *online.Peer != replacement || online.Sequence <= offline.Sequence {
		t.Fatalf("replacement events = %+v, %+v", offline, online)
	}
	hub.Disconnect("home")
	disconnected := <-subscription.Events
	if disconnected.Type != ContextDisconnected || disconnected.Peer != nil || disconnected.Peers != nil {
		t.Fatalf("disconnect = %+v", disconnected)
	}
	select {
	case event := <-subscription.Events:
		t.Fatalf("disconnect synthesized peer event %+v", event)
	default:
	}
	hub.Connect("home", []Peer{replacement, beta})
	reconnected := <-subscription.Events
	if reconnected.Type != ContextConnected || reconnected.Snapshot || len(reconnected.Peers) != 2 || reconnected.Peers[0] != replacement || reconnected.Peers[1] != beta {
		t.Fatalf("reconnect baseline = %+v", reconnected)
	}
}

func TestProjectionRejectsMalformedAuthoritativeBaselineAndJoin(t *testing.T) {
	hub := NewHub()
	valid := testPeer(1, "peer")
	for _, baseline := range [][]Peer{
		{{DeviceID: "invalid", Label: "peer"}},
		{{DeviceID: valid.DeviceID, Label: "bad label"}},
		{valid, {DeviceID: testPeer(2, "other").DeviceID, Label: "PEER"}},
		{valid, {DeviceID: valid.DeviceID, Label: "other"}},
		make([]Peer, MaxPeers+1),
	} {
		if err := hub.Connect("home", baseline); !errors.Is(err, ErrInvalidProjection) {
			t.Fatalf("malformed baseline error = %v", err)
		}
	}
	if err := hub.Connect("home", []Peer{valid}); err != nil {
		t.Fatal(err)
	}
	subscription, err := hub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	<-subscription.Events
	for _, peer := range []Peer{
		{DeviceID: "invalid", Label: "joined"},
		{DeviceID: testPeer(2, "joined").DeviceID, Label: "bad label"},
		{DeviceID: valid.DeviceID, Label: "renamed"},
	} {
		if err := hub.Join("home", peer); !errors.Is(err, ErrInvalidProjection) {
			t.Fatalf("malformed join %+v error = %v", peer, err)
		}
		select {
		case event := <-subscription.Events:
			t.Fatalf("malformed join emitted %+v", event)
		default:
		}
	}
}

func TestSubscriberBoundAndIdempotentClose(t *testing.T) {
	hub := NewHub()
	subscriptions := make([]*Subscription, 0, MaxSubscribers)
	for range MaxSubscribers {
		subscription, err := hub.Subscribe("home")
		if err != nil {
			t.Fatal(err)
		}
		subscriptions = append(subscriptions, subscription)
	}
	if _, err := hub.Subscribe("home"); !errors.Is(err, ErrSubscriberCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	subscriptions[0].Close()
	subscriptions[0].Close()
	if _, err := hub.Subscribe("home"); err != nil {
		t.Fatalf("subscribe after close: %v", err)
	}
}

func TestSlowConsumerGapDoesNotAffectFastConsumer(t *testing.T) {
	hub := NewHub()
	hub.Connect("home", nil)
	slow, err := hub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	fast, err := hub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()
	fastEvents := make(chan Event)
	go func() {
		for event := range fast.Events {
			fastEvents <- event
		}
	}()
	if event := <-fastEvents; event.Type != ContextConnected {
		t.Fatalf("fast initial = %+v", event)
	}
	peer := testPeer(1, "peer")
	for range OrdinaryQueueDepth {
		hub.Join("home", peer)
		if event := <-fastEvents; event.Type != PeerOnline {
			t.Fatalf("fast online = %+v", event)
		}
		hub.Leave("home", peer.DeviceID)
		if event := <-fastEvents; event.Type != PeerOffline {
			t.Fatalf("fast offline = %+v", event)
		}
	}
	var events []Event
	for event := range slow.Events {
		events = append(events, event)
	}
	if len(events) != OrdinaryQueueDepth+1 || events[len(events)-1].Type != StreamGap || !events[len(events)-1].ResyncRequired || events[len(events)-1].FirstDroppedSequence != events[len(events)-1].Sequence {
		t.Fatalf("slow terminal events = %d, last=%+v", len(events), events[len(events)-1])
	}
}

func TestCloseRacesWithSendAndUnsubscribe(t *testing.T) {
	for range 100 {
		hub := NewHub()
		hub.Connect("home", nil)
		subscription, err := hub.Subscribe("home")
		if err != nil {
			t.Fatal(err)
		}
		peer := testPeer(1, "peer")
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(3)
		go func() { defer wait.Done(); <-start; hub.Join("home", peer) }()
		go func() { defer wait.Done(); <-start; subscription.Close() }()
		go func() { defer wait.Done(); <-start; hub.Close() }()
		close(start)
		wait.Wait()
		subscription.Close()
	}
}

func TestConnectedSnapshotLineIsBoundedAndEmptyPeersAreArray(t *testing.T) {
	hub := NewHub()
	peers := make([]Peer, 0, MaxPeers)
	for index := range MaxPeers {
		peers = append(peers, testPeer(index, fmt.Sprintf("peer-%02d-%s", index, "abcdefghijklmnopqrstuvwxyz")))
	}
	hub.Connect("home", peers)
	subscription, err := hub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(<-subscription.Events)
	if err != nil {
		t.Fatal(err)
	}
	if len(data)+1 > localipc.MaxResponseBytes {
		t.Fatalf("snapshot line = %d bytes", len(data)+1)
	}
	if _, err := DecodeStrict(data); err != nil {
		t.Fatal(err)
	}
	emptyHub := NewHub()
	emptyHub.Connect("home", nil)
	empty, err := emptyHub.Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	emptyData, err := json.Marshal(<-empty.Events)
	if err != nil || !strings.Contains(string(emptyData), `"peers":[]`) {
		t.Fatalf("empty snapshot = %s, %v", emptyData, err)
	}
}

func TestDecodeStrictRejectsMalformedTypeFields(t *testing.T) {
	peer := testPeer(1, "peer")
	valid := Event{Version: Version, StreamID: strings.Repeat("a", 32), Sequence: 1, ObservedAt: time.Unix(1, 0).UTC(), Context: "home", Type: ContextConnected, Snapshot: true, Peers: []Peer{peer}}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict(data); err != nil {
		t.Fatalf("valid event: %v", err)
	}
	for _, malformed := range []string{
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"context.connected","snapshot":true}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"context.disconnected","snapshot":true,"peers":[]}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"peer.online","snapshot":true,"peer":{"device_id":"` + peer.DeviceID + `","label":"peer"}}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"stream.gap","first_dropped_sequence":1,"resync_required":false}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T01:00:01+01:00","context":"home","type":"context.disconnected","snapshot":true}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"context.connected","snapshot":true,"peers":[],"unknown":true}`,
		`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home","type":"context.connected","snapshot":true,"peers":[]} {}`,
	} {
		if _, err := DecodeStrict([]byte(malformed)); err == nil {
			t.Fatalf("accepted malformed event: %s", malformed)
		}
	}
}

func TestDecodeStrictRejectsDuplicateObjectKeysRecursively(t *testing.T) {
	peer := testPeer(1, "peer")
	base := `"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"observed_at":"1970-01-01T00:00:01Z","context":"home"`
	for _, malformed := range []string{
		`{` + base + `,"type":"context.connected","type":"context.connected","snapshot":true,"peers":[]}`,
		`{` + base + `,"sequence":1,"type":"context.connected","snapshot":true,"peers":[]}`,
		`{` + base + `,"type":"context.connected","snapshot":true,"snapshot":true,"peers":[]}`,
		`{` + base + `,"type":"peer.online","peer":{"device_id":"` + peer.DeviceID + `","device_id":"` + peer.DeviceID + `","label":"peer"}}`,
		`{` + base + `,"type":"context.connected","snapshot":true,"peers":[{"device_id":"` + peer.DeviceID + `","label":"peer","label":"peer"}]}`,
	} {
		if _, err := DecodeStrict([]byte(malformed)); err == nil {
			t.Fatalf("accepted duplicate object key: %s", malformed)
		}
	}
}

func TestDecodeStrictMapsAndRedactsStructuralErrors(t *testing.T) {
	const sensitive = "private-member-or-value"
	for _, data := range []string{
		`{"` + sensitive + `":"` + sensitive + `","` + sensitive + `":"other"}`,
		`{"version":1} "` + sensitive + `"`,
	} {
		_, err := DecodeStrict([]byte(data))
		if err == nil || err.Error() != "invalid context watch event fields" || strings.Contains(err.Error(), sensitive) {
			t.Fatalf("DecodeStrict() error = %v", err)
		}
	}
}

func testPeer(value int, label string) Peer {
	data := make([]byte, 32)
	data[30], data[31] = byte(value>>8), byte(value)
	return Peer{DeviceID: base64.RawURLEncoding.EncodeToString(data), Label: label}
}
