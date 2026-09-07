package contexts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/rendezvousproto"
)

func TestOperationalEventsAreStructuredAndRedacted(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	manager := &Manager{logger: logger}
	control := &controlConnection{manager: manager, context: State{Name: "home"}, peers: make(map[string]membership.Member), sessions: make(map[string]*contextSignaler)}
	peer := membership.Member{DeviceID: strings.Repeat("A", 43), Label: "vm"}
	if err := manager.watchHub().Connect("home", nil); err != nil {
		t.Fatal(err)
	}
	control.handle(controlMessage{Type: "presence.joined", Member: &peer})
	sessionContext, cancelSession := context.WithCancel(context.Background())
	control.sessions["px-recent-session"] = &contextSignaler{peerID: peer.DeviceID, ctx: sessionContext, cancel: cancelSession}
	control.handle(controlMessage{Type: "presence.left", DeviceID: peer.DeviceID})
	if sessionContext.Err() == nil || len(control.sessions) != 0 || control.currentPeer(peer.DeviceID, peer.Label) {
		t.Fatal("presence leave retained peer or direct session")
	}
	recentChannel := &operationalRecentChannel{receive: recent.Message{Text: true, Data: []byte(`{"version":1,"limit":1}`)}}
	err := recent.Serve(context.Background(), recentChannel, recent.Reporter{DeviceID: strings.Repeat("A", 43), Label: "device"}, peer.DeviceID, func(ctx context.Context, peerID string, limit int) ([]recent.Observation, error) {
		return manager.recentForPeer(ctx, control, "home", peer, peerID, limit)
	})
	if !errors.Is(err, ErrPeerOffline) || recentChannel.sent {
		t.Fatalf("delayed recent after leave = %v, snapshot sent=%t", err, recentChannel.sent)
	}
	manager.logTransfer("transfer.started", "outgoing transfer started", "outgoing", "home", "vm", "transfer-id", "artifact.bin", 0)
	manager.logTransfer("transfer.committed", "outgoing transfer committed", "outgoing", "home", "vm", "transfer-id", "artifact.bin", 42)
	manager.logTransfer("transfer.failed", "incoming transfer failed", "incoming", "home", "vm", "", "", 0)

	decoder := json.NewDecoder(&output)
	events := make(map[string]map[string]any)
	for decoder.More() {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		event, _ := record["event"].(string)
		events[event] = record
		for _, forbidden := range []string{"credential", "private_key", "resume_token", "candidate", "remote_address", "path", "sha256", "reason"} {
			for key := range record {
				if strings.Contains(key, forbidden) {
					t.Fatalf("event %q contains forbidden field %q: %+v", event, key, record)
				}
			}
		}
	}
	for _, event := range []string{"peer.joined", "peer.left", "transfer.started", "transfer.committed", "transfer.failed"} {
		if events[event] == nil {
			t.Fatalf("missing event %q in %+v", event, events)
		}
		if events[event]["context"] != "home" || events[event]["peer"] != "@vm" {
			t.Fatalf("event %q fields = %+v", event, events[event])
		}
	}
	if events["transfer.committed"]["bytes"] != float64(42) || events["transfer.committed"]["transfer_id"] != "transfer-id" {
		t.Fatalf("committed event = %+v", events["transfer.committed"])
	}
}

func TestMalformedAuthoritativeJoinFailsControlWithoutProjectionMutation(t *testing.T) {
	manager := &Manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := manager.watchHub().Connect("home", nil); err != nil {
		t.Fatal(err)
	}
	control := &controlConnection{manager: manager, context: State{Name: "home", DeviceID: strings.Repeat("A", 43)}, peers: make(map[string]membership.Member), sessions: make(map[string]*contextSignaler)}
	for _, member := range []*membership.Member{
		nil,
		{DeviceID: "invalid", Label: "peer"},
		{DeviceID: strings.Repeat("B", 43), Label: "bad label"},
		{DeviceID: control.context.DeviceID, Label: "self"},
	} {
		if err := control.handleData(nil, controlMessage{Type: "presence.joined", Member: member}); err == nil {
			t.Fatalf("malformed authoritative join accepted: %+v", member)
		}
		if len(control.peers) != 0 {
			t.Fatalf("malformed join changed control peers: %+v", control.peers)
		}
	}
}

func TestAuthoritativePresenceRejectsRequestIDWithoutProjectionMutation(t *testing.T) {
	manager := &Manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := manager.watchHub().Connect("home", nil); err != nil {
		t.Fatal(err)
	}
	control := &controlConnection{manager: manager, context: State{Name: "home", DeviceID: strings.Repeat("A", 43)}, peers: make(map[string]membership.Member), sessions: make(map[string]*contextSignaler)}
	for _, message := range []controlMessage{
		{Version: rendezvousproto.Version, Type: "presence.joined", RequestID: strings.Repeat("a", 32), Member: &membership.Member{DeviceID: "invalid", Label: "peer"}},
		{Version: rendezvousproto.Version, Type: "presence.joined", RequestID: strings.Repeat("b", 32), Member: &membership.Member{DeviceID: control.context.DeviceID, Label: "self"}},
		{Version: rendezvousproto.Version, Type: "presence.left", RequestID: strings.Repeat("c", 32), DeviceID: control.context.DeviceID},
	} {
		if err := control.handleData(nil, message); !errors.Is(err, contextwatch.ErrInvalidProjection) {
			t.Fatalf("presence with request ID error = %v", err)
		}
		if len(control.peers) != 0 {
			t.Fatalf("presence with request ID changed control peers: %+v", control.peers)
		}
	}
	subscription, err := manager.watchHub().Subscribe("home")
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	initial := <-subscription.Events
	if initial.Type != contextwatch.ContextConnected || len(initial.Peers) != 0 {
		t.Fatalf("presence with request ID changed watch projection: %+v", initial)
	}
}

type operationalRecentChannel struct {
	receive recent.Message
	sent    bool
}

func (c *operationalRecentChannel) Send(context.Context, recent.Message) error {
	c.sent = true
	return nil
}

func (c *operationalRecentChannel) Receive(context.Context) (recent.Message, error) {
	return c.receive, nil
}

func TestReconnectEventRateLimit(t *testing.T) {
	for failure := 1; failure <= 30; failure++ {
		want := failure == 1 || failure == 10 || failure == 20 || failure == 30
		if actual := shouldLogReconnect(failure); actual != want {
			t.Fatalf("shouldLogReconnect(%d) = %v, want %v", failure, actual, want)
		}
	}
}
