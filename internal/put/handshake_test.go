//go:build !windows

package put

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type senderScriptChannel struct {
	responses    chan Message
	wrongAt      string
	terminalAt   string
	terminalType string
	id           string
	waited       bool
}

func (c *senderScriptChannel) Send(_ context.Context, message Message) error {
	if !message.Text {
		id := c.id
		if c.wrongAt == "ack" {
			id = "ffffffffffffffffffffffffffffffff"
		}
		data, _ := marshalControl(control{Version: protocolVersion, Type: "ack", ID: id, Offset: int64(len(message.Data))})
		c.responses <- Message{Text: true, Data: data}
		return nil
	}
	var header struct {
		Type     string    `json:"type"`
		Manifest *Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(message.Data, &header); err != nil {
		return err
	}
	if header.Manifest != nil {
		c.id = header.Manifest.ID
	}
	id := c.id
	if c.wrongAt == header.Type || c.wrongAt == responseFor(header.Type) {
		id = "ffffffffffffffffffffffffffffffff"
	}
	var response control
	if c.terminalAt == header.Type {
		response = control{Version: protocolVersion, Type: c.terminalType, ID: id, Error: "bounded terminal disposition"}
	} else {
		switch header.Type {
		case "offer":
			response = control{Version: protocolVersion, Type: "prepared", ID: id, RootRevision: 7}
		case "start":
			response = control{Version: protocolVersion, Type: "ready", ID: id}
		case "complete":
			response = control{Version: protocolVersion, Type: "committed", ID: id, Bytes: 1, Created: true, Durability: "durability_confirmed", RootRevision: 7}
		case "result_ack":
			return nil
		default:
			return nil
		}
	}
	data, err := marshalControl(response)
	if err != nil {
		return err
	}
	c.responses <- Message{Text: true, Data: data}
	return nil
}

func (c *senderScriptChannel) WaitPeerClose(context.Context) error {
	c.waited = true
	return nil
}

func responseFor(request string) string {
	switch request {
	case "offer":
		return "prepared"
	case "start":
		return "ready"
	case "complete":
		return "committed"
	default:
		return ""
	}
}

func (c *senderScriptChannel) Receive(ctx context.Context) (Message, error) {
	select {
	case message := <-c.responses:
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

func TestSenderRejectsMismatchedControlIDs(t *testing.T) {
	for _, controlType := range []string{"prepared", "ready", "ack", "committed"} {
		t.Run(controlType, func(t *testing.T) {
			db := recoveryDatabase(t)
			store := NewStore(func() *sql.DB { return db })
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			channel := &senderScriptChannel{responses: make(chan Message, 4), wrongAt: controlType}
			if _, err := Send(t.Context(), channel, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store}); err == nil {
				t.Fatalf("mismatched %s ID accepted", controlType)
			}
		})
	}
}

func TestSenderAcknowledgesTerminalDispositionBeforeReturning(t *testing.T) {
	for _, test := range []struct {
		name, terminalType string
		wantRows           int
	}{
		{name: "committed", wantRows: 1},
		{name: "rejected", terminalType: "error"},
		{name: "retryable", terminalType: "retryable_error", wantRows: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := recoveryDatabase(t)
			store := NewStore(func() *sql.DB { return db })
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			channel := &senderScriptChannel{responses: make(chan Message, 4), terminalType: test.terminalType}
			if test.terminalType != "" {
				channel.terminalAt = "start"
			}
			result, err := Send(t.Context(), channel, SendConfig{Source: source, Destination: "result", Context: "home", SenderID: "sender", ReceiverID: "receiver", PeerLabel: "receiver", Store: store})
			if test.terminalType == "" {
				if err != nil || !result.Created {
					t.Fatalf("committed result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "bounded terminal disposition") {
				t.Fatalf("terminal error=%v", err)
			}
			if !channel.waited {
				t.Fatal("sender did not wait for peer-first close")
			}
			records, inventoryErr := store.Inventory(t.Context(), "home", 64)
			if inventoryErr != nil || len(records) != test.wantRows {
				t.Fatalf("inventory=%+v err=%v", records, inventoryErr)
			}
		})
	}
}

func TestReceiverRejectsMismatchedStartAndCompleteIDs(t *testing.T) {
	for _, phase := range []string{"start", "complete"} {
		t.Run(phase, func(t *testing.T) {
			db := recoveryDatabase(t)
			store := NewStore(func() *sql.DB { return db })
			root := t.TempDir()
			manifest := recoveryManifest("result")
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
			if _, err := receiveControl(t.Context(), sender); err != nil {
				t.Fatal(err)
			}
			startID := manifest.ID
			if phase == "start" {
				startID = "ffffffffffffffffffffffffffffffff"
			}
			if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "start", ID: startID}); err != nil {
				t.Fatal(err)
			}
			if phase == "complete" {
				if _, err := receiveControl(t.Context(), sender); err != nil {
					t.Fatal(err)
				}
				if err := sender.Send(t.Context(), Message{Data: []byte("x")}); err != nil {
					t.Fatal(err)
				}
				if _, err := receiveControl(t.Context(), sender); err != nil {
					t.Fatal(err)
				}
				if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "complete", ID: "ffffffffffffffffffffffffffffffff"}); err != nil {
					t.Fatal(err)
				}
				rejected, err := receiveControl(t.Context(), sender)
				if err != nil || rejected.Type != "error" || rejected.ID != manifest.ID {
					t.Fatalf("rejected=%+v err=%v", rejected, err)
				}
				if err := sendControl(t.Context(), sender, control{Version: protocolVersion, Type: "result_ack", ID: manifest.ID}); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-result; err == nil {
				t.Fatalf("mismatched %s ID accepted", phase)
			}
			if phase == "complete" {
				if _, err := os.Stat(filepath.Join(root, "result")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destination published: %v", err)
				}
			}
		})
	}
}

func TestControlAdmissionRejectsUppercaseTransferID(t *testing.T) {
	id := strings.Repeat("A", 32)
	data, err := json.Marshal(map[string]any{"version": protocolVersion, "type": "start", "id": id})
	if err != nil {
		t.Fatal(err)
	}
	channel := &senderScriptChannel{responses: make(chan Message, 1)}
	channel.responses <- Message{Text: true, Data: data}
	if _, err := receiveControl(t.Context(), channel); err == nil {
		t.Fatal("uppercase control transfer ID was admitted")
	}
}

func TestDetachedSettlementContextIgnoresCallerCancellationAndIsBounded(t *testing.T) {
	caller, cancelCaller := context.WithCancel(t.Context())
	cancelCaller()
	if caller.Err() == nil {
		t.Fatal("caller cancellation was not established")
	}
	var attempted bool
	if err := runSettlement(func(ctx context.Context) error {
		attempted = true
		if ctx.Err() != nil {
			return errors.New("settlement inherited caller cancellation")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > settlementTimeout {
			return errors.New("settlement context is not bounded")
		}
		return nil
	}); err != nil || !attempted {
		t.Fatalf("settlement attempt = %t, %v", attempted, err)
	}
	bounded, cancelBounded := newDetachedContext(time.Millisecond)
	defer cancelBounded()
	<-bounded.Done()
	if !errors.Is(bounded.Err(), context.DeadlineExceeded) {
		t.Fatalf("bounded context error = %v", bounded.Err())
	}
}
