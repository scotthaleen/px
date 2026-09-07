package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFastSendWritesVisibleDestination(t *testing.T) {
	source := filepath.Join(t.TempDir(), "artifact.bin")
	content := []byte(strings.Repeat("fast-send", 100_000))
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := t.TempDir()
	sent, received, sendErr, receiveErr := runFastTransfer(t, FastSendConfig{Source: source}, FastReceiveConfig{InboxRoot: inbox, OfferedRoot: t.TempDir(), Context: "home", SenderLabel: "mac"})
	if sendErr != nil || receiveErr != nil || sent.SHA256 != "" || received.SHA256 != "" || sent.Bytes != int64(len(content)) {
		t.Fatalf("sent=%+v received=%+v sendErr=%v receiveErr=%v", sent, received, sendErr, receiveErr)
	}
	actual, err := os.ReadFile(filepath.Join(inbox, "home", "mac", "artifact.bin"))
	if err != nil || string(actual) != string(content) {
		t.Fatalf("destination differs: %v", err)
	}
}

func TestFastSendRefusesExistingDestination(t *testing.T) {
	source := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := t.TempDir()
	destination := filepath.Join(inbox, "home", "mac", "artifact.bin")
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, sendErr, receiveErr := runFastTransfer(t, FastSendConfig{Source: source}, FastReceiveConfig{InboxRoot: inbox, OfferedRoot: t.TempDir(), Context: "home", SenderLabel: "mac"})
	if sendErr == nil || receiveErr == nil {
		t.Fatalf("sendErr=%v receiveErr=%v", sendErr, receiveErr)
	}
	if actual, _ := os.ReadFile(destination); string(actual) != "existing" {
		t.Fatalf("existing destination changed to %q", actual)
	}
}

func TestFastSendAcknowledgesRejection(t *testing.T) {
	source := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	rejected, err := json.Marshal(fastControl{Version: fastVersion, Type: "rejected", Error: "destination already exists"})
	if err != nil {
		t.Fatal(err)
	}
	channel := &scriptedChannel{messages: []Message{{Text: true, Data: rejected}}}
	_, err = SendFast(context.Background(), channel, FastSendConfig{Source: source})
	if err == nil || len(channel.sent) != 2 {
		t.Fatalf("error=%v sent=%+v", err, channel.sent)
	}
	ack, err := decodeFastControl(channel.sent[1])
	if err != nil || ack.Type != "ack" {
		t.Fatalf("ack=%+v error=%v", ack, err)
	}
}

func TestInterruptedFastSendLeavesVisiblePartial(t *testing.T) {
	inbox := t.TempDir()
	offer, err := json.Marshal(fastControl{Version: fastVersion, Type: "offer", Name: "partial.bin", Size: 7})
	if err != nil {
		t.Fatal(err)
	}
	channel := &scriptedChannel{messages: []Message{{Text: true, Data: offer}, {Data: []byte("par")}}}
	_, err = ReceiveFast(context.Background(), channel, FastReceiveConfig{InboxRoot: inbox, OfferedRoot: t.TempDir(), Context: "home", SenderLabel: "mac"})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error=%v", err)
	}
	actual, readErr := os.ReadFile(filepath.Join(inbox, "home", "mac", "partial.bin"))
	if readErr != nil || string(actual) != "par" {
		t.Fatalf("partial=%q err=%v", actual, readErr)
	}
}

func TestFastSendCompletionLossIsOutcomeUnknown(t *testing.T) {
	source := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ready, err := json.Marshal(fastControl{Version: fastVersion, Type: "ready"})
	if err != nil {
		t.Fatal(err)
	}
	var events []ResumeEvent
	channel := &scriptedChannel{messages: []Message{{Text: true, Data: ready}}}
	result, err := SendFast(context.Background(), channel, FastSendConfig{Source: source, Progress: func(event ResumeEvent) { events = append(events, event) }})
	if !errors.Is(err, ErrFastOutcomeUnknown) || result.Bytes != 4 || len(events) == 0 {
		t.Fatalf("result=%+v error=%v events=%+v", result, err, events)
	}
	terminal := events[len(events)-1]
	if terminal.State != "failed" || terminal.ErrorCode != FastOutcomeUnknownCode || terminal.Outcome != FastOutcomeUnknownCode || terminal.Bytes != 4 {
		t.Fatalf("terminal=%+v", terminal)
	}
}

func TestReceiveFastPreservesCanceledControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, channel := newMemoryPipe()
	_, err := ReceiveFast(ctx, channel, FastReceiveConfig{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func runFastTransfer(t *testing.T, sendConfig FastSendConfig, receiveConfig FastReceiveConfig) (Result, Result, error, error) {
	t.Helper()
	sender, receiver := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type outcome struct {
		result Result
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := ReceiveFast(ctx, receiver, receiveConfig)
		finished <- outcome{result: result, err: err}
	}()
	sent, sendErr := SendFast(ctx, sender, sendConfig)
	received := <-finished
	return sent, received.result, sendErr, received.err
}

func decodeFastControl(message Message) (fastControl, error) {
	if !message.Text {
		return fastControl{}, errors.New("control message is binary")
	}
	var control fastControl
	err := json.Unmarshal(message.Data, &control)
	return control, err
}
