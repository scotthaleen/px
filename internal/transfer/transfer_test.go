package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTransferRoundTrip(t *testing.T) {
	sourceDir := t.TempDir()
	inbox := t.TempDir()
	source := filepath.Join(sourceDir, "archive.bin")
	content := []byte(strings.Repeat("bounded-transfer-data", 100_000))
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}

	sent, received, sendErr, receiveErr := runTransfer(t, SendConfig{Source: source}, ReceiveConfig{
		InboxRoot: inbox,
		Context:   "home",
		Sender:    "laptop",
	})
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	if receiveErr != nil {
		t.Fatal(receiveErr)
	}
	if sent.Bytes != int64(len(content)) || received.Bytes != sent.Bytes || received.SHA256 != sent.SHA256 {
		t.Fatalf("sender result = %+v, receiver result = %+v", sent, received)
	}
	destination := filepath.Join(inbox, "home", "laptop", "archive.bin")
	actual, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(content) {
		t.Fatal("destination content differs")
	}
	assertNoPartFiles(t, filepath.Dir(destination))
}

func TestTransferRefusesExistingDestination(t *testing.T) {
	sourceDir := t.TempDir()
	inbox := t.TempDir()
	source := filepath.Join(sourceDir, "report.txt")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	destinationDir := filepath.Join(inbox, "work", "builder")
	if err := os.MkdirAll(destinationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(destinationDir, "report.txt")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, sendErr, receiveErr := runTransfer(t, SendConfig{Source: source}, ReceiveConfig{
		InboxRoot: inbox,
		Context:   "work",
		Sender:    "builder",
	})
	if sendErr == nil || receiveErr == nil {
		t.Fatalf("send error = %v, receive error = %v", sendErr, receiveErr)
	}
	actual, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "existing" {
		t.Fatalf("existing destination changed to %q", actual)
	}
}

func TestTransferChecksumFailureCleansTemporaryFile(t *testing.T) {
	sourceDir := t.TempDir()
	inbox := t.TempDir()
	source := filepath.Join(sourceDir, "payload.bin")
	if err := os.WriteFile(source, []byte(strings.Repeat("x", MaxMessageBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	sender, receiver := newMemoryPipe()
	var once sync.Once
	sender.mutate = func(message Message) Message {
		if !message.Text {
			once.Do(func() { message.Data[0] ^= 0xff })
		}
		return message
	}

	type receiveOutcome struct {
		result Result
		err    error
	}
	outcomes := make(chan receiveOutcome, 1)
	go func() {
		result, err := Receive(context.Background(), receiver, ReceiveConfig{InboxRoot: inbox, Context: "home", Sender: "peer"})
		outcomes <- receiveOutcome{result: result, err: err}
	}()
	_, sendErr := Send(context.Background(), sender, SendConfig{Source: source})
	received := <-outcomes
	if sendErr == nil || received.err == nil || !strings.Contains(received.err.Error(), "checksum") {
		t.Fatalf("send error = %v, receive error = %v", sendErr, received.err)
	}
	directory := filepath.Join(inbox, "home", "peer")
	assertNoPartFiles(t, directory)
	if _, err := os.Stat(filepath.Join(directory, "payload.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after checksum failure: %v", err)
	}
}

func TestTransferRejectsInsufficientSpace(t *testing.T) {
	source := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(source, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, sendErr, receiveErr := runTransfer(t, SendConfig{Source: source}, ReceiveConfig{
		InboxRoot: t.TempDir(),
		Context:   "home",
		Sender:    "peer",
		AvailableSpace: func(string) (uint64, error) {
			return 1, nil
		},
	})
	if sendErr == nil || receiveErr == nil || !strings.Contains(receiveErr.Error(), "insufficient") {
		t.Fatalf("send error = %v, receive error = %v", sendErr, receiveErr)
	}
}

func TestReceiveDisconnectCleansTemporaryFile(t *testing.T) {
	inbox := t.TempDir()
	hash := sha256.Sum256([]byte("partial"))
	offer, err := jsonMessage(control{
		Version: protocolVersion,
		Type:    "offer",
		ID:      strings.Repeat("a", 32),
		Name:    "partial.bin",
		Size:    7,
		SHA256:  hex.EncodeToString(hash[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	channel := &scriptedChannel{messages: []Message{offer, {Data: []byte("par")}}}
	_, err = Receive(context.Background(), channel, ReceiveConfig{InboxRoot: inbox, Context: "home", Sender: "peer"})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want disconnect", err)
	}
	directory := filepath.Join(inbox, "home", "peer")
	assertNoPartFiles(t, directory)
}

func TestReceiveCancellationCleansTemporaryFile(t *testing.T) {
	inbox := t.TempDir()
	hash := sha256.Sum256([]byte("partial"))
	sender, receiver := newMemoryPipe()
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct{ err error }
	finished := make(chan outcome, 1)
	go func() {
		_, err := Receive(ctx, receiver, ReceiveConfig{InboxRoot: inbox, Context: "home", Sender: "peer"})
		finished <- outcome{err: err}
	}()
	if err := sendControl(ctx, sender, control{
		Version: protocolVersion,
		Type:    "offer",
		ID:      strings.Repeat("b", 32),
		Name:    "partial.bin",
		Size:    7,
		SHA256:  hex.EncodeToString(hash[:]),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveControl(ctx, sender); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(ctx, Message{Data: []byte("par")}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := (<-finished).err; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	directory := filepath.Join(inbox, "home", "peer")
	assertNoPartFiles(t, directory)
}

func TestValidateSourceCategories(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path  string
		limit int64
		code  string
	}{
		{path: filepath.Join(dir, "missing"), limit: 10, code: SourceNotFoundCode},
		{path: "bad\npath", limit: 10, code: SourceInvalidCode},
		{path: "bad\u0085path", limit: 10, code: SourceInvalidCode},
		{path: filepath.Join(dir, strings.Repeat("x", 300)), limit: 10, code: SourceInvalidCode},
		{path: dir, limit: 10, code: SourceDirectoryCode},
		{path: target, limit: 3, code: SourceTooLargeCode},
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err == nil {
		tests = append(tests, struct {
			path  string
			limit int64
			code  string
		}{path: link, limit: 10, code: SourceSymlinkCode})
	}
	for _, test := range tests {
		err := ValidateSource(test.path, test.limit)
		var sourceErr *SourceError
		if !errors.As(err, &sourceErr) || sourceErr.Code != test.code || strings.Contains(sourceErr.Error(), test.path) {
			t.Errorf("ValidateSource(%q) = %#v, want safe %s", test.path, err, test.code)
		}
	}
	if err := os.Chmod(target, 0); err == nil {
		err := ValidateSource(target, 10)
		_ = os.Chmod(target, 0o600)
		if err != nil {
			var sourceErr *SourceError
			if !errors.As(err, &sourceErr) || sourceErr.Code != SourceUnreadableCode {
				t.Errorf("unreadable source = %#v", err)
			}
		}
	}
}

func TestValidatePortableName(t *testing.T) {
	for _, value := range []string{"file.txt", "release 1.tar", "résumé.pdf"} {
		if err := ValidatePortableName(value); err != nil {
			t.Errorf("ValidatePortableName(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", ".", "..", "../escape", `dir\\file`, "NUL.txt", "COM¹", "com².log", "LPT³", "lpt¹.txt", "name.", "name ", "bad:name"} {
		if err := ValidatePortableName(value); err == nil {
			t.Errorf("ValidatePortableName(%q) succeeded", value)
		}
	}
}

type memoryChannel struct {
	in     <-chan Message
	out    chan<- Message
	mutate func(Message) Message
}

func newMemoryPipe() (*memoryChannel, *memoryChannel) {
	aToB := make(chan Message, DefaultQueueDepth)
	bToA := make(chan Message, DefaultQueueDepth)
	return &memoryChannel{in: bToA, out: aToB}, &memoryChannel{in: aToB, out: bToA}
}

func (c *memoryChannel) Send(ctx context.Context, message Message) error {
	message.Data = append([]byte(nil), message.Data...)
	if c.mutate != nil {
		message = c.mutate(message)
	}
	select {
	case c.out <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *memoryChannel) Receive(ctx context.Context) (Message, error) {
	select {
	case message := <-c.in:
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

type scriptedChannel struct {
	messages []Message
	sent     []Message
}

func (c *scriptedChannel) Send(_ context.Context, message Message) error {
	c.sent = append(c.sent, message)
	return nil
}

func (c *scriptedChannel) Receive(context.Context) (Message, error) {
	if len(c.messages) == 0 {
		return Message{}, io.EOF
	}
	message := c.messages[0]
	c.messages = c.messages[1:]
	return message, nil
}

func runTransfer(t *testing.T, sendConfig SendConfig, receiveConfig ReceiveConfig) (Result, Result, error, error) {
	t.Helper()
	sender, receiver := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type receiveOutcome struct {
		result Result
		err    error
	}
	outcomes := make(chan receiveOutcome, 1)
	go func() {
		result, err := Receive(ctx, receiver, receiveConfig)
		outcomes <- receiveOutcome{result: result, err: err}
	}()
	sent, sendErr := Send(ctx, sender, sendConfig)
	received := <-outcomes
	return sent, received.result, sendErr, received.err
}

func jsonMessage(value control) (Message, error) {
	data, err := json.Marshal(value)
	return Message{Text: true, Data: data}, err
}

func assertNoPartFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".px-") && strings.HasSuffix(entry.Name(), ".part") {
			t.Errorf("temporary file remains: %s", entry.Name())
		}
	}
}
