package offered

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/getcleanup"
)

func requestGet(ctx context.Context, channel Channel, path, destination string, maxFileBytes int64) (GetResult, error) {
	return requestGetProgress(ctx, channel, path, destination, maxFileBytes, nil)
}

func requestGetProgress(ctx context.Context, channel Channel, path, destination string, maxFileBytes int64, progress func(GetEvent)) (GetResult, error) {
	return RequestGetProgressStaged(ctx, channel, path, destination, maxFileBytes, createTestStage, progress)
}

type testStage struct {
	destination string
	temporary   string
	file        *os.File
}

func createTestStage(_ context.Context, destination string, _ int64) (StagedFile, error) {
	if _, err := os.Lstat(destination); err == nil {
		return nil, errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect local destination failed")
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".px-test-*.part")
	if err != nil {
		return nil, errors.New("create local temporary file failed")
	}
	return &testStage{destination: destination, temporary: file.Name(), file: file}, nil
}

func (stage *testStage) File() *os.File { return stage.file }

func (stage *testStage) Publish(_ context.Context, destinationBase string) (bool, error) {
	if destinationBase != filepath.Base(stage.destination) {
		return false, errors.New("invalid destination name")
	}
	if err := stage.file.Sync(); err != nil {
		return false, errors.New("sync local destination failed")
	}
	if err := stage.file.Close(); err != nil {
		return false, errors.New("close local destination failed")
	}
	if err := os.Link(stage.temporary, stage.destination); err != nil {
		if _, statErr := os.Lstat(stage.destination); statErr == nil {
			return false, errors.New("destination already exists")
		}
		return false, errors.New("commit local destination failed")
	}
	if err := os.Remove(stage.temporary); err != nil {
		return true, errors.New("remove local temporary file failed")
	}
	return true, nil
}

func (stage *testStage) Cleanup(context.Context) error {
	_ = stage.file.Close()
	err := os.Remove(stage.temporary)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func TestListIsBoundedPortableAndDeterministic(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "z.txt"), []byte("zzz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "café.txt"), []byte("unicode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(t.TempDir(), "secret"), filepath.Join(root, "link"))
	entries, err := List(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Name != "café.txt" || entries[1].Name != "dir" || entries[2].Name != "z.txt" || entries[0].Size != 7 {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestListEmptyRoot(t *testing.T) {
	root := t.TempDir()
	entries, err := List(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v", entries)
	}

	client, server := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, server, root) }()
	entries, err = RequestList(ctx, client, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("remote entries = %+v", entries)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestReservedTransferNamesAreHiddenAndUnreadable(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"visible.txt": "visible", ".px-staging.part": "secret", ".PX-ORPHAN.PART": "secret"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := List(root, "")
	if err != nil || len(entries) != 1 || entries[0].Name != "visible.txt" {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	for _, path := range []string{".px-staging.part", ".PX-ORPHAN.PART", "dir/.px-part"} {
		if err := ValidatePath(path, false); err == nil {
			t.Fatalf("reserved path %q validated", path)
		}
		if _, _, err := Open(root, path); err == nil {
			t.Fatalf("reserved path %q opened", path)
		}
	}
}

func TestPortablePathRejectsTraversalReservedNamesAndLimits(t *testing.T) {
	valid := []string{"release/app.tar", "日本語/結果.txt", "a_b/c-d.1"}
	for _, path := range valid {
		if err := ValidatePath(path, false); err != nil {
			t.Errorf("ValidatePath(%q): %v", path, err)
		}
	}
	invalid := []string{"", "/absolute", "trailing/", "../escape", "dir/../escape", `dir\file`, "NUL/file", strings.Repeat("a", MaxPathBytes+1), strings.Repeat("a/", MaxPathDepth) + "a"}
	for _, path := range invalid {
		if err := ValidatePath(path, false); err == nil {
			t.Errorf("ValidatePath(%q) succeeded", path)
		}
	}
}

func TestRootRejectsSymlinkAndSiblingEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	sibling := filepath.Join(parent, "root-other")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(sibling, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sibling, filepath.Join(root, "escape")); err == nil {
		if _, _, err := Open(root, "escape/secret.txt"); err == nil {
			t.Fatal("opened a file through a symlink")
		}
	}
	if _, _, err := Open(root, "../root-other/secret.txt"); err == nil {
		t.Fatal("opened a similarly prefixed sibling root")
	}
}

func TestRootAllowsContainedSymlinkWhereSupported(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target", "artifact.txt"), []byte("contained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	file, _, err := Open(root, "link/artifact.txt")
	if err != nil {
		t.Skipf("contained symlink resolution unavailable: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "contained" {
		t.Fatalf("contained symlink content = %q, %v", data, err)
	}
}

func TestFilesystemRootCanOpenControlledLocalFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows filesystem-root validation remains issue #138")
	}
	fixtureRoot := t.TempDir()
	fixture := filepath.Join(fixtureRoot, "artifact.txt")
	if err := os.WriteFile(fixture, []byte("controlled"), 0o600); err != nil {
		t.Fatal(err)
	}
	portable := strings.TrimPrefix(filepath.ToSlash(fixture), "/")
	file, _, err := Open("/", portable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "controlled" {
		t.Fatalf("filesystem-root fixture = %q, %v", data, err)
	}
}

func TestOpenedFileSurvivesPathReplacementWithoutSwitchingContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact.txt")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _, err := Open(root, "artifact.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(path, filepath.Join(root, "old.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	if _, err := file.Read(buffer); err != nil || string(buffer) != "original" {
		t.Fatalf("opened content = %q, %v", buffer, err)
	}
}

func TestListRejectsPortableCaseCollision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the native filesystem rejects this collision")
	}
	root := t.TempDir()
	for _, name := range []string{"Report.txt", "report.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nativeEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(nativeEntries) < 2 {
		t.Skip("the native filesystem is case-insensitive")
	}
	if _, err := List(root, ""); err == nil || !strings.Contains(err.Error(), "case collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestGetRoundTripAndNoOverwrite(t *testing.T) {
	root := t.TempDir()
	content := []byte(strings.Repeat("offered-data", 10_000))
	if err := os.WriteFile(filepath.Join(root, "artifact.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "artifact.bin")
	client, server := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, server, root) }()
	events := make([]GetEvent, 0)
	result, err := requestGetProgress(ctx, client, "artifact.bin", destination, int64(len(content)), func(event GetEvent) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(destination)
	if err != nil || string(actual) != string(content) || result.Bytes != int64(len(content)) {
		t.Fatalf("result = %+v, read error = %v", result, err)
	}
	if len(events) < 2 || events[0].State != "transferring" || events[0].Bytes != 0 || events[len(events)-1].State != "committed" || events[len(events)-1].Version != GetEventVersion || events[len(events)-1].Duration <= 0 {
		t.Fatalf("progress events = %+v", events)
	}
	encoded, err := json.Marshal(events[len(events)-1])
	if err != nil || bytes.Contains(encoded, []byte(destination)) || bytes.Contains(encoded, []byte(`"path"`)) {
		t.Fatalf("committed event exposed destination: %s, %v", encoded, err)
	}
	client, server = newMemoryPipe()
	go func() { served <- Serve(ctx, server, root) }()
	if _, err := requestGet(ctx, client, "artifact.bin", destination, int64(len(content))); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error = %v", err)
	}
}

func TestGetCommittedEventReportsCleanupPendingWithoutPath(t *testing.T) {
	content := []byte("verified")
	hash := sha256.Sum256(content)
	metadata, err := json.Marshal(control{Version: protocolVersion, Type: "file", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", hash)})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := json.Marshal(control{Version: protocolVersion, Type: "complete"})
	if err != nil {
		t.Fatal(err)
	}
	channel := &stagedCollisionChannel{messages: []Message{{Text: true, Data: metadata}, {Data: content}, {Text: true, Data: complete}}}
	file, err := os.CreateTemp(t.TempDir(), "stage")
	if err != nil {
		t.Fatal(err)
	}
	events := make([]GetEvent, 0)
	result, err := RequestGetProgressStaged(context.Background(), channel, "artifact.bin", filepath.Join(t.TempDir(), "private-destination"), int64(len(content)), func(context.Context, string, int64) (StagedFile, error) {
		return &cleanupPendingStage{file: file}, nil
	}, func(event GetEvent) { events = append(events, event) })
	if err == nil || result.Bytes != int64(len(content)) || len(events) == 0 {
		t.Fatalf("result = %+v, error = %v, events = %+v", result, err, events)
	}
	terminal := events[len(events)-1]
	encoded, marshalErr := json.Marshal(terminal)
	if terminal.State != "committed" || !terminal.CleanupPending || marshalErr != nil || bytes.Contains(encoded, []byte("private-destination")) || bytes.Contains(encoded, []byte(`"path"`)) {
		t.Fatalf("terminal = %+v, JSON = %s, error = %v", terminal, encoded, marshalErr)
	}
}

func TestGetRejectsDestinationCreatedAfterStaging(t *testing.T) {
	content := []byte("verified offered content")
	hash := sha256.Sum256(content)
	metadata, err := json.Marshal(control{Version: protocolVersion, Type: "file", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", hash)})
	if err != nil {
		t.Fatal(err)
	}
	complete, err := json.Marshal(control{Version: protocolVersion, Type: "complete"})
	if err != nil {
		t.Fatal(err)
	}
	for _, collision := range []string{"file", "symlink"} {
		t.Run(collision, func(t *testing.T) {
			directory := t.TempDir()
			destination := filepath.Join(directory, "artifact.bin")
			target := destination
			if collision == "symlink" {
				target = filepath.Join(t.TempDir(), "target.bin")
				if err := os.WriteFile(target, []byte("competing"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, destination); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				if err := os.Remove(destination); err != nil {
					t.Fatal(err)
				}
			}
			channel := &stagedCollisionChannel{
				messages: []Message{{Text: true, Data: metadata}, {Data: content}, {Text: true, Data: complete}},
				onReady: func() error {
					if collision == "symlink" {
						return os.Symlink(target, destination)
					}
					return os.WriteFile(destination, []byte("competing"), 0o600)
				},
			}
			if _, err := requestGet(context.Background(), channel, "artifact.bin", destination, int64(len(content))); err == nil || !strings.Contains(err.Error(), "destination already exists") {
				t.Fatalf("late collision error = %v", err)
			}
			if !channel.ready || channel.readyErr != nil {
				t.Fatalf("create competing destination after staging: ready=%t, error=%v", channel.ready, channel.readyErr)
			}
			actual, err := os.ReadFile(target)
			if err != nil || string(actual) != "competing" {
				t.Fatalf("competing destination changed: %q, %v", actual, err)
			}
			if collision == "symlink" {
				info, err := os.Lstat(destination)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("competing symlink changed: %v, %v", info, err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(destination) {
				t.Fatalf("temporary get data remains: %+v, %v", entries, err)
			}
		})
	}
}

func TestGetChecksumFailureCleansTemporaryDestination(t *testing.T) {
	root := t.TempDir()
	content := []byte(strings.Repeat("checksum-data", 10_000))
	if err := os.WriteFile(filepath.Join(root, "artifact.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	destinationDir := t.TempDir()
	destination := filepath.Join(destinationDir, "artifact.bin")
	client, server := newMemoryPipe()
	var once sync.Once
	server.mutate = func(message Message) Message {
		if !message.Text {
			once.Do(func() { message.Data[0] ^= 0xff })
		}
		return message
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = Serve(ctx, server, root) }()
	if _, err := requestGet(ctx, client, "artifact.bin", destination, int64(len(content))); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after checksum failure: %v", err)
	}
	entries, err := os.ReadDir(destinationDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files remain: %+v", entries)
	}
}

func TestGetCancellationCleansTemporaryDestination(t *testing.T) {
	root := t.TempDir()
	content := []byte(strings.Repeat("cancel-data", 1_000_000))
	if err := os.WriteFile(filepath.Join(root, "artifact.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	destinationDir := t.TempDir()
	destination := filepath.Join(destinationDir, "artifact.bin")
	client, server := newMemoryPipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, server, root) }()
	events := make([]GetEvent, 0)
	_, err := requestGetProgress(ctx, client, "artifact.bin", destination, int64(len(content)), func(event GetEvent) {
		events = append(events, event)
		if event.Bytes > 0 {
			cancel()
		}
	})
	if err == nil {
		t.Fatal("cancelled get succeeded")
	}
	<-served
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination exists after cancellation: %v", err)
	}
	entries, err := os.ReadDir(destinationDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files after cancellation = %+v, %v", entries, err)
	}
	if len(events) < 2 || events[len(events)-1].State == "committed" {
		t.Fatalf("cancellation events = %+v", events)
	}
}

func TestGetReportsDurableCommitWhenPeerConfirmationIsLost(t *testing.T) {
	root := t.TempDir()
	content := []byte("durable")
	if err := os.WriteFile(filepath.Join(root, "artifact.bin"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "artifact.bin")
	client, server := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, server, root) }()
	events := make([]GetEvent, 0)
	result, err := requestGetProgress(ctx, &failOfferedControl{Channel: client, controlType: "committed"}, "artifact.bin", destination, int64(len(content)), func(event GetEvent) { events = append(events, event) })
	if err == nil || result.Bytes != int64(len(content)) || len(events) == 0 || events[len(events)-1].State != "committed" {
		t.Fatalf("lost-confirmation outcome = %+v, %v, events %+v", result, err, events)
	}
	if getcleanup.IsCommittedCleanupPending(err) {
		t.Fatalf("lost peer confirmation was mislabeled as retained cleanup: %v", err)
	}
	actual, readErr := os.ReadFile(destination)
	if readErr != nil || !bytes.Equal(actual, content) {
		t.Fatalf("durable destination = %q, %v", actual, readErr)
	}
	cancel()
	<-served
}

func TestListEntryLimit(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= MaxEntries; index++ {
		name := filepath.Join(root, fmt.Sprintf("entry-%04d", index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := List(root, ""); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("entry limit error = %v", err)
	}
}

func TestRemoteErrorDoesNotExposeOfferedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-native-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	client, server := newMemoryPipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, server, root) }()
	_, err := RequestList(ctx, client, "missing")
	if err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("remote error = %v", err)
	}
	if serveErr := <-served; !errors.Is(serveErr, ErrUnavailable) {
		t.Fatalf("serve error = %v", serveErr)
	}
}

type cleanupPendingStage struct {
	file *os.File
}

func (s *cleanupPendingStage) File() *os.File { return s.file }

func (s *cleanupPendingStage) Publish(context.Context, string) (bool, error) {
	_ = s.file.Close()
	return true, cleanupPendingTestError{}
}

func (s *cleanupPendingStage) Cleanup(context.Context) error { return s.file.Close() }

type cleanupPendingTestError struct{}

func (cleanupPendingTestError) Error() string        { return "cleanup pending" }
func (cleanupPendingTestError) CleanupPending() bool { return true }

type memoryChannel struct {
	in     <-chan Message
	out    chan<- Message
	mutate func(Message) Message
}

type failOfferedControl struct {
	Channel
	controlType string
	failed      bool
}

type stagedCollisionChannel struct {
	messages []Message
	onReady  func() error
	ready    bool
	readyErr error
}

func (c *stagedCollisionChannel) Send(_ context.Context, message Message) error {
	if !message.Text || c.onReady == nil {
		return nil
	}
	var value control
	if json.Unmarshal(message.Data, &value) == nil && value.Type == "ready" {
		c.ready = true
		c.readyErr = c.onReady()
		c.onReady = nil
		return c.readyErr
	}
	return nil
}

func (c *stagedCollisionChannel) Receive(context.Context) (Message, error) {
	if len(c.messages) == 0 {
		return Message{}, errors.New("scripted peer has no message")
	}
	message := c.messages[0]
	c.messages = c.messages[1:]
	return message, nil
}

func (c *failOfferedControl) Send(ctx context.Context, message Message) error {
	if message.Text && !c.failed {
		var value control
		if json.Unmarshal(message.Data, &value) == nil && value.Type == c.controlType {
			c.failed = true
			return errors.New("simulated confirmation loss")
		}
	}
	return c.Channel.Send(ctx, message)
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
