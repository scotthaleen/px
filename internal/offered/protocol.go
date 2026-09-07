package offered

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/scotthaleen/px/internal/transfer"
)

const (
	Protocol             = "px-offered-v1"
	MaxMessageBytes      = 32 << 10
	MaxControlBytes      = 4 << 10
	DefaultMaxFileBytes  = 1 << 30
	DefaultQueueDepth    = 8
	DefaultBufferedBytes = 256 << 10
	protocolVersion      = 1
	GetEventVersion      = 1
	progressInterval     = 8 << 20
)

type Message struct {
	Text bool
	Data []byte
}

type Channel interface {
	Send(context.Context, Message) error
	Receive(context.Context) (Message, error)
}

type StagedFile interface {
	File() *os.File
	Publish(context.Context, string) (bool, error)
	Cleanup(context.Context) error
}

type StageFunc func(context.Context, string, int64) (StagedFile, error)

type GetResult struct {
	Bytes    int64         `json:"bytes"`
	SHA256   string        `json:"sha256"`
	Duration time.Duration `json:"duration"`
}

type GetEvent struct {
	Version        int           `json:"version"`
	State          string        `json:"state"`
	Bytes          int64         `json:"bytes"`
	Total          int64         `json:"total"`
	Duration       time.Duration `json:"duration,omitempty"`
	SHA256         string        `json:"sha256,omitempty"`
	CleanupPending bool          `json:"cleanup_pending,omitempty"`
	Error          string        `json:"error,omitempty"`
}

type control struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Path    string `json:"path,omitempty"`
	Entry   *Entry `json:"entry,omitempty"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Error   string `json:"error,omitempty"`
}

func RequestList(ctx context.Context, channel Channel, path string) ([]Entry, error) {
	if err := ValidatePath(path, true); err != nil {
		return nil, err
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "list", Path: path}); err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	for {
		response, err := receiveControl(ctx, channel)
		if err != nil {
			return nil, err
		}
		switch response.Type {
		case "entry":
			if response.Entry == nil || len(entries) >= MaxEntries || transfer.ValidatePortableName(response.Entry.Name) != nil || (response.Entry.Kind != "file" && response.Entry.Kind != "directory") || response.Entry.Size < 0 {
				return nil, errors.New("peer sent an invalid directory entry")
			}
			entries = append(entries, *response.Entry)
		case "done":
			if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ack"}); err != nil {
				return nil, err
			}
			return entries, nil
		case "error":
			return nil, fmt.Errorf("peer refused list: %s", response.Error)
		default:
			return nil, errors.New("peer sent an unexpected list response")
		}
	}
}

func Serve(ctx context.Context, channel Channel, rootPath string) error {
	request, err := receiveControl(ctx, channel)
	if err != nil {
		return err
	}
	switch request.Type {
	case "list":
		return serveList(ctx, channel, rootPath, request.Path)
	case "get":
		return serveGet(ctx, channel, rootPath, request.Path)
	default:
		_ = sendError(ctx, channel, "unsupported offered-root operation")
		return errors.New("unsupported offered-root operation")
	}
}

func serveList(ctx context.Context, channel Channel, rootPath, path string) error {
	entries, err := List(rootPath, path)
	if err != nil {
		_ = sendError(ctx, channel, publicError(err))
		return err
	}
	for _, entry := range entries {
		value := entry
		if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "entry", Entry: &value}); err != nil {
			return err
		}
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "done"}); err != nil {
		return err
	}
	acknowledgement, err := receiveControl(ctx, channel)
	if err != nil || acknowledgement.Type != "ack" {
		return errors.New("requester sent an invalid list acknowledgement")
	}
	return nil
}

func RequestGetProgressStaged(ctx context.Context, channel Channel, path, destination string, maxFileBytes int64, stageFile StageFunc, progress func(GetEvent)) (GetResult, error) {
	started := time.Now()
	if err := ValidatePath(path, false); err != nil {
		return GetResult{}, err
	}
	if destination == "" {
		destination = filepath.FromSlash(filepath.Base(path))
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "get", Path: path}); err != nil {
		return GetResult{}, err
	}
	metadata, err := receiveControl(ctx, channel)
	if err != nil {
		return GetResult{}, err
	}
	if metadata.Type == "error" {
		return GetResult{}, fmt.Errorf("peer refused get: %s", metadata.Error)
	}
	limit := maxFileBytes
	if limit <= 0 {
		limit = DefaultMaxFileBytes
	}
	if metadata.Type != "file" || metadata.Size < 0 || metadata.Size > limit || !validHash(metadata.SHA256) {
		return GetResult{}, errors.New("peer sent invalid file metadata")
	}
	emitGet(progress, GetEvent{Version: GetEventVersion, State: "transferring", Total: metadata.Size})
	if stageFile == nil {
		return GetResult{}, errors.New("get stager is required")
	}
	stage, err := stageFile(ctx, destination, metadata.Size)
	if err != nil {
		return GetResult{}, err
	}
	file := stage.File()
	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = stage.Cleanup(cleanupCtx)
			cancel()
		}
	}()
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ready"}); err != nil {
		return GetResult{}, err
	}
	hasher := sha256.New()
	var received int64
	lastEvent := int64(0)
	for received < metadata.Size {
		message, err := channel.Receive(ctx)
		if err != nil {
			return GetResult{}, err
		}
		if message.Text || len(message.Data) == 0 || len(message.Data) > MaxMessageBytes || received+int64(len(message.Data)) > metadata.Size {
			return GetResult{}, errors.New("peer sent an invalid file chunk")
		}
		if _, err := file.Write(message.Data); err != nil {
			return GetResult{}, errors.New("write local destination failed")
		}
		_, _ = hasher.Write(message.Data)
		received += int64(len(message.Data))
		if received-lastEvent >= progressInterval || received == metadata.Size {
			emitGet(progress, GetEvent{Version: GetEventVersion, State: "transferring", Bytes: received, Total: metadata.Size})
			lastEvent = received
		}
	}
	complete, err := receiveControl(ctx, channel)
	if err != nil || complete.Type != "complete" {
		return GetResult{}, errors.New("peer sent an invalid completion message")
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != metadata.SHA256 {
		return GetResult{}, errors.New("complete-file checksum mismatch")
	}
	name := filepath.Base(destination)
	result := GetResult{Bytes: received, SHA256: actualHash, Duration: time.Since(started)}
	committed, err := stage.Publish(ctx, name)
	if err != nil {
		if !committed {
			result = GetResult{}
			return result, err
		}
		cleanupNeeded = false
		emitGet(progress, GetEvent{Version: GetEventVersion, State: "committed", Bytes: received, Total: metadata.Size, Duration: result.Duration, SHA256: actualHash, CleanupPending: isCleanupPending(err)})
		return result, err
	}
	cleanupNeeded = false
	emitGet(progress, GetEvent{Version: GetEventVersion, State: "committed", Bytes: received, Total: metadata.Size, Duration: result.Duration, SHA256: actualHash})
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "committed", Bytes: received}); err != nil {
		return result, err
	}
	return result, nil
}

func emitGet(progress func(GetEvent), event GetEvent) {
	if progress != nil {
		progress(event)
	}
}

func isCleanupPending(err error) bool {
	var pending interface{ CleanupPending() bool }
	return errors.As(err, &pending) && pending.CleanupPending()
}

func serveGet(ctx context.Context, channel Channel, rootPath, path string) error {
	file, info, err := Open(rootPath, path)
	if err != nil {
		_ = sendError(ctx, channel, publicError(err))
		return err
	}
	defer file.Close()
	hash, err := hashFile(ctx, file, info.Size())
	if err != nil {
		_ = sendError(ctx, channel, "offered file is unavailable")
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "file", Size: info.Size(), SHA256: hash}); err != nil {
		return err
	}
	ready, err := receiveControl(ctx, channel)
	if err != nil || ready.Type != "ready" {
		return errors.New("requester did not accept offered file")
	}
	buffer := make([]byte, MaxMessageBytes)
	var sent int64
	for sent < info.Size() {
		count, err := file.Read(buffer)
		if count > 0 {
			if sendErr := channel.Send(ctx, Message{Data: buffer[:count]}); sendErr != nil {
				return sendErr
			}
			sent += int64(count)
		}
		if err != nil {
			return errors.New("offered file changed during transfer")
		}
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "complete"}); err != nil {
		return err
	}
	committed, err := receiveControl(ctx, channel)
	if err != nil || committed.Type != "committed" || committed.Bytes != sent {
		return errors.New("requester sent invalid commit confirmation")
	}
	return nil
}

func hashFile(ctx context.Context, file *os.File, size int64) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, MaxMessageBytes)
	var read int64
	for read < size {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count, err := file.Read(buffer)
		if count > 0 {
			_, _ = hasher.Write(buffer[:count])
			read += int64(count)
		}
		if err != nil {
			return "", errors.New("offered file changed while hashing")
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func sendControl(ctx context.Context, channel Channel, value control) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxControlBytes {
		return errors.New("offered-root control message is invalid")
	}
	return channel.Send(ctx, Message{Text: true, Data: data})
}

func receiveControl(ctx context.Context, channel Channel) (control, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return control{}, err
	}
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxControlBytes {
		return control{}, errors.New("invalid offered-root control message")
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Data))
	decoder.DisallowUnknownFields()
	var value control
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != protocolVersion {
		return control{}, errors.New("invalid offered-root control message")
	}
	return value, nil
}

func sendError(ctx context.Context, channel Channel, message string) error {
	return sendControl(ctx, channel, control{Version: protocolVersion, Type: "error", Error: message})
}

func publicError(err error) string {
	switch {
	case errors.Is(err, ErrNotRegular):
		return ErrNotRegular.Error()
	case errors.Is(err, ErrNotDirectory):
		return ErrNotDirectory.Error()
	default:
		return ErrUnavailable.Error()
	}
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
