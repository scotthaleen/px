package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Protocol             = "px-transfer-v1"
	MaxMessageBytes      = 32 << 10
	MaxControlBytes      = 4 << 10
	DefaultMaxFileBytes  = 1 << 30
	DefaultQueueDepth    = 8
	DefaultBufferedBytes = 4 << 20
	protocolVersion      = 1
)

const (
	SourceInvalidCode     = "source_invalid"
	SourceNotFoundCode    = "source_not_found"
	SourceDirectoryCode   = "source_directory"
	SourceSymlinkCode     = "source_symlink"
	SourceUnsupportedCode = "source_unsupported"
	SourceUnreadableCode  = "source_unreadable"
	SourceTooLargeCode    = "source_too_large"
)

type SourceError struct {
	Code    string
	Message string
	cause   error
}

func (e *SourceError) Error() string { return e.Message }
func (e *SourceError) Unwrap() error { return e.cause }

func sourceError(code, message string, cause error) error {
	return &SourceError{Code: code, Message: message, cause: cause}
}

type Message struct {
	Text bool
	Data []byte
}

type Channel interface {
	Send(context.Context, Message) error
	Receive(context.Context) (Message, error)
}

type peerCloseWaiter interface {
	WaitPeerClose(context.Context) error
}

type SendConfig struct {
	Source       string
	Name         string
	MaxFileBytes int64
	Progress     func(completed, total int64)
}

type ReceiveConfig struct {
	InboxRoot      string
	Context        string
	Sender         string
	MaxFileBytes   int64
	AvailableSpace func(string) (uint64, error)
	Progress       func(completed, total int64)
}

type Result struct {
	Name     string        `json:"name"`
	Bytes    int64         `json:"bytes"`
	SHA256   string        `json:"sha256"`
	Duration time.Duration `json:"duration"`
	Path     string        `json:"path,omitempty"`
}

type control struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

func Send(ctx context.Context, channel Channel, cfg SendConfig) (Result, error) {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	file, info, err := openSource(cfg.Source)
	if err != nil {
		return Result{}, err
	}
	defer file.Close()

	name := cfg.Name
	if name == "" {
		name = filepath.Base(cfg.Source)
	}
	if err := ValidatePortableName(name); err != nil {
		return Result{}, fmt.Errorf("destination name: %w", err)
	}
	maxFileBytes := fileLimit(cfg.MaxFileBytes)
	if info.Size() > maxFileBytes {
		return Result{}, sourceError(SourceTooLargeCode, "local source exceeds the transfer limit", nil)
	}
	expectedHash, err := hashFile(ctx, file, info.Size())
	if err != nil {
		return Result{}, fmt.Errorf("hash source: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind source: %w", err)
	}
	transferID, err := randomID()
	if err != nil {
		return Result{}, err
	}
	metadata := control{
		Version: protocolVersion,
		Type:    "offer",
		ID:      transferID,
		Name:    name,
		Size:    info.Size(),
		SHA256:  expectedHash,
	}
	if err := sendControl(ctx, channel, metadata); err != nil {
		return Result{}, err
	}
	response, err := receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "error" {
		return Result{}, fmt.Errorf("receiver refused transfer: %s", response.Error)
	}
	if response.Type != "ready" || response.ID != transferID {
		return Result{}, errors.New("receiver sent an unexpected transfer response")
	}

	hasher := sha256.New()
	buffer := make([]byte, MaxMessageBytes)
	var sent int64
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			if sent+int64(count) > info.Size() {
				_ = sendFailure(ctx, channel, transferID, "source changed during transfer")
				return Result{}, errors.New("source changed during transfer")
			}
			if _, err := hasher.Write(buffer[:count]); err != nil {
				return Result{}, fmt.Errorf("hash source chunk: %w", err)
			}
			if err := channel.Send(ctx, Message{Data: buffer[:count]}); err != nil {
				return Result{}, fmt.Errorf("send file chunk: %w", err)
			}
			sent += int64(count)
			if cfg.Progress != nil {
				cfg.Progress(sent, info.Size())
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = sendFailure(ctx, channel, transferID, "source read failed")
			return Result{}, fmt.Errorf("read source: %w", readErr)
		}
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if sent != info.Size() || actualHash != expectedHash {
		_ = sendFailure(ctx, channel, transferID, "source changed during transfer")
		return Result{}, errors.New("source changed during transfer")
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "complete", ID: transferID}); err != nil {
		return Result{}, err
	}
	response, err = receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "error" {
		return Result{}, fmt.Errorf("receiver failed transfer: %s", response.Error)
	}
	if response.Type != "committed" || response.ID != transferID || response.Bytes != sent || response.SHA256 != expectedHash {
		return Result{}, errors.New("receiver sent an invalid commit confirmation")
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ack", ID: transferID}); err != nil {
		return Result{}, err
	}
	if channel, ok := channel.(peerCloseWaiter); ok {
		if err := channel.WaitPeerClose(ctx); err != nil {
			return Result{}, fmt.Errorf("wait for receiver shutdown: %w", err)
		}
	}
	return Result{Name: name, Bytes: sent, SHA256: expectedHash, Duration: time.Since(started), Path: response.Path}, nil
}

func Receive(ctx context.Context, channel Channel, cfg ReceiveConfig) (result Result, err error) {
	started := time.Now()
	metadata, err := receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	fail := func(cause error) (Result, error) {
		_ = sendFailure(ctx, channel, metadata.ID, cause.Error())
		return Result{}, cause
	}
	if metadata.Type != "offer" || !validID(metadata.ID) {
		return fail(errors.New("invalid transfer offer"))
	}
	if err := ValidatePortableName(metadata.Name); err != nil {
		return fail(fmt.Errorf("destination name: %w", err))
	}
	if err := ValidatePortableName(cfg.Context); err != nil {
		return fail(fmt.Errorf("context name: %w", err))
	}
	if err := ValidatePortableName(cfg.Sender); err != nil {
		return fail(fmt.Errorf("sender name: %w", err))
	}
	maxFileBytes := fileLimit(cfg.MaxFileBytes)
	if metadata.Size < 0 || metadata.Size > maxFileBytes {
		return fail(fmt.Errorf("offered file is %d bytes, limit is %d", metadata.Size, maxFileBytes))
	}
	if !validHash(metadata.SHA256) {
		return fail(errors.New("invalid complete-file hash"))
	}
	space := cfg.AvailableSpace
	if space == nil {
		space = availableSpace
	}
	available, err := space(cfg.InboxRoot)
	if err != nil {
		return fail(fmt.Errorf("check inbox free space: %w", err))
	}
	if uint64(metadata.Size) > available {
		return fail(fmt.Errorf("insufficient inbox space: need %d bytes, have %d", metadata.Size, available))
	}

	root, err := os.OpenRoot(cfg.InboxRoot)
	if err != nil {
		return fail(fmt.Errorf("open inbox root: %w", err))
	}
	defer root.Close()
	directory := filepath.Join(cfg.Context, cfg.Sender)
	if err := root.MkdirAll(directory, 0o700); err != nil {
		return fail(fmt.Errorf("create inbox namespace: %w", err))
	}
	destination := filepath.Join(directory, metadata.Name)
	if _, err := root.Lstat(destination); err == nil {
		return fail(errors.New("destination already exists"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("inspect destination: %w", err))
	}
	tempID, err := randomID()
	if err != nil {
		return fail(err)
	}
	temporary := filepath.Join(directory, ".px-"+tempID+".part")
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(fmt.Errorf("create temporary destination: %w", err))
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = root.Remove(temporary)
		}
	}()
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ready", ID: metadata.ID}); err != nil {
		return Result{}, err
	}

	hasher := sha256.New()
	var received int64
	for {
		message, receiveErr := channel.Receive(ctx)
		if receiveErr != nil {
			return Result{}, fmt.Errorf("receive transfer message: %w", receiveErr)
		}
		if !message.Text {
			if len(message.Data) == 0 || len(message.Data) > MaxMessageBytes || received+int64(len(message.Data)) > metadata.Size {
				return fail(errors.New("invalid file chunk"))
			}
			if err := writeAll(file, message.Data); err != nil {
				return fail(fmt.Errorf("write temporary destination: %w", err))
			}
			if _, err := hasher.Write(message.Data); err != nil {
				return fail(fmt.Errorf("hash received chunk: %w", err))
			}
			received += int64(len(message.Data))
			if cfg.Progress != nil {
				cfg.Progress(received, metadata.Size)
			}
			continue
		}
		complete, err := decodeControl(message)
		if err != nil {
			return fail(err)
		}
		if complete.Type == "error" && complete.ID == metadata.ID {
			return Result{}, fmt.Errorf("sender aborted transfer: %s", complete.Error)
		}
		if complete.Type != "complete" || complete.ID != metadata.ID {
			return fail(errors.New("unexpected transfer control message"))
		}
		break
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if received != metadata.Size {
		return fail(fmt.Errorf("received %d bytes, expected %d", received, metadata.Size))
	}
	if actualHash != metadata.SHA256 {
		return fail(errors.New("complete-file checksum mismatch"))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync temporary destination: %w", err))
	}
	if err := file.Close(); err != nil {
		return fail(fmt.Errorf("close temporary destination: %w", err))
	}
	if err := root.Link(temporary, destination); err != nil {
		if _, statErr := root.Lstat(destination); statErr == nil {
			return fail(errors.New("destination already exists"))
		}
		return fail(fmt.Errorf("commit destination: %w", err))
	}
	if err := root.Remove(temporary); err != nil {
		return fail(fmt.Errorf("remove committed temporary file: %w", err))
	}
	removeTemporary = false
	result = Result{
		Name:     metadata.Name,
		Bytes:    received,
		SHA256:   actualHash,
		Duration: time.Since(started),
		Path:     filepath.ToSlash(destination),
	}
	if err := sendControl(ctx, channel, control{
		Version: protocolVersion,
		Type:    "committed",
		ID:      metadata.ID,
		Bytes:   received,
		SHA256:  actualHash,
		Path:    result.Path,
	}); err != nil {
		return Result{}, err
	}
	acknowledgement, err := receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if acknowledgement.Type != "ack" || acknowledgement.ID != metadata.ID {
		return Result{}, errors.New("sender sent an invalid commit acknowledgement")
	}
	return result, nil
}

func ValidatePortableName(name string) error {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return errors.New("must be valid UTF-8 between 1 and 255 bytes")
	}
	if name == "." || name == ".." || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return errors.New("is not a portable filename")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"/\|?*`, r) {
			return errors.New("contains a non-portable character")
		}
	}
	base := strings.ToUpper(name)
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || isReservedPortName(base) {
		return errors.New("is a reserved device name")
	}
	return nil
}

func isReservedPortName(base string) bool {
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3] >= '1' && base[3] <= '9'
	}
	if len(base) == 5 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3:] == "¹" || base[3:] == "²" || base[3:] == "³"
	}
	return false
}

func ValidateSource(path string, maxFileBytes int64) error {
	file, info, err := openSource(path)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return sourceError(SourceUnreadableCode, "local source cannot be read", err)
	}
	if info.Size() > fileLimit(maxFileBytes) {
		return sourceError(SourceTooLargeCode, "local source exceeds the transfer limit", nil)
	}
	return nil
}

func openSource(path string) (*os.File, os.FileInfo, error) {
	if path == "" {
		return nil, nil, sourceError(SourceInvalidCode, "local source path is invalid", nil)
	}
	for _, value := range path {
		if unicode.IsControl(value) {
			return nil, nil, sourceError(SourceInvalidCode, "local source path contains a control character", nil)
		}
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, nil, sourceError(SourceNotFoundCode, "local source does not exist or is unavailable", err)
		case os.IsPermission(err):
			return nil, nil, sourceError(SourceUnreadableCode, "local source cannot be read", err)
		case invalidSourcePathError(err):
			return nil, nil, sourceError(SourceInvalidCode, "local source path is invalid", err)
		default:
			return nil, nil, fmt.Errorf("inspect source path: %w", err)
		}
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, sourceError(SourceSymlinkCode, "local source is a symlink", nil)
	}
	if pathInfo.IsDir() {
		return nil, nil, sourceError(SourceDirectoryCode, "local source is a directory", nil)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, nil, sourceError(SourceUnsupportedCode, "local source is not a regular file", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, sourceError(SourceNotFoundCode, "local source does not exist or is unavailable", err)
		}
		if os.IsPermission(err) {
			return nil, nil, sourceError(SourceUnreadableCode, "local source cannot be read", err)
		}
		if invalidSourcePathError(err) {
			return nil, nil, sourceError(SourceInvalidCode, "local source path is invalid", err)
		}
		return nil, nil, fmt.Errorf("open source: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect opened source: %w", err)
	}
	pathInfo, err = os.Lstat(path)
	if err != nil {
		file.Close()
		if os.IsNotExist(err) {
			return nil, nil, sourceError(SourceNotFoundCode, "local source does not exist or is unavailable", err)
		}
		return nil, nil, fmt.Errorf("inspect source path: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !info.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		file.Close()
		return nil, nil, sourceError(SourceInvalidCode, "local source changed while it was opened", nil)
	}
	return file, info, nil
}

func fileLimit(value int64) int64 {
	if value <= 0 {
		return DefaultMaxFileBytes
	}
	return value
}

func hashFile(ctx context.Context, file *os.File, expectedSize int64) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, MaxMessageBytes)
	var hashed int64
	for hashed < expectedSize {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := expectedSize - hashed
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		count, err := file.Read(chunk)
		if count > 0 {
			if _, writeErr := hasher.Write(buffer[:count]); writeErr != nil {
				return "", writeErr
			}
			hashed += int64(count)
		}
		if errors.Is(err, io.EOF) {
			return "", sourceError(SourceInvalidCode, "local source changed while hashing", err)
		}
		if err != nil {
			return "", sourceError(SourceUnreadableCode, "local source cannot be read", err)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func sendControl(ctx context.Context, channel Channel, value control) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode transfer control: %w", err)
	}
	if len(encoded) > MaxControlBytes {
		return errors.New("transfer control message is too large")
	}
	if err := channel.Send(ctx, Message{Text: true, Data: encoded}); err != nil {
		return fmt.Errorf("send transfer control: %w", err)
	}
	return nil
}

func sendFailure(ctx context.Context, channel Channel, id, message string) error {
	if len(message) > 512 {
		message = message[:512]
	}
	return sendControl(ctx, channel, control{Version: protocolVersion, Type: "error", ID: id, Error: message})
}

func receiveControl(ctx context.Context, channel Channel) (control, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return control{}, fmt.Errorf("receive transfer control: %w", err)
	}
	return decodeControl(message)
}

func decodeControl(message Message) (control, error) {
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxControlBytes {
		return control{}, errors.New("invalid transfer control message")
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Data))
	decoder.DisallowUnknownFields()
	var value control
	if err := decoder.Decode(&value); err != nil {
		return control{}, fmt.Errorf("decode transfer control: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return control{}, errors.New("transfer control has trailing data")
	}
	if value.Version != protocolVersion {
		return control{}, fmt.Errorf("unsupported transfer protocol version %d", value.Version)
	}
	return value, nil
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate transfer ID: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func validID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
