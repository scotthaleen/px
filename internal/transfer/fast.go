package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	FastProtocol      = "px-fast-send-v1"
	FastSessionPrefix = "px-fast-send-"
	FastChannelLabel  = "px-fast-send"
	fastVersion       = 1
	fastControlWait   = 5 * time.Second
	fastInactivity    = 30 * time.Second
)

const FastOutcomeUnknownCode = "outcome_unknown"

var ErrFastOutcomeUnknown = errors.New("fast-send outcome_unknown: the visible destination may be complete; inspect it before removing or retrying")

type FastSendConfig struct {
	Source       string
	Name         string
	Public       bool
	MaxFileBytes int64
	Progress     func(ResumeEvent)
}

type FastReceiveConfig struct {
	InboxRoot    string
	OfferedRoot  string
	Context      string
	SenderLabel  string
	MaxFileBytes int64
	Progress     func(ResumeEvent)
}

type fastControl struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Public  bool   `json:"public,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Error   string `json:"error,omitempty"`
}

func SendFast(ctx context.Context, channel Channel, cfg FastSendConfig) (Result, error) {
	started := time.Now()
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
	if cfg.Public && IsReservedName(name) {
		return Result{}, errors.New("public destination uses a reserved name")
	}
	if info.Size() > fileLimit(cfg.MaxFileBytes) {
		return Result{}, sourceError(SourceTooLargeCode, "local source exceeds the transfer limit", nil)
	}
	emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "submitted", Total: info.Size(), Name: name})
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "offer", Name: name, Size: info.Size(), Public: cfg.Public}); err != nil {
		return Result{}, err
	}
	response, err := receiveFastControlWithin(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "rejected" {
		_ = sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "ack"})
		emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "rejected", Error: response.Error})
		return Result{}, fmt.Errorf("receiver rejected fast send: %s", response.Error)
	}
	if response.Type != "ready" {
		return Result{}, errors.New("receiver sent an invalid fast-send response")
	}
	buffer := make([]byte, MaxMessageBytes)
	var sent, lastEvent int64
	for sent < info.Size() {
		remaining := info.Size() - sent
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		count, readErr := io.ReadFull(file, chunk)
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return Result{}, sourceError(SourceInvalidCode, "local source changed during fast send", readErr)
		}
		if count == 0 {
			return Result{}, sourceError(SourceInvalidCode, "local source changed during fast send", readErr)
		}
		if err := sendFastMessage(ctx, channel, Message{Data: chunk[:count]}, fastInactivity); err != nil {
			return Result{}, err
		}
		sent += int64(count)
		if sent-lastEvent >= 8<<20 || sent == info.Size() {
			emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "transferring", Bytes: sent, Total: info.Size()})
			lastEvent = sent
		}
	}
	if info.Size() == 0 {
		emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "transferring"})
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		return Result{}, sourceError(SourceInvalidCode, "local source changed during fast send", readErr)
	}
	if err := file.Close(); err != nil {
		return Result{}, fmt.Errorf("close fast-send source: %w", err)
	}
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "complete"}); err != nil {
		return Result{}, err
	}
	result := Result{Name: name, Bytes: sent, Duration: time.Since(started)}
	response, err = receiveFastControlWithin(ctx, channel)
	if err != nil {
		return fastOutcomeUnknown(cfg.Progress, result, err)
	}
	if response.Type != "completed" || response.Bytes != sent {
		return fastOutcomeUnknown(cfg.Progress, result, errors.New("receiver sent an invalid fast-send completion"))
	}
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "ack"}); err != nil {
		return fastOutcomeUnknown(cfg.Progress, result, err)
	}
	if waiter, ok := channel.(peerCloseWaiter); ok {
		waitContext, cancel := context.WithTimeout(ctx, fastControlWait)
		err := waiter.WaitPeerClose(waitContext)
		cancel()
		if err != nil {
			return fastOutcomeUnknown(cfg.Progress, result, err)
		}
	}
	emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "committed", Bytes: sent, Total: sent, Name: name})
	return result, nil
}

func ReceiveFast(ctx context.Context, channel Channel, cfg FastReceiveConfig) (Result, error) {
	started := time.Now()
	offer, err := receiveFastControlWithin(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if offer.Type != "offer" || ValidatePortableName(offer.Name) != nil || offer.Size < 0 || offer.Size > fileLimit(cfg.MaxFileBytes) {
		_ = rejectFast(ctx, channel, "invalid fast-send offer")
		return Result{}, errors.New("invalid fast-send offer")
	}
	if offer.Public && IsReservedName(offer.Name) {
		_ = rejectFast(ctx, channel, "invalid public destination")
		return Result{}, errors.New("invalid public fast-send destination")
	}
	rootPath, directory := cfg.InboxRoot, filepath.Join(cfg.Context, cfg.SenderLabel)
	if offer.Public {
		rootPath, directory = cfg.OfferedRoot, ""
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return Result{}, errors.New("open fast-send destination root failed")
	}
	defer root.Close()
	if directory != "" {
		if err := root.MkdirAll(directory, 0o700); err != nil {
			return Result{}, errors.New("create fast-send inbox namespace failed")
		}
	}
	destination := filepath.Join(directory, offer.Name)
	var file *os.File
	if offer.Public {
		publicCommitMu.Lock()
		collisionErr := rejectPortableCollision(root, offer.Name)
		if collisionErr == nil {
			file, err = root.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
		publicCommitMu.Unlock()
		if collisionErr != nil {
			_ = rejectFast(ctx, channel, "destination already exists or case-collides")
			return Result{}, collisionErr
		}
	} else {
		file, err = root.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	if err != nil {
		_ = rejectFast(ctx, channel, "destination already exists or is unavailable")
		return Result{}, errors.New("fast-send destination already exists or is unavailable")
	}
	defer file.Close()
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "ready"}); err != nil {
		return Result{}, err
	}
	var received, lastEvent int64
	for received < offer.Size {
		message, err := receiveFastMessage(ctx, channel, fastInactivity)
		if err != nil {
			return Result{}, err
		}
		if message.Text || len(message.Data) == 0 || len(message.Data) > MaxMessageBytes || received+int64(len(message.Data)) > offer.Size {
			return Result{}, errors.New("invalid fast-send data")
		}
		if err := writeAll(file, message.Data); err != nil {
			return Result{}, errors.New("write fast-send destination failed")
		}
		received += int64(len(message.Data))
		if received-lastEvent >= 8<<20 || received == offer.Size {
			emitFast(cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "transferring", Bytes: received, Total: offer.Size, Name: offer.Name})
			lastEvent = received
		}
	}
	complete, err := receiveFastControlWithin(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if complete.Type != "complete" {
		return Result{}, errors.New("sender did not complete fast send")
	}
	if err := file.Close(); err != nil {
		return Result{}, errors.New("close fast-send destination failed")
	}
	info, err := root.Stat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Size() != offer.Size {
		return Result{}, errors.New("fast-send destination changed during transfer")
	}
	result := Result{Name: offer.Name, Bytes: received, Duration: time.Since(started), Path: filepath.ToSlash(destination)}
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "completed", Bytes: received}); err != nil {
		return result, err
	}
	ack, err := receiveFastControlWithin(ctx, channel)
	if err != nil {
		return result, fmt.Errorf("sender did not acknowledge fast-send completion: %w", err)
	}
	if ack.Type != "ack" {
		return result, errors.New("sender sent an invalid fast-send acknowledgement")
	}
	return result, nil
}

func emitFast(progress func(ResumeEvent), event ResumeEvent) {
	if progress != nil {
		progress(event)
	}
}

func sendFastControl(ctx context.Context, channel Channel, value fastControl) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxControlBytes {
		return errors.New("encode fast-send control failed")
	}
	return channel.Send(ctx, Message{Text: true, Data: encoded})
}

func sendFastControlWithin(ctx context.Context, channel Channel, value fastControl) error {
	waitContext, cancel := context.WithTimeout(ctx, fastControlWait)
	defer cancel()
	return sendFastControl(waitContext, channel, value)
}

func receiveFastControl(ctx context.Context, channel Channel) (fastControl, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return fastControl{}, err
	}
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxControlBytes {
		return fastControl{}, errors.New("invalid fast-send control")
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Data))
	decoder.DisallowUnknownFields()
	var value fastControl
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != fastVersion {
		return fastControl{}, errors.New("invalid fast-send control")
	}
	if !validFastControl(value) {
		return fastControl{}, errors.New("invalid fast-send control fields")
	}
	return value, nil
}

func receiveFastControlWithin(ctx context.Context, channel Channel) (fastControl, error) {
	waitContext, cancel := context.WithTimeout(ctx, fastControlWait)
	defer cancel()
	return receiveFastControl(waitContext, channel)
}

func sendFastMessage(ctx context.Context, channel Channel, message Message, timeout time.Duration) error {
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return channel.Send(waitContext, message)
}

func receiveFastMessage(ctx context.Context, channel Channel, timeout time.Duration) (Message, error) {
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return channel.Receive(waitContext)
}

func fastOutcomeUnknown(progress func(ResumeEvent), result Result, cause error) (Result, error) {
	emitFast(progress, ResumeEvent{Version: ResumeEventVersion, State: "failed", Bytes: result.Bytes, Total: result.Bytes, Name: result.Name, Error: ErrFastOutcomeUnknown.Error(), ErrorCode: FastOutcomeUnknownCode, Outcome: FastOutcomeUnknownCode})
	return result, fmt.Errorf("%w: %w", ErrFastOutcomeUnknown, cause)
}

func rejectFast(ctx context.Context, channel Channel, message string) error {
	if err := sendFastControlWithin(ctx, channel, fastControl{Version: fastVersion, Type: "rejected", Error: message}); err != nil {
		return err
	}
	ack, err := receiveFastControlWithin(ctx, channel)
	if err != nil {
		return err
	}
	if ack.Type != "ack" {
		return errors.New("sender did not acknowledge fast-send rejection")
	}
	return nil
}

func validFastControl(value fastControl) bool {
	switch value.Type {
	case "offer":
		return value.Name != "" && value.Size >= 0 && value.Bytes == 0 && value.Error == ""
	case "ready", "complete", "ack":
		return value.Name == "" && value.Size == 0 && !value.Public && value.Bytes == 0 && value.Error == ""
	case "completed":
		return value.Name == "" && value.Size == 0 && !value.Public && value.Bytes >= 0 && value.Error == ""
	case "rejected":
		return value.Name == "" && value.Size == 0 && !value.Public && value.Bytes == 0 && value.Error != ""
	default:
		return false
	}
}
