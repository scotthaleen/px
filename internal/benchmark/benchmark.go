package benchmark

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/scotthaleen/px/internal/direct"
)

const (
	Version          = 1
	SessionPrefix    = "px-benchmark-"
	ChannelLabel     = "px-benchmark"
	Protocol         = "px-benchmark-v1"
	DefaultDuration  = 5 * time.Second
	MinDuration      = time.Second
	MaxDuration      = 30 * time.Second
	MaxMessageBytes  = 32 << 10
	MessageQueue     = 8
	MaxBufferedBytes = 4 << 20
	InboundLifetime  = 90 * time.Second
	controlLimit     = 1024
)

var controlTimeout = 5 * time.Second

type Identity struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label,omitempty"`
}

type Direction struct {
	Bytes        int64   `json:"bytes"`
	DurationNS   int64   `json:"duration_ns"`
	MiBPerSecond float64 `json:"mib_per_second"`
}

type Result struct {
	Version                     int       `json:"version"`
	Reporter                    Identity  `json:"reporter"`
	Target                      Identity  `json:"target"`
	RequestedDurationNS         int64     `json:"requested_duration_ns"`
	SetupDurationNS             int64     `json:"setup_duration_ns"`
	RTTNS                       int64     `json:"rtt_ns"`
	Upload                      Direction `json:"upload"`
	Download                    Direction `json:"download"`
	GatheredCandidateTypes      []string  `json:"gathered_candidate_types,omitempty"`
	SelectedLocalCandidateType  string    `json:"selected_local_candidate_type"`
	SelectedRemoteCandidateType string    `json:"selected_remote_candidate_type"`
	RelayUsed                   bool      `json:"relay_used"`
}

type Channel interface {
	Send(context.Context, direct.Message) error
	Receive(context.Context) (direct.Message, error)
}

type peerCloseWaiter interface {
	WaitPeerClose(context.Context) error
}

type control struct {
	Version    int    `json:"version"`
	Type       string `json:"type"`
	DurationNS int64  `json:"duration_ns,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
}

func Run(ctx context.Context, channel Channel, duration time.Duration) (Result, error) {
	if err := ValidateDuration(duration); err != nil {
		return Result{}, err
	}
	result := Result{Version: Version, RequestedDurationNS: duration.Nanoseconds()}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "start", DurationNS: duration.Nanoseconds()}); err != nil {
		return Result{}, err
	}
	if err := expectControl(ctx, channel, "ready", 0, ""); err != nil {
		return Result{}, err
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Result{}, errors.New("generate benchmark nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	rttStarted := time.Now()
	if err := sendControl(ctx, channel, control{Version: Version, Type: "ping", Nonce: nonce}); err != nil {
		return Result{}, err
	}
	if err := expectControl(ctx, channel, "pong", 0, nonce); err != nil {
		return Result{}, err
	}
	result.RTTNS = time.Since(rttStarted).Nanoseconds()

	if err := sendControl(ctx, channel, control{Version: Version, Type: "upload"}); err != nil {
		return Result{}, err
	}
	if err := expectControl(ctx, channel, "upload_ready", 0, ""); err != nil {
		return Result{}, err
	}
	bytesSent, err := sendPayload(ctx, channel, duration)
	if err != nil {
		return Result{}, err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "upload_end", Bytes: bytesSent}); err != nil {
		return Result{}, err
	}
	upload, err := receiveDirection(ctx, channel, "upload_done", bytesSent)
	if err != nil {
		return Result{}, err
	}
	result.Upload = upload

	if err := sendControl(ctx, channel, control{Version: Version, Type: "download"}); err != nil {
		return Result{}, err
	}
	downloadContext, cancelDownload := context.WithTimeout(ctx, duration+5*time.Second)
	download, err := receivePayload(downloadContext, channel, "download_end")
	cancelDownload()
	if err != nil {
		return Result{}, err
	}
	result.Download = download
	if err := sendControl(ctx, channel, control{Version: Version, Type: "download_done", Bytes: download.Bytes}); err != nil {
		return Result{}, err
	}
	if err := expectControl(ctx, channel, "completed", 0, ""); err != nil {
		return Result{}, err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "ack"}); err != nil {
		return Result{}, err
	}
	if err := expectControl(ctx, channel, "closed", 0, ""); err != nil {
		return Result{}, err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "close_ack"}); err != nil {
		return Result{}, err
	}
	if waiter, ok := channel.(peerCloseWaiter); ok {
		if err := waiter.WaitPeerClose(ctx); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func Serve(ctx context.Context, channel Channel) error {
	ctx, cancel := context.WithTimeout(ctx, InboundLifetime)
	defer cancel()
	start, err := receiveControlWithin(ctx, channel)
	if err != nil {
		return err
	}
	if start.Type != "start" || ValidateDuration(time.Duration(start.DurationNS)) != nil {
		return errors.New("invalid benchmark start")
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "ready"}); err != nil {
		return err
	}
	ping, err := receiveControlWithin(ctx, channel)
	if err != nil {
		return err
	}
	if ping.Type != "ping" || ping.Nonce == "" {
		return errors.New("invalid benchmark ping")
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "pong", Nonce: ping.Nonce}); err != nil {
		return err
	}
	if err := expectControl(ctx, channel, "upload", 0, ""); err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "upload_ready"}); err != nil {
		return err
	}
	uploadContext, cancelUpload := context.WithTimeout(ctx, time.Duration(start.DurationNS)+5*time.Second)
	upload, err := receivePayload(uploadContext, channel, "upload_end")
	cancelUpload()
	if err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "upload_done", Bytes: upload.Bytes, DurationNS: upload.DurationNS}); err != nil {
		return err
	}
	if err := expectControl(ctx, channel, "download", 0, ""); err != nil {
		return err
	}
	bytesSent, err := sendPayload(ctx, channel, time.Duration(start.DurationNS))
	if err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "download_end", Bytes: bytesSent}); err != nil {
		return err
	}
	if err := expectControl(ctx, channel, "download_done", bytesSent, ""); err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "completed"}); err != nil {
		return err
	}
	if err := expectControl(ctx, channel, "ack", 0, ""); err != nil {
		return err
	}
	if err := sendControl(ctx, channel, control{Version: Version, Type: "closed"}); err != nil {
		return err
	}
	return expectControl(ctx, channel, "close_ack", 0, "")
}

func ValidateDuration(duration time.Duration) error {
	if duration < MinDuration || duration > MaxDuration || duration%time.Millisecond != 0 {
		return fmt.Errorf("duration must be from %s through %s in whole milliseconds", MinDuration, MaxDuration)
	}
	return nil
}

func sendPayload(ctx context.Context, channel Channel, duration time.Duration) (int64, error) {
	payload := make([]byte, MaxMessageBytes)
	if _, err := rand.Read(payload); err != nil {
		return 0, errors.New("generate benchmark payload")
	}
	phaseContext, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	var sent int64
	for {
		if err := channel.Send(phaseContext, direct.Message{Data: payload}); err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				break
			}
			return 0, err
		}
		sent += int64(len(payload))
	}
	if sent == 0 {
		return 0, errors.New("benchmark produced no payload sample")
	}
	return sent, nil
}

func receivePayload(ctx context.Context, channel Channel, terminalType string) (Direction, error) {
	var received int64
	var started time.Time
	for {
		message, err := channel.Receive(ctx)
		if err != nil {
			return Direction{}, err
		}
		if !message.Text {
			if len(message.Data) != MaxMessageBytes {
				return Direction{}, errors.New("invalid benchmark payload")
			}
			if started.IsZero() {
				started = time.Now()
			}
			received += int64(len(message.Data))
			continue
		}
		value, err := decodeControl(message)
		if err != nil || value.Type != terminalType || value.Bytes != received || received == 0 || started.IsZero() {
			return Direction{}, errors.New("invalid benchmark payload completion")
		}
		duration := time.Since(started).Nanoseconds()
		return newDirection(received, duration), nil
	}
}

func receiveDirection(ctx context.Context, channel Channel, messageType string, expectedBytes int64) (Direction, error) {
	value, err := receiveControlWithin(ctx, channel)
	if err != nil {
		return Direction{}, err
	}
	if value.Type != messageType || value.Bytes != expectedBytes || value.DurationNS <= 0 {
		return Direction{}, errors.New("invalid benchmark direction result")
	}
	return newDirection(value.Bytes, value.DurationNS), nil
}

func newDirection(byteCount, durationNS int64) Direction {
	return Direction{Bytes: byteCount, DurationNS: durationNS, MiBPerSecond: float64(byteCount) / (1 << 20) / (float64(durationNS) / float64(time.Second))}
}

func expectControl(ctx context.Context, channel Channel, messageType string, byteCount int64, nonce string) error {
	value, err := receiveControlWithin(ctx, channel)
	if err != nil {
		return err
	}
	if value.Type != messageType || value.Bytes != byteCount || value.Nonce != nonce {
		return fmt.Errorf("invalid benchmark %s response", messageType)
	}
	return nil
}

func sendControl(ctx context.Context, channel Channel, value control) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > controlLimit {
		return errors.New("encode benchmark control")
	}
	controlContext, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	return channel.Send(controlContext, direct.Message{Text: true, Data: data})
}

func receiveControl(ctx context.Context, channel Channel) (control, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return control{}, err
	}
	return decodeControl(message)
}

func receiveControlWithin(ctx context.Context, channel Channel) (control, error) {
	controlContext, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	return receiveControl(controlContext, channel)
}

func decodeControl(message direct.Message) (control, error) {
	if !message.Text || len(message.Data) == 0 || len(message.Data) > controlLimit {
		return control{}, errors.New("invalid benchmark control")
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Data))
	decoder.DisallowUnknownFields()
	var value control
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != Version || !validControl(value) {
		return control{}, errors.New("invalid benchmark control")
	}
	return value, nil
}

func validControl(value control) bool {
	switch value.Type {
	case "start":
		return value.DurationNS > 0 && value.Nonce == "" && value.Bytes == 0
	case "ping", "pong":
		return value.DurationNS == 0 && value.Nonce != "" && value.Bytes == 0
	case "upload_end", "download_end", "download_done":
		return value.DurationNS == 0 && value.Nonce == "" && value.Bytes > 0
	case "upload_done":
		return value.DurationNS > 0 && value.Nonce == "" && value.Bytes > 0
	case "ready", "upload", "upload_ready", "download", "completed", "ack", "closed", "close_ack":
		return value.DurationNS == 0 && value.Nonce == "" && value.Bytes == 0
	default:
		return false
	}
}
