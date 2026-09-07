package ping

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/scotthaleen/px/internal/direct"
)

const (
	Version          = 2
	DefaultCount     = 4
	MaxCount         = 10
	SessionPrefix    = "px-ping-"
	ChannelLabel     = "px-ping"
	Protocol         = "px-ping-v1"
	MaxMessageBytes  = frameSize
	MessageQueue     = 2
	MaxBufferedBytes = frameSize * 2
	SampleTimeout    = 2 * time.Second
	SampleInterval   = 100 * time.Millisecond
	InboundIdle      = 3 * time.Second
	InboundLifetime  = 25 * time.Second

	frameSize    = 38
	frameVersion = 1
	typePing     = 1
	typePong     = 2
)

type Identity struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label,omitempty"`
}

type Sample struct {
	Sequence int    `json:"sequence"`
	Status   string `json:"status"`
	RTTNS    *int64 `json:"rtt_ns,omitempty"`
}

type Result struct {
	Version                     int      `json:"version"`
	Mode                        string   `json:"mode"`
	Reporter                    Identity `json:"reporter"`
	Target                      Identity `json:"target"`
	SetupDurationNS             *int64   `json:"setup_duration_ns,omitempty"`
	Samples                     []Sample `json:"samples"`
	Requested                   int      `json:"requested"`
	Attempted                   int      `json:"attempted"`
	Succeeded                   int      `json:"succeeded"`
	Lost                        int      `json:"lost"`
	LossBasisPoints             int      `json:"loss_basis_points"`
	MinRTTNS                    *int64   `json:"min_rtt_ns"`
	AvgRTTNS                    *int64   `json:"avg_rtt_ns"`
	MaxRTTNS                    *int64   `json:"max_rtt_ns"`
	JitterNS                    *int64   `json:"jitter_ns"`
	GatheredCandidateTypes      []string `json:"gathered_candidate_types,omitempty"`
	SelectedLocalCandidateType  string   `json:"selected_local_candidate_type,omitempty"`
	SelectedRemoteCandidateType string   `json:"selected_remote_candidate_type,omitempty"`
	SelectedLocalAddress        string   `json:"selected_local_address,omitempty"`
	SelectedRemoteAddress       string   `json:"selected_remote_address,omitempty"`
	RelayUsed                   *bool    `json:"relay_used,omitempty"`
}

type Channel interface {
	Send(context.Context, direct.Message) error
	Receive(context.Context) (direct.Message, error)
}

type RoundTrip func(context.Context, int) error

func Measure(ctx context.Context, count int, roundTrip RoundTrip) Result {
	result := Result{Version: Version, Samples: make([]Sample, 0, count), Requested: count}
	for sequence := 1; sequence <= count; sequence++ {
		if ctx.Err() != nil {
			appendRemaining(&result, sequence, "canceled")
			break
		}
		if sequence > 1 {
			if !wait(ctx, SampleInterval) {
				appendRemaining(&result, sequence, "canceled")
				break
			}
		}
		sampleCtx, cancel := context.WithTimeout(ctx, SampleTimeout)
		started := time.Now()
		result.Attempted++
		err := roundTrip(sampleCtx, sequence)
		duration := time.Since(started).Nanoseconds()
		cancel()
		if err == nil {
			result.Samples = append(result.Samples, Sample{Sequence: sequence, Status: "success", RTTNS: &duration})
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			result.Samples = append(result.Samples, Sample{Sequence: sequence, Status: "timeout"})
			continue
		}
		status := "unavailable"
		remainingStatus := "skipped"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = "canceled"
			remainingStatus = "canceled"
		}
		result.Samples = append(result.Samples, Sample{Sequence: sequence, Status: status})
		appendRemaining(&result, sequence+1, remainingStatus)
		break
	}
	return Calculate(result)
}

func Peer(ctx context.Context, channel Channel, count int) Result {
	return Measure(ctx, count, func(sampleCtx context.Context, sequence int) error {
		payload := [32]byte{}
		if _, err := rand.Read(payload[:]); err != nil {
			return errors.New("generate ping payload")
		}
		if err := channel.Send(sampleCtx, direct.Message{Data: encode(typePing, sequence, payload)}); err != nil {
			return err
		}
		message, err := channel.Receive(sampleCtx)
		if err != nil {
			return err
		}
		messageType, receivedSequence, receivedPayload, err := decode(message)
		if err != nil || messageType != typePong || receivedSequence != sequence || receivedPayload != payload {
			return errors.New("invalid ping response")
		}
		return nil
	})
}

func Serve(ctx context.Context, channel Channel) error {
	ctx, cancel := context.WithTimeout(ctx, InboundLifetime)
	defer cancel()
	for expected := 1; expected <= MaxCount; expected++ {
		sampleCtx, sampleCancel := context.WithTimeout(ctx, InboundIdle)
		message, err := channel.Receive(sampleCtx)
		if err != nil {
			sampleCancel()
			return err
		}
		messageType, sequence, payload, err := decode(message)
		if err != nil || messageType != typePing || sequence != expected {
			sampleCancel()
			return errors.New("invalid ping request")
		}
		err = channel.Send(sampleCtx, direct.Message{Data: encode(typePong, sequence, payload)})
		sampleCancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func Calculate(result Result) Result {
	result.Succeeded = 0
	result.LossBasisPoints = 0
	result.MinRTTNS = nil
	result.AvgRTTNS = nil
	result.MaxRTTNS = nil
	result.JitterNS = nil
	var total, jitter int64
	var previous *int64
	for _, sample := range result.Samples {
		if sample.Status != "success" || sample.RTTNS == nil {
			continue
		}
		value := *sample.RTTNS
		if result.Succeeded == 0 || value < *result.MinRTTNS {
			result.MinRTTNS = int64Pointer(value)
		}
		if result.Succeeded == 0 || value > *result.MaxRTTNS {
			result.MaxRTTNS = int64Pointer(value)
		}
		if previous != nil {
			difference := value - *previous
			if difference < 0 {
				difference = -difference
			}
			jitter += difference
		}
		previous = int64Pointer(value)
		total += value
		result.Succeeded++
	}
	result.Lost = result.Attempted - result.Succeeded
	if result.Attempted > 0 {
		result.LossBasisPoints = result.Lost * 10000 / result.Attempted
	}
	if result.Succeeded > 0 {
		result.AvgRTTNS = int64Pointer(total / int64(result.Succeeded))
	}
	if result.Succeeded > 1 {
		result.JitterNS = int64Pointer(jitter / int64(result.Succeeded-1))
	}
	return result
}

func ValidateCount(count int) error {
	if count < 1 || count > MaxCount {
		return fmt.Errorf("count must be between 1 and %d", MaxCount)
	}
	return nil
}

func encode(messageType byte, sequence int, payload [32]byte) []byte {
	data := make([]byte, frameSize)
	data[0], data[1] = frameVersion, messageType
	binary.BigEndian.PutUint32(data[2:6], uint32(sequence))
	copy(data[6:], payload[:])
	return data
}

func decode(message direct.Message) (byte, int, [32]byte, error) {
	payload := [32]byte{}
	if message.Text || len(message.Data) != frameSize || message.Data[0] != frameVersion || message.Data[1] != typePing && message.Data[1] != typePong {
		return 0, 0, payload, errors.New("invalid ping frame")
	}
	sequence := binary.BigEndian.Uint32(message.Data[2:6])
	if sequence == 0 || sequence > MaxCount {
		return 0, 0, payload, errors.New("invalid ping sequence")
	}
	copy(payload[:], message.Data[6:])
	return message.Data[1], int(sequence), payload, nil
}

func appendRemaining(result *Result, sequence int, status string) {
	for ; sequence <= result.Requested; sequence++ {
		result.Samples = append(result.Samples, Sample{Sequence: sequence, Status: status})
	}
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func int64Pointer(value int64) *int64 { return &value }
