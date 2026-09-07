package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/direct"
)

func TestBidirectionalBenchmark(t *testing.T) {
	initiator, responder := newPipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	served := make(chan error, 1)
	channel := &scriptedChannel{receive: responder.Receive, send: func(ctx context.Context, message direct.Message) error {
		if message.Text {
			value, err := decodeControl(message)
			if err != nil {
				return err
			}
			if value.Type == "pong" {
				// Give the measured RTT real elapsed time beyond Windows clock resolution.
				timer := time.NewTimer(20 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return responder.Send(ctx, message)
	}}
	go func() { served <- Serve(ctx, channel) }()
	result, err := Run(ctx, initiator, MinDuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if result.Version != Version || result.RTTNS <= 0 || result.Upload.Bytes <= 0 || result.Download.Bytes <= 0 || result.Upload.MiBPerSecond <= 0 || result.Download.MiBPerSecond <= 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestServeRejectsInvalidDuration(t *testing.T) {
	data, err := json.Marshal(control{Version: Version, Type: "start", DurationNS: (MinDuration - time.Millisecond).Nanoseconds()})
	if err != nil {
		t.Fatal(err)
	}
	channel := &scriptedChannel{messages: []direct.Message{{Text: true, Data: data}}}
	if err := Serve(context.Background(), channel); err == nil {
		t.Fatal("invalid duration was accepted")
	}
}

func TestDecodeControlRejectsUnknownFields(t *testing.T) {
	_, err := decodeControl(direct.Message{Text: true, Data: []byte(`{"version":1,"type":"ready","extra":true}`)})
	if err == nil {
		t.Fatal("unknown control field was accepted")
	}
}

func TestServeBoundsSilentPeer(t *testing.T) {
	oldTimeout := controlTimeout
	controlTimeout = 10 * time.Millisecond
	t.Cleanup(func() { controlTimeout = oldTimeout })
	channel := &scriptedChannel{receive: func(ctx context.Context) (direct.Message, error) {
		<-ctx.Done()
		return direct.Message{}, ctx.Err()
	}}
	started := time.Now()
	if err := Serve(context.Background(), channel); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("error=%v elapsed=%s", err, time.Since(started))
	}
}

func TestSendPayloadBoundsBlockedSend(t *testing.T) {
	channel := &scriptedChannel{send: func(ctx context.Context, _ direct.Message) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	started := time.Now()
	bytesSent, err := sendPayload(context.Background(), channel, 10*time.Millisecond)
	if err == nil || bytesSent != 0 || time.Since(started) > time.Second {
		t.Fatalf("bytes=%d error=%v elapsed=%s", bytesSent, err, time.Since(started))
	}
}

func TestSendControlBoundsBlockedSend(t *testing.T) {
	oldTimeout := controlTimeout
	controlTimeout = 10 * time.Millisecond
	t.Cleanup(func() { controlTimeout = oldTimeout })
	channel := &scriptedChannel{send: func(ctx context.Context, _ direct.Message) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	started := time.Now()
	err := sendControl(context.Background(), channel, control{Version: Version, Type: "ready"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("error=%v elapsed=%s", err, time.Since(started))
	}
}

type memoryChannel struct {
	in  <-chan direct.Message
	out chan<- direct.Message
}

func newPipe() (*memoryChannel, *memoryChannel) {
	left, right := make(chan direct.Message, MessageQueue), make(chan direct.Message, MessageQueue)
	return &memoryChannel{in: left, out: right}, &memoryChannel{in: right, out: left}
}

func (c *memoryChannel) Send(ctx context.Context, message direct.Message) error {
	data := append([]byte(nil), message.Data...)
	select {
	case c.out <- direct.Message{Text: message.Text, Data: data}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *memoryChannel) Receive(ctx context.Context) (direct.Message, error) {
	select {
	case message := <-c.in:
		return message, nil
	case <-ctx.Done():
		return direct.Message{}, ctx.Err()
	}
}

type scriptedChannel struct {
	messages []direct.Message
	send     func(context.Context, direct.Message) error
	receive  func(context.Context) (direct.Message, error)
}

func (c *scriptedChannel) Send(ctx context.Context, message direct.Message) error {
	if c.send != nil {
		return c.send(ctx, message)
	}
	return nil
}

func (c *scriptedChannel) Receive(ctx context.Context) (direct.Message, error) {
	if c.receive != nil {
		return c.receive(ctx)
	}
	if len(c.messages) == 0 {
		return direct.Message{}, errors.New("no message")
	}
	message := c.messages[0]
	c.messages = c.messages[1:]
	return message, nil
}
