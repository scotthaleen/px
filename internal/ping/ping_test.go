package ping

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/scotthaleen/px/internal/direct"
)

func TestCalculateVectors(t *testing.T) {
	values := []int64{10, 20, 15}
	result := Result{Requested: 5, Attempted: 5, Samples: []Sample{
		{Sequence: 1, Status: "success", RTTNS: &values[0]},
		{Sequence: 2, Status: "timeout"},
		{Sequence: 3, Status: "success", RTTNS: &values[1]},
		{Sequence: 4, Status: "success", RTTNS: &values[2]},
		{Sequence: 5, Status: "timeout"},
	}}
	result = Calculate(result)
	if result.Succeeded != 3 || result.Lost != 2 || result.LossBasisPoints != 4000 || *result.MinRTTNS != 10 || *result.AvgRTTNS != 15 || *result.MaxRTTNS != 20 || *result.JitterNS != 7 {
		t.Fatalf("result = %+v", result)
	}
	allLost := Calculate(Result{Requested: 2, Attempted: 2, Samples: []Sample{{Sequence: 1, Status: "timeout"}, {Sequence: 2, Status: "timeout"}}})
	if allLost.MinRTTNS != nil || allLost.AvgRTTNS != nil || allLost.MaxRTTNS != nil || allLost.JitterNS != nil || allLost.LossBasisPoints != 10000 {
		t.Fatalf("all lost = %+v", allLost)
	}
}

func TestFrameStrictness(t *testing.T) {
	payload := [32]byte{1}
	valid := direct.Message{Data: encode(typePing, 1, payload)}
	if _, _, _, err := decode(valid); err != nil {
		t.Fatal(err)
	}
	for _, message := range []direct.Message{
		{Text: true, Data: valid.Data},
		{Data: append(valid.Data, 0)},
		{Data: valid.Data[:len(valid.Data)-1]},
		{Data: append([]byte{2}, valid.Data[1:]...)},
		{Data: append([]byte{1, 9}, valid.Data[2:]...)},
	} {
		if _, _, _, err := decode(message); err == nil {
			t.Fatalf("accepted malformed frame: %v", message)
		}
	}
}

func TestMeasureStopsAfterUnusableSample(t *testing.T) {
	result := Measure(context.Background(), 4, func(context.Context, int) error { return errors.New("closed") })
	if result.Requested != 4 || result.Attempted != 1 || result.Succeeded != 0 || result.Lost != 1 || len(result.Samples) != 4 || result.Samples[1].Status != "skipped" {
		t.Fatalf("result = %+v", result)
	}
}

func TestMeasurePartialAndAllLoss(t *testing.T) {
	partial := Measure(context.Background(), 3, func(_ context.Context, sequence int) error {
		if sequence == 2 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if partial.Succeeded != 2 || partial.Lost != 1 || partial.LossBasisPoints != 3333 {
		t.Fatalf("partial = %+v", partial)
	}
	all := Measure(context.Background(), 2, func(context.Context, int) error { return context.DeadlineExceeded })
	if all.Succeeded != 0 || all.Lost != 2 || all.MinRTTNS != nil || all.JitterNS != nil {
		t.Fatalf("all = %+v", all)
	}
}

func TestMeasureCancellationStopsRemainingAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	result := Measure(ctx, 3, func(context.Context, int) error {
		cancel()
		return context.Canceled
	})
	if result.Requested != 3 || result.Attempted != 1 || result.Lost != 1 || len(result.Samples) != 3 || result.Samples[0].Status != "canceled" || result.Samples[2].Status != "canceled" {
		t.Fatalf("result = %+v", result)
	}
}

func TestMeasureCanceledBeforeFirstAttemptHasZeroLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	result := Measure(ctx, 2, func(context.Context, int) error {
		called = true
		return nil
	})
	if called || result.Attempted != 0 || result.Succeeded != 0 || result.Lost != 0 || result.LossBasisPoints != 0 || result.Samples[0].Status != "canceled" {
		t.Fatalf("result = %+v, called=%t", result, called)
	}
}

type loopChannel struct {
	mu       sync.Mutex
	response func(direct.Message) direct.Message
	next     direct.Message
}

type duplicateChannel struct {
	first direct.Message
	next  direct.Message
}

func (c *duplicateChannel) Send(_ context.Context, message direct.Message) error {
	message.Data[1] = typePong
	if c.first.Data == nil {
		c.first = message
		c.next = message
	} else {
		c.next = c.first
	}
	return nil
}

func (c *duplicateChannel) Receive(context.Context) (direct.Message, error) { return c.next, nil }

func (c *loopChannel) Send(_ context.Context, message direct.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next = c.response(message)
	return nil
}

func (c *loopChannel) Receive(context.Context) (direct.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next, nil
}

func TestPeerRejectsStaleMismatchedAndOversizedResponses(t *testing.T) {
	for name, response := range map[string]func(direct.Message) direct.Message{
		"stale": func(message direct.Message) direct.Message {
			message.Data[5]++
			message.Data[1] = typePong
			return message
		},
		"mismatched payload": func(message direct.Message) direct.Message {
			message.Data[1] = typePong
			message.Data[6] ^= 1
			return message
		},
		"oversized": func(message direct.Message) direct.Message {
			message.Data[1] = typePong
			message.Data = append(message.Data, 0)
			return message
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := Peer(context.Background(), &loopChannel{response: response}, 2)
			if result.Attempted != 1 || result.Succeeded != 0 || result.Lost != 1 || result.Samples[0].Status != "unavailable" || result.Samples[1].Status != "skipped" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestPeerMatchingResponse(t *testing.T) {
	channel := &loopChannel{response: func(message direct.Message) direct.Message {
		message.Data[1] = typePong
		return message
	}}
	result := Peer(context.Background(), channel, 2)
	if result.Succeeded != 2 || result.Lost != 0 || result.JitterNS == nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestPeerRejectsDuplicatePongAsStale(t *testing.T) {
	result := Peer(context.Background(), &duplicateChannel{}, 3)
	if result.Attempted != 2 || result.Succeeded != 1 || result.Lost != 1 || result.Samples[1].Status != "unavailable" || result.Samples[2].Status != "skipped" {
		t.Fatalf("result = %+v", result)
	}
}

type serveChannel struct {
	receive []direct.Message
	sent    []direct.Message
}

func (c *serveChannel) Send(_ context.Context, message direct.Message) error {
	c.sent = append(c.sent, message)
	return nil
}

func (c *serveChannel) Receive(context.Context) (direct.Message, error) {
	if len(c.receive) == 0 {
		return direct.Message{}, errors.New("no message")
	}
	message := c.receive[0]
	c.receive = c.receive[1:]
	return message, nil
}

func pingRequest(sequence int) direct.Message {
	return direct.Message{Data: encode(typePing, sequence, [32]byte{byte(sequence)})}
}

func TestServeRequiresSequentialRequests(t *testing.T) {
	for name, messages := range map[string][]direct.Message{
		"duplicate":    {pingRequest(1), pingRequest(1)},
		"out of order": {pingRequest(2)},
	} {
		t.Run(name, func(t *testing.T) {
			channel := &serveChannel{receive: messages}
			if err := Serve(context.Background(), channel); err == nil || len(channel.sent) != len(messages)-1 {
				t.Fatalf("Serve sent=%d err=%v", len(channel.sent), err)
			}
		})
	}
}

func TestServeStopsAfterMaximumCount(t *testing.T) {
	messages := make([]direct.Message, 0, MaxCount+1)
	for sequence := 1; sequence <= MaxCount; sequence++ {
		messages = append(messages, pingRequest(sequence))
	}
	messages = append(messages, pingRequest(1))
	channel := &serveChannel{receive: messages}
	if err := Serve(context.Background(), channel); err != nil || len(channel.sent) != MaxCount || len(channel.receive) != 1 {
		t.Fatalf("Serve sent=%d remaining=%d err=%v", len(channel.sent), len(channel.receive), err)
	}
}
