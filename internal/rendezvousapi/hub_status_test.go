package rendezvousapi

import (
	"encoding/json"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/scotthaleen/px/internal/membership"
)

func TestHubSnapshotTracksQueuePressureAndProcessCounters(t *testing.T) {
	hub := NewHub()
	value := &client{member: membership.Member{DeviceID: "device", Label: "device"}, send: make(chan outbound, clientQueueSize), cancel: func() {}}
	if _, err := hub.register(value); err != nil {
		t.Fatal(err)
	}
	for range clientQueueSize {
		if err := hub.enqueue(value, wireMessage{Type: "presence.left", DeviceID: "peer"}, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := hub.forward("peer", "device", json.RawMessage(`{"candidate":"bounded"}`)); err == nil {
		t.Fatal("signal into full queue succeeded")
	}
	hub.EnrollmentRejected()
	hub.AuthenticationFailed()

	snapshot := hub.Snapshot()
	if snapshot.AuthenticatedConnections != 1 || snapshot.Queue.Queued != clientQueueSize || snapshot.Queue.Capacity != clientQueueSize || snapshot.Queue.MaxDepth != clientQueueSize || snapshot.Queue.PerClientCapacity != clientQueueSize {
		t.Fatalf("queue snapshot = %+v", snapshot)
	}
	if snapshot.Counters.EnrollmentRejected != 1 || snapshot.Counters.AuthenticationFailed != 1 || snapshot.Counters.SignalingRejected != 1 || snapshot.Counters.QueueOverflow != 1 || snapshot.Counters.AuthenticatedConnected != 1 || snapshot.Counters.AuthenticatedDisconnected != 0 {
		t.Fatalf("counter snapshot = %+v", snapshot.Counters)
	}
	hub.unregister(value)
	snapshot = hub.Snapshot()
	if snapshot.AuthenticatedConnections != 0 || snapshot.Counters.AuthenticatedDisconnected != 1 {
		t.Fatalf("disconnected snapshot = %+v", snapshot)
	}
}

func TestProcessCountersSaturateUnderConcurrency(t *testing.T) {
	hub := NewHub()
	counters := []struct {
		name    string
		counter *atomic.Uint64
	}{
		{"enrollment rejected", &hub.counters.enrollmentRejected},
		{"authentication failed", &hub.counters.authenticationFailed},
		{"signaling rejected", &hub.counters.signalingRejected},
		{"queue overflow", &hub.counters.queueOverflow},
		{"authenticated connected", &hub.counters.authenticatedConnected},
		{"authenticated disconnected", &hub.counters.authenticatedDisconnected},
	}
	for _, item := range counters {
		t.Run(item.name, func(t *testing.T) {
			item.counter.Store(math.MaxUint64 - 10)
			var wait sync.WaitGroup
			for range 100 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					incrementSaturating(item.counter)
				}()
			}
			wait.Wait()
			if got := item.counter.Load(); got != math.MaxUint64 {
				t.Fatalf("counter = %d, want saturation", got)
			}
			incrementSaturating(item.counter)
			if got := item.counter.Load(); got != math.MaxUint64 {
				t.Fatalf("saturated counter wrapped to %d", got)
			}
		})
	}
}
