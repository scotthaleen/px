package rendezvousapi

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/scotthaleen/go-app"
	"github.com/scotthaleen/px/internal/membership"
)

const clientQueueSize = 32

const maxOnlineSessions = 256

type Hub struct {
	mu       sync.Mutex
	clients  map[string]*client
	closed   bool
	counters processCounters
}

type processCounters struct {
	enrollmentRejected        atomic.Uint64
	authenticationFailed      atomic.Uint64
	signalingRejected         atomic.Uint64
	queueOverflow             atomic.Uint64
	authenticatedConnected    atomic.Uint64
	authenticatedDisconnected atomic.Uint64
}

type OperationalSnapshot struct {
	AuthenticatedConnections uint64
	Queue                    QueueSnapshot
	Counters                 CounterSnapshot
}

type QueueSnapshot struct {
	Queued            uint64 `json:"queued"`
	Capacity          uint64 `json:"capacity"`
	MaxDepth          uint64 `json:"max_depth"`
	PerClientCapacity uint64 `json:"per_client_capacity"`
}

type CounterSnapshot struct {
	EnrollmentRejected        uint64 `json:"enrollment_rejected"`
	AuthenticationFailed      uint64 `json:"authentication_failed"`
	SignalingRejected         uint64 `json:"signaling_rejected"`
	QueueOverflow             uint64 `json:"queue_overflow"`
	AuthenticatedConnected    uint64 `json:"authenticated_connected"`
	AuthenticatedDisconnected uint64 `json:"authenticated_disconnected"`
}

type client struct {
	member membership.Member
	send   chan outbound
	cancel func()
}

type outbound struct {
	data       []byte
	closeAfter bool
}

func NewHub() *Hub {
	return &Hub{clients: make(map[string]*client)}
}

func (h *Hub) Component() *app.Component {
	return app.NewComponent(
		app.WithName("rendezvous presence"),
		app.WithOnStop(func(context.Context) error {
			h.Close()
			return nil
		}),
	)
}

func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	clients := make([]*client, 0, len(h.clients))
	for _, value := range h.clients {
		clients = append(clients, value)
	}
	h.mu.Unlock()
	for _, value := range clients {
		value.cancel()
	}
}

func (h *Hub) register(value *client) ([]membership.Member, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("rendezvous presence is shutting down")
	}
	if len(h.clients) >= maxOnlineSessions {
		return nil, errors.New("online session capacity reached")
	}
	if _, exists := h.clients[value.member.DeviceID]; exists {
		return nil, errors.New("device already has an online session")
	}
	peers := make([]membership.Member, 0, len(h.clients))
	for _, peer := range h.clients {
		peers = append(peers, peer.member)
	}
	slices.SortFunc(peers, compareMembers)
	h.clients[value.member.DeviceID] = value
	incrementSaturating(&h.counters.authenticatedConnected)
	h.broadcastLocked(value.member.DeviceID, wireMessage{Version: Version, Type: "presence.joined", Member: &value.member})
	return peers, nil
}

func compareMembers(a, b membership.Member) int {
	if value := strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)); value != 0 {
		return value
	}
	return strings.Compare(a.DeviceID, b.DeviceID)
}

func (h *Hub) unregister(value *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[value.member.DeviceID] != value {
		return
	}
	delete(h.clients, value.member.DeviceID)
	incrementSaturating(&h.counters.authenticatedDisconnected)
	h.broadcastLocked(value.member.DeviceID, wireMessage{Version: Version, Type: "presence.left", DeviceID: value.member.DeviceID})
}

func (h *Hub) forward(from, to string, payload json.RawMessage) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	target := h.clients[to]
	if target == nil {
		incrementSaturating(&h.counters.signalingRejected)
		return errors.New("signaling target is not online")
	}
	err := h.enqueue(target, wireMessage{Version: Version, Type: "signal", From: from, Payload: payload}, false)
	if err != nil {
		incrementSaturating(&h.counters.signalingRejected)
	}
	return err
}

func (h *Hub) Revoke(deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	target := h.clients[deviceID]
	if target == nil {
		return
	}
	_ = h.enqueue(target, wireMessage{Version: Version, Type: "revoked", DeviceID: deviceID}, true)
}

func (h *Hub) broadcastLocked(except string, message wireMessage) {
	for deviceID, target := range h.clients {
		if deviceID != except {
			_ = h.enqueue(target, message, false)
		}
	}
}

func (h *Hub) enqueue(target *client, message any, closeAfter bool) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > MaxControlBytes {
		return errors.New("control response exceeds bounds")
	}
	select {
	case target.send <- outbound{data: data, closeAfter: closeAfter}:
		return nil
	default:
		incrementSaturating(&h.counters.queueOverflow)
		target.cancel()
		return errors.New("client event queue is full")
	}
}

func (h *Hub) EnrollmentRejected() {
	incrementSaturating(&h.counters.enrollmentRejected)
}

func (h *Hub) AuthenticationFailed() {
	incrementSaturating(&h.counters.authenticationFailed)
}

func (h *Hub) SignalingRejected() {
	incrementSaturating(&h.counters.signalingRejected)
}

func incrementSaturating(counter *atomic.Uint64) {
	for {
		current := counter.Load()
		if current == ^uint64(0) || counter.CompareAndSwap(current, current+1) {
			return
		}
	}
}

func (h *Hub) Snapshot() OperationalSnapshot {
	h.mu.Lock()
	connections := uint64(len(h.clients))
	queue := QueueSnapshot{Capacity: connections * clientQueueSize, PerClientCapacity: clientQueueSize}
	for _, value := range h.clients {
		depth := uint64(len(value.send))
		queue.Queued += depth
		queue.MaxDepth = max(queue.MaxDepth, depth)
	}
	snapshot := OperationalSnapshot{
		AuthenticatedConnections: connections,
		Queue:                    queue,
		Counters: CounterSnapshot{
			EnrollmentRejected:        h.counters.enrollmentRejected.Load(),
			AuthenticationFailed:      h.counters.authenticationFailed.Load(),
			SignalingRejected:         h.counters.signalingRejected.Load(),
			QueueOverflow:             h.counters.queueOverflow.Load(),
			AuthenticatedConnected:    h.counters.authenticatedConnected.Load(),
			AuthenticatedDisconnected: h.counters.authenticatedDisconnected.Load(),
		},
	}
	h.mu.Unlock()
	return snapshot
}
