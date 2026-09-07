package contextwatch

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/scotthaleen/go-toolbelt/strictjson"
	"github.com/scotthaleen/px/internal/membership"
)

const (
	Version            = 1
	MaxSubscribers     = 64
	OrdinaryQueueDepth = 32
	MaxPeers           = membership.MaxMembers - 1
)

const (
	ContextConnected    = "context.connected"
	ContextDisconnected = "context.disconnected"
	PeerOnline          = "peer.online"
	PeerOffline         = "peer.offline"
	StreamGap           = "stream.gap"
)

var (
	ErrSubscriberCapacity = errors.New("context watch subscriber capacity reached")
	ErrHubClosed          = errors.New("context watch hub is closed")
	ErrInvalidProjection  = errors.New("invalid authoritative context watch projection")
)

type Peer struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
}

type Event struct {
	Version              int       `json:"version"`
	StreamID             string    `json:"stream_id"`
	Sequence             uint64    `json:"sequence"`
	ObservedAt           time.Time `json:"observed_at"`
	Context              string    `json:"context"`
	Type                 string    `json:"type"`
	Snapshot             bool      `json:"snapshot,omitempty"`
	Peers                []Peer    `json:"peers,omitempty"`
	Peer                 *Peer     `json:"peer,omitempty"`
	FirstDroppedSequence uint64    `json:"first_dropped_sequence,omitempty"`
	ResyncRequired       bool      `json:"resync_required,omitempty"`
}

func (e Event) MarshalJSON() ([]byte, error) {
	type common struct {
		Version    int       `json:"version"`
		StreamID   string    `json:"stream_id"`
		Sequence   uint64    `json:"sequence"`
		ObservedAt time.Time `json:"observed_at"`
		Context    string    `json:"context"`
		Type       string    `json:"type"`
	}
	base := common{Version: e.Version, StreamID: e.StreamID, Sequence: e.Sequence, ObservedAt: e.ObservedAt, Context: e.Context, Type: e.Type}
	switch e.Type {
	case ContextConnected:
		return json.Marshal(struct {
			common
			Snapshot bool   `json:"snapshot,omitempty"`
			Peers    []Peer `json:"peers"`
		}{base, e.Snapshot, e.Peers})
	case ContextDisconnected:
		return json.Marshal(struct {
			common
			Snapshot bool `json:"snapshot,omitempty"`
		}{base, e.Snapshot})
	case PeerOnline, PeerOffline:
		return json.Marshal(struct {
			common
			Peer *Peer `json:"peer"`
		}{base, e.Peer})
	case StreamGap:
		return json.Marshal(struct {
			common
			FirstDroppedSequence uint64 `json:"first_dropped_sequence"`
			ResyncRequired       bool   `json:"resync_required"`
		}{base, e.FirstDroppedSequence, e.ResyncRequired})
	default:
		return nil, errors.New("invalid context watch event type")
	}
}

func DecodeStrict(data []byte) (Event, error) {
	var event Event
	if err := strictjson.Decode(data, &event, strictjson.DisallowUnknownFields()); err != nil {
		return Event{}, errors.New("invalid context watch event fields")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || !validFields(event, fields) {
		return Event{}, errors.New("invalid context watch event fields")
	}
	if err := Validate(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func validFields(event Event, fields map[string]json.RawMessage) bool {
	allowed := map[string]struct{}{
		"version": {}, "stream_id": {}, "sequence": {}, "observed_at": {}, "context": {}, "type": {},
	}
	required := []string{"version", "stream_id", "sequence", "observed_at", "context", "type"}
	switch event.Type {
	case ContextConnected:
		allowed["snapshot"], allowed["peers"] = struct{}{}, struct{}{}
		required = append(required, "peers")
	case ContextDisconnected:
		allowed["snapshot"] = struct{}{}
	case PeerOnline, PeerOffline:
		allowed["peer"] = struct{}{}
		required = append(required, "peer")
	case StreamGap:
		allowed["first_dropped_sequence"], allowed["resync_required"] = struct{}{}, struct{}{}
		required = append(required, "first_dropped_sequence", "resync_required")
	default:
		return false
	}
	for field := range fields {
		if _, ok := allowed[field]; !ok {
			return false
		}
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return false
		}
	}
	if _, present := fields["snapshot"]; present && !event.Snapshot {
		return false
	}
	return true
}

func Validate(event Event) error {
	if event.Version != Version || !validStreamID(event.StreamID) || event.Sequence == 0 || event.ObservedAt.IsZero() || event.ObservedAt.Location() != time.UTC || membership.ValidateLabel(event.Context) != nil {
		return errors.New("invalid context watch event envelope")
	}
	switch event.Type {
	case ContextConnected:
		if event.Peer != nil || event.FirstDroppedSequence != 0 || event.ResyncRequired || event.Peers == nil || len(event.Peers) > MaxPeers || !validSortedPeers(event.Peers) {
			return errors.New("invalid context connected event")
		}
	case ContextDisconnected:
		if event.Peer != nil || event.Peers != nil || event.FirstDroppedSequence != 0 || event.ResyncRequired {
			return errors.New("invalid context disconnected event")
		}
	case PeerOnline, PeerOffline:
		if event.Snapshot || event.Peer == nil || !validPeer(*event.Peer) || event.Peers != nil || event.FirstDroppedSequence != 0 || event.ResyncRequired {
			return errors.New("invalid context peer event")
		}
	case StreamGap:
		if event.Snapshot || event.Peer != nil || event.Peers != nil || event.FirstDroppedSequence == 0 || !event.ResyncRequired {
			return errors.New("invalid context watch gap")
		}
	default:
		return errors.New("invalid context watch event type")
	}
	return nil
}

func validStreamID(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 16
}

func validPeer(peer Peer) bool {
	data, err := base64.RawURLEncoding.DecodeString(peer.DeviceID)
	return err == nil && len(data) == 32 && membership.ValidateLabel(peer.Label) == nil
}

func validSortedPeers(peers []Peer) bool {
	if !validUniquePeers(peers) {
		return false
	}
	return slices.IsSortedFunc(peers, comparePeer)
}

func validUniquePeers(peers []Peer) bool {
	seenIDs := make(map[string]struct{}, len(peers))
	seenLabels := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		if !validPeer(peer) {
			return false
		}
		label := strings.ToLower(peer.Label)
		if _, exists := seenIDs[peer.DeviceID]; exists {
			return false
		}
		if _, exists := seenLabels[label]; exists {
			return false
		}
		seenIDs[peer.DeviceID] = struct{}{}
		seenLabels[label] = struct{}{}
	}
	return true
}

type projection struct {
	connected bool
	peers     map[string]Peer
}

type subscriber struct {
	streamID string
	context  string
	events   chan Event
}

type Subscription struct {
	Events      <-chan Event
	unsubscribe func()
	once        sync.Once
}

func (s *Subscription) Close() {
	if s != nil {
		s.once.Do(s.unsubscribe)
	}
}

type Hub struct {
	mu          sync.Mutex
	sequence    uint64
	closed      bool
	contexts    map[string]projection
	subscribers map[*subscriber]struct{}
	now         func() time.Time
}

func NewHub() *Hub {
	return &Hub{contexts: make(map[string]projection), subscribers: make(map[*subscriber]struct{}), now: func() time.Time { return time.Now().UTC() }}
}

func (h *Hub) Subscribe(contextName string) (*Subscription, error) {
	if membership.ValidateLabel(contextName) != nil {
		return nil, errors.New("invalid context watch context")
	}
	streamID, err := newStreamID()
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrHubClosed
	}
	if len(h.subscribers) >= MaxSubscribers {
		return nil, ErrSubscriberCapacity
	}
	sub := &subscriber{streamID: streamID, context: contextName, events: make(chan Event, OrdinaryQueueDepth+1)}
	h.subscribers[sub] = struct{}{}
	state := h.contexts[contextName]
	eventType := ContextDisconnected
	var peers []Peer
	if state.connected {
		eventType = ContextConnected
		peers = sortedProjection(state.peers)
	}
	event := h.nextLocked(contextName, eventType)
	event.StreamID, event.Snapshot, event.Peers = streamID, true, peers
	sub.events <- event
	return &Subscription{Events: sub.events, unsubscribe: func() { h.unsubscribe(sub) }}, nil
}

func (h *Hub) Connect(contextName string, baseline []Peer) error {
	if membership.ValidateLabel(contextName) != nil || len(baseline) > MaxPeers || !validUniquePeers(baseline) {
		return ErrInvalidProjection
	}
	peers := make(map[string]Peer, len(baseline))
	for _, peer := range baseline {
		peers[strings.ToLower(peer.Label)] = peer
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return ErrHubClosed
	}
	h.contexts[contextName] = projection{connected: true, peers: peers}
	event := h.nextLocked(contextName, ContextConnected)
	event.Peers = sortedProjection(peers)
	h.publishLocked(event)
	return nil
}

func (h *Hub) Disconnect(contextName string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || !h.contexts[contextName].connected {
		return
	}
	h.contexts[contextName] = projection{peers: make(map[string]Peer)}
	h.publishLocked(h.nextLocked(contextName, ContextDisconnected))
}

func (h *Hub) Join(contextName string, peer Peer) error {
	if membership.ValidateLabel(contextName) != nil || !validPeer(peer) {
		return ErrInvalidProjection
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.contexts[contextName]
	if h.closed || !state.connected {
		return ErrInvalidProjection
	}
	key := strings.ToLower(peer.Label)
	for label, existing := range state.peers {
		if existing.DeviceID == peer.DeviceID && label != key {
			return ErrInvalidProjection
		}
	}
	if previous, exists := state.peers[key]; exists {
		if previous.DeviceID == peer.DeviceID {
			return nil
		}
		h.publishPeerLocked(contextName, PeerOffline, previous)
	} else if len(state.peers) >= MaxPeers {
		return ErrInvalidProjection
	}
	state.peers[key] = peer
	h.contexts[contextName] = state
	h.publishPeerLocked(contextName, PeerOnline, peer)
	return nil
}

func (h *Hub) Leave(contextName, deviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.contexts[contextName]
	if h.closed || !state.connected {
		return
	}
	for label, peer := range state.peers {
		if peer.DeviceID == deviceID {
			delete(state.peers, label)
			h.contexts[contextName] = state
			h.publishPeerLocked(contextName, PeerOffline, peer)
			return
		}
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for sub := range h.subscribers {
		delete(h.subscribers, sub)
		close(sub.events)
	}
}

func (h *Hub) publishPeerLocked(contextName, eventType string, peer Peer) {
	event := h.nextLocked(contextName, eventType)
	event.Peer = &Peer{DeviceID: peer.DeviceID, Label: peer.Label}
	h.publishLocked(event)
}

func (h *Hub) nextLocked(contextName, eventType string) Event {
	h.sequence++
	return Event{Version: Version, Sequence: h.sequence, ObservedAt: h.now().UTC(), Context: contextName, Type: eventType}
}

func (h *Hub) publishLocked(event Event) {
	for sub := range h.subscribers {
		if sub.context != event.Context {
			continue
		}
		value := event
		value.StreamID = sub.streamID
		if len(sub.events) < OrdinaryQueueDepth {
			sub.events <- value
			continue
		}
		delete(h.subscribers, sub)
		gap := Event{Version: Version, StreamID: sub.streamID, Sequence: event.Sequence, ObservedAt: event.ObservedAt, Context: event.Context, Type: StreamGap, FirstDroppedSequence: event.Sequence, ResyncRequired: true}
		sub.events <- gap
		close(sub.events)
	}
}

func (h *Hub) unsubscribe(sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.subscribers[sub]; !exists {
		return
	}
	delete(h.subscribers, sub)
	close(sub.events)
}

func sortedProjection(values map[string]Peer) []Peer {
	result := make([]Peer, 0, len(values))
	for _, peer := range values {
		result = append(result, peer)
	}
	slices.SortFunc(result, comparePeer)
	if result == nil {
		return []Peer{}
	}
	return result
}

func comparePeer(a, b Peer) int {
	if value := strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)); value != 0 {
		return value
	}
	if value := strings.Compare(a.Label, b.Label); value != 0 {
		return value
	}
	return strings.Compare(a.DeviceID, b.DeviceID)
}

func newStreamID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func Wait(ctx context.Context, subscription *Subscription) (Event, error) {
	select {
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case event, ok := <-subscription.Events:
		if !ok {
			return Event{}, io.EOF
		}
		return event, nil
	}
}
