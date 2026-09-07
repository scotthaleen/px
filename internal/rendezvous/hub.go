package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/signalproto"
)

const (
	defaultMaxSessions = 128
	defaultQueueSize   = 32
	defaultPendingTTL  = 5 * time.Minute
)

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Config struct {
	MaxSessions int
	QueueSize   int
}

type Hub struct {
	mu              sync.Mutex
	cfg             Config
	sessions        map[string]*session
	pendingLifetime time.Duration
	now             func() time.Time
}

type session struct {
	peers   map[string]*participant
	pending []pendingMessage
	expires time.Time
}

type participant struct {
	device string
	send   chan []byte
}

type pendingMessage struct {
	to   string
	data []byte
}

type route struct {
	Session string `json:"session"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func New(cfg Config) *Hub {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	return &Hub{cfg: cfg, sessions: make(map[string]*session), pendingLifetime: defaultPendingTTL, now: time.Now}
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /signal", h.serveSignal)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (h *Hub) serveSignal(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	deviceID := r.URL.Query().Get("device")
	if !sessionPattern.MatchString(sessionID) {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	if _, err := identity.ParseID(deviceID); err != nil {
		http.Error(w, "invalid device", http.StatusBadRequest)
		return
	}

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(signalproto.MaxEnvelopeBytes)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer conn.CloseNow()

	peer := &participant{device: deviceID, send: make(chan []byte, h.cfg.QueueSize)}
	queued, err := h.register(sessionID, peer)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.unregister(sessionID, peer)
	for _, message := range queued {
		peer.send <- message
	}

	writerDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				writerDone <- ctx.Err()
				return
			case message := <-peer.send:
				if err := conn.Write(ctx, websocket.MessageText, message); err != nil {
					writerDone <- err
					cancel()
					return
				}
			}
		}
	}()

	for {
		messageType, data, err := conn.Read(ctx)
		if err != nil {
			break
		}
		if messageType != websocket.MessageText {
			_ = conn.Close(websocket.StatusUnsupportedData, "text messages required")
			break
		}
		if err := h.forward(sessionID, deviceID, data); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
			break
		}
	}
	cancel()
	<-writerDone
}

func (h *Hub) register(sessionID string, peer *participant) ([][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpired(h.now())

	s := h.sessions[sessionID]
	if s == nil {
		if len(h.sessions) >= h.cfg.MaxSessions {
			return nil, errors.New("session capacity reached")
		}
		s = &session{peers: make(map[string]*participant)}
		h.sessions[sessionID] = s
	}
	if _, exists := s.peers[peer.device]; exists {
		return nil, errors.New("device is already connected")
	}
	if len(s.peers) >= 2 {
		return nil, errors.New("probe session already has two devices")
	}
	s.peers[peer.device] = peer

	queued := make([][]byte, 0, len(s.pending))
	remaining := s.pending[:0]
	for _, message := range s.pending {
		if message.to == peer.device {
			queued = append(queued, message.data)
		} else {
			remaining = append(remaining, message)
		}
	}
	s.pending = remaining
	if len(s.pending) == 0 {
		s.expires = time.Time{}
	}
	return queued, nil
}

func (h *Hub) pruneExpired(now time.Time) {
	for sessionID, s := range h.sessions {
		if s.expires.IsZero() || now.Before(s.expires) {
			continue
		}
		s.pending = nil
		s.expires = time.Time{}
		if len(s.peers) == 0 {
			delete(h.sessions, sessionID)
		}
	}
}

func (h *Hub) unregister(sessionID string, peer *participant) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[sessionID]
	if s == nil || s.peers[peer.device] != peer {
		return
	}
	delete(s.peers, peer.device)
	if len(s.peers) == 0 && len(s.pending) == 0 {
		delete(h.sessions, sessionID)
	}
}

func (h *Hub) forward(sessionID, deviceID string, data []byte) error {
	if len(data) > signalproto.MaxEnvelopeBytes {
		return errors.New("signaling message too large")
	}
	var target route
	if err := json.Unmarshal(data, &target); err != nil {
		return fmt.Errorf("decode signaling route: %w", err)
	}
	if target.Session != sessionID || target.From != deviceID || target.To == "" || target.To == deviceID {
		return errors.New("invalid signaling route")
	}
	if _, err := identity.ParseID(target.To); err != nil {
		return errors.New("invalid signaling recipient")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[sessionID]
	if s == nil {
		return errors.New("signaling session is not registered")
	}
	if peer := s.peers[target.To]; peer != nil {
		select {
		case peer.send <- append([]byte(nil), data...):
			return nil
		default:
			return errors.New("signaling recipient queue is full")
		}
	}
	if len(s.pending) >= h.cfg.QueueSize {
		return errors.New("pending signaling queue is full")
	}
	if len(s.pending) == 0 {
		s.expires = h.now().Add(h.pendingLifetime)
	}
	s.pending = append(s.pending, pendingMessage{to: target.To, data: append([]byte(nil), data...)})
	return nil
}
