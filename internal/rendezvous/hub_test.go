package rendezvous

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/signalproto"
)

func TestHubForwardsQueuedMessage(t *testing.T) {
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(Config{}).Handler())
	t.Cleanup(server.Close)
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/signal"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connA := dial(t, ctx, endpoint, "probe", identity.ID(publicA))
	defer connA.CloseNow()

	message, err := signalproto.Sign(privateA, "probe", identity.ID(publicB), signalproto.KindCandidate, map[string]string{"candidate": "host"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := connA.Write(ctx, websocket.MessageText, message); err != nil {
		t.Fatal(err)
	}

	connB := dial(t, ctx, endpoint, "probe", identity.ID(publicB))
	defer connB.CloseNow()
	_, received, err := connB.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(received) != string(message) {
		t.Fatal("forwarded message differs")
	}
}

func TestExpiredPendingSessionReleasesCapacity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	hub := New(Config{MaxSessions: 1})
	hub.pendingLifetime = time.Minute
	hub.now = func() time.Time { return now }
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerA := &participant{device: identity.ID(publicA), send: make(chan []byte, 1)}
	if _, err := hub.register("stale", peerA); err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"session":"stale","from":"` + peerA.device + `","to":"` + identity.ID(publicB) + `"}`)
	if err := hub.forward("stale", peerA.device, message); err != nil {
		t.Fatal(err)
	}
	hub.unregister("stale", peerA)
	if _, err := hub.register("fresh", &participant{device: peerA.device}); err == nil || err.Error() != "session capacity reached" {
		t.Fatalf("capacity before expiry = %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := hub.register("fresh", &participant{device: peerA.device}); err != nil {
		t.Fatalf("capacity after expiry = %v", err)
	}
	if _, exists := hub.sessions["stale"]; exists {
		t.Fatal("expired peerless session remains")
	}
}

func TestPendingLifetimeDoesNotSlide(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	hub := New(Config{})
	hub.pendingLifetime = time.Minute
	hub.now = func() time.Time { return now }
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerA := &participant{device: identity.ID(publicA), send: make(chan []byte, 1)}
	if _, err := hub.register("probe", peerA); err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"session":"probe","from":"` + peerA.device + `","to":"` + identity.ID(publicB) + `"}`)
	if err := hub.forward("probe", peerA.device, message); err != nil {
		t.Fatal(err)
	}
	expires := hub.sessions["probe"].expires
	now = now.Add(30 * time.Second)
	if err := hub.forward("probe", peerA.device, message); err != nil {
		t.Fatal(err)
	}
	if !hub.sessions["probe"].expires.Equal(expires) {
		t.Fatal("additional pending message extended session lifetime")
	}
	hub.unregister("probe", peerA)
	now = expires
	queued, err := hub.register("probe", &participant{device: identity.ID(publicB)})
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 0 {
		t.Fatalf("expired messages delivered: %d", len(queued))
	}
}

func dial(t *testing.T, ctx context.Context, endpoint, session, device string) *websocket.Conn {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("session", session)
	query.Set("device", device)
	parsed.RawQuery = query.Encode()
	conn, _, err := websocket.Dial(ctx, parsed.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
