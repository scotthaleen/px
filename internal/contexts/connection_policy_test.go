package contexts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestConnectionPolicyBoundsAndBackoff(t *testing.T) {
	policy := defaultConnectionPolicy()
	for _, sample := range []uint64{0, 1, ^uint64(0)} {
		policy.random = func() uint64 { return sample }
		keepalive := policy.nextKeepalive()
		if keepalive < 27*time.Second || keepalive > 33*time.Second {
			t.Fatalf("keepalive = %s", keepalive)
		}
		previous := time.Duration(0)
		for failures := 1; failures <= 20; failures++ {
			delay := policy.reconnectDelay(failures)
			if delay < 500*time.Millisecond || delay > 30*time.Second {
				t.Fatalf("failure %d delay = %s", failures, delay)
			}
			if failures <= 5 && delay < previous {
				t.Fatalf("backoff decreased at failure %d: %s -> %s", failures, previous, delay)
			}
			previous = delay
		}
	}
}

func TestKeepaliveReceivesPong(t *testing.T) {
	client, stop := websocketTestPair(t, true)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _, _ = client.Read(ctx)
	}()
	policy := defaultConnectionPolicy()
	policy.keepaliveInterval = time.Millisecond
	policy.keepaliveJitter = 0
	policy.pongTimeout = 100 * time.Millisecond
	resultDone := make(chan keepaliveResult, 1)
	go func() { resultDone <- runKeepalive(ctx, client, &contextWriteGate{}, policy) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	result := <-resultDone
	<-readDone
	if result.err != nil || !result.healthy {
		t.Fatalf("keepalive = %+v", result)
	}
}

func TestKeepaliveTimesOutWithoutReaderAtPeer(t *testing.T) {
	client, stop := websocketTestPair(t, false)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _, _, _ = client.Read(ctx) }()
	policy := defaultConnectionPolicy()
	policy.keepaliveInterval = time.Millisecond
	policy.keepaliveJitter = 0
	policy.pongTimeout = 10 * time.Millisecond
	result := runKeepalive(ctx, client, &contextWriteGate{}, policy)
	if result.err == nil || result.healthy {
		t.Fatalf("keepalive = %+v", result)
	}
}

func websocketTestPair(t *testing.T, read bool) (*websocket.Conn, func()) {
	t.Helper()
	serverConnection := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		serverConnection <- conn
		if read {
			for {
				if _, _, err := conn.Read(r.Context()); err != nil {
					return
				}
			}
		}
		<-r.Context().Done()
	}))
	client, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	peer := <-serverConnection
	return client, func() {
		_ = client.CloseNow()
		_ = peer.CloseNow()
		server.Close()
	}
}
