package contexts

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type stalledSignalConn struct {
	net.Conn
	stall   atomic.Bool
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *stalledSignalConn) Write(data []byte) (int, error) {
	if c.stall.CompareAndSwap(true, false) {
		close(c.started)
		select {
		case <-c.release:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	return c.Conn.Write(data)
}

func (c *stalledSignalConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestSignalerCancellationPreservesControlConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	received := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			received <- struct{}{}
		}
	}))
	defer server.Close()
	wire := &stalledSignalConn{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		wire.Conn = conn
		return wire, err
	}}
	defer transport.CloseIdleConnections()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	signaler := &contextSignaler{control: &controlConnection{ctx: ctx, conn: conn}, peerID: "peer"}
	requestContext, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	wire.stall.Store(true)
	result := make(chan error, 1)
	go func() { result <- signaler.Send(requestContext, []byte(`{}`)) }()
	select {
	case <-wire.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancelRequest()
	select {
	case <-wire.closed:
		t.Fatal("session cancellation closed the shared control connection")
	case <-time.After(100 * time.Millisecond):
	}
	close(wire.release)
	if err := <-result; err != nil {
		t.Fatalf("admitted signaling write: %v", err)
	}
	if err := signaler.Send(requestContext, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signaling write = %v", err)
	}
	if err := signaler.Send(ctx, []byte(`{}`)); err != nil {
		t.Fatalf("subsequent signaling write: %v", err)
	}
	for range 2 {
		select {
		case <-received:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
