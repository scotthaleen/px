package direct

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

func TestSendRejectsCanceledSessionBeforeWritableTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &Session{ctx: ctx, maxMessageBytes: 1, maxBufferedBytes: 1}
	if err := session.Send(context.Background(), Message{Data: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("send after cancellation = %v", err)
	}
}

func TestReceiveReturnsEOFWhenPeerCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerClosed := make(chan struct{})
	close(peerClosed)
	session := &Session{ctx: ctx, messages: make(chan Message), errors: make(chan error), peerClosed: peerClosed}
	if _, err := session.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("receive after peer close = %v", err)
	}
}

func TestReceiveDrainsQueuedMessageWhenPeerCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerClosed := make(chan struct{})
	close(peerClosed)
	messages := make(chan Message, 1)
	messages <- Message{Data: []byte("final")}
	session := &Session{ctx: ctx, messages: messages, errors: make(chan error), peerClosed: peerClosed}
	message, err := session.Receive(context.Background())
	if err != nil || string(message.Data) != "final" {
		t.Fatalf("final message = %q, %v", message.Data, err)
	}
	if _, err := session.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("receive after drain = %v", err)
	}
}

func TestReceiveCancellationPrecedesQueuedMessage(t *testing.T) {
	sessionContext, cancelSession := context.WithCancel(context.Background())
	defer cancelSession()
	messages := make(chan Message, 1)
	messages <- Message{Data: []byte("queued")}
	session := &Session{ctx: sessionContext, messages: messages, errors: make(chan error), peerClosed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive after cancellation = %v", err)
	}
}

func TestAllowedIPRejectsOverlayAndLoopback(t *testing.T) {
	for _, value := range []string{"100.64.0.1", "fd7a:115c:a1e0::1"} {
		if allowedIP(net.ParseIP(value), true) {
			t.Fatalf("expected %s to be rejected", value)
		}
	}
	if allowedIP(net.ParseIP("127.0.0.1"), false) {
		t.Fatal("expected loopback to be rejected")
	}
	if !allowedIP(net.ParseIP("127.0.0.1"), true) {
		t.Fatal("expected test loopback to be allowed")
	}
}

func TestAllowedInterfaceRejectsOverlays(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags net.Flags
	}{
		{name: "tailscale0"},
		{name: "utun7", flags: net.FlagPointToPoint},
	} {
		if allowedInterface(test.name, test.flags) {
			t.Fatalf("allowed overlay interface %q", test.name)
		}
	}
	if !allowedInterface("en0", net.FlagUp|net.FlagBroadcast) {
		t.Fatal("rejected LAN interface")
	}
}

func TestSTUNURLsExcludeRelaysAndAreBounded(t *testing.T) {
	if err := ValidateSTUNURLs([]string{"stun:stun.example:3478", "stun:other.example:3478"}); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{
		{"turn:relay.example:3478"},
		{"stuns:stun.example:5349"},
		{"stun:stun.example:3478", "stun:stun.example:3478"},
		{"stun:one", "stun:two", "stun:three", "stun:four", "stun:five"},
		{"https://stun.example"},
	} {
		if err := ValidateSTUNURLs(values); err == nil {
			t.Fatalf("accepted STUN URLs %v", values)
		}
	}
}
