package stunserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/scotthaleen/go-app"
)

func TestBindingResponseReportsSourceAddress(t *testing.T) {
	server := New("127.0.0.1:0", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := app.New(ctx, app.WithSignalHandling(false), app.WithSequentialStartup(app.Managed(server)))
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	for range 100 {
		if server.Addr() != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if server.Addr() == nil {
		t.Fatal("STUN server did not start")
	}
	conn, err := net.DialUDP("udp", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if _, err := conn.Write(request.Raw); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPacketBytes)
	count, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response := &stun.Message{Raw: buffer[:count]}
	if err := response.Decode(); err != nil {
		t.Fatal(err)
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	if !mapped.IP.Equal(local.IP) || mapped.Port != local.Port {
		t.Fatalf("mapped address = %s, local = %s", mapped.String(), local.String())
	}
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
