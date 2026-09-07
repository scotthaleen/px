//go:build process

package testscript_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/direct"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/rendezvousproto"
	"github.com/scotthaleen/px/internal/signalproto"
)

type pingFixturePlan struct {
	requests int
	replies  map[int]bool
	ignore   bool
	started  chan struct{}
	sampled  chan struct{}
	release  <-chan struct{}
}

type pingPeerFixture struct {
	ctx       context.Context
	conn      *websocket.Conn
	private   ed25519.PrivateKey
	peerKey   ed25519.PublicKey
	peerID    string
	plans     chan pingFixturePlan
	writeMu   sync.Mutex
	mu        sync.Mutex
	signalers map[string]*pingFixtureSignaler
	ignored   map[string]bool
	active    atomic.Int32
	opened    atomic.Int32
}

type pingFixtureSignaler struct {
	fixture  *pingPeerFixture
	session  string
	ctx      context.Context
	cancel   context.CancelFunc
	incoming chan []byte
	once     sync.Once
}

type pingStallProxy struct {
	listener net.Listener
	target   string
	paused   atomic.Bool
	ctx      context.Context
	cancel   context.CancelFunc
}

func TestPingDiagnosticsProcesses(t *testing.T) {
	dir := t.TempDir()
	serverHome := filepath.Join(dir, "server")
	if output, err := exec.Command(binaryPath("px-server"), "--home", serverHome, "init").CombinedOutput(); err != nil {
		t.Fatalf("init server: %v\n%s", err, output)
	}
	address := reserveTCPAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	server := startServerProcess(t, ctx, serverHome, address)
	defer stopAgentProcess(server)
	waitServerReady(t, ctx, "http://"+address)
	proxy := startPingStallProxy(t, ctx, reserveTCPAddress(t), address)
	defer proxy.Close()

	home := filepath.Join(dir, "agent")
	for _, root := range []string{filepath.Join(dir, "offered"), filepath.Join(dir, "inbox")} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	agent := startAgentProcess(t, ctx, home)
	defer stopAgentProcess(agent)
	paths, err := apphome.Resolve(home)
	if err != nil {
		t.Fatal(err)
	}
	waitAgentStatus(t, ctx, paths.AgentEndpoint)
	joinOutput := runPXOutput(t, ctx, home, "--context", "home", "join", "http://"+proxy.listener.Addr().String(), "--name", "agent", "--offered-root", filepath.Join(dir, "offered"), "--inbox-root", filepath.Join(dir, "inbox"), "--no-stun", "--json")
	var state contextstate.State
	if err := json.Unmarshal(joinOutput, &state); err != nil || state.PendingCode == "" {
		t.Fatalf("join = %+v, %v\n%s", state, err, joinOutput)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", state.PendingCode, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve agent: %v\n%s", err, output)
	}
	waitContextStates(t, ctx, home, map[string]string{"home": "connected"})

	fixture := startPingPeerFixture(t, ctx, "http://"+address, serverHome, "fixture", state.DeviceID)
	defer fixture.Close()
	waitContextPeer(t, ctx, home, "fixture")

	partial := fixture.runPing(t, ctx, home, 3, pingFixturePlan{requests: 3, replies: map[int]bool{1: true, 3: true}})
	if partial.Requested != 3 || partial.Attempted != 3 || partial.Succeeded != 2 || partial.Lost != 1 || partial.LossBasisPoints != 3333 || partial.Samples[1].Status != "timeout" {
		t.Fatalf("partial ping = %+v", partial)
	}
	all := fixture.runPing(t, ctx, home, 2, pingFixturePlan{requests: 2, replies: map[int]bool{}})
	if all.Requested != 2 || all.Attempted != 2 || all.Succeeded != 0 || all.Lost != 2 || all.LossBasisPoints != 10000 || all.MinRTTNS != nil || all.JitterNS != nil {
		t.Fatalf("all-loss ping = %+v", all)
	}

	for attempt := range 17 {
		started := make(chan struct{})
		fixture.plans <- pingFixturePlan{ignore: true, started: started}
		requestContext, requestCancel := context.WithCancel(ctx)
		result := make(chan error, 1)
		go func() {
			var output ping.Result
			result <- localipc.NewAgentClient(paths.AgentEndpoint).JSONStrict(requestContext, http.MethodPost, "/v1/ping", agentapi.PingRequest{Version: ping.Version, Context: "home", Peer: "fixture", Count: 1}, &output)
		}()
		select {
		case <-started:
		case err := <-result:
			requestCancel()
			t.Fatalf("setup cancellation %d returned before fixture signaling: %v", attempt+1, err)
		case <-ctx.Done():
			requestCancel()
			t.Fatalf("setup cancellation %d waiting for fixture signaling: %v", attempt+1, ctx.Err())
		}
		requestCancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("setup cancellation = %v", err)
		}
	}
	sampled := make(chan struct{})
	samplingRelease := make(chan struct{})
	fixture.plans <- pingFixturePlan{requests: 10, replies: map[int]bool{}, sampled: sampled, release: samplingRelease}
	samplingContext, cancelSampling := context.WithCancel(ctx)
	samplingResult := make(chan error, 1)
	go func() {
		var output ping.Result
		samplingResult <- localipc.NewAgentClient(paths.AgentEndpoint).JSONStrict(samplingContext, http.MethodPost, "/v1/ping", agentapi.PingRequest{Version: ping.Version, Context: "home", Peer: "fixture", Count: 10}, &output)
	}()
	select {
	case <-sampled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancelSampling()
	close(samplingRelease)
	if err := <-samplingResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("sampling cancellation = %v", err)
	}
	waitFixtureIdle(t, ctx, fixture)

	const concurrent = 4
	cancels := make([]context.CancelFunc, 0, concurrent)
	results := make(chan error, concurrent)
	started := make([]chan struct{}, 0, concurrent)
	for range concurrent {
		ready := make(chan struct{})
		started = append(started, ready)
		fixture.plans <- pingFixturePlan{ignore: true, started: ready}
		requestContext, requestCancel := context.WithCancel(ctx)
		cancels = append(cancels, requestCancel)
		go func() {
			// Client cancellation is not an acknowledgment of agent cleanup.
			// Retry only rejected admission; it has not consumed a fixture plan.
			for {
				var output ping.Result
				err := localipc.NewAgentClient(paths.AgentEndpoint).JSONStrict(requestContext, http.MethodPost, "/v1/ping", agentapi.PingRequest{Version: ping.Version, Context: "home", Peer: "fixture", Count: 10}, &output)
				var responseError *localipc.Error
				if !errors.As(err, &responseError) || responseError.Status != http.StatusTooManyRequests {
					results <- err
					return
				}
				select {
				case <-requestContext.Done():
					results <- requestContext.Err()
					return
				case <-time.After(25 * time.Millisecond):
				}
			}
		}()
	}
	for _, ready := range started {
		select {
		case <-ready:
		case err := <-results:
			t.Fatalf("concurrent ping returned before fixture signaling: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var capacityResult ping.Result
	capacityErr := localipc.NewAgentClient(paths.AgentEndpoint).JSONStrict(ctx, http.MethodPost, "/v1/ping", agentapi.PingRequest{Version: ping.Version, Context: "home", Server: true, Count: 1}, &capacityResult)
	var responseError *localipc.Error
	if !errors.As(capacityErr, &responseError) || responseError.Status != http.StatusTooManyRequests {
		t.Fatalf("fifth operation = %#v, %v", responseError, capacityErr)
	}
	for _, requestCancel := range cancels {
		requestCancel()
	}
	for range concurrent {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatalf("sampling cancellation = %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	proxy.paused.Store(true)
	waiterCancels := make([]context.CancelFunc, 0, concurrent)
	waiterResults := make(chan error, concurrent)
	for range concurrent {
		requestContext, requestCancel := context.WithCancel(ctx)
		waiterCancels = append(waiterCancels, requestCancel)
		go func() {
			var output ping.Result
			waiterResults <- localipc.NewAgentClient(paths.AgentEndpoint).JSONStrict(requestContext, http.MethodPost, "/v1/ping", agentapi.PingRequest{Version: ping.Version, Context: "home", Server: true, Count: 1}, &output)
		}()
	}
	time.Sleep(200 * time.Millisecond)
	for _, requestCancel := range waiterCancels {
		requestCancel()
	}
	for range concurrent {
		if err := <-waiterResults; !errors.Is(err, context.Canceled) {
			t.Fatalf("server waiter cancellation = %v", err)
		}
	}
	proxy.paused.Store(false)
	time.Sleep(200 * time.Millisecond)

	serverPing := runPXOutput(t, ctx, home, "--context", "home", "ping", "--server", "--count", "1", "--json")
	if json.Unmarshal(serverPing, &capacityResult) != nil || capacityResult.Succeeded != 1 {
		t.Fatalf("server ping after cancellation = %+v\n%s", capacityResult, serverPing)
	}
	success := fixture.runPing(t, ctx, home, 1, pingFixturePlan{requests: 1, replies: map[int]bool{1: true}})
	if success.Succeeded != 1 || success.Lost != 0 {
		t.Fatalf("peer ping after cleanup = %+v", success)
	}
	waitFixtureIdle(t, ctx, fixture)

	opened := fixture.opened.Load()
	statusOutput := runPXOutput(t, ctx, home, "--context", "home", "status", "--json")
	var status agentapi.Summary
	if err := json.Unmarshal(statusOutput, &status); err != nil || status.Status != "ok" || status.Context == nil || status.Context.State != "connected" || status.Context.OnlinePeers == nil || *status.Context.OnlinePeers != 1 {
		t.Fatalf("status after pings = %+v, %v\n%s", status, err, statusOutput)
	}
	time.Sleep(100 * time.Millisecond)
	if fixture.opened.Load() != opened {
		t.Fatal("passive status opened a peer session")
	}
}

func startPingStallProxy(t *testing.T, parent context.Context, address, target string) *pingStallProxy {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	proxy := &pingStallProxy{listener: listener, target: target, ctx: ctx, cancel: cancel}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			go func() {
				defer client.Close()
				defer server.Close()
				_, _ = io.Copy(server, client)
			}()
			go proxy.copyDownstream(client, server)
		}
	}()
	return proxy
}

func (p *pingStallProxy) copyDownstream(destination, source net.Conn) {
	defer destination.Close()
	defer source.Close()
	buffer := make([]byte, 32<<10)
	for {
		count, err := source.Read(buffer)
		if count > 0 {
			for p.paused.Load() {
				select {
				case <-p.ctx.Done():
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
			if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *pingStallProxy) Close() {
	p.cancel()
	_ = p.listener.Close()
}

func startPingPeerFixture(t *testing.T, ctx context.Context, serverURL, serverHome, label, peerID string) *pingPeerFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := rendezvousapi.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: label}
	var enrollment membership.Enrollment
	postHTTPJSON(t, ctx, serverURL+"/v1/enrollments", request, &enrollment)
	if enrollment.State != "pending" {
		t.Fatalf("fixture enrollment = %+v", enrollment)
	}
	if output, err := exec.CommandContext(ctx, binaryPath("px-server"), "--home", serverHome, "devices", "approve", enrollment.Code, "--json").CombinedOutput(); err != nil {
		t.Fatalf("approve fixture: %v\n%s", err, output)
	}
	postHTTPJSON(t, ctx, serverURL+"/v1/enrollments", request, &enrollment)
	if enrollment.State != "enrolled" || enrollment.Credential == nil {
		t.Fatalf("fixture credential = %+v", enrollment)
	}
	conn := authenticateServerConnection(t, ctx, serverURL, privateKey, *enrollment.Credential)
	readServerMessageType(t, ctx, conn, "authenticated")
	peerKey, err := identity.ParseID(peerID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &pingPeerFixture{ctx: ctx, conn: conn, private: privateKey, peerKey: peerKey, peerID: peerID, plans: make(chan pingFixturePlan, 32), signalers: make(map[string]*pingFixtureSignaler), ignored: make(map[string]bool)}
	go fixture.readLoop()
	return fixture
}

func (f *pingPeerFixture) readLoop() {
	for {
		_, data, err := f.conn.Read(f.ctx)
		if err != nil {
			return
		}
		var message rendezvousproto.ControlMessage
		if json.Unmarshal(data, &message) != nil || message.Version != rendezvousproto.Version || message.Type != "signal" || message.From != f.peerID {
			continue
		}
		var envelope signalproto.Envelope
		if json.Unmarshal(message.Payload, &envelope) != nil {
			continue
		}
		f.mu.Lock()
		if f.ignored[envelope.Session] {
			f.mu.Unlock()
			continue
		}
		signaler := f.signalers[envelope.Session]
		if signaler == nil {
			plan := <-f.plans
			if plan.ignore {
				f.ignored[envelope.Session] = true
				f.mu.Unlock()
				close(plan.started)
				continue
			}
			signalContext, cancel := context.WithCancel(f.ctx)
			signaler = &pingFixtureSignaler{fixture: f, session: envelope.Session, ctx: signalContext, cancel: cancel, incoming: make(chan []byte, 32)}
			f.signalers[envelope.Session] = signaler
			f.opened.Add(1)
			f.active.Add(1)
			if plan.started != nil {
				close(plan.started)
			}
			go f.serve(signaler, plan)
		}
		f.mu.Unlock()
		select {
		case signaler.incoming <- append([]byte(nil), message.Payload...):
		case <-signaler.ctx.Done():
		}
	}
}

func (f *pingPeerFixture) serve(signaler *pingFixtureSignaler, plan pingFixturePlan) {
	defer f.active.Add(-1)
	session, err := direct.Connect(f.ctx, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: f.private, PeerKey: f.peerKey,
		AllowLoopback: true, ChannelLabel: ping.ChannelLabel, ChannelProtocol: ping.Protocol,
		MaxMessageBytes: ping.MaxMessageBytes, MessageQueue: ping.MessageQueue, MaxBufferedBytes: ping.MaxBufferedBytes, RetainSignaler: true,
	})
	if err != nil {
		_ = signaler.Close()
		return
	}
	defer session.Close()
	sampled := false
	for count := 0; count < plan.requests; count++ {
		message, err := session.Receive(f.ctx)
		if err != nil {
			return
		}
		if !sampled && plan.sampled != nil {
			close(plan.sampled)
			sampled = true
		}
		if len(message.Data) != ping.MaxMessageBytes || message.Text {
			return
		}
		sequence := int(message.Data[5])
		if plan.replies[sequence] {
			response := append([]byte(nil), message.Data...)
			response[1] = 2
			if session.Send(f.ctx, direct.Message{Data: response}) != nil {
				return
			}
		}
		if plan.release != nil {
			select {
			case <-plan.release:
				return
			case <-f.ctx.Done():
				return
			}
		}
	}
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
	}
}

func (f *pingPeerFixture) runPing(t *testing.T, ctx context.Context, home string, count int, plan pingFixturePlan) ping.Result {
	t.Helper()
	f.plans <- plan
	output := runPXOutput(t, ctx, home, "--context", "home", "ping", "fixture", "--count", strconv.Itoa(count), "--json")
	var result ping.Result
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode ping: %v\n%s", err, output)
	}
	return result
}

func (f *pingPeerFixture) Close() { _ = f.conn.CloseNow() }

func (s *pingFixtureSignaler) Send(ctx context.Context, payload []byte) error {
	s.fixture.writeMu.Lock()
	defer s.fixture.writeMu.Unlock()
	data, err := json.Marshal(rendezvousproto.ControlMessage{Version: rendezvousproto.Version, Type: "signal", To: s.fixture.peerID, Payload: json.RawMessage(payload)})
	if err != nil {
		return err
	}
	return s.fixture.conn.Write(ctx, websocket.MessageText, data)
}

func (s *pingFixtureSignaler) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case data := <-s.incoming:
		return data, nil
	}
}

func (s *pingFixtureSignaler) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.fixture.mu.Lock()
		delete(s.fixture.signalers, s.session)
		// Late ICE candidates must not consume a plan for the next ping.
		s.fixture.ignored[s.session] = true
		s.fixture.mu.Unlock()
	})
	return nil
}

func TestPingFixtureIgnoresClosedSessionSignals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for _, session := range []string{"closed", "live"} {
			payload, _ := json.Marshal(signalproto.Envelope{Session: session, Kind: signalproto.KindCandidate})
			data, _ := json.Marshal(rendezvousproto.ControlMessage{Version: rendezvousproto.Version, Type: "signal", From: "peer", Payload: payload})
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				return
			}
		}
		<-conn.CloseRead(ctx).Done()
	}))
	defer server.Close()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &pingPeerFixture{ctx: ctx, conn: conn, peerID: "peer", plans: make(chan pingFixturePlan, 1), signalers: make(map[string]*pingFixtureSignaler), ignored: make(map[string]bool)}
	defer f.Close()
	closedContext, closeSession := context.WithCancel(ctx)
	closed := &pingFixtureSignaler{fixture: f, session: "closed", ctx: closedContext, cancel: closeSession}
	f.signalers[closed.session] = closed
	_ = closed.Close()
	live := &pingFixtureSignaler{ctx: ctx, incoming: make(chan []byte, 1)}
	f.signalers["live"] = live
	f.plans <- pingFixturePlan{ignore: true, started: make(chan struct{})}
	go f.readLoop()
	select {
	case <-live.incoming:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(f.plans) != 1 {
		t.Fatal("late signaling consumed the next ping plan")
	}
}

func waitContextPeer(t *testing.T, ctx context.Context, home, label string) {
	t.Helper()
	for {
		var peers []contextstate.Peer
		output := runPXOutput(t, ctx, home, "--context", "home", "peers", "--json")
		if json.Unmarshal(output, &peers) == nil {
			for _, peer := range peers {
				if strings.EqualFold(peer.Label, label) {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func waitFixtureIdle(t *testing.T, ctx context.Context, fixture *pingPeerFixture) {
	t.Helper()
	for fixture.active.Load() != 0 {
		select {
		case <-ctx.Done():
			t.Fatalf("fixture sessions remained active: %d", fixture.active.Load())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
