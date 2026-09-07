package direct

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/webrtc/v4"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/signalproto"
)

const (
	signalingLifetime = time.Minute
	maxICECandidates  = 32
	maxSTUNServers    = 4
)

var overlayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

type Config struct {
	SignalURL        string
	Signaler         Signaler
	Session          string
	PrivateKey       ed25519.PrivateKey
	PeerKey          ed25519.PublicKey
	Offer            bool
	AllowLoopback    bool
	STUNURLs         []string
	ChannelLabel     string
	ChannelProtocol  string
	MaxMessageBytes  uint32
	MessageQueue     int
	MaxBufferedBytes uint64
	Logger           *slog.Logger
	RetainSignaler   bool
}

type Message struct {
	Text bool
	Data []byte
}

type Signaler interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

type CandidatePair struct {
	LocalAddress  string
	RemoteAddress string
	LocalType     string
	RemoteType    string
}

type Session struct {
	connection        *webrtc.PeerConnection
	channel           *webrtc.DataChannel
	messages          chan Message
	errors            chan error
	bufferedAmountLow chan struct{}
	peerClosed        chan struct{}
	maxMessageBytes   uint64
	maxBufferedBytes  uint64
	ctx               context.Context
	cancel            context.CancelFunc
	channelMu         sync.RWMutex
	closeOnce         sync.Once
	peerCloseOnce     sync.Once
	candidateMu       sync.Mutex
	gatheredTypes     map[string]struct{}
	signaler          Signaler
}

type signalClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func Connect(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if (cfg.SignalURL == "" && cfg.Signaler == nil) || cfg.Session == "" || cfg.ChannelLabel == "" || cfg.ChannelProtocol == "" {
		return nil, errors.New("signaler, session, channel label, and channel protocol are required")
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize || len(cfg.PeerKey) != ed25519.PublicKeySize {
		return nil, errors.New("valid local private key and peer public key are required")
	}
	if cfg.MaxMessageBytes == 0 {
		return nil, errors.New("maximum message size is required")
	}
	if cfg.MessageQueue <= 0 {
		return nil, errors.New("message queue depth must be positive")
	}
	if cfg.MaxBufferedBytes < uint64(cfg.MaxMessageBytes) {
		return nil, errors.New("maximum buffered bytes must fit one message")
	}
	if err := ValidateSTUNURLs(cfg.STUNURLs); err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	fail := func(err error) (*Session, error) {
		cancel()
		return nil, err
	}
	ownKey := cfg.PrivateKey.Public().(ed25519.PublicKey)
	ownID := identity.ID(ownKey)
	peerID := identity.ID(cfg.PeerKey)
	client := cfg.Signaler
	var err error
	if client == nil {
		client, err = dialSignal(sessionCtx, cfg.SignalURL, cfg.Session, ownID)
		if err != nil {
			return fail(err)
		}
	}
	retainSignaler := false
	defer func() {
		if !retainSignaler {
			_ = client.Close()
		}
	}()
	signalCtx, stopSignaling := context.WithCancel(sessionCtx)
	defer stopSignaling()

	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settingEngine.SetIncludeLoopbackCandidate(cfg.AllowLoopback)
	settingEngine.SetInterfaceFilter(func(name string) bool {
		iface, err := net.InterfaceByName(name)
		return err == nil && allowedInterface(name, iface.Flags)
	})
	settingEngine.SetIPFilter(func(ip net.IP) bool { return allowedIP(ip, cfg.AllowLoopback) })
	settingEngine.SetRemoteIPFilter(func(ip net.IP) bool { return allowedIP(ip, cfg.AllowLoopback) })
	settingEngine.SetSCTPMaxMessageSize(cfg.MaxMessageBytes)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))
	configuration := webrtc.Configuration{}
	if len(cfg.STUNURLs) > 0 {
		configuration.ICEServers = []webrtc.ICEServer{{URLs: append([]string(nil), cfg.STUNURLs...)}}
	}
	connection, err := api.NewPeerConnection(configuration)
	if err != nil {
		return fail(fmt.Errorf("create peer connection: %w", err))
	}
	session := &Session{
		connection:        connection,
		messages:          make(chan Message, cfg.MessageQueue),
		errors:            make(chan error, 16),
		bufferedAmountLow: make(chan struct{}, 1),
		peerClosed:        make(chan struct{}),
		maxMessageBytes:   uint64(cfg.MaxMessageBytes),
		maxBufferedBytes:  cfg.MaxBufferedBytes,
		ctx:               sessionCtx,
		cancel:            cancel,
		gatheredTypes:     make(map[string]struct{}),
	}
	failSession := func(err error) (*Session, error) {
		session.Close()
		return nil, err
	}
	report := func(err error) {
		if err == nil {
			return
		}
		select {
		case session.errors <- err:
		default:
		}
	}

	incoming := make(chan signalproto.Envelope, 32)
	go func() {
		for {
			data, err := client.Receive(signalCtx)
			if err != nil {
				if signalCtx.Err() == nil {
					report(fmt.Errorf("read signaling message: %w", err))
				}
				return
			}
			envelope, err := signalproto.Verify(data, cfg.PeerKey, ownID, cfg.Session, time.Now())
			if err != nil {
				report(err)
				return
			}
			select {
			case incoming <- envelope:
			case <-signalCtx.Done():
				return
			}
		}
	}()

	localCandidates := 0
	var localCandidateMu sync.Mutex
	connection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		localCandidateMu.Lock()
		localCandidates++
		count := localCandidates
		localCandidateMu.Unlock()
		if count > maxICECandidates {
			report(errors.New("too many local ICE candidates"))
			return
		}
		typeName := candidate.Typ.String()
		session.candidateMu.Lock()
		session.gatheredTypes[typeName] = struct{}{}
		session.candidateMu.Unlock()
		cfg.Logger.Debug("gathered ICE candidate", "candidate_type", typeName, "protocol", candidate.Protocol.String(), "address", "[redacted]")
		candidateJSON := candidate.ToJSON()
		go func() {
			if err := sendSigned(signalCtx, client, cfg.PrivateKey, cfg.Session, peerID, signalproto.KindCandidate, candidateJSON); err != nil && signalCtx.Err() == nil {
				report(err)
			}
		}()
	})
	connection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		cfg.Logger.Debug("direct peer state changed", "state", state)
		if state == webrtc.PeerConnectionStateFailed {
			report(errors.New("direct peer connection failed"))
		}
	})
	opened := make(chan struct{}, 1)
	attach := func(channel *webrtc.DataChannel) {
		if channel.Label() != cfg.ChannelLabel || channel.Protocol() != cfg.ChannelProtocol || !channel.Ordered() {
			report(errors.New("unexpected direct data channel"))
			return
		}
		session.channelMu.Lock()
		if session.channel != nil {
			session.channelMu.Unlock()
			report(errors.New("multiple direct data channels are not allowed"))
			return
		}
		session.channel = channel
		session.channelMu.Unlock()
		channel.SetBufferedAmountLowThreshold(cfg.MaxBufferedBytes / 2)
		channel.OnBufferedAmountLow(func() {
			select {
			case session.bufferedAmountLow <- struct{}{}:
			default:
			}
		})
		channel.OnMessage(func(message webrtc.DataChannelMessage) {
			if uint64(len(message.Data)) > uint64(cfg.MaxMessageBytes) {
				report(errors.New("direct message exceeds configured limit"))
				return
			}
			value := Message{Text: message.IsString, Data: append([]byte(nil), message.Data...)}
			select {
			case session.messages <- value:
			case <-sessionCtx.Done():
			}
		})
		channel.OnError(func(err error) { report(fmt.Errorf("direct data channel: %w", err)) })
		channel.OnClose(func() {
			session.peerCloseOnce.Do(func() { close(session.peerClosed) })
		})
		channel.OnOpen(func() {
			select {
			case opened <- struct{}{}:
			default:
			}
		})
	}

	if cfg.Offer {
		channel, err := connection.CreateDataChannel(cfg.ChannelLabel, &webrtc.DataChannelInit{Ordered: boolPointer(true), Protocol: stringPointer(cfg.ChannelProtocol)})
		if err != nil {
			return failSession(fmt.Errorf("create direct data channel: %w", err))
		}
		attach(channel)
		offer, err := connection.CreateOffer(nil)
		if err != nil {
			return failSession(fmt.Errorf("create offer: %w", err))
		}
		if err := connection.SetLocalDescription(offer); err != nil {
			return failSession(fmt.Errorf("set local offer: %w", err))
		}
		if err := sendSigned(signalCtx, client, cfg.PrivateKey, cfg.Session, peerID, signalproto.KindDescription, offer); err != nil {
			return failSession(err)
		}
	} else {
		connection.OnDataChannel(attach)
	}

	remoteDescriptionSet := false
	remoteCandidates := 0
	pendingCandidates := make([]webrtc.ICECandidateInit, 0, 8)
	for {
		select {
		case <-sessionCtx.Done():
			return failSession(sessionCtx.Err())
		case err := <-session.errors:
			return failSession(err)
		case <-opened:
			if cfg.RetainSignaler {
				session.signaler = client
				retainSignaler = true
			}
			return session, nil
		case envelope := <-incoming:
			switch envelope.Kind {
			case signalproto.KindDescription:
				var description webrtc.SessionDescription
				if err := json.Unmarshal(envelope.Payload, &description); err != nil {
					return failSession(fmt.Errorf("decode peer description: %w", err))
				}
				if cfg.Offer && description.Type != webrtc.SDPTypeAnswer {
					return failSession(errors.New("offering peer expected an answer"))
				}
				if !cfg.Offer && description.Type != webrtc.SDPTypeOffer {
					return failSession(errors.New("answering peer expected an offer"))
				}
				if err := connection.SetRemoteDescription(description); err != nil {
					return failSession(fmt.Errorf("set remote description: %w", err))
				}
				remoteDescriptionSet = true
				for _, candidate := range pendingCandidates {
					if err := connection.AddICECandidate(candidate); err != nil {
						return failSession(fmt.Errorf("add queued ICE candidate: %w", err))
					}
				}
				pendingCandidates = nil
				if !cfg.Offer {
					answer, err := connection.CreateAnswer(nil)
					if err != nil {
						return failSession(fmt.Errorf("create answer: %w", err))
					}
					if err := connection.SetLocalDescription(answer); err != nil {
						return failSession(fmt.Errorf("set local answer: %w", err))
					}
					if err := sendSigned(signalCtx, client, cfg.PrivateKey, cfg.Session, peerID, signalproto.KindDescription, answer); err != nil {
						return failSession(err)
					}
				}
			case signalproto.KindCandidate:
				remoteCandidates++
				if remoteCandidates > maxICECandidates {
					return failSession(errors.New("too many remote ICE candidates"))
				}
				var candidate webrtc.ICECandidateInit
				if err := json.Unmarshal(envelope.Payload, &candidate); err != nil {
					return failSession(fmt.Errorf("decode peer ICE candidate: %w", err))
				}
				if !remoteDescriptionSet {
					pendingCandidates = append(pendingCandidates, candidate)
					continue
				}
				if err := connection.AddICECandidate(candidate); err != nil {
					return failSession(fmt.Errorf("add ICE candidate: %w", err))
				}
			}
		}
	}
}

func (s *Session) Send(ctx context.Context, message Message) error {
	if uint64(len(message.Data)) > s.maxMessageBytes {
		return fmt.Errorf("direct message is %d bytes, limit is %d", len(message.Data), s.maxMessageBytes)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}
	channel := s.dataChannel()
	for channel.BufferedAmount()+uint64(len(message.Data)) > s.maxBufferedBytes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		case err := <-s.errors:
			return err
		case <-s.bufferedAmountLow:
		}
	}
	var err error
	if message.Text {
		err = channel.SendText(string(message.Data))
	} else {
		err = channel.Send(message.Data)
	}
	if err != nil {
		return fmt.Errorf("send direct message: %w", err)
	}
	return nil
}

func (s *Session) Receive(ctx context.Context) (Message, error) {
	select {
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-s.ctx.Done():
		return Message{}, s.ctx.Err()
	default:
	}
	select {
	case message := <-s.messages:
		return message, nil
	default:
	}
	select {
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-s.ctx.Done():
		return Message{}, s.ctx.Err()
	case err := <-s.errors:
		return Message{}, err
	case <-s.peerClosed:
		select {
		case message := <-s.messages:
			return message, nil
		default:
			return Message{}, io.EOF
		}
	case message := <-s.messages:
		return message, nil
	}
}

func (s *Session) WaitPeerClose(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-s.peerClosed:
		return nil
	case err := <-s.errors:
		return err
	}
}

func (s *Session) CandidatePair() CandidatePair {
	if s.connection.SCTP() == nil || s.connection.SCTP().Transport() == nil || s.connection.SCTP().Transport().ICETransport() == nil {
		return CandidatePair{}
	}
	pair, err := s.connection.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return CandidatePair{}
	}
	return CandidatePair{
		LocalAddress:  candidateAddress(pair.Local.Address, pair.Local.Port),
		RemoteAddress: candidateAddress(pair.Remote.Address, pair.Remote.Port),
		LocalType:     pair.Local.Typ.String(),
		RemoteType:    pair.Remote.Typ.String(),
	}
}

func candidateAddress(host string, port uint16) string {
	return net.JoinHostPort(host, fmt.Sprint(port))
}

func (s *Session) GatheredCandidateTypes() []string {
	s.candidateMu.Lock()
	defer s.candidateMu.Unlock()
	result := make([]string, 0, len(s.gatheredTypes))
	for candidateType := range s.gatheredTypes {
		result = append(result, candidateType)
	}
	slices.Sort(result)
	return result
}

func (s *Session) Context() context.Context {
	return s.ctx
}

func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = errors.Join(s.connection.Close(), closeSignaler(s.signaler))
	})
	return err
}

func closeSignaler(signaler Signaler) error {
	if signaler == nil {
		return nil
	}
	return signaler.Close()
}

func (s *Session) dataChannel() *webrtc.DataChannel {
	s.channelMu.RLock()
	defer s.channelMu.RUnlock()
	return s.channel
}

func ValidateSTUNURLs(values []string) error {
	if len(values) > maxSTUNServers {
		return fmt.Errorf("too many STUN servers: %d, limit is %d", len(values), maxSTUNServers)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		parsed, err := stun.ParseURI(value)
		if err != nil || parsed.Scheme.String() != "stun" || parsed.Proto.String() != "udp" {
			return fmt.Errorf("invalid STUN URL %q", value)
		}
		if seen[value] {
			return fmt.Errorf("duplicate STUN URL %q", value)
		}
		seen[value] = true
	}
	return nil
}

func GatherCandidateTypes(ctx context.Context, stunURLs []string, allowLoopback bool) ([]string, error) {
	if err := ValidateSTUNURLs(stunURLs); err != nil {
		return nil, err
	}
	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settingEngine.SetIncludeLoopbackCandidate(allowLoopback)
	settingEngine.SetInterfaceFilter(func(name string) bool {
		iface, err := net.InterfaceByName(name)
		return err == nil && allowedInterface(name, iface.Flags)
	})
	settingEngine.SetIPFilter(func(ip net.IP) bool { return allowedIP(ip, allowLoopback) })
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))
	connection, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{{URLs: append([]string(nil), stunURLs...)}}})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	var mu sync.Mutex
	types := make(map[string]struct{})
	count := 0
	tooMany := make(chan struct{}, 1)
	connection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		count++
		if count > maxICECandidates {
			select {
			case tooMany <- struct{}{}:
			default:
			}
			return
		}
		types[candidate.Typ.String()] = struct{}{}
	})
	if _, err := connection.CreateDataChannel("px-gather", nil); err != nil {
		return nil, err
	}
	offer, err := connection.CreateOffer(nil)
	if err != nil {
		return nil, err
	}
	complete := webrtc.GatheringCompletePromise(connection)
	if err := connection.SetLocalDescription(offer); err != nil {
		return nil, err
	}
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		result := make([]string, 0, len(types))
		for candidateType := range types {
			result = append(result, candidateType)
		}
		slices.Sort(result)
		return result
	}
	select {
	case <-ctx.Done():
		return snapshot(), ctx.Err()
	case <-tooMany:
		return snapshot(), errors.New("too many local ICE candidates")
	case <-complete:
	}
	return snapshot(), nil
}

func dialSignal(ctx context.Context, endpoint, session, device string) (*signalClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse signal URL: %w", err)
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		return nil, errors.New("signal URL must use ws or wss")
	}
	query := parsed.Query()
	query.Set("session", session)
	query.Set("device", device)
	parsed.RawQuery = query.Encode()
	conn, response, err := websocket.Dial(ctx, parsed.String(), nil)
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("connect to signaling: %w", err)
	}
	conn.SetReadLimit(signalproto.MaxEnvelopeBytes)
	return &signalClient{conn: conn}, nil
}

func sendSigned(ctx context.Context, client Signaler, privateKey ed25519.PrivateKey, session, peerID, kind string, payload any) error {
	encoded, err := signalproto.Sign(privateKey, session, peerID, kind, payload, time.Now().Add(signalingLifetime))
	if err != nil {
		return err
	}
	if err := client.Send(ctx, encoded); err != nil {
		return fmt.Errorf("write signaling message: %w", err)
	}
	return nil
}

func (c *signalClient) Send(ctx context.Context, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Write(ctx, websocket.MessageText, data)
}

func (c *signalClient) Receive(ctx context.Context) ([]byte, error) {
	_, data, err := c.conn.Read(ctx)
	return data, err
}

func (c *signalClient) Close() error {
	return c.conn.CloseNow()
}

func allowedIP(ip net.IP, allowLoopback bool) bool {
	if ip.IsLoopback() {
		return allowLoopback
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range overlayPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func allowedInterface(name string, flags net.Flags) bool {
	return flags&net.FlagPointToPoint == 0 && !strings.Contains(strings.ToLower(name), "tailscale")
}

func boolPointer(value bool) *bool       { return &value }
func stringPointer(value string) *string { return &value }
