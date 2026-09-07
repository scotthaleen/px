package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/direct"
)

const (
	probeChannel       = "px-probe"
	probeProtocol      = "px-probe-v1"
	defaultTimeout     = 20 * time.Second
	shutdownGrace      = 200 * time.Millisecond
	maxProbeMessageLen = 256
)

type Config struct {
	SignalURL     string
	Signaler      direct.Signaler
	Session       string
	PrivateKey    ed25519.PrivateKey
	PeerKey       ed25519.PublicKey
	Offer         bool
	Timeout       time.Duration
	AllowLoopback bool
	STUNURLs      []string
	Logger        *slog.Logger
}

type Result struct {
	SetupDuration time.Duration `json:"setup_duration_ns"`
	HealthRTT     time.Duration `json:"health_rtt_ns,omitempty"`
	LocalAddress  string        `json:"local_address"`
	RemoteAddress string        `json:"remote_address"`
	CandidateType string        `json:"candidate_type"`
	RemoteType    string        `json:"remote_candidate_type"`
	GatheredTypes []string      `json:"gathered_candidate_types"`
	RelayUsed     bool          `json:"relay_used"`
}

func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	started := time.Now()
	session, err := direct.Connect(ctx, direct.Config{
		SignalURL:        cfg.SignalURL,
		Signaler:         cfg.Signaler,
		Session:          cfg.Session,
		PrivateKey:       cfg.PrivateKey,
		PeerKey:          cfg.PeerKey,
		Offer:            cfg.Offer,
		AllowLoopback:    cfg.AllowLoopback,
		STUNURLs:         cfg.STUNURLs,
		ChannelLabel:     probeChannel,
		ChannelProtocol:  probeProtocol,
		MaxMessageBytes:  maxProbeMessageLen,
		MessageQueue:     1,
		MaxBufferedBytes: maxProbeMessageLen,
		Logger:           cfg.Logger,
	})
	if err != nil {
		return Result{}, probeError(ctx, err)
	}
	defer session.Close()
	setupDuration := time.Since(started)

	var healthRTT time.Duration
	if cfg.Offer {
		token, err := randomToken()
		if err != nil {
			return Result{}, err
		}
		healthStarted := time.Now()
		if err := session.Send(ctx, direct.Message{Text: true, Data: []byte("ping:" + token)}); err != nil {
			return Result{}, probeError(ctx, err)
		}
		message, err := session.Receive(ctx)
		if err != nil {
			return Result{}, probeError(ctx, err)
		}
		if !message.Text || string(message.Data) != "pong:"+token {
			return Result{}, errors.New("invalid probe response")
		}
		healthRTT = time.Since(healthStarted)
	} else {
		message, err := session.Receive(ctx)
		if err != nil {
			return Result{}, probeError(ctx, err)
		}
		value := string(message.Data)
		if !message.Text || len(value) > maxProbeMessageLen || !strings.HasPrefix(value, "ping:") {
			return Result{}, errors.New("invalid probe message")
		}
		if err := session.Send(ctx, direct.Message{Text: true, Data: []byte("pong:" + strings.TrimPrefix(value, "ping:"))}); err != nil {
			return Result{}, probeError(ctx, err)
		}
		timer := time.NewTimer(shutdownGrace)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}

	pair := session.CandidatePair()
	result := Result{
		SetupDuration: setupDuration,
		HealthRTT:     healthRTT,
		LocalAddress:  pair.LocalAddress,
		RemoteAddress: pair.RemoteAddress,
		CandidateType: pair.LocalType,
		RemoteType:    pair.RemoteType,
		GatheredTypes: session.GatheredCandidateTypes(),
		RelayUsed:     pair.LocalType == "relay" || pair.RemoteType == "relay",
	}
	cfg.Logger.Debug("direct probe succeeded",
		"setup_duration", result.SetupDuration,
		"health_rtt", result.HealthRTT,
		"candidate_type", result.CandidateType,
		"remote_candidate_type", result.RemoteType,
		"gathered_candidate_types", result.GatheredTypes,
		"candidate_addresses", "[redacted]",
	)
	return result, nil
}

func probeError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("probe timed out: %w", ctx.Err())
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("probe canceled: %w", ctx.Err())
	}
	return err
}

func randomToken() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate probe token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
