package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/go-app"
	"github.com/scotthaleen/px/internal/rendezvous"
	"github.com/scotthaleen/px/internal/stunserver"
)

func TestDirectProbe(t *testing.T) {
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/signal"
	stunURL := startTestSTUNServer(t)
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		type outcome struct {
			result Result
			err    error
		}
		outcomes := make(chan outcome, 2)
		go func() {
			result, err := Run(ctx, Config{
				SignalURL:     signalURL,
				Session:       "test-probe",
				PrivateKey:    privateB,
				PeerKey:       publicA,
				Timeout:       10 * time.Second,
				AllowLoopback: true,
				STUNURLs:      []string{stunURL},
				Logger:        slog.New(slog.DiscardHandler),
			})
			outcomes <- outcome{result: result, err: err}
		}()
		go func() {
			result, err := Run(ctx, Config{
				SignalURL:     signalURL,
				Session:       "test-probe",
				PrivateKey:    privateA,
				PeerKey:       publicB,
				Offer:         true,
				Timeout:       10 * time.Second,
				AllowLoopback: true,
				STUNURLs:      []string{stunURL},
				Logger:        slog.New(slog.DiscardHandler),
			})
			outcomes <- outcome{result: result, err: err}
		}()

		for range 2 {
			outcome := <-outcomes
			if outcome.err != nil {
				cancel()
				t.Fatal(outcome.err)
			}
			if outcome.result.CandidateType != "host" {
				cancel()
				t.Fatalf("candidate type = %q, want host", outcome.result.CandidateType)
			}
			if outcome.result.LocalAddress == "" || outcome.result.RemoteAddress == "" {
				cancel()
				t.Fatalf("missing candidate pair: %+v", outcome.result)
			}
			if !slices.Contains(outcome.result.GatheredTypes, "srflx") {
				cancel()
				t.Fatalf("gathered candidate types = %v, want srflx", outcome.result.GatheredTypes)
			}
		}
		cancel()
	}
}

func startTestSTUNServer(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	server := stunserver.New("127.0.0.1:0", slog.New(slog.DiscardHandler))
	a := app.New(ctx, app.WithSignalHandling(false), app.WithSequentialStartup(app.Managed(server)))
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	for range 100 {
		if server.Addr() != nil {
			t.Cleanup(func() {
				cancel()
				shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
				defer shutdownCancel()
				_ = a.Close(shutdownContext)
				<-done
			})
			return "stun:" + server.Addr().String()
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	t.Fatal("STUN server did not start")
	return ""
}

func TestProbeTimesOutWithoutPeer(t *testing.T) {
	_, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/signal"

	_, err = Run(context.Background(), Config{
		SignalURL:     signalURL,
		Session:       "timeout-probe",
		PrivateKey:    privateA,
		PeerKey:       publicB,
		Offer:         true,
		Timeout:       100 * time.Millisecond,
		AllowLoopback: true,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestProbeCancellation(t *testing.T) {
	_, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(rendezvous.New(rendezvous.Config{}).Handler())
	t.Cleanup(server.Close)
	signalURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/signal"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = Run(ctx, Config{
		SignalURL:     signalURL,
		Session:       "canceled-probe",
		PrivateKey:    privateA,
		PeerKey:       publicB,
		AllowLoopback: true,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}
