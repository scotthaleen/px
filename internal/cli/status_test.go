package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/transfer"
)

func TestWriteStatusStableAndRedacted(t *testing.T) {
	online := 2
	result := agentapi.Summary{
		Version:   agentapi.SummaryVersion,
		Build:     agentapi.Build{Version: "2026.07.30", Commit: "abc123", Date: "2026-07-30T10:00:00Z"},
		StartedAt: time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC),
		Context:   &agentapi.SummaryContext{Name: "home", State: "connected", Enabled: true, OnlinePeers: &online},
		Transfers: &transfer.Counts{Active: 1, Retryable: 3},
		Status:    "ok",
	}
	var output bytes.Buffer
	if err := writeStatus(IOStreams{Out: &output}, result); err != nil {
		t.Fatal(err)
	}
	want := "PX is ready\n\nAgent      running | version 2026.07.30\nContext    home | connected\nPeers      2 online\nTransfers  1 active | 3 retryable\n"
	if output.String() != want {
		t.Fatalf("status output = %q, want %q", output.String(), want)
	}
	for _, secret := range []string{"build-vm", "/private/path", "192.0.2.1", "transfer_id"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("status contains %q: %q", secret, output.String())
		}
	}
}

func TestWriteStatusDegradedWithoutContext(t *testing.T) {
	result := agentapi.Summary{Build: agentapi.Build{Version: "dev", Commit: "unknown", Date: "unknown"}, StartedAt: time.Unix(1, 0), Status: "degraded", Next: "px doctor"}
	var output bytes.Buffer
	if err := writeStatus(IOStreams{Out: &output}, result); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"PX needs attention", "Agent      running | version dev", "Context    not configured", "Peers      unknown", "Transfers  unknown", "Next       px doctor"} {
		if !strings.Contains(output.String(), value) {
			t.Errorf("status missing %q: %q", value, output.String())
		}
	}
}

func TestWriteStatusWithNoTransfers(t *testing.T) {
	online := 2
	result := agentapi.Summary{
		Build:     agentapi.Build{Version: "2026.07.31"},
		Context:   &agentapi.SummaryContext{Name: "lan", State: "connected", Enabled: true, OnlinePeers: &online},
		Transfers: &transfer.Counts{},
		Status:    "ok",
	}
	var output bytes.Buffer
	if err := writeStatus(IOStreams{Out: &output}, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Transfers  none\n") {
		t.Fatalf("status output = %q", output.String())
	}
}
