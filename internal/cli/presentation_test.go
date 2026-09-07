package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/scotthaleen/px/internal/diagnostics"
)

func TestProgressRendererPlainAndTTY(t *testing.T) {
	var plain bytes.Buffer
	plainRenderer := newProgressRenderer(&plain, false)
	if err := plainRenderer.Render(progressUpdate{State: "transferring", ID: "id", Bytes: 512, Total: 1024}); err != nil {
		t.Fatal(err)
	}
	if plain.String() != "transferring\tid\t512/1024\n" || strings.Contains(plain.String(), "\x1b") {
		t.Fatalf("plain progress = %q", plain.String())
	}

	var tty bytes.Buffer
	ttyRenderer := newProgressRenderer(&tty, true)
	ttyRenderer.started = time.Unix(0, 0)
	ttyRenderer.now = func() time.Time { return time.Unix(1, 0) }
	if err := ttyRenderer.Render(progressUpdate{State: "transferring", Bytes: 512, Total: 1024}); err != nil {
		t.Fatal(err)
	}
	if output := tty.String(); !strings.Contains(output, "50.0%") || !strings.Contains(output, "512 B/1.0 KiB") || !strings.Contains(output, "512 B/s") || !strings.HasPrefix(output, "\r") || strings.Contains(output, "\x1b[2K") || strings.HasSuffix(output, "\n") {
		t.Fatalf("TTY progress = %q", output)
	}
	var resumed bytes.Buffer
	resumedRenderer := newProgressRenderer(&resumed, true)
	resumedRenderer.started = time.Unix(0, 0)
	current := time.Unix(1, 0)
	resumedRenderer.now = func() time.Time { return current }
	if err := resumedRenderer.Render(progressUpdate{State: "resumed", Bytes: 8 << 20, Total: 16 << 20}); err != nil {
		t.Fatal(err)
	}
	current = time.Unix(2, 0)
	if err := resumedRenderer.Render(progressUpdate{State: "transferring", Bytes: 9 << 20, Total: 16 << 20}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resumed.String(), "1.0 MiB/s") {
		t.Fatalf("resumed rate includes prior bytes: %q", resumed.String())
	}
	var narrow bytes.Buffer
	narrowRenderer := newProgressRenderer(&narrow, true)
	narrowRenderer.width = 10
	narrowRenderer.now = func() time.Time { return narrowRenderer.started.Add(time.Second) }
	if err := narrowRenderer.Render(progressUpdate{State: "transferring", Bytes: 512, Total: 1024}); err != nil {
		t.Fatal(err)
	}
	if lipgloss.Width(strings.TrimPrefix(narrow.String(), "\r")) > narrowRenderer.width {
		t.Fatalf("narrow progress wrapped: %q", narrow.String())
	}
	if err := ttyRenderer.Render(progressUpdate{State: "committed", Bytes: 0, Total: 0}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tty.String(), "\n") || !strings.Contains(tty.String(), "100.0%") {
		t.Fatalf("terminal TTY progress = %q", tty.String())
	}
}

func TestDoctorTTYIncludesDirectRoute(t *testing.T) {
	report := diagnostics.New([]diagnostics.Check{{
		ID: "peer.direct", Layer: "peer", Context: "home", Peer: "vm", Status: diagnostics.Pass, Summary: "direct probe succeeded",
		LocalCandidateType: "host", RemoteCandidateType: "srflx", LocalAddress: "10.0.0.1:1", RemoteAddress: "203.0.113.1:2", SetupDuration: 12 * time.Millisecond,
	}})
	var output bytes.Buffer
	if err := renderDoctorTTY(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"PX Doctor", "peer.direct [home/@vm]", "host/srflx", "10.0.0.1:1", "203.0.113.1:2", "connect 12ms", "relay no"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("doctor output missing %q: %q", expected, output.String())
		}
	}
}

func TestDoctorTTYDisambiguatesContexts(t *testing.T) {
	report := diagnostics.New([]diagnostics.Check{
		{ID: "context.control", Layer: "context", Context: "home", Status: diagnostics.Pass, Summary: "connected"},
		{ID: "context.control", Layer: "context", Context: "work", Status: diagnostics.Fail, Summary: "disconnected"},
	})
	var output bytes.Buffer
	if err := renderDoctorTTY(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"context.control [home]", "context.control [work]"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("doctor output missing %q: %q", expected, output.String())
		}
	}
}
