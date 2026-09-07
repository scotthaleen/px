package cli

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/scotthaleen/px/internal/diagnostics"
	"golang.org/x/term"
)

type progressUpdate struct {
	State string
	ID    string
	Bytes int64
	Total int64
	Error string
}

type progressRenderer struct {
	output   io.Writer
	tty      bool
	started  time.Time
	now      func() time.Time
	baseline int64
	width    int
	lastLine int
}

func newProgressRenderer(output io.Writer, tty bool) *progressRenderer {
	return &progressRenderer{output: output, tty: tty, started: time.Now(), now: time.Now, width: terminalWidth(output)}
}

func (r *progressRenderer) Render(update progressUpdate) error {
	if !r.tty {
		suffix := ""
		if update.Error != "" {
			suffix = "\t" + update.Error
		}
		if update.ID == "" {
			_, err := fmt.Fprintf(r.output, "%s\t%d/%d%s\n", update.State, update.Bytes, update.Total, suffix)
			return err
		}
		_, err := fmt.Fprintf(r.output, "%s\t%s\t%d/%d%s\n", update.State, update.ID, update.Bytes, update.Total, suffix)
		return err
	}
	percent := 0.0
	if update.Total > 0 {
		percent = math.Min(1, float64(update.Bytes)/float64(update.Total))
	} else if update.State == "committed" {
		percent = 1
	}
	if update.State == "resumed" {
		r.baseline = update.Bytes
		r.started = r.now()
	}
	width := min(24, max(8, r.width-62))
	filled := int(math.Round(percent * float64(width)))
	bar := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(strings.Repeat("░", width-filled))
	now := r.now()
	elapsed := now.Sub(r.started).Seconds()
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(max(int64(0), update.Bytes-r.baseline)) / elapsed
	}
	state := lipgloss.NewStyle().Bold(true).Render(update.State)
	line := fmt.Sprintf("%s [%s] %6.1f%%  %s/%s  %s/s", state, bar, percent*100, formatBytes(update.Bytes), formatBytes(update.Total), formatBytes(int64(rate)))
	if r.width < 60 {
		line = fmt.Sprintf("%s %6.1f%% %s/%s", state, percent*100, formatBytes(update.Bytes), formatBytes(update.Total))
	}
	if r.width < 40 {
		line = fmt.Sprintf("%s %.0f%%", state, percent*100)
	}
	if r.width > 0 && lipgloss.Width(line) > r.width {
		line = fmt.Sprintf("%.0f%%", percent*100)
	}
	terminal := update.State == "committed" || update.State == "failed" || update.State == "rejected"
	ending := ""
	if terminal {
		ending = "\n"
	}
	visibleWidth := lipgloss.Width(line)
	padding := ""
	if r.lastLine > visibleWidth {
		padding = strings.Repeat(" ", r.lastLine-visibleWidth)
	}
	r.lastLine = visibleWidth
	_, err := fmt.Fprintf(r.output, "\r%s%s%s", line, padding, ending)
	return err
}

func formatBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	number := float64(value)
	unit := "B"
	for _, candidate := range units {
		number /= 1024
		unit = candidate
		if number < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", number, unit)
}

func outputIsTerminal(output io.Writer) bool {
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := output.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func terminalWidth(output io.Writer) int {
	file, ok := output.(*os.File)
	if !ok {
		return 80
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func renderDoctorTTY(output io.Writer, report diagnostics.Report) error {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("PX Doctor")
	if _, err := fmt.Fprintln(output, title); err != nil {
		return err
	}
	for _, check := range report.Checks {
		symbol := "•"
		color := lipgloss.Color("214")
		switch check.Status {
		case diagnostics.Pass:
			symbol, color = "✓", lipgloss.Color("42")
		case diagnostics.Fail:
			symbol, color = "✗", lipgloss.Color("196")
		}
		name := check.ID
		if check.Context != "" {
			name += " [" + check.Context
			if check.Peer != "" {
				name += "/@" + check.Peer
			}
			name += "]"
		}
		label := lipgloss.NewStyle().Foreground(color).Render(symbol + " " + name)
		if _, err := fmt.Fprintf(output, "%s  %s\n", label, check.Summary); err != nil {
			return err
		}
		if check.HeartbeatRTT > 0 {
			if _, err := fmt.Fprintf(output, "   heartbeat RTT %s\n", check.HeartbeatRTT.Round(time.Millisecond)); err != nil {
				return err
			}
		}
		if check.LocalAddress != "" || check.RemoteAddress != "" {
			relay := "no"
			if relayUsed(check) {
				relay = "yes"
			}
			if _, err := fmt.Fprintf(output, "   route %s/%s  %s -> %s  connect %s  relay %s\n", check.LocalCandidateType, check.RemoteCandidateType, check.LocalAddress, check.RemoteAddress, check.SetupDuration.Round(time.Millisecond), relay); err != nil {
				return err
			}
		}
	}
	return nil
}

func relayUsed(check diagnostics.Check) bool {
	return check.RelayUsed != nil && *check.RelayUsed
}
