package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scotthaleen/go-toolbelt/logging"
	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/apphost"
	"github.com/scotthaleen/px/internal/benchmark"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/direct"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/offered"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/probe"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/startup"
	"github.com/scotthaleen/px/internal/transfer"
	"github.com/scotthaleen/px/internal/versioninfo"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type IOStreams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type rootOptions struct {
	home      string
	context   string
	verbosity int
	logFormat string
}

func validateAgentIPCVersion(version int) error {
	if version != agentapi.Version {
		return fmt.Errorf("%s (agent reported version %d)", localipc.AgentVersionMismatchMessage, version)
	}
	return nil
}

func NewPXCommand(ctx context.Context, streams IOStreams) (*cobra.Command, error) {
	return newPXCommand(ctx, streams, nil)
}

func newPXCommand(ctx context.Context, streams IOStreams, completion completionSource) (*cobra.Command, error) {
	opts := &rootOptions{}
	if completion == nil {
		completion = &ipcCompletionSource{opts: opts}
	}
	root := newRootCommand("px", "Persistent direct peer-to-peer file exchange", streams, opts, "c")
	root.PersistentPreRunE = func(command *cobra.Command, _ []string) error {
		return ensureAgentForCommand(ctx, command, streams, opts)
	}
	root.Example = "  px -c home \"@vm\" ls releases\n  px \"@vm\" get releases/app.tar.zst\n  px \"@vm\" send ./artifact.tar.zst\n  px \"@vm\" text \"build is ready\"\n  px \"@vm\" doctor"
	root.AddCommand(
		newVersionCommand("px", streams),
		agentCommand(newStatusCommand(ctx, streams, opts)),
		newAgentCommand(ctx, streams, opts),
		newStartupCommand(ctx, streams, opts),
		newOnboardCommand(ctx, streams, opts),
		agentCommand(newJoinCommand(ctx, streams, opts)),
		agentCommand(newContextCommand(ctx, streams, opts)),
		agentCommand(newPeersCommand(ctx, streams, opts)),
		agentCommand(newWatchCommand(ctx, streams, opts)),
		agentCommand(newInboxCommand(ctx, streams, opts)),
		agentCommand(newDevicesCommand(ctx, streams, opts)),
		agentCommand(newInviteCommand(ctx, streams, opts)),
		agentCommand(newListOfferedCommand(ctx, streams, opts)),
		agentCommand(newGetOfferedCommand(ctx, streams, opts)),
		agentCommand(newPutCommand(ctx, streams, opts)),
		agentCommand(newTransferCommand(ctx, streams, opts)),
		agentCommand(newRecentCommand(ctx, streams, opts)),
		agentCommand(newPingCommand(ctx, streams, opts)),
		agentCommand(newBenchmarkCommand(ctx, streams, opts)),
		newDoctorCommand(ctx, streams, opts),
		agentCommand(newIPCProbeCommand(ctx, streams, opts)),
		agentCommand(newIPCSendCommand(ctx, streams, opts)),
		agentCommand(newIPCTextCommand(ctx, streams, opts)),
		newDebugCommand(ctx, streams, opts),
		newPeerCompletionCommand(),
	)
	root.AddCommand(newShellCompletionCommand(root))
	if err := configureCompletions(root, opts, completion); err != nil {
		return nil, err
	}
	return root, nil
}

var errWatchGap = errors.New("context watch stream gap; restart px watch to resync")

func newWatchCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "watch",
		Short: "Watch selected-context connection and peer presence",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			watchContext, stop := signal.NotifyContext(ctx, os.Interrupt)
			defer stop()
			validator := watchEventValidator{context: contextName}
			path := "/v1/contexts/" + url.PathEscape(contextName) + "/watch"
			err = client.StreamNDJSON(watchContext, http.MethodGet, path, nil, func(data json.RawMessage) error {
				event, decodeErr := validator.Decode(data)
				if decodeErr != nil {
					return decodeErr
				}
				if jsonOutput {
					if _, writeErr := streams.Out.Write(append(data, '\n')); writeErr != nil {
						return writeErr
					}
				} else if writeErr := writeWatchEvent(streams.Out, event); writeErr != nil {
					return writeErr
				}
				if event.Type == contextwatch.StreamGap {
					return errWatchGap
				}
				return nil
			})
			if watchContext.Err() != nil {
				return nil
			}
			if err != nil {
				return err
			}
			return errors.New("context watch ended unexpectedly; restart px watch to resync")
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit one versioned NDJSON event per line")
	return command
}

type watchEventValidator struct {
	context  string
	streamID string
	sequence uint64
	seen     bool
}

func (v *watchEventValidator) Decode(data []byte) (contextwatch.Event, error) {
	event, err := contextwatch.DecodeStrict(data)
	if err != nil || event.Context != v.context || v.seen && event.StreamID != v.streamID || v.seen && event.Sequence <= v.sequence || !v.seen && (!event.Snapshot || event.Type != contextwatch.ContextConnected && event.Type != contextwatch.ContextDisconnected) || v.seen && event.Snapshot {
		return contextwatch.Event{}, errors.New("agent emitted an invalid context watch event")
	}
	if !v.seen {
		v.streamID = event.StreamID
	}
	v.seen = true
	v.sequence = event.Sequence
	return event, nil
}

func writeWatchEvent(output io.Writer, event contextwatch.Event) error {
	if event.Snapshot {
		if event.Type == contextwatch.ContextConnected {
			_, err := fmt.Fprintf(output, "watching context %s (%d peers online)\n", event.Context, len(event.Peers))
			return err
		}
		_, err := fmt.Fprintf(output, "watching context %s (disconnected)\n", event.Context)
		return err
	}
	timestamp := event.ObservedAt.Local().Format("15:04:05")
	switch event.Type {
	case contextwatch.ContextConnected:
		_, err := fmt.Fprintf(output, "%s  context connected (%d peers online)\n", timestamp, len(event.Peers))
		return err
	case contextwatch.ContextDisconnected:
		_, err := fmt.Fprintf(output, "%s  context disconnected\n", timestamp)
		return err
	case contextwatch.PeerOnline:
		_, err := fmt.Fprintf(output, "%s  %s online\n", timestamp, event.Peer.Label)
		return err
	case contextwatch.PeerOffline:
		_, err := fmt.Fprintf(output, "%s  %s offline\n", timestamp, event.Peer.Label)
		return err
	case contextwatch.StreamGap:
		_, err := fmt.Fprintf(output, "%s  stream gap at sequence %d; resync required\n", timestamp, event.FirstDroppedSequence)
		return err
	default:
		return errors.New("invalid context watch event")
	}
}

func newRecentCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	limit := recent.DefaultLimit
	jsonOutput := false
	peerTarget := ""
	command := &cobra.Command{
		Use:   "recent [PEER]",
		Short: "List retained endpoint send observations",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if limit <= 0 || limit > recent.MaxLimit {
				return fmt.Errorf("--limit must be between 1 and %d", recent.MaxLimit)
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			var snapshot recent.Snapshot
			if peerTarget != "" && len(args) != 0 {
				return errors.New("peer-first recent cannot be combined with a positional peer")
			}
			if len(args) == 0 && peerTarget == "" {
				query := url.Values{"context": {contextName}, "limit": {fmt.Sprint(limit)}}
				err = client.JSONStrict(ctx, "GET", "/v1/recent?"+query.Encode(), nil, &snapshot)
			} else {
				peer := peerTarget
				if peer == "" {
					peer = strings.TrimPrefix(args[0], "@")
				}
				if err := membership.ValidateLabel(peer); err != nil {
					return fmt.Errorf("peer: %w", err)
				}
				err = client.JSONStrict(ctx, "POST", "/v1/recent/peer", agentapi.RecentPeerRequest{Context: contextName, Peer: peer, Limit: limit}, &snapshot)
			}
			if err != nil {
				return err
			}
			if recent.ValidateSnapshot(snapshot, len(args) != 0 || peerTarget != "") != nil {
				return errors.New("agent returned an invalid recent observation snapshot")
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(snapshot)
			}
			return writeRecent(streams.Out, snapshot)
		},
	}
	command.PersistentFlags().IntVar(&limit, "limit", recent.DefaultLimit, "maximum observations to return")
	command.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit a versioned endpoint-observation snapshot")
	command.Flags().StringVar(&peerTarget, "peer-target", "", "internal peer-first target")
	_ = command.Flags().MarkHidden("peer-target")
	var yes bool
	clear := &cobra.Command{Use: "clear", Short: "Clear selected-context endpoint observations", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if jsonOutput && !yes {
			return errors.New("JSON recent clearing requires --yes")
		}
		if !yes {
			if !inputIsTerminal(streams.In) {
				return errors.New("recent clearing requires --yes when input is not a terminal")
			}
			if _, err := fmt.Fprint(streams.Err, "Clear retained endpoint observations for the selected context? Files and transfer recovery state are unchanged. [y/N] "); err != nil {
				return err
			}
			answer, err := bufio.NewReader(streams.In).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if answer = strings.ToLower(strings.TrimSpace(answer)); answer != "y" && answer != "yes" {
				return errors.New("recent clearing cancelled")
			}
		}
		contextName, client, err := selectedContextClient(ctx, streams, opts)
		if err != nil {
			return err
		}
		var result recent.ClearResult
		if err := client.JSONStrict(ctx, "DELETE", "/v1/recent", agentapi.ClearRecentRequest{Context: contextName, Confirmed: true}, &result); err != nil {
			return err
		}
		if result.Version != recent.Version || result.Description != recent.Description || result.Reporter.Context != contextName || result.Reporter.DeviceID == "" || result.Reporter.Label == "" || result.Cleared < 0 {
			return errors.New("agent returned an invalid recent clear result")
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err = fmt.Fprintf(streams.Out, "Cleared %d endpoint observations reported by @%s (%s); files and recovery state were unchanged.\n", result.Cleared, result.Reporter.Label, result.Reporter.DeviceID)
		return err
	}}
	clear.Flags().BoolVar(&yes, "yes", false, "confirm endpoint-observation clearing")
	command.AddCommand(clear)
	return command
}

func writeRecent(output io.Writer, snapshot recent.Snapshot) error {
	location := "@" + snapshot.Reporter.Label
	if snapshot.Reporter.Context != "" {
		location = "this device (@" + snapshot.Reporter.Label + ")"
	}
	if _, err := fmt.Fprintf(output, "Recent activity on %s\n", location); err != nil {
		return err
	}
	if len(snapshot.Observations) == 0 {
		_, err := fmt.Fprintln(output, "\nNo observations.")
		return err
	}

	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "\nTIME (UTC)\tACTION\tPEER\tFILE\tACCESS\tSIZE"); err != nil {
		return err
	}
	for _, value := range snapshot.Observations {
		action := "sent"
		if value.Direction == "receive" {
			action = "received"
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t@%s\t%s\t%s\t%s\n", value.ObservedAt.UTC().Format("2006-01-02 15:04:05"), action, value.PeerLabel, value.Destination, value.Visibility, formatBytes(value.Bytes)); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "\nEndpoint observations only; not receipts or global settlement.")
	return err
}

func newPingCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	count := ping.DefaultCount
	server := false
	showAddresses := false
	jsonOutput := false
	command := &cobra.Command{
		Use:   "ping [PEER]",
		Short: "Measure authenticated application round trips",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ping.ValidateCount(count); err != nil {
				return fmt.Errorf("--%w", err)
			}
			if server == (len(args) == 1) {
				return errors.New("ping requires exactly one peer or --server")
			}
			if server && showAddresses {
				return errors.New("--show-addresses is available only for peer ping")
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			request := agentapi.PingRequest{Version: ping.Version, Context: contextName, Server: server, ShowAddresses: showAddresses, Count: count}
			if len(args) == 1 {
				request.Peer = strings.TrimPrefix(args[0], "@")
				if err := membership.ValidateLabel(request.Peer); err != nil {
					return fmt.Errorf("peer: %w", err)
				}
			}
			operationContext, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			var result ping.Result
			if err := client.JSONStrict(operationContext, "POST", "/v1/ping", request, &result); err != nil {
				return err
			}
			if err := validatePingResult(result, count, server, showAddresses); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			return writePingResult(streams.Out, result, showAddresses)
		},
	}
	command.Flags().IntVar(&count, "count", ping.DefaultCount, "number of sequential application ping samples")
	command.Flags().BoolVar(&server, "server", false, "measure the selected context rendezvous server")
	command.Flags().BoolVar(&showAddresses, "show-addresses", false, "show the selected local and remote addresses (may expose network topology)")
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit a versioned ping result")
	command.Long = "Measure authenticated application round trips.\n\n--show-addresses reveals only the selected local and remote route. Addresses may expose public IPs, private topology, VPNs, and stable IPv6 identifiers."
	return command
}

func newBenchmarkCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	duration := benchmark.DefaultDuration
	jsonOutput := false
	command := &cobra.Command{
		Use:   "benchmark PEER",
		Short: "Measure bidirectional authenticated peer throughput",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := benchmark.ValidateDuration(duration); err != nil {
				return fmt.Errorf("--%w", err)
			}
			peer := strings.TrimPrefix(args[0], "@")
			if err := membership.ValidateLabel(peer); err != nil {
				return fmt.Errorf("peer: %w", err)
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			operationContext, cancel := context.WithTimeout(ctx, 30*time.Second+2*duration)
			defer cancel()
			request := agentapi.BenchmarkRequest{Version: benchmark.Version, Context: contextName, Peer: peer, Duration: duration}
			var result benchmark.Result
			if err := client.JSONStrict(operationContext, http.MethodPost, "/v1/benchmark", request, &result); err != nil {
				return err
			}
			if err := validateBenchmarkResult(result, duration); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			return writeBenchmarkResult(streams.Out, result)
		},
	}
	command.Flags().DurationVar(&duration, "duration", benchmark.DefaultDuration, "measurement time per direction (1s through 30s)")
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit a versioned benchmark result")
	return command
}

func validateBenchmarkResult(result benchmark.Result, duration time.Duration) error {
	if result.Version != benchmark.Version || result.Reporter.DeviceID == "" || result.Target.DeviceID == "" || result.RequestedDurationNS != duration.Nanoseconds() || result.SetupDurationNS < 0 || result.RTTNS <= 0 || result.SelectedLocalCandidateType == "" || result.SelectedRemoteCandidateType == "" {
		return errors.New("agent returned an invalid benchmark result")
	}
	for _, direction := range []benchmark.Direction{result.Upload, result.Download} {
		if direction.Bytes <= 0 || direction.DurationNS <= 0 || math.IsNaN(direction.MiBPerSecond) || math.IsInf(direction.MiBPerSecond, 0) || direction.MiBPerSecond <= 0 {
			return errors.New("agent returned invalid benchmark throughput")
		}
		calculated := float64(direction.Bytes) / (1 << 20) / (float64(direction.DurationNS) / float64(time.Second))
		if math.Abs(calculated-direction.MiBPerSecond) > calculated*1e-9 {
			return errors.New("agent returned inconsistent benchmark throughput")
		}
	}
	return nil
}

func writeBenchmarkResult(output io.Writer, result benchmark.Result) error {
	target := result.Target.DeviceID
	if result.Target.Label != "" {
		target = "@" + result.Target.Label
	}
	if _, err := fmt.Fprintf(output, "%s  direct %s/%s  relay %t\n", target, result.SelectedLocalCandidateType, result.SelectedRemoteCandidateType, result.RelayUsed); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "connect %s  rtt %s\n", time.Duration(result.SetupDurationNS).Round(time.Microsecond), time.Duration(result.RTTNS).Round(time.Microsecond)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "upload %.2f MiB/s  download %.2f MiB/s  duration %s each\n", result.Upload.MiBPerSecond, result.Download.MiBPerSecond, time.Duration(result.RequestedDurationNS))
	return err
}

func validatePingResult(result ping.Result, count int, server, showAddresses bool) error {
	wantMode := "peer"
	if server {
		wantMode = "server"
	}
	if result.Version != ping.Version || result.Mode != wantMode || result.Requested != count || result.Attempted < 0 || result.Attempted > result.Requested || len(result.Samples) != result.Requested || result.Succeeded+result.Lost != result.Attempted || result.LossBasisPoints < 0 || result.LossBasisPoints > 10000 || result.Reporter.DeviceID == "" || result.Target.DeviceID == "" {
		return errors.New("agent returned an invalid ping result")
	}
	if server && (result.SetupDurationNS != nil || result.RelayUsed != nil || result.SelectedLocalCandidateType != "" || result.SelectedRemoteCandidateType != "") || !server && (result.SetupDurationNS == nil || result.RelayUsed == nil || result.SelectedLocalCandidateType == "" || result.SelectedRemoteCandidateType == "") {
		return errors.New("agent returned invalid ping route fields")
	}
	if result.SetupDurationNS != nil && *result.SetupDurationNS < 0 {
		return errors.New("agent returned invalid ping route fields")
	}
	hasLocalAddress := result.SelectedLocalAddress != ""
	hasRemoteAddress := result.SelectedRemoteAddress != ""
	if hasLocalAddress != hasRemoteAddress || showAddresses != (hasLocalAddress && hasRemoteAddress) {
		return errors.New("agent returned invalid ping address fields")
	}
	successfulSamples := 0
	var total, minimum, maximum, jitter int64
	var previous *int64
	for index, sample := range result.Samples {
		validStatus := sample.Status == "success" || sample.Status == "timeout" || sample.Status == "unavailable" || sample.Status == "canceled" || sample.Status == "skipped"
		if !validStatus || sample.Sequence != index+1 || sample.Status == "success" && (sample.RTTNS == nil || *sample.RTTNS < 0) || sample.Status != "success" && sample.RTTNS != nil {
			return errors.New("agent returned an invalid ping sample")
		}
		if index < result.Attempted && sample.Status == "skipped" {
			return errors.New("agent skipped an attempted ping sample")
		}
		if index >= result.Attempted && sample.Status != "skipped" && sample.Status != "canceled" && sample.Status != "unavailable" {
			return errors.New("agent returned an attempted unrequested ping sample")
		}
		if index < result.Attempted && sample.Status == "success" {
			value := *sample.RTTNS
			if value > math.MaxInt64-total {
				return errors.New("agent returned invalid ping statistics")
			}
			total += value
			if successfulSamples == 0 || value < minimum {
				minimum = value
			}
			if successfulSamples == 0 || value > maximum {
				maximum = value
			}
			if previous != nil {
				difference := value - *previous
				if difference < 0 {
					difference = -difference
				}
				if difference > math.MaxInt64-jitter {
					return errors.New("agent returned invalid ping statistics")
				}
				jitter += difference
			}
			previous = sample.RTTNS
			successfulSamples++
		}
	}
	wantLossBasisPoints := 0
	if result.Attempted > 0 {
		wantLossBasisPoints = result.Lost * 10000 / result.Attempted
	}
	if result.Succeeded != successfulSamples || result.Lost != result.Attempted-successfulSamples || result.LossBasisPoints != wantLossBasisPoints {
		return errors.New("agent returned inconsistent ping accounting")
	}
	if result.Succeeded == 0 && (result.MinRTTNS != nil || result.AvgRTTNS != nil || result.MaxRTTNS != nil || result.JitterNS != nil) || result.Succeeded > 0 && (result.MinRTTNS == nil || result.AvgRTTNS == nil || result.MaxRTTNS == nil) || result.Succeeded < 2 && result.JitterNS != nil || result.Succeeded > 1 && result.JitterNS == nil {
		return errors.New("agent returned invalid ping statistics")
	}
	if result.Succeeded > 0 && (*result.MinRTTNS != minimum || *result.AvgRTTNS != total/int64(result.Succeeded) || *result.MaxRTTNS != maximum) || result.Succeeded > 1 && *result.JitterNS != jitter/int64(result.Succeeded-1) {
		return errors.New("agent returned inconsistent ping statistics")
	}
	return nil
}

func writePingResult(output io.Writer, result ping.Result, showAddresses bool) error {
	target := result.Target.DeviceID
	if result.Target.Label != "" {
		target = "@" + result.Target.Label
	}
	if result.Mode == "peer" {
		relay := "no"
		if result.RelayUsed != nil && *result.RelayUsed {
			relay = "yes"
		}
		addressRoute := ""
		if showAddresses {
			addressRoute = "  " + result.SelectedLocalAddress + " -> " + result.SelectedRemoteAddress
		}
		if _, err := fmt.Fprintf(output, "%s  direct %s/%s%s  relay %s\n", target, result.SelectedLocalCandidateType, result.SelectedRemoteCandidateType, addressRoute, relay); err != nil {
			return err
		}
	}
	statistics := "rtt min/avg/max -/-/-  jitter -"
	if result.Succeeded > 0 {
		statistics = fmt.Sprintf("rtt min/avg/max %s/%s/%s  jitter %s", formatPingDuration(result.MinRTTNS), formatPingDuration(result.AvgRTTNS), formatPingDuration(result.MaxRTTNS), formatPingDuration(result.JitterNS))
	}
	prefix := ""
	if result.SetupDurationNS != nil {
		prefix = "connect " + formatPingDuration(result.SetupDurationNS) + "  "
	}
	_, err := fmt.Fprintf(output, "%s%s  loss %.2f%% (%d/%d attempted, %d requested)\n", prefix, statistics, float64(result.LossBasisPoints)/100, result.Lost, result.Attempted, result.Requested)
	return err
}

func formatPingDuration(value *int64) string {
	if value == nil {
		return "-"
	}
	return time.Duration(*value).Round(time.Microsecond).String()
}

func newPutCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var timeout time.Duration
	var jsonOutput bool
	var replace bool
	var expectSHA256 string
	command := &cobra.Command{Use: "put PEER SOURCE DESTINATION", Short: "Create or explicitly replace one file beneath a peer's opt-in put root", Args: cobra.ExactArgs(3), RunE: func(_ *cobra.Command, args []string) error {
		peer := strings.TrimPrefix(args[0], "@")
		if err := membership.ValidateLabel(peer); err != nil {
			return fmt.Errorf("peer: %w", err)
		}
		if err := transfer.ValidateSource(args[1], put.MaxFileBytes); err != nil {
			return err
		}
		if err := put.ValidateDestination(args[2]); err != nil {
			return err
		}
		if expectSHA256 != "" && !replace {
			return errors.New("--expect-sha256 requires --replace")
		}
		if err := put.ValidateExpectedSHA256(expectSHA256); err != nil {
			return err
		}
		if timeout <= 0 {
			return errors.New("--timeout must be positive")
		}
		paths, _, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		contextName, err := selectedContext(ctx, streams, opts)
		if err != nil {
			return err
		}
		operation, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		terminal := put.Event{}
		renderer := newProgressRenderer(streams.Out, outputIsTerminal(streams.Out))
		request := agentapi.ContextPutRequest{Context: contextName, Peer: peer, Source: args[1], Destination: args[2], Replace: replace, ExpectSHA256: expectSHA256}
		err = localipc.NewAgentClient(paths.AgentEndpoint).StreamJSON(operation, "POST", "/v1/context/put", request, func(data json.RawMessage) error {
			var event put.Event
			if json.Unmarshal(data, &event) != nil || event.Version != put.EventVersion {
				return errors.New("agent emitted an invalid put event")
			}
			terminal = event
			if jsonOutput {
				_, err := streams.Out.Write(append(data, '\n'))
				return err
			}
			return renderer.Render(progressUpdate{State: event.State, ID: event.TransferID, Bytes: event.Bytes, Total: event.Total, Error: event.Error})
		})
		if err != nil {
			return err
		}
		if terminal.State == "failed" {
			return errors.New(terminal.Error)
		}
		if terminal.State != "committed" {
			return errors.New("put ended without a terminal result")
		}
		if !jsonOutput {
			status := "durability confirmed"
			if terminal.DurabilityUnconfirmed {
				status = "durability unconfirmed"
			}
			outcome := "created"
			if terminal.Replaced {
				outcome = "replaced"
			}
			_, err = fmt.Fprintf(streams.Out, "%s\t%s\t%s\n", terminal.Destination, outcome, status)
		}
		return err
	}}
	command.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "complete put timeout")
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON events")
	command.Flags().BoolVar(&replace, "replace", false, "atomically replace an existing safe regular destination")
	command.Flags().StringVar(&expectSHA256, "expect-sha256", "", "replace only when the existing content has this lowercase SHA-256")
	return command
}

func newInboxCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "inbox [@SENDER]",
		Short: "List received files in the selected context",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			sender := ""
			if len(args) == 1 {
				if !strings.HasPrefix(args[0], "@") {
					return errors.New("sender must be @LABEL")
				}
				sender = strings.TrimPrefix(args[0], "@")
				if err := membership.ValidateLabel(sender); err != nil {
					return fmt.Errorf("sender: %w", err)
				}
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			endpoint := "/v1/contexts/" + url.PathEscape(contextName) + "/inbox"
			if sender != "" {
				endpoint += "?sender=" + url.QueryEscape(sender)
			}
			var entries []inbox.Entry
			if err := client.JSON(ctx, "GET", endpoint, nil, &entries); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(entries)
			}
			for _, entry := range entries {
				if _, err := fmt.Fprintf(streams.Out, "%s\t%s\n", entry.Path, formatBytes(entry.Size)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	pathCommand := &cobra.Command{Use: "path SENDER/FILE", Short: "Print one validated inbox file path", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if _, _, err := inbox.ValidatePath(args[0]); err != nil {
			return err
		}
		contextName, client, err := selectedContextClient(ctx, streams, opts)
		if err != nil {
			return err
		}
		var result inbox.PathResult
		if err := client.JSON(ctx, "POST", "/v1/contexts/"+url.PathEscape(contextName)+"/inbox/path", agentapi.InboxPathRequest{Path: args[0]}, &result); err != nil {
			return err
		}
		if result.Version != inbox.ResultVersion || result.Source != args[0] || !filepath.IsAbs(result.Path) {
			return errors.New("agent returned an invalid inbox path")
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err = fmt.Fprintln(streams.Out, result.Path)
		return err
	}}
	moveCommand := &cobra.Command{Use: "move SENDER/FILE DEST", Short: "Move one inbox file without overwriting", Args: cobra.ExactArgs(2), RunE: func(_ *cobra.Command, args []string) error {
		if _, _, err := inbox.ValidatePath(args[0]); err != nil {
			return err
		}
		destination, err := resolveInboxDestination(args[0], args[1])
		if err != nil {
			return err
		}
		contextName, client, err := selectedContextClient(ctx, streams, opts)
		if err != nil {
			return err
		}
		var result inbox.MoveResult
		if err := client.JSON(ctx, "POST", "/v1/contexts/"+url.PathEscape(contextName)+"/inbox/move", agentapi.InboxMoveRequest{Path: args[0], Destination: destination}, &result); err != nil {
			return err
		}
		if result.Version != inbox.ResultVersion || result.Source != args[0] || result.Destination != destination || !result.DestinationCommitted || result.State != inbox.MoveStateMoved && result.State != inbox.MoveStateRetained && result.State != inbox.MoveStateUncertain || result.State == inbox.MoveStateMoved != result.SourceRemovalConfirmed {
			return errors.New("agent returned an invalid inbox move result")
		}
		if jsonOutput {
			if err := json.NewEncoder(streams.Out).Encode(result); err != nil {
				return err
			}
		} else if result.State == inbox.MoveStateMoved {
			if _, err := fmt.Fprintf(streams.Out, "%s -> %s\n", result.Source, result.Destination); err != nil {
				return err
			}
		} else if result.State == inbox.MoveStateUncertain {
			if _, err := fmt.Fprintf(streams.Out, "destination committed\t%s\nsource removal durability uncertain\t%s\n", result.Destination, result.Source); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(streams.Out, "destination committed\t%s\nsource retained\t%s\n", result.Destination, result.Source); err != nil {
			return err
		}
		if result.State != inbox.MoveStateMoved {
			return errors.New(result.Warning)
		}
		return nil
	}}
	pathCommand.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	moveCommand.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	}
	cmd.AddCommand(pathCommand, moveCommand)
	return cmd
}

func resolveInboxDestination(source, destination string) (string, error) {
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return "", errors.New("resolve inbox move destination failed")
	}
	info, err := os.Stat(absolute)
	if err == nil && info.IsDir() {
		return filepath.Join(absolute, path.Base(source)), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("inspect inbox move destination failed")
	}
	return filepath.Clean(absolute), nil
}

func newTransferCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{Use: "transfer", Short: "Inspect and control bounded transfer state"}
	command.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	listLimit := transfer.DefaultInventoryLimit
	list := &cobra.Command{
		Use: "list", Short: "List active and expiry-bound transfers", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if listLimit <= 0 || listLimit > transfer.MaxInventoryLimit {
				return fmt.Errorf("--limit must be between 1 and %d", transfer.MaxInventoryLimit)
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			query := url.Values{"context": {contextName}, "limit": {fmt.Sprint(listLimit)}}
			var inventory transfer.Inventory
			if err := client.JSON(ctx, "GET", "/v1/transfers?"+query.Encode(), nil, &inventory); err != nil {
				return err
			}
			if inventory.Version != transfer.InventoryVersion {
				return errors.New("agent emitted an unsupported transfer inventory")
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(inventory)
			}
			for _, item := range inventory.Transfers {
				if err := writeTransferListItem(streams.Out, item); err != nil {
					return err
				}
			}
			return nil
		},
	}
	list.Flags().IntVar(&listLimit, "limit", transfer.DefaultInventoryLimit, "maximum transfers to return")
	show := &cobra.Command{
		Use: "show ID", Short: "Show one redacted transfer", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			item, err := requestTransferItem(ctx, streams, opts, "GET", args[0])
			if err != nil {
				return err
			}
			return writeTransferItem(streams.Out, jsonOutput, item)
		},
	}
	cancel := &cobra.Command{
		Use: "cancel ID", Short: "Cancel one active transfer", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			query := url.Values{"context": {contextName}}
			result := map[string]string{}
			if err := client.JSON(ctx, "POST", "/v1/transfers/"+url.PathEscape(args[0])+"/cancel?"+query.Encode(), nil, &result); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "%s\tcancel requested\n", args[0])
			return err
		},
	}
	var yes bool
	remove := &cobra.Command{
		Use: "delete ID", Short: "Delete abandoned retry state and private partial data", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if jsonOutput && !yes {
				return errors.New("JSON transfer deletion requires --yes")
			}
			if !yes {
				if !inputIsTerminal(streams.In) {
					return errors.New("transfer deletion requires --yes when input is not a terminal")
				}
				if _, err := fmt.Fprintf(streams.Err, "Delete retry state %q? Retained stdin or receiver partial data will be discarded; source and committed files are preserved. [y/N] ", args[0]); err != nil {
					return err
				}
				answer, err := bufio.NewReader(streams.In).ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer != "y" && answer != "yes" {
					return errors.New("transfer deletion cancelled")
				}
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			var item transfer.InventoryItem
			request := agentapi.DeleteTransferRequest{Context: contextName, Confirmed: true}
			if err := client.JSON(ctx, "DELETE", "/v1/transfers/"+url.PathEscape(args[0]), request, &item); err != nil {
				return err
			}
			return writeTransferDelete(streams.Out, jsonOutput, item)
		},
	}
	remove.Flags().BoolVar(&yes, "yes", false, "confirm destructive retry-state deletion")
	var timeout time.Duration
	retry := &cobra.Command{
		Use: "retry ID", Short: "Retry a persisted send or put with its original authority and immutable manifest", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if timeout <= 0 {
				return errors.New("--timeout must be positive")
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			contextName, err := selectedContext(ctx, streams, opts)
			if err != nil {
				return err
			}
			operationContext, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			terminal := transfer.ResumeEvent{}
			renderer := newProgressRenderer(streams.Out, outputIsTerminal(streams.Out))
			request := agentapi.TransferContextRequest{Context: contextName}
			err = localipc.NewAgentClient(paths.AgentEndpoint).StreamJSON(operationContext, "POST", "/v1/transfers/"+url.PathEscape(args[0])+"/retry", request, func(data json.RawMessage) error {
				var event transfer.ResumeEvent
				if err := json.Unmarshal(data, &event); err != nil || event.Version != transfer.ResumeEventVersion {
					return errors.New("agent emitted an invalid transfer event")
				}
				terminal = event
				if jsonOutput {
					_, err := streams.Out.Write(append(data, '\n'))
					return err
				}
				return renderer.Render(progressUpdate{State: event.State, ID: event.TransferID, Bytes: event.Bytes, Total: event.Total, Error: event.Error})
			})
			if err != nil {
				return err
			}
			if terminal.State == "failed" || terminal.State == "rejected" {
				if terminal.ErrorCode != "" {
					return &localipc.Error{Status: 422, Code: terminal.ErrorCode, Message: terminal.Error}
				}
				return errors.New(terminal.Error)
			}
			if terminal.State != "committed" {
				return errors.New("transfer retry ended without a terminal event")
			}
			if !jsonOutput && terminal.Outcome != "" {
				_, err = fmt.Fprintf(streams.Out, "%s\t%s\t%s\n", terminal.Name, terminal.Outcome, strings.ReplaceAll(terminal.Durability, "_", " "))
			}
			return nil
		},
	}
	retry.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "complete transfer timeout")
	var acceptCurrent, resolveYes bool
	resolve := &cobra.Command{
		Use: "resolve ID", Short: "Accept a verified current put destination as local final state", Long: "Accept a verified current put destination as local final state. This irreversible local adjudication may discard an identity-proven prior backup and never claims remote settlement.", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if !acceptCurrent || !resolveYes {
				return errors.New("transfer resolution requires --accept-current and --yes")
			}
			contextName, client, err := selectedContextClient(ctx, streams, opts)
			if err != nil {
				return err
			}
			request := agentapi.ResolveTransferRequest{Context: contextName, AcceptCurrent: true, Confirmed: true}
			var result put.ResolutionResult
			if err := client.JSON(ctx, "POST", "/v1/transfers/"+url.PathEscape(args[0])+"/resolve", request, &result); err != nil {
				return err
			}
			if result.Version != put.ResolutionVersion || result.TransferID != args[0] || result.Context != contextName || result.State != "resolved_accept_current" {
				return errors.New("agent emitted an invalid transfer resolution result")
			}
			return writeTransferResolution(streams.Out, jsonOutput, result)
		},
	}
	resolve.Flags().BoolVar(&acceptCurrent, "accept-current", false, "accept the verified current destination and discard exact owned recovery artifacts")
	resolve.Flags().BoolVar(&resolveYes, "yes", false, "confirm irreversible local accept-current resolution")
	command.AddCommand(list, show, retry, cancel, remove, resolve)
	return command
}

func writeTransferResolution(output io.Writer, jsonOutput bool, result put.ResolutionResult) error {
	if jsonOutput {
		return json.NewEncoder(output).Encode(result)
	}
	_, err := fmt.Fprintf(output, "%s\t%s\t%s\n", result.TransferID, result.Destination, strings.ReplaceAll(result.State, "_", " "))
	return err
}

func requestTransferItem(ctx context.Context, streams IOStreams, opts *rootOptions, method, id string) (transfer.InventoryItem, error) {
	contextName, client, err := selectedContextClient(ctx, streams, opts)
	if err != nil {
		return transfer.InventoryItem{}, err
	}
	query := url.Values{"context": {contextName}}
	var item transfer.InventoryItem
	err = client.JSON(ctx, method, "/v1/transfers/"+url.PathEscape(id)+"?"+query.Encode(), nil, &item)
	return item, err
}

func writeTransferItem(output io.Writer, jsonOutput bool, item transfer.InventoryItem) error {
	if jsonOutput {
		return json.NewEncoder(output).Encode(item)
	}
	fields := []struct{ name, value string }{
		{"id", item.ID},
		{"kind", item.Kind},
		{"context", item.Context},
		{"peer", item.Peer},
		{"name", item.Name},
		{"visibility", string(item.Visibility)},
		{"state", item.State},
		{"bytes", fmt.Sprint(item.Bytes)},
		{"total", fmt.Sprint(item.Total)},
		{"retryable", fmt.Sprint(item.Retryable)},
		{"local_committed", fmt.Sprint(item.LocalCommitted)},
		{"created_at", inventoryTime(item.CreatedAt)},
		{"updated_at", inventoryTime(item.UpdatedAt)},
		{"expires_at", inventoryExpiry(item.ExpiresAt)},
		{"cleanup_pending", fmt.Sprint(item.CleanupPending)},
		{"created", fmt.Sprint(item.Created)},
		{"replaced", fmt.Sprint(item.Replaced)},
		{"durability", item.Durability},
		{"outcome_unknown", fmt.Sprint(item.OutcomeUnknown)},
		{"action_required", fmt.Sprint(item.ActionRequired)},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(output, "%s\t%s\n", field.name, field.value); err != nil {
			return err
		}
	}
	if item.PeerConfirmation != "" {
		_, err := fmt.Fprintf(output, "peer_confirmation\t%s\n", item.PeerConfirmation)
		return err
	}
	return nil
}

func inventoryTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func inventoryExpiry(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return inventoryTime(*value)
}

func optionalDisplay(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

func writeTransferDelete(output io.Writer, jsonOutput bool, item transfer.InventoryItem) error {
	if jsonOutput {
		return json.NewEncoder(output).Encode(item)
	}
	if item.CleanupPending {
		_, err := fmt.Fprintf(output, "%s\tretry state deleted; private cleanup queued\n", item.ID)
		return err
	}
	_, err := fmt.Fprintf(output, "%s\tretry state deleted\n", item.ID)
	return err
}

func writeTransferListItem(output io.Writer, item transfer.InventoryItem) error {
	_, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n", item.ID, item.Kind, item.Peer, item.Name, item.State, item.Bytes, item.Total, inventoryTime(item.UpdatedAt), inventoryExpiry(item.ExpiresAt))
	return err
}

func newPeersCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput, wide bool
	command := &cobra.Command{
		Use:   "peers",
		Short: "List online peers in the selected context",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			contextName, err := selectedContext(ctx, streams, opts)
			if err != nil {
				return err
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			peers := make([]contextstate.Peer, 0)
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(contextName)+"/peers", nil, &peers); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(peers)
			}
			return writePeers(streams.Out, peers, wide)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	command.Flags().BoolVar(&wide, "wide", false, "include complete device identities")
	return command
}

func writePeers(output io.Writer, peers []contextstate.Peer, wide bool) error {
	for _, peer := range peers {
		if err := writePeer(output, peer, wide); err != nil {
			return err
		}
	}
	return nil
}

func writePeer(output io.Writer, peer contextstate.Peer, wide bool) error {
	fields := []string{"@" + peer.Label, "online"}
	if wide {
		fields = append(fields, peer.DeviceID)
	}
	if len(peer.Aliases) != 0 {
		fields = append(fields, "aliases: "+strings.Join(peer.Aliases, ","))
	}
	_, err := fmt.Fprintln(output, strings.Join(fields, "\t"))
	return err
}

func newInviteCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput, yes bool
	command := &cobra.Command{Use: "invite", Short: "Administer one-time enrollment invites"}
	command.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit a JSON result; creation output contains a sensitive token")

	lifetime := membership.DefaultInviteLifetime
	create := &cobra.Command{Use: "create LABEL", Short: "Create a label-bound enrollment invite", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if err := membership.ValidateLabel(args[0]); err != nil {
			return err
		}
		if lifetime < membership.MinInviteLifetime || lifetime > membership.MaxInviteLifetime || lifetime%time.Second != 0 {
			return errors.New("--expires must be a whole-second duration from 1m through 168h")
		}
		contextName, client, err := selectedContextClient(ctx, streams, opts)
		if err != nil {
			return err
		}
		var state contextstate.State
		if err := client.JSONStrict(ctx, "GET", "/v1/contexts/"+url.PathEscape(contextName), nil, &state); err != nil {
			return err
		}
		request := inviteapi.CreateRequest{Version: inviteapi.Version, Label: args[0], LifetimeSeconds: int64(lifetime / time.Second)}
		var result inviteapi.Creation
		if err := client.JSONStrict(ctx, "POST", "/v1/contexts/"+url.PathEscape(contextName)+"/invites", request, &result); err != nil {
			return classifyMemberInviteMutation("create", "", err)
		}
		if inviteapi.ValidateCreation(result, state.ServerID, args[0], "member", state.DeviceID, lifetime) != nil {
			return memberInviteOutcomeUnknown("create", "")
		}
		if _, err := fmt.Fprintf(streams.Err, "Created invite %s for %s; expires %s UTC. Warning: the enrollment token is sensitive and is shown only once.\n", result.InviteID, result.Label, result.ExpiresAt); err != nil {
			return memberInviteOutcomeUnknown("create", result.InviteID)
		}
		if jsonOutput {
			if err := json.NewEncoder(streams.Out).Encode(result); err != nil {
				return memberInviteOutcomeUnknown("create", result.InviteID)
			}
			return nil
		}
		if _, err := fmt.Fprintln(streams.Out, result.Token); err != nil {
			return memberInviteOutcomeUnknown("create", result.InviteID)
		}
		return nil
	}}
	create.Flags().DurationVar(&lifetime, "expires", membership.DefaultInviteLifetime, "invite lifetime from 1m through 168h")

	list := &cobra.Command{Use: "list", Short: "List active enrollment invites without tokens", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		_, _, result, err := listMemberInvites(ctx, streams, opts)
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		for _, invite := range result.Invites {
			issuer := invite.IssuerType
			if invite.IssuerDeviceID != "" {
				issuer += ":" + invite.IssuerDeviceID
			}
			if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%s\t%s\t%s\n", invite.InviteID, invite.Label, issuer, invite.CreatedAt, invite.ExpiresAt); err != nil {
				return err
			}
		}
		return nil
	}}

	revoke := &cobra.Command{Use: "revoke INVITE_ID", Short: "Revoke one unused enrollment invite", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if membership.ValidateInviteID(args[0]) != nil {
			return errors.New("invalid invite ID")
		}
		if jsonOutput && !yes {
			return errors.New("JSON invite revocation requires --yes")
		}
		if !yes && !inputIsTerminal(streams.In) {
			return errors.New("invite revocation requires --yes when input is not a terminal")
		}
		client, contextName, listed, err := listMemberInvites(ctx, streams, opts)
		if err != nil {
			return err
		}
		var selected inviteapi.Invite
		for _, invite := range listed.Invites {
			if invite.InviteID == args[0] {
				selected = invite
				break
			}
		}
		if selected.InviteID == "" {
			return errors.New("invite is unavailable")
		}
		if !jsonOutput {
			if yes {
				err = writeMemberInviteRevocationPreview(streams.Err, selected)
			} else {
				var confirmed bool
				confirmed, err = confirmMemberInviteRevocation(bufio.NewReader(streams.In), streams.Err, selected)
				if err == nil && !confirmed {
					return errors.New("invite revocation cancelled")
				}
			}
			if err != nil {
				return err
			}
		}
		var result inviteapi.Revocation
		path := "/v1/contexts/" + url.PathEscape(contextName) + "/invites/" + args[0]
		if err := client.JSONStrict(ctx, "DELETE", path, nil, &result); err != nil {
			return classifyMemberInviteMutation("revoke", args[0], err)
		}
		if result.Version != inviteapi.Version || result.State != "revoked" || result.Invite != selected || inviteapi.Validate(result.Invite) != nil {
			return memberInviteOutcomeUnknown("revoke", args[0])
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err = fmt.Fprintf(streams.Out, "revoked %s (%s)\n", result.Invite.Label, result.Invite.InviteID)
		return err
	}}
	revoke.Flags().BoolVar(&yes, "yes", false, "confirm invite revocation")
	command.AddCommand(create, list, revoke)
	return command
}

func listMemberInvites(ctx context.Context, streams IOStreams, opts *rootOptions) (*localipc.Client, string, inviteapi.List, error) {
	contextName, client, err := selectedContextClient(ctx, streams, opts)
	if err != nil {
		return nil, "", inviteapi.List{}, err
	}
	var result inviteapi.List
	path := "/v1/contexts/" + url.PathEscape(contextName) + "/invites"
	if err := client.JSONStrict(ctx, "GET", path, nil, &result); err != nil {
		return nil, "", inviteapi.List{}, err
	}
	if inviteapi.ValidateList(result) != nil {
		return nil, "", inviteapi.List{}, errors.New("PX agent returned an invalid invite list")
	}
	return client, contextName, result, nil
}

func writeMemberInviteRevocationPreview(output io.Writer, invite inviteapi.Invite) error {
	_, err := fmt.Fprintf(output, "Revoke invite %s for %s, expiring %s UTC?\nThe one-time token will immediately stop authorizing enrollment and cannot be recovered.\n", invite.InviteID, invite.Label, invite.ExpiresAt)
	return err
}

func confirmMemberInviteRevocation(reader *bufio.Reader, output io.Writer, invite inviteapi.Invite) (bool, error) {
	if err := writeMemberInviteRevocationPreview(output, invite); err != nil {
		return false, err
	}
	if _, err := fmt.Fprint(output, "Continue? [y/N] "); err != nil {
		return false, err
	}
	answer, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func classifyMemberInviteMutation(action, inviteID string, err error) error {
	if err.Error() == localipc.AgentVersionMismatchMessage {
		return err
	}
	var responseError *localipc.Error
	if errors.As(err, &responseError) && trustedMemberInviteError(action, responseError) {
		return err
	}
	return memberInviteOutcomeUnknown(action, inviteID)
}

func trustedMemberInviteError(action string, err *localipc.Error) bool {
	switch err.Code {
	case "invalid_request":
		return err.Status == http.StatusBadRequest
	case string(membership.CodeInviteLabelUnavailable):
		return action == "create" && err.Status == http.StatusConflict
	case string(membership.CodeInviteCapacity):
		return action == "create" && err.Status == http.StatusTooManyRequests
	case string(membership.CodeInviteUnavailable):
		return action == "revoke" && err.Status == http.StatusNotFound
	case agentapi.InviteCodeContextNotFound:
		return err.Status == http.StatusNotFound
	case agentapi.InviteCodeMemberOperationCapacity:
		return err.Status == http.StatusTooManyRequests
	case agentapi.InviteCodeContextDisconnected:
		return err.Status == http.StatusServiceUnavailable
	case agentapi.InviteCodeRequestTimeout:
		return err.Status == http.StatusRequestTimeout
	case agentapi.InviteCodeInvalidContext:
		return err.Status == http.StatusUnprocessableEntity
	case "outcome_unknown":
		return err.Status == http.StatusBadGateway
	default:
		return false
	}
}

func memberInviteOutcomeUnknown(action, inviteID string) error {
	if action == "create" {
		return contextstate.ErrInviteCreateOutcomeUnknown
	}
	return fmt.Errorf("invite revocation outcome_unknown: revocation of %s may have committed; list active invites before deciding whether another action is needed", inviteID)
}

func newDevicesCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	devices := &cobra.Command{Use: "devices", Short: "Inspect and approve devices in the selected context"}
	devices.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	devices.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List active enrolled members",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				contextName, client, err := selectedContextClient(ctx, streams, opts)
				if err != nil {
					return err
				}
				members := make([]contextstate.Device, 0)
				if err := client.JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(contextName)+"/members", nil, &members); err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(members)
				}
				for _, member := range members {
					if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%s\t%s\n", member.Label, member.DeviceID, member.Status, strings.Join(member.Aliases, ",")); err != nil {
						return err
					}
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "pending",
			Short: "List pending enrollment requests",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				contextName, client, err := selectedContextClient(ctx, streams, opts)
				if err != nil {
					return err
				}
				pending := make([]contextstate.PendingDevice, 0)
				if err := client.JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(contextName)+"/devices/pending", nil, &pending); err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(pending)
				}
				for _, device := range pending {
					if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%s\n", device.Code, device.Label, device.DeviceID); err != nil {
						return err
					}
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "approve CODE",
			Short: "Approve one pending enrollment",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				code, err := membership.NormalizeApprovalCode(args[0])
				if err != nil {
					return err
				}
				contextName, client, err := selectedContextClient(ctx, streams, opts)
				if err != nil {
					return err
				}
				var member contextstate.Device
				if err := client.JSON(ctx, "POST", "/v1/contexts/"+url.PathEscape(contextName)+"/devices/approve", agentapi.ApproveDeviceRequest{Code: code}, &member); err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(member)
				}
				_, err = fmt.Fprintf(streams.Out, "approved %s (%s)\n", member.Label, member.DeviceID)
				return err
			},
		},
	)
	return devices
}

func selectedContextClient(ctx context.Context, streams IOStreams, opts *rootOptions) (string, *localipc.Client, error) {
	contextName, err := selectedContext(ctx, streams, opts)
	if err != nil {
		return "", nil, err
	}
	paths, _, err := prepare(streams, opts)
	if err != nil {
		return "", nil, err
	}
	return contextName, localipc.NewAgentClient(paths.AgentEndpoint), nil
}

func newStartupCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "startup",
		Short: "Manage per-user agent startup",
		Long:  "Install and manage PX as a per-user systemd service, LaunchAgent, or Windows logon task.",
	}
	for _, action := range []string{"install", "start", "stop", "restart", "status", "upgrade", "uninstall"} {
		action := action
		command.AddCommand(&cobra.Command{
			Use:   action,
			Short: startupDescription(action),
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				paths, _, err := prepare(streams, opts)
				if err != nil {
					return err
				}
				lock, err := acquireStartupLock(ctx)
				if err != nil {
					return err
				}
				defer lock.Stop(context.Background())
				plan, err := startup.CurrentPlan(paths.Root)
				if err != nil {
					return err
				}
				_, err = startup.Execute(ctx, plan, action, nil)
				if err != nil {
					return err
				}
				if action == "status" {
					_, err = fmt.Fprintln(streams.Out, "PX per-user startup is active")
				} else {
					_, err = fmt.Fprintf(streams.Out, "PX per-user startup %s complete; PX state was preserved\n", action)
				}
				return err
			},
		})
	}
	return command
}

func startupDescription(action string) string {
	switch action {
	case "install":
		return "Install and start per-user agent startup"
	case "upgrade":
		return "Reinstall and restart after replacing the PX binary"
	case "uninstall":
		return "Remove per-user startup without deleting PX state"
	default:
		return strings.ToUpper(action[:1]) + action[1:] + " the per-user PX agent"
	}
}

func newDoctorCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var localOnly, jsonOutput bool
	var peer string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local, context, and direct peer health",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if localOnly && peer != "" {
				return errors.New("--local and --peer cannot be combined")
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			client := localipc.NewAgentClient(paths.AgentEndpoint)
			statusContext, cancelStatus := context.WithTimeout(ctx, time.Second)
			var agentStatus agentapi.Status
			statusErr := client.JSON(statusContext, "GET", "/v1/status", nil, &agentStatus)
			cancelStatus()
			agentReachable := statusErr == nil
			if statusErr != nil && !errors.Is(statusErr, localipc.ErrAgentUnavailable) {
				return statusErr
			}
			if agentReachable {
				if err := validateAgentIPCVersion(agentStatus.Version); err != nil {
					return err
				}
			}
			var states []contextstate.State
			if agentReachable {
				_ = client.JSON(ctx, "GET", "/v1/contexts", nil, &states)
			}
			selected := opts.context
			if selected == "" {
				selected = os.Getenv("PX_CONTEXT")
			}
			roots := make([]diagnostics.Root, 0, len(states)*2)
			for _, state := range states {
				if selected != "" && state.Name != selected {
					continue
				}
				roots = append(roots,
					diagnostics.Root{Context: state.Name, Kind: "offered", Path: state.OfferedRoot, Scope: state.OfferedRootScope, Revision: state.OfferedRootRevision, FilesystemRootAcknowledged: state.FilesystemRootAcknowledged, AuthorityValid: state.OfferedRootAuthorityValid},
					diagnostics.Root{Context: state.Name, Kind: "inbox", Path: state.InboxRoot},
				)
				if state.PutRoot != nil {
					roots = append(roots, diagnostics.Root{Context: state.Name, Kind: "put", Path: *state.PutRoot, Revision: state.PutRootRevision, AuthorityValid: state.PutRootAuthorityValid})
				}
			}
			checks := diagnostics.Local(paths, agentReachable, roots)
			startupPlan, startupErr := startup.CurrentPlan(paths.Root)
			if startupErr != nil {
				checks = append(checks, diagnostics.Check{ID: "local.startup", Layer: "local", Status: diagnostics.Fail, Summary: "per-user startup configuration could not be inspected"})
			} else {
				startupStatus, summary := startup.InspectRuntime(ctx, startupPlan, nil)
				checks = append(checks, diagnostics.Check{ID: "local.startup", Layer: "local", Status: startupStatus, Summary: summary})
			}
			if !localOnly {
				if !agentReachable {
					checks = append(checks, diagnostics.Check{ID: "context.prerequisite", Layer: "context", Context: selected, Status: diagnostics.Skipped, Summary: "agent reachability prerequisite failed"})
				} else {
					var contextChecks []diagnostics.Check
					request := agentapi.ContextDiagnosticsRequest{Context: selected}
					if err := client.JSON(ctx, "POST", "/v1/doctor/contexts", request, &contextChecks); err != nil {
						checks = append(checks, diagnostics.Check{ID: "context.request", Layer: "context", Context: selected, Status: diagnostics.Fail, Summary: "context diagnostics request failed"})
					} else {
						checks = append(checks, contextChecks...)
					}
				}
			}
			if peer != "" {
				if selected == "" && agentReachable {
					var current struct {
						Name string `json:"name"`
					}
					if client.JSON(ctx, "GET", "/v1/default-context", nil, &current) == nil {
						selected = current.Name
					}
				}
				if !agentReachable || selected == "" || !diagnosticPrerequisitesPass(checks, selected) {
					checks = append(checks, diagnostics.Check{ID: "peer.direct", Layer: "peer", Context: selected, Peer: peer, Status: diagnostics.Skipped, Summary: "context enrollment and control prerequisites failed"})
				} else {
					var check diagnostics.Check
					request := agentapi.PeerDiagnosticRequest{Context: selected, Peer: peer, Timeout: timeout}
					if err := client.JSON(ctx, "POST", "/v1/doctor/peer", request, &check); err != nil {
						check = diagnostics.Check{ID: "peer.direct", Layer: "peer", Context: selected, Peer: peer, Status: diagnostics.Fail, Summary: "peer diagnostic request failed"}
					}
					checks = append(checks, check)
				}
			}
			diagnostics.Sort(checks)
			report := diagnostics.New(checks)
			if jsonOutput {
				if err := json.NewEncoder(streams.Out).Encode(report); err != nil {
					return err
				}
			} else if outputIsTerminal(streams.Out) {
				if err := renderDoctorTTY(streams.Out, report); err != nil {
					return err
				}
			} else {
				for _, check := range report.Checks {
					scope := check.Layer
					if check.Context != "" {
						scope += "/" + check.Context
					}
					if check.Peer != "" {
						scope += "/" + check.Peer
					}
					summary := check.Summary
					if check.HeartbeatRTT > 0 {
						summary += fmt.Sprintf("; heartbeat RTT %s", check.HeartbeatRTT.Round(time.Millisecond))
					}
					if check.LocalAddress != "" && check.RemoteAddress != "" {
						summary += fmt.Sprintf(" via %s/%s %s -> %s connect=%s relay=%t", check.LocalCandidateType, check.RemoteCandidateType, check.LocalAddress, check.RemoteAddress, check.SetupDuration.Round(time.Millisecond), relayUsed(check))
					}
					if _, err := fmt.Fprintf(streams.Out, "[%s] %s %s: %s\n", check.Status, scope, check.ID, summary); err != nil {
						return err
					}
				}
			}
			if report.Status == diagnostics.Fail {
				return markErrorReported(errors.New("diagnostic checks failed"))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&localOnly, "local", false, "run only local checks without remote network work")
	cmd.Flags().StringVar(&peer, "peer", "", "run an authenticated direct probe to one peer")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "direct peer probe timeout")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit a versioned JSON report")
	return cmd
}

func diagnosticPrerequisitesPass(checks []diagnostics.Check, contextName string) bool {
	enrollment, control := false, false
	for _, check := range checks {
		if check.Context != contextName || check.Status != diagnostics.Pass {
			continue
		}
		switch check.ID {
		case "context.enrollment":
			enrollment = true
		case "context.control":
			control = true
		}
	}
	return enrollment && control
}

func newListOfferedCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "ls PEER [PATH]",
		Short: "List one directory beneath a peer's offered root",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			contextName, err := selectedContext(ctx, streams, opts)
			if err != nil {
				return err
			}
			path := ""
			if len(args) == 2 {
				path = args[1]
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			var entries []offered.Entry
			request := agentapi.ListOfferedRequest{Context: contextName, Peer: args[0], Path: path}
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/offered/list", request, &entries); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(entries)
			}
			for _, entry := range entries {
				if _, err := fmt.Fprintf(streams.Out, "%s\t%d\t%s\n", entry.Kind, entry.Size, entry.Name); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	return cmd
}

func newGetOfferedCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var output string
	var maxFileBytes int64
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "get PEER PATH",
		Short: "Get one file from a peer's offered root",
		Long: "Get one file from a peer's offered root and publish it at a local path. " +
			"The verified file is published exclusively and never replaces an existing entry. " +
			"On collision, choose another --output or move or remove the local entry before retrying. " +
			"Get does not retain resume state: after interruption or agent restart, rerunning starts at byte zero. " +
			"The destination parent must prevent other unprivileged accounts from replacing entries; unsafe shared directories are unsupported. " +
			"PX durably cleans its owner-only hidden .px-<64 hex>.get staging directory on handled failure or a later get to the same parent; startup only resets DB leases. " +
			"At most 64 cleanup rows and 4 GiB of declared data are retained; unavailable paths remain quota-charged until safely resolved.",
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			contextName, err := selectedContext(ctx, streams, opts)
			if err != nil {
				return err
			}
			destination := output
			if destination == "" {
				destination = filepath.Base(filepath.FromSlash(args[1]))
			}
			destination, err = filepath.Abs(destination)
			if err != nil {
				return err
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			request := agentapi.GetOfferedRequest{Context: contextName, Peer: args[0], Path: args[1], Destination: destination, MaxFileBytes: maxFileBytes}
			renderer := newProgressRenderer(streams.Out, outputIsTerminal(streams.Out))
			terminal := offered.GetEvent{}
			err = localipc.NewAgentClient(paths.AgentEndpoint).StreamJSON(ctx, "POST", "/v1/offered/get", request, func(data json.RawMessage) error {
				var event offered.GetEvent
				if err := json.Unmarshal(data, &event); err != nil || event.Version != offered.GetEventVersion {
					return errors.New("agent emitted an invalid get event")
				}
				terminal = event
				if jsonOutput {
					_, err := streams.Out.Write(append(data, '\n'))
					return err
				}
				return renderer.Render(progressUpdate{State: event.State, Bytes: event.Bytes, Total: event.Total, Error: event.Error})
			})
			if err != nil {
				return err
			}
			if terminal.State == "failed" {
				return errors.New(terminal.Error)
			}
			if terminal.State != "committed" {
				return errors.New("get ended without a terminal event")
			}
			if terminal.CleanupPending {
				return errors.New("get committed; durable staging cleanup remains pending")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "local destination path, which must not already exist")
	cmd.Flags().Int64Var(&maxFileBytes, "max-file-bytes", offered.DefaultMaxFileBytes, "maximum received file size")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	return cmd
}

func newJoinCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var label, offeredRoot, inboxRoot, putRoot string
	var stunURLs []string
	var wait, jsonOutput, noSTUN, allowFilesystemRoot, allowPut bool
	cmd := &cobra.Command{
		Use:   "join [SERVER]",
		Short: "Create or resume an agent-managed context enrollment",
		Args: func(command *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(command, args); err != nil {
				return err
			}
			if len(args) == 0 && DefaultServerURL == "" {
				return errors.New("SERVER is required by this build")
			}
			return validateSTUNCreationFlags(command, noSTUN)
		},
		RunE: func(command *cobra.Command, args []string) error {
			if label == "" {
				return errors.New("--name is required")
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			contextName := opts.context
			if contextName == "" {
				contextName = os.Getenv("PX_CONTEXT")
			}
			if contextName == "" {
				contextName = "default"
			}
			serverURL := DefaultServerURL
			if len(args) == 1 {
				serverURL = args[0]
			}
			client := localipc.NewAgentClient(paths.AgentEndpoint)
			request := contextstate.JoinRequest{Name: contextName, ServerURL: serverURL, Label: label, OfferedRoot: offeredRoot, InboxRoot: inboxRoot, STUNURLs: stunURLs, DefaultSTUN: !noSTUN && !command.Flags().Changed("stun"), NoSTUN: noSTUN, AllowFilesystemRoot: allowFilesystemRoot, AllowPut: allowPut, AllowPutSet: command.Flags().Changed("allow-put")}
			if command.Flags().Changed("put-root") {
				request.PutRoot = &putRoot
			}
			var state contextstate.State
			if err := client.JSON(ctx, "POST", "/v1/contexts/join", request, &state); err != nil {
				return err
			}
			if err := writeContextState(streams, jsonOutput, state, true); err != nil {
				return err
			}
			if !wait || state.State != "pending" {
				return terminalJoinError(state)
			}
			lastState, lastCode := state.State, state.PendingCode
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					if err := client.JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(contextName), nil, &state); err != nil {
						return err
					}
					if state.State != lastState || state.PendingCode != lastCode {
						if err := writeContextState(streams, jsonOutput, state, false); err != nil {
							return err
						}
						lastState, lastCode = state.State, state.PendingCode
					}
					if state.State != "pending" {
						return terminalJoinError(state)
					}
				}
			}
		},
	}
	cmd.Flags().StringVar(&label, "name", "", "device label requested from the server")
	cmd.Flags().StringVar(&offeredRoot, "offered-root", "", "native root offered to remote peers")
	cmd.Flags().BoolVar(&allowFilesystemRoot, "allow-filesystem-root", false, "acknowledge dangerous filesystem-root exposure")
	cmd.Flags().StringVar(&inboxRoot, "inbox-root", "", "native root for received files")
	cmd.Flags().StringVar(&putRoot, "put-root", "", "existing canonical narrow root for remote put")
	cmd.Flags().BoolVar(&allowPut, "allow-put", false, "allow every authenticated context member to create files and request supported replacement beneath put root")
	cmd.Flags().StringSliceVar(&stunURLs, "stun", nil, "context STUN URL (repeatable, maximum four)")
	cmd.Flags().BoolVar(&noSTUN, "no-stun", false, "create the context without a STUN service")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for approval or expiration")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON state events")
	return cmd
}

func newContextCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{Use: "context", Short: "Manage agent contexts"}
	command.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit JSON output")
	command.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List configured contexts",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				paths, _, err := prepare(streams, opts)
				if err != nil {
					return err
				}
				var states []contextstate.State
				if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", "/v1/contexts", nil, &states); err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(states)
				}
				for _, state := range states {
					status := contextListStatus(state)
					if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%s\n", state.Name, state.Label, status); err != nil {
						return err
					}
				}
				return nil
			},
		},
		newContextShowCommand(ctx, streams, opts, &jsonOutput),
		newContextConfigureCommand(ctx, streams, opts, &jsonOutput),
		&cobra.Command{
			Use:   "current",
			Short: "Print the selected context",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				name, err := selectedContext(ctx, streams, opts)
				if err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(map[string]string{"name": name})
				}
				_, err = fmt.Fprintln(streams.Out, name)
				return err
			},
		},
		&cobra.Command{
			Use:   "default NAME",
			Short: "Set the default context",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				paths, _, err := prepare(streams, opts)
				if err != nil {
					return err
				}
				request := map[string]string{"name": args[0]}
				if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/default-context", request, &request); err != nil {
					return err
				}
				if jsonOutput {
					return json.NewEncoder(streams.Out).Encode(request)
				}
				_, err = fmt.Fprintln(streams.Out, args[0])
				return err
			},
		},
		newContextEnabledCommand(ctx, streams, opts, &jsonOutput, false),
		newContextEnabledCommand(ctx, streams, opts, &jsonOutput, true),
		newContextRemoveCommand(ctx, streams, opts, &jsonOutput),
		newContextAliasCommand(ctx, streams, opts, &jsonOutput),
	)
	return command
}

func contextListStatus(state contextstate.State) string {
	status := state.State
	if !state.Enabled {
		status = "disabled"
	}
	if !state.OfferedRootAuthorityValid {
		return status + " FAILURE: inconsistent offered-root authority"
	}
	if state.AllowPut && !state.PutRootAuthorityValid {
		return status + " FAILURE: invalid put authority"
	}
	if state.AllowPut {
		status += " WARNING: remote put enabled"
	}
	if state.OfferedRootScope == contextstate.OfferedRootScopeFilesystemRoot {
		return status + " WARNING: filesystem-root authority"
	}
	return status
}

func newContextEnabledCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool, enabled bool) *cobra.Command {
	action := "disable"
	description := "Disable a context without deleting its identity"
	if enabled {
		action = "enable"
		description = "Enable a disabled context"
	}
	return &cobra.Command{
		Use:   action + " NAME",
		Short: description,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			var state contextstate.State
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/contexts/"+url.PathEscape(args[0])+"/"+action, nil, &state); err != nil {
				return err
			}
			if *jsonOutput {
				return json.NewEncoder(streams.Out).Encode(state)
			}
			_, err = fmt.Fprintf(streams.Out, "%s\t%s\n", state.Name, action+"d")
			return err
		},
	}
}

func newContextRemoveCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool) *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove local context identity and configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if !yes {
				input, ok := streams.In.(*os.File)
				if !ok || !term.IsTerminal(int(input.Fd())) {
					return errors.New("context removal requires --yes when input is not a terminal")
				}
				if err := writeContextRemovalPrompt(streams.Err, args[0]); err != nil {
					return err
				}
				answer, err := bufio.NewReader(streams.In).ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer != "y" && answer != "yes" {
					return errors.New("context removal cancelled")
				}
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			result := map[string]string{}
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "DELETE", "/v1/contexts/"+url.PathEscape(args[0]), nil, &result); err != nil {
				return err
			}
			if *jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "%s\tremoved locally; server membership unchanged\n", args[0])
			return err
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm noninteractive context removal")
	return command
}

func writeContextRemovalPrompt(output io.Writer, contextName string) error {
	_, err := fmt.Fprintf(output, "Remove context %q locally? Offered, inbox, and put-root visible files remain unchanged. [y/N] ", contextName)
	return err
}

func newContextAliasCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool) *cobra.Command {
	alias := &cobra.Command{Use: "alias", Short: "Manage context-local peer aliases"}
	alias.AddCommand(
		&cobra.Command{
			Use:   "set ALIAS TARGET",
			Short: "Set one alias in the selected context",
			Args:  cobra.ExactArgs(2),
			RunE: func(_ *cobra.Command, args []string) error {
				name, err := selectedContext(ctx, streams, opts)
				if err != nil {
					return err
				}
				paths, _, err := prepare(streams, opts)
				if err != nil {
					return err
				}
				request := map[string]string{"context": name, "alias": args[0], "target": args[1]}
				response := map[string]string{}
				if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/contexts/alias", request, &response); err != nil {
					return err
				}
				value := contextstate.Alias{Name: response["alias"], Target: response["target"]}
				if *jsonOutput {
					return json.NewEncoder(streams.Out).Encode(value)
				}
				_, err = fmt.Fprintf(streams.Out, "%s=%s\n", value.Name, value.Target)
				return err
			},
		},
		newContextAliasReadCommand(ctx, streams, opts, jsonOutput, "list"),
		newContextAliasReadCommand(ctx, streams, opts, jsonOutput, "show"),
		newContextAliasReadCommand(ctx, streams, opts, jsonOutput, "remove"),
	)
	return alias
}

func newContextAliasReadCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool, action string) *cobra.Command {
	use, short := action, "List aliases in the selected context"
	args := cobra.NoArgs
	method := "GET"
	if action != "list" {
		use = action + " ALIAS"
		args = cobra.ExactArgs(1)
		short = strings.ToUpper(action[:1]) + action[1:] + " one alias in the selected context"
	}
	if action == "remove" {
		method = "DELETE"
	}
	return &cobra.Command{
		Use: use, Short: short, Args: args,
		RunE: func(_ *cobra.Command, values []string) error {
			name, err := selectedContext(ctx, streams, opts)
			if err != nil {
				return err
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			path := "/v1/contexts/" + url.PathEscape(name) + "/aliases"
			if action == "list" {
				result := make([]contextstate.Alias, 0)
				if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, method, path, nil, &result); err != nil {
					return err
				}
				if *jsonOutput {
					return json.NewEncoder(streams.Out).Encode(result)
				}
				for _, value := range result {
					if _, err := fmt.Fprintf(streams.Out, "%s=%s\n", value.Name, value.Target); err != nil {
						return err
					}
				}
				return nil
			}
			path += "/" + url.PathEscape(values[0])
			var result contextstate.Alias
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, method, path, nil, &result); err != nil {
				return err
			}
			if *jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "%s=%s\n", result.Name, result.Target)
			return err
		},
	}
}

func newContextShowCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool) *cobra.Command {
	return &cobra.Command{
		Use: "show [NAME]", Short: "Show redacted effective context configuration", Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name, err := contextArgument(ctx, streams, opts, args)
			if err != nil {
				return err
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			var configuration contextstate.Configuration
			path := "/v1/contexts/" + url.PathEscape(name) + "/configuration"
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", path, nil, &configuration); err != nil {
				return err
			}
			return writeContextConfiguration(streams, *jsonOutput, configuration)
		},
	}
}

func newContextConfigureCommand(ctx context.Context, streams IOStreams, opts *rootOptions, jsonOutput *bool) *cobra.Command {
	var offeredRoot, inboxRoot, putRoot string
	var stunURLs []string
	var clearSTUN, allowFilesystemRoot, clearPutRoot, allowPut bool
	command := &cobra.Command{
		Use: "configure [NAME]", Short: "Update context roots or replace ordered STUN URLs", Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if clearSTUN && command.Flags().Changed("stun") {
				return errors.New("--clear-stun and --stun cannot be combined")
			}
			request := contextstate.UpdateRequest{}
			if command.Flags().Changed("put-root") {
				root, err := filepath.Abs(putRoot)
				if err != nil {
					return fmt.Errorf("put root: %w", err)
				}
				root = filepath.Clean(root)
				request.PutRoot = &root
			}
			request.ClearPutRoot = clearPutRoot
			if command.Flags().Changed("allow-put") {
				request.AllowPut = &allowPut
			}
			if command.Flags().Changed("offered-root") {
				if err := contextstate.ValidateOfferedRootPath(offeredRoot); err != nil {
					return fmt.Errorf("offered root: %w", err)
				}
				root, err := filepath.Abs(offeredRoot)
				if err != nil {
					return fmt.Errorf("offered root: %w", err)
				}
				root = filepath.Clean(root)
				request.OfferedRoot = &root
				request.AllowFilesystemRoot = allowFilesystemRoot
			} else if allowFilesystemRoot {
				return errors.New("--allow-filesystem-root requires --offered-root")
			}
			if command.Flags().Changed("inbox-root") {
				root, err := filepath.Abs(inboxRoot)
				if err != nil {
					return fmt.Errorf("inbox root: %w", err)
				}
				root = filepath.Clean(root)
				request.InboxRoot = &root
			}
			if command.Flags().Changed("stun") || clearSTUN {
				values := append([]string(nil), stunURLs...)
				if clearSTUN {
					values = []string{}
				}
				request.STUNURLs = &values
			}
			if request.OfferedRoot == nil && request.InboxRoot == nil && request.STUNURLs == nil && request.PutRoot == nil && !request.ClearPutRoot && request.AllowPut == nil {
				return errors.New("at least one root, put-policy, or STUN option is required")
			}
			name, err := contextArgument(ctx, streams, opts, args)
			if err != nil {
				return err
			}
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			var configuration contextstate.Configuration
			path := "/v1/contexts/" + url.PathEscape(name) + "/configuration"
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "PUT", path, request, &configuration); err != nil {
				return err
			}
			return writeContextConfiguration(streams, *jsonOutput, configuration)
		},
	}
	command.Flags().StringVar(&offeredRoot, "offered-root", "", "absolute or working-directory-relative offered root")
	command.Flags().BoolVar(&allowFilesystemRoot, "allow-filesystem-root", false, "acknowledge dangerous filesystem-root exposure")
	command.Flags().StringVar(&inboxRoot, "inbox-root", "", "absolute or working-directory-relative inbox root")
	command.Flags().StringVar(&putRoot, "put-root", "", "existing canonical narrow root for remote put")
	command.Flags().BoolVar(&clearPutRoot, "clear-put-root", false, "clear the put root while put is disabled")
	command.Flags().BoolVar(&allowPut, "allow-put", false, "enable or disable remote put (use --allow-put=false to disable)")
	command.Flags().StringSliceVar(&stunURLs, "stun", nil, "replacement STUN URL (repeatable, maximum four)")
	command.Flags().BoolVar(&clearSTUN, "clear-stun", false, "replace the STUN URL list with an empty list")
	return command
}

func contextArgument(ctx context.Context, streams IOStreams, opts *rootOptions, args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}
	return selectedContext(ctx, streams, opts)
}

func writeContextConfiguration(streams IOStreams, jsonOutput bool, configuration contextstate.Configuration) error {
	if jsonOutput {
		return json.NewEncoder(streams.Out).Encode(configuration)
	}
	fields := []struct{ name, value string }{
		{"name", configuration.Name},
		{"is_default", fmt.Sprint(configuration.IsDefault)},
		{"server_origin", configuration.ServerOrigin},
		{"server_id", configuration.ServerID},
		{"device_id", configuration.DeviceID},
		{"label", configuration.Label},
		{"enabled", fmt.Sprint(configuration.Enabled)},
		{"state", configuration.State},
		{"offered_root", configuration.OfferedRoot},
		{"offered_root_scope", configuration.OfferedRootScope},
		{"offered_root_revision", fmt.Sprint(configuration.OfferedRootRevision)},
		{"filesystem_root_acknowledged", fmt.Sprint(configuration.FilesystemRootAcknowledged)},
		{"offered_root_authority_valid", fmt.Sprint(configuration.OfferedRootAuthorityValid)},
		{"inbox_root", configuration.InboxRoot},
		{"put_root", optionalDisplay(configuration.PutRoot)},
		{"allow_put", fmt.Sprint(configuration.AllowPut)},
		{"put_root_revision", fmt.Sprint(configuration.PutRootRevision)},
		{"put_root_authority_valid", fmt.Sprint(configuration.PutRootAuthorityValid)},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(streams.Out, "%s\t%s\n", field.name, field.value); err != nil {
			return err
		}
	}
	for _, value := range configuration.STUNURLs {
		if _, err := fmt.Fprintf(streams.Out, "stun_url\t%s\n", value); err != nil {
			return err
		}
	}
	if len(configuration.STUNURLs) == 0 {
		if _, err := fmt.Fprintln(streams.Out, "stun_urls\t[]"); err != nil {
			return err
		}
	}
	for _, value := range configuration.Aliases {
		if _, err := fmt.Fprintf(streams.Out, "alias\t%s=%s\n", value.Name, value.Target); err != nil {
			return err
		}
	}
	if len(configuration.Aliases) == 0 {
		if _, err := fmt.Fprintln(streams.Out, "aliases\t[]"); err != nil {
			return err
		}
	}
	for _, warning := range configuration.Warnings {
		if _, err := fmt.Fprintf(streams.Err, "warning: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func selectedContext(ctx context.Context, streams IOStreams, opts *rootOptions) (string, error) {
	if opts.context != "" {
		return opts.context, nil
	}
	if value := os.Getenv("PX_CONTEXT"); value != "" {
		return value, nil
	}
	paths, _, err := prepare(streams, opts)
	if err != nil {
		return "", err
	}
	var result struct {
		Name string `json:"name"`
	}
	if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "GET", "/v1/default-context", nil, &result); err != nil {
		return "", err
	}
	return result.Name, nil
}

func writeContextState(streams IOStreams, jsonOutput bool, state contextstate.State, approvalGuidance bool) error {
	if state.OfferedRootScope == contextstate.OfferedRootScopeFilesystemRoot {
		if _, err := fmt.Fprintln(streams.Err, "warning: DANGER: this context offers the filesystem root to every authenticated member"); err != nil {
			return err
		}
	}
	if jsonOutput {
		return json.NewEncoder(streams.Out).Encode(state)
	}
	if state.State == "pending" {
		if _, err := fmt.Fprintf(streams.Out, "%s: pending approval %s\n", state.Name, state.PendingCode); err != nil {
			return err
		}
		if approvalGuidance {
			_, err := fmt.Fprintf(streams.Out, "Approve on an existing device: px --context %s devices approve %s\nFirst device or recovery: px-server devices approve %s\n", state.Name, state.PendingCode, state.PendingCode)
			return err
		}
		return nil
	}
	_, err := fmt.Fprintf(streams.Out, "%s: %s\n", state.Name, state.State)
	return err
}

func terminalJoinError(state contextstate.State) error {
	switch state.State {
	case "expired":
		return errors.New("enrollment expired")
	case "revoked":
		return errors.New("membership revoked")
	default:
		return nil
	}
}

func newIPCProbeCommand(ctx context.Context, streams IOStreams, rootOpts *rootOptions) *cobra.Command {
	request := &agentapi.ProbeRequest{}
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:    "probe",
		Short:  "Run a direct connectivity probe through the local agent",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := prepare(streams, rootOpts)
			if err != nil {
				return err
			}
			var result probe.Result
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(ctx, "POST", "/v1/probe", request, &result); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "direct probe succeeded: setup %s health RTT %s via %s/%s %s -> %s\n", result.SetupDuration.Round(time.Millisecond), result.HealthRTT.Round(time.Millisecond), result.CandidateType, result.RemoteType, result.LocalAddress, result.RemoteAddress)
			return err
		},
	}
	addIPCConnectionFlags(cmd, &request.ConnectionRequest)
	cmd.Flags().BoolVar(&request.Offer, "offer", false, "act as the offering peer")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	return cmd
}

func newIPCSendCommand(ctx context.Context, streams IOStreams, rootOpts *rootOptions) *cobra.Command {
	var name, retryID string
	var stdinInput, public, recoverable, jsonOutput bool
	var maxFileBytes int64
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "send PEER [FILE]",
		Short: "Send one file through the local PX agent",
		Long: "Send one file through the local PX agent. The default fast mode writes directly to the visible destination without hashing, syncing, atomic staging, cleanup, or retry state; interruption can leave a partial file that must be removed or renamed manually. " +
			"Use --recoverable for verified atomic publication and retry state. Private sends use the peer's namespaced inbox; --public uses the peer's offered-root basename. Neither mode replaces an existing entry.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			if maxFileBytes <= 0 || maxFileBytes > transfer.DefaultMaxFileBytes || timeout <= 0 {
				return errors.New("--max-file-bytes and --timeout must be within supported positive limits")
			}
			if stdinInput && (len(args) != 1 || name == "" || retryID != "") {
				return errors.New("--stdin requires --name and cannot be combined with FILE or --retry")
			}
			if retryID != "" && (len(args) != 1 || stdinInput || name != "" || public || recoverable) {
				return errors.New("--retry cannot be combined with FILE, --stdin, --name, --public, or --recoverable")
			}
			if !stdinInput && retryID == "" && len(args) != 2 {
				return errors.New("FILE, --stdin, or --retry is required")
			}
			paths, _, err := prepare(streams, rootOpts)
			if err != nil {
				return err
			}
			contextName, err := selectedContext(ctx, streams, rootOpts)
			if err != nil {
				return err
			}
			request := agentapi.ContextSendRequest{Context: contextName, Peer: args[0], Name: name, TransferID: retryID, Public: public, Recoverable: recoverable || retryID != "", MaxFileBytes: maxFileBytes}
			if stdinInput {
				request.Source, err = spoolInput(streams.In, paths.AgentTransfers, maxFileBytes)
				if err != nil {
					return err
				}
				request.StdinSpool = true
			} else if retryID == "" {
				request.Source, err = filepath.Abs(args[1])
				if err != nil {
					return err
				}
			}
			return submitContextSend(ctx, streams, paths.AgentEndpoint, request, timeout, jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&stdinInput, "stdin", false, "spool standard input before submitting")
	cmd.Flags().StringVar(&name, "name", "", "portable destination filename, which must not already exist")
	cmd.Flags().StringVar(&retryID, "retry", "", "retry a persisted transfer ID")
	cmd.Flags().BoolVar(&public, "public", false, "publish exclusively at the peer offered-root basename")
	cmd.Flags().BoolVar(&recoverable, "recoverable", false, "use verified atomic publication and retain retry state")
	cmd.Flags().Int64Var(&maxFileBytes, "max-file-bytes", transfer.DefaultMaxFileBytes, "maximum source or stdin spool size")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "complete transfer timeout")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	return cmd
}

const maxTextBytes int64 = 64 << 10

func newIPCTextCommand(ctx context.Context, streams IOStreams, rootOpts *rootOptions) *cobra.Command {
	var name string
	var timeout time.Duration
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "text PEER [TEXT]",
		Short: "Send text as a private inbox file",
		Long:  "Send literal text or piped standard input as a bounded .txt file in the peer's namespaced inbox using verified atomic recoverable delivery. This is asynchronous file delivery, not chat.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			if timeout <= 0 {
				return errors.New("--timeout must be positive")
			}
			if name == "" {
				var err error
				name, err = textDestinationName(time.Now(), rand.Reader)
				if err != nil {
					return err
				}
			}
			if err := transfer.ValidatePortableName(name); err != nil {
				return fmt.Errorf("destination name: %w", err)
			}
			paths, _, err := prepare(streams, rootOpts)
			if err != nil {
				return err
			}
			contextName, err := selectedContext(ctx, streams, rootOpts)
			if err != nil {
				return err
			}
			input := streams.In
			if len(args) == 2 {
				input = strings.NewReader(args[1])
			}
			source, err := spoolInput(input, paths.AgentTransfers, maxTextBytes)
			if err != nil {
				return err
			}
			request := agentapi.ContextSendRequest{Context: contextName, Peer: args[0], Source: source, Name: name, StdinSpool: true, Recoverable: true, MaxFileBytes: maxTextBytes}
			return submitContextSend(ctx, streams, paths.AgentEndpoint, request, timeout, jsonOutput)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "portable destination filename, which must not already exist")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "complete transfer timeout")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	return cmd
}

func textDestinationName(now time.Time, random io.Reader) (string, error) {
	data := make([]byte, 4)
	if _, err := io.ReadFull(random, data); err != nil {
		return "", fmt.Errorf("generate text destination name: %w", err)
	}
	return "pxmsg-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(data) + ".txt", nil
}

func submitContextSend(ctx context.Context, streams IOStreams, endpoint string, request agentapi.ContextSendRequest, timeout time.Duration, jsonOutput bool) error {
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	terminal := transfer.ResumeEvent{}
	renderer := newProgressRenderer(streams.Out, outputIsTerminal(streams.Out))
	err := localipc.NewAgentClient(endpoint).StreamJSON(operationContext, "POST", "/v1/context/send", request, func(data json.RawMessage) error {
		var event transfer.ResumeEvent
		if err := json.Unmarshal(data, &event); err != nil || event.Version != transfer.ResumeEventVersion {
			return errors.New("agent emitted an invalid transfer event")
		}
		terminal = event
		if jsonOutput {
			_, err := streams.Out.Write(append(data, '\n'))
			return err
		}
		return renderer.Render(progressUpdate{State: event.State, ID: event.TransferID, Bytes: event.Bytes, Total: event.Total, Error: event.Error})
	})
	if err != nil {
		if shouldRemoveUnsubmittedSpool(request, terminal, err) {
			_ = os.Remove(request.Source)
		}
		return err
	}
	if shouldRemoveUnsubmittedSpool(request, terminal, nil) {
		_ = os.Remove(request.Source)
	}
	if terminal.State == "rejected" || terminal.State == "failed" {
		if terminal.ErrorCode != "" {
			return &localipc.Error{Status: 422, Code: terminal.ErrorCode, Message: terminal.Error}
		}
		return errors.New(terminal.Error)
	}
	if terminal.State != "committed" {
		return errors.New("transfer ended without a terminal event")
	}
	return nil
}

func shouldRemoveUnsubmittedSpool(request agentapi.ContextSendRequest, terminal transfer.ResumeEvent, err error) bool {
	if request.StdinSpool && !request.Recoverable {
		return true
	}
	var responseErr *localipc.Error
	preStreamResponse := errors.As(err, &responseErr)
	definitivePrePersistenceFailure := err == nil && terminal.State == "failed" && terminal.TransferID == ""
	return request.StdinSpool && terminal.TransferID == "" && (preStreamResponse || definitivePrePersistenceFailure)
}

func spoolInput(input io.Reader, directory string, maxBytes int64) (path string, err error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate stdin spool name: %w", err)
	}
	path = filepath.Join(directory, ".stdin-"+hex.EncodeToString(data)+".spool")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create stdin spool: %w", err)
	}
	keep := false
	defer func(spoolPath string) {
		_ = file.Close()
		if !keep {
			_ = os.Remove(spoolPath)
		}
	}(path)
	written, err := io.Copy(file, io.LimitReader(input, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("spool stdin: %w", err)
	}
	if written > maxBytes {
		return "", fmt.Errorf("stdin exceeds %d byte limit", maxBytes)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync stdin spool: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close stdin spool: %w", err)
	}
	keep = true
	return path, nil
}

func addIPCConnectionFlags(cmd *cobra.Command, request *agentapi.ConnectionRequest) {
	cmd.Flags().StringVar(&request.SignalURL, "signal", "", "WebSocket signaling URL")
	cmd.Flags().StringVar(&request.Session, "session", "", "direct session identifier")
	cmd.Flags().StringVar(&request.PrivatePath, "private", "", "local private key path")
	cmd.Flags().StringVar(&request.PeerPublicPath, "peer-public", "", "expected peer public key path")
	cmd.Flags().DurationVar(&request.Timeout, "timeout", 10*time.Minute, "complete operation timeout")
	cmd.Flags().BoolVar(&request.AllowLoopback, "allow-loopback", false, "allow loopback ICE candidates for local tests")
	cmd.Flags().StringSliceVar(&request.STUNURLs, "stun", nil, "external STUN URL (repeatable, maximum four)")
}

func newDebugCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	debug := &cobra.Command{Use: "debug", Short: "Run experimental PX diagnostics"}
	debug.AddCommand(
		newKeygenCommand(streams),
		newProbeCommand(ctx, streams, opts),
		newSendFileCommand(ctx, streams, opts),
		newReceiveFileCommand(ctx, streams, opts),
	)
	return debug
}

func newKeygenCommand(streams IOStreams) *cobra.Command {
	var privatePath, publicPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a manually provisioned probe identity",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if privatePath == "" || publicPath == "" {
				return errors.New("--private and --public are required")
			}
			if err := identity.WriteFiles(privatePath, publicPath); err != nil {
				return err
			}
			_, err := fmt.Fprintln(streams.Out, publicPath)
			return err
		},
	}
	cmd.Flags().StringVar(&privatePath, "private", "", "private key output path")
	cmd.Flags().StringVar(&publicPath, "public", "", "public key output path")
	return cmd
}

func newProbeCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var signalURL, session, privatePath, peerPublicPath string
	var stunURLs []string
	var offer, allowLoopback, jsonOutput bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Establish an authenticated direct DataChannel probe",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if signalURL == "" || session == "" || privatePath == "" || peerPublicPath == "" {
				return errors.New("--signal, --session, --private, and --peer-public are required")
			}
			privateKey, err := identity.LoadPrivate(privatePath)
			if err != nil {
				return err
			}
			peerKey, err := identity.LoadPublic(peerPublicPath)
			if err != nil {
				return err
			}
			_, logger, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			result, err := probe.Run(ctx, probe.Config{
				SignalURL:     signalURL,
				Session:       session,
				PrivateKey:    privateKey,
				PeerKey:       peerKey,
				Offer:         offer,
				Timeout:       timeout,
				AllowLoopback: allowLoopback,
				STUNURLs:      stunURLs,
				Logger:        logger,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "direct probe succeeded: setup %s health RTT %s via %s %s -> %s\n", result.SetupDuration.Round(time.Millisecond), result.HealthRTT.Round(time.Millisecond), result.CandidateType, result.LocalAddress, result.RemoteAddress)
			return err
		},
	}
	cmd.Flags().StringVar(&signalURL, "signal", "", "WebSocket signaling URL")
	cmd.Flags().StringVar(&session, "session", "", "probe session identifier")
	cmd.Flags().StringVar(&privatePath, "private", "", "local private key path")
	cmd.Flags().StringVar(&peerPublicPath, "peer-public", "", "expected peer public key path")
	cmd.Flags().BoolVar(&offer, "offer", false, "act as the offering peer")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "probe timeout")
	cmd.Flags().BoolVar(&allowLoopback, "allow-loopback", false, "allow loopback ICE candidates for local tests")
	cmd.Flags().StringSliceVar(&stunURLs, "stun", nil, "external STUN URL (repeatable, maximum four)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	return cmd
}

type transferOptions struct {
	signalURL      string
	session        string
	privatePath    string
	peerPublicPath string
	timeout        time.Duration
	maxFileBytes   int64
	allowLoopback  bool
	stunURLs       []string
	jsonOutput     bool
}

type directTransferResult struct {
	transfer.Result
	LocalAddress  string   `json:"local_address"`
	RemoteAddress string   `json:"remote_address"`
	CandidateType string   `json:"candidate_type"`
	RemoteType    string   `json:"remote_candidate_type"`
	GatheredTypes []string `json:"gathered_candidate_types"`
}

func newSendFileCommand(ctx context.Context, streams IOStreams, rootOpts *rootOptions) *cobra.Command {
	var source, name string
	opts := &transferOptions{}
	cmd := &cobra.Command{
		Use:   "send-file",
		Short: "Send one file over an authenticated direct connection",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if source == "" {
				return errors.New("--source is required")
			}
			session, logger, cancel, err := connectTransfer(ctx, streams, rootOpts, opts, true)
			if err != nil {
				return err
			}
			defer cancel()
			defer session.Close()
			result, err := transfer.Send(session.Context(), transfer.NewDirectChannel(session), transfer.SendConfig{
				Source:       source,
				Name:         name,
				MaxFileBytes: opts.maxFileBytes,
				Progress:     transferProgress(logger),
			})
			if err != nil {
				return err
			}
			return writeTransferResult(streams, opts.jsonOutput, result, session)
		},
	}
	addTransferFlags(cmd, opts)
	cmd.Flags().StringVar(&source, "source", "", "regular source file path")
	cmd.Flags().StringVar(&name, "name", "", "portable destination filename")
	return cmd
}

func newReceiveFileCommand(ctx context.Context, streams IOStreams, rootOpts *rootOptions) *cobra.Command {
	var inbox, contextName, sender string
	opts := &transferOptions{}
	cmd := &cobra.Command{
		Use:   "receive-file",
		Short: "Receive one file into a controlled inbox",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if inbox == "" || contextName == "" || sender == "" {
				return errors.New("--inbox, --context-name, and --sender are required")
			}
			if err := os.MkdirAll(inbox, 0o700); err != nil {
				return fmt.Errorf("create inbox root: %w", err)
			}
			session, logger, cancel, err := connectTransfer(ctx, streams, rootOpts, opts, false)
			if err != nil {
				return err
			}
			defer cancel()
			defer session.Close()
			result, err := transfer.Receive(session.Context(), transfer.NewDirectChannel(session), transfer.ReceiveConfig{
				InboxRoot:    inbox,
				Context:      contextName,
				Sender:       sender,
				MaxFileBytes: opts.maxFileBytes,
				Progress:     transferProgress(logger),
			})
			if err != nil {
				return err
			}
			return writeTransferResult(streams, opts.jsonOutput, result, session)
		},
	}
	addTransferFlags(cmd, opts)
	cmd.Flags().StringVar(&inbox, "inbox", "", "controlled receiver inbox root")
	cmd.Flags().StringVar(&contextName, "context-name", "", "receiver context namespace")
	cmd.Flags().StringVar(&sender, "sender", "", "authenticated sender label namespace")
	return cmd
}

func addTransferFlags(cmd *cobra.Command, opts *transferOptions) {
	cmd.Flags().StringVar(&opts.signalURL, "signal", "", "WebSocket signaling URL")
	cmd.Flags().StringVar(&opts.session, "session", "", "transfer session identifier")
	cmd.Flags().StringVar(&opts.privatePath, "private", "", "local private key path")
	cmd.Flags().StringVar(&opts.peerPublicPath, "peer-public", "", "expected peer public key path")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 10*time.Minute, "complete transfer timeout")
	cmd.Flags().Int64Var(&opts.maxFileBytes, "max-file-bytes", transfer.DefaultMaxFileBytes, "maximum source or received file size")
	cmd.Flags().BoolVar(&opts.allowLoopback, "allow-loopback", false, "allow loopback ICE candidates for local tests")
	cmd.Flags().StringSliceVar(&opts.stunURLs, "stun", nil, "external STUN URL (repeatable, maximum four)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a JSON result")
}

func connectTransfer(parent context.Context, streams IOStreams, rootOpts *rootOptions, opts *transferOptions, offer bool) (*direct.Session, *slog.Logger, context.CancelFunc, error) {
	if opts.signalURL == "" || opts.session == "" || opts.privatePath == "" || opts.peerPublicPath == "" {
		return nil, nil, nil, errors.New("--signal, --session, --private, and --peer-public are required")
	}
	if opts.timeout <= 0 || opts.maxFileBytes <= 0 {
		return nil, nil, nil, errors.New("--timeout and --max-file-bytes must be positive")
	}
	privateKey, err := identity.LoadPrivate(opts.privatePath)
	if err != nil {
		return nil, nil, nil, err
	}
	peerKey, err := identity.LoadPublic(opts.peerPublicPath)
	if err != nil {
		return nil, nil, nil, err
	}
	_, logger, err := prepare(streams, rootOpts)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, opts.timeout)
	session, err := direct.Connect(ctx, direct.Config{
		SignalURL:        opts.signalURL,
		Session:          opts.session,
		PrivateKey:       privateKey,
		PeerKey:          peerKey,
		Offer:            offer,
		AllowLoopback:    opts.allowLoopback,
		STUNURLs:         opts.stunURLs,
		ChannelLabel:     "px-transfer",
		ChannelProtocol:  transfer.Protocol,
		MaxMessageBytes:  transfer.MaxMessageBytes,
		MessageQueue:     transfer.DefaultQueueDepth,
		MaxBufferedBytes: transfer.DefaultBufferedBytes,
		Logger:           logger,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return session, logger, cancel, nil
}

func transferProgress(logger *slog.Logger) func(int64, int64) {
	var last int64
	return func(completed, total int64) {
		if completed == total || completed-last >= 8<<20 {
			logger.Info("direct file transfer progress", "bytes", completed, "total", total)
			last = completed
		}
	}
}

func writeTransferResult(streams IOStreams, jsonOutput bool, result transfer.Result, session *direct.Session) error {
	pair := session.CandidatePair()
	output := directTransferResult{
		Result:        result,
		LocalAddress:  pair.LocalAddress,
		RemoteAddress: pair.RemoteAddress,
		CandidateType: pair.LocalType,
		RemoteType:    pair.RemoteType,
		GatheredTypes: session.GatheredCandidateTypes(),
	}
	if jsonOutput {
		return json.NewEncoder(streams.Out).Encode(output)
	}
	_, err := fmt.Fprintf(streams.Out, "transferred %d bytes as %s in %s via %s/%s %s -> %s\n", result.Bytes, result.Path, result.Duration.Round(time.Millisecond), pair.LocalType, pair.RemoteType, pair.LocalAddress, pair.RemoteAddress)
	return err
}

func newRootCommand(use, short string, streams IOStreams, opts *rootOptions, contextShorthand string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           use,
		Short:         short,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetIn(streams.In)
	cmd.SetOut(streams.Out)
	cmd.SetErr(streams.Err)
	cmd.PersistentFlags().StringVar(&opts.home, "home", "", "PX application home (overrides PX_HOME)")
	cmd.PersistentFlags().StringVarP(&opts.context, "context", contextShorthand, "", "PX context (overrides PX_CONTEXT and the configured default)")
	cmd.PersistentFlags().CountVarP(&opts.verbosity, "verbose", "v", "increase log verbosity")
	cmd.PersistentFlags().StringVar(&opts.logFormat, "log-format", string(logging.FormatAuto), "log format: auto, text, tint, or json")
	return cmd
}

func newVersionCommand(name string, streams IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintln(streams.Out, versioninfo.String(name))
			return err
		},
	}
}

func newAgentCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	agent := &cobra.Command{Use: "agent", Short: "Manage the local PX agent"}
	var logFile string
	run := &cobra.Command{
		Use:   "run",
		Short: "Run the per-user PX agent",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			agentVerbosity := max(opts.verbosity, 1)
			logger, err := logging.NewLogger(logging.Config{Verbosity: agentVerbosity, Output: streams.Err, Format: logging.Format(opts.logFormat)})
			if err != nil {
				return err
			}
			if logFile != "" {
				if !filepath.IsAbs(logFile) {
					return errors.New("--log-file must be an absolute path")
				}
				if err := os.MkdirAll(filepath.Dir(logFile), 0o700); err != nil {
					return err
				}
				if err := os.Chmod(filepath.Dir(logFile), 0o700); err != nil {
					return err
				}
				output, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					return err
				}
				defer output.Close()
				if err := output.Chmod(0o600); err != nil {
					return err
				}
				logger, err = logging.NewLogger(logging.Config{Verbosity: agentVerbosity, Output: output, Format: logging.Format(opts.logFormat)})
				if err != nil {
					return err
				}
			}
			return apphost.RunAgent(ctx, paths, logger)
		},
	}
	run.Flags().StringVar(&logFile, "log-file", "", "append agent logs to a private file")
	agent.AddCommand(run)
	var jsonOutput bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Report local PX agent status",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var result agentapi.Status
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(requestContext, "GET", "/v1/status", nil, &result); err != nil {
				return err
			}
			if err := validateAgentIPCVersion(result.Version); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err = fmt.Fprintf(streams.Out, "PX agent is running (pid %d, IPC v%d)\n", result.PID, result.Version)
			return err
		},
	}
	status.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop the local PX agent",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var result struct {
				Stopping bool `json:"stopping"`
			}
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(requestContext, "POST", "/v1/shutdown", nil, &result); err != nil {
				return err
			}
			if !result.Stopping {
				return errors.New("PX agent did not accept shutdown request")
			}
			_, err = fmt.Fprintln(streams.Out, "PX agent is stopping")
			return err
		},
	}
	agent.AddCommand(status, stop)
	return agent
}

func prepare(streams IOStreams, opts *rootOptions) (apphome.Paths, *slog.Logger, error) {
	paths, err := apphome.Resolve(opts.home)
	if err != nil {
		return apphome.Paths{}, nil, err
	}
	logger, err := logging.NewLogger(logging.Config{
		Verbosity: opts.verbosity,
		Output:    streams.Err,
		Format:    logging.Format(opts.logFormat),
	})
	if err != nil {
		return apphome.Paths{}, nil, err
	}
	return paths, logger, nil
}
