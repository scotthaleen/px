package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/benchmark"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/transfer"
	"github.com/spf13/cobra"
)

func TestWatchHumanOutputAndStrictValidation(t *testing.T) {
	peer := contextwatch.Peer{DeviceID: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Label: "vm"}
	base := contextwatch.Event{Version: contextwatch.Version, StreamID: strings.Repeat("a", 32), Sequence: 10, ObservedAt: time.Date(2026, 8, 1, 14, 31, 8, 0, time.UTC), Context: "home", Type: contextwatch.ContextConnected, Snapshot: true, Peers: []contextwatch.Peer{peer}}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	validator := watchEventValidator{context: "home"}
	initial, err := validator.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeWatchEvent(&output, initial); err != nil || output.String() != "watching context home (1 peers online)\n" {
		t.Fatalf("initial output = %q, %v", output.String(), err)
	}
	offline := base
	offline.Sequence++
	offline.Snapshot = false
	offline.Peers = nil
	offline.Type = contextwatch.PeerOffline
	offline.Peer = &peer
	data, err = json.Marshal(offline)
	if err != nil {
		t.Fatal(err)
	}
	event, err := validator.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	wantOffline := event.ObservedAt.Local().Format("15:04:05") + "  vm offline\n"
	if err := writeWatchEvent(&output, event); err != nil || output.String() != wantOffline {
		t.Fatalf("peer output = %q, %v", output.String(), err)
	}
	for _, malformed := range [][]byte{
		[]byte(`{"version":1,"stream_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":12,"observed_at":"2026-08-01T14:31:08Z","context":"home","type":"peer.online","peer":{"device_id":"` + peer.DeviceID + `","label":"vm"},"extra":true}`),
		data,
	} {
		if _, err := validator.Decode(malformed); err == nil {
			t.Fatalf("accepted malformed/repeated watch event: %s", malformed)
		}
	}
}

func TestWriteRecentHumanOutput(t *testing.T) {
	snapshot := recent.Snapshot{
		Reporter: recent.Reporter{DeviceID: strings.Repeat("A", 43), Label: "commando"},
		Observations: []recent.Observation{
			{Direction: "receive", Kind: "receiver_published", PeerLabel: "mac", Destination: "foo.bar.txt", Visibility: "private", TransferID: strings.Repeat("a", 64), Bytes: 11, ObservedAt: time.Date(2026, 8, 20, 2, 44, 2, 0, time.UTC)},
			{Direction: "send", Kind: "sender_observed_commit", PeerLabel: "mac", Destination: "result.zip", Visibility: "public", TransferID: strings.Repeat("b", 64), Bytes: 1536, ObservedAt: time.Date(2026, 8, 20, 2, 39, 8, 0, time.UTC)},
		},
	}
	var output bytes.Buffer
	if err := writeRecent(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Recent activity on @commando", "TIME (UTC)", "ACTION", "2026-08-20 02:44:02", "received", "@mac", "foo.bar.txt", "11 B", "sent", "result.zip", "1.5 KiB", "Endpoint observations only; not receipts or global settlement."} {
		if !strings.Contains(text, want) {
			t.Fatalf("recent output missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{snapshot.Reporter.DeviceID, snapshot.Observations[0].TransferID, "receiver_published", "sender_observed_commit"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("recent output contains %q:\n%s", unwanted, text)
		}
	}

	output.Reset()
	snapshot.Reporter.Context = "home"
	snapshot.Observations = nil
	if err := writeRecent(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "Recent activity on this device (@commando)\n\nNo observations.\n"; got != want {
		t.Fatalf("empty recent output = %q, want %q", got, want)
	}
}

func TestWatchGapIsPrintedBeforeStableError(t *testing.T) {
	event := contextwatch.Event{Version: contextwatch.Version, StreamID: strings.Repeat("a", 32), Sequence: 20, ObservedAt: time.Date(2026, 8, 1, 14, 31, 8, 0, time.UTC), Context: "home", Type: contextwatch.StreamGap, FirstDroppedSequence: 20, ResyncRequired: true}
	var output bytes.Buffer
	want := event.ObservedAt.Local().Format("15:04:05") + "  stream gap at sequence 20; resync required\n"
	if err := writeWatchEvent(&output, event); err != nil || output.String() != want || errWatchGap.Error() != "context watch stream gap; restart px watch to resync" {
		t.Fatalf("gap = %q, %v", output.String(), err)
	}
}

func TestPingPresentationSeparatesSetupAndRTT(t *testing.T) {
	setup, minimum, average, maximum, jitter := int64(time.Second), int64(10*time.Millisecond), int64(12*time.Millisecond), int64(15*time.Millisecond), int64(3*time.Millisecond)
	relay := false
	result := ping.Result{
		Version: ping.Version, Mode: "peer", Target: ping.Identity{DeviceID: "device", Label: "vm"}, SetupDurationNS: &setup,
		Requested: 4, Attempted: 4, Succeeded: 3, Lost: 1, LossBasisPoints: 2500, MinRTTNS: &minimum, AvgRTTNS: &average, MaxRTTNS: &maximum, JitterNS: &jitter,
		SelectedLocalCandidateType: "host", SelectedRemoteCandidateType: "srflx", RelayUsed: &relay,
	}
	var output bytes.Buffer
	if err := writePingResult(&output, result, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"@vm  direct host/srflx", "connect 1s", "rtt min/avg/max 10ms/12ms/15ms", "jitter 3ms", "loss 25.00% (1/4 attempted, 4 requested)"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output %q missing %q", output.String(), expected)
		}
	}
}

func TestValidatePingResultRejectsInvalidDurationsAndStatistics(t *testing.T) {
	validResult := func() ping.Result {
		setup, first, second := int64(time.Second), int64(10*time.Millisecond), int64(20*time.Millisecond)
		minimum, average, maximum, jitter := first, int64(15*time.Millisecond), second, int64(10*time.Millisecond)
		relay := false
		return ping.Result{
			Version: ping.Version, Mode: "peer", Reporter: ping.Identity{DeviceID: "reporter"}, Target: ping.Identity{DeviceID: "target"}, SetupDurationNS: &setup,
			Samples:   []ping.Sample{{Sequence: 1, Status: "success", RTTNS: &first}, {Sequence: 2, Status: "success", RTTNS: &second}},
			Requested: 2, Attempted: 2, Succeeded: 2, MinRTTNS: &minimum, AvgRTTNS: &average, MaxRTTNS: &maximum, JitterNS: &jitter,
			SelectedLocalCandidateType: "host", SelectedRemoteCandidateType: "host", RelayUsed: &relay,
		}
	}
	if err := validatePingResult(validResult(), 2, false, false); err != nil {
		t.Fatalf("valid result: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ping.Result)
	}{
		{name: "negative setup", mutate: func(result *ping.Result) { value := int64(-1); result.SetupDurationNS = &value }},
		{name: "old result version", mutate: func(result *ping.Result) { result.Version-- }},
		{name: "negative minimum", mutate: func(result *ping.Result) { value := int64(-1); result.MinRTTNS = &value }},
		{name: "inconsistent average", mutate: func(result *ping.Result) { *result.AvgRTTNS++ }},
		{name: "inconsistent jitter", mutate: func(result *ping.Result) { *result.JitterNS++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := validResult()
			test.mutate(&result)
			if err := validatePingResult(result, 2, false, false); err == nil {
				t.Fatal("validatePingResult accepted malformed result")
			}
		})
	}
}

func TestPingAddressesRequireExplicitCompleteOptIn(t *testing.T) {
	setup := int64(time.Second)
	relay := false
	base := ping.Result{
		Version: ping.Version, Mode: "peer", Reporter: ping.Identity{DeviceID: "reporter"}, Target: ping.Identity{DeviceID: "target"}, SetupDurationNS: &setup,
		Samples: []ping.Sample{{Sequence: 1, Status: "timeout"}}, Requested: 1, Attempted: 1, Lost: 1, LossBasisPoints: 10000,
		SelectedLocalCandidateType: "host", SelectedRemoteCandidateType: "srflx", RelayUsed: &relay,
	}
	if err := validatePingResult(base, 1, false, false); err != nil {
		t.Fatalf("redacted result: %v", err)
	}
	for _, test := range []struct {
		name          string
		showAddresses bool
		local         string
		remote        string
	}{
		{name: "opted in without addresses", showAddresses: true},
		{name: "local only", showAddresses: true, local: "10.0.0.1:1"},
		{name: "remote only", showAddresses: true, remote: "203.0.113.1:2"},
		{name: "addresses without opt in", local: "10.0.0.1:1", remote: "203.0.113.1:2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := base
			result.SelectedLocalAddress = test.local
			result.SelectedRemoteAddress = test.remote
			if err := validatePingResult(result, 1, false, test.showAddresses); err == nil {
				t.Fatal("accepted invalid address fields")
			}
		})
	}

	base.SelectedLocalAddress = "10.0.0.1:1"
	base.SelectedRemoteAddress = "203.0.113.1:2"
	if err := validatePingResult(base, 1, false, true); err != nil {
		t.Fatalf("explicit result: %v", err)
	}
	var output bytes.Buffer
	if err := writePingResult(&output, base, true); err != nil || !strings.Contains(output.String(), "10.0.0.1:1 -> 203.0.113.1:2") {
		t.Fatalf("explicit output = %q, %v", output.String(), err)
	}
}

func TestPingShowAddressesRejectsServerAndWarnsInHelp(t *testing.T) {
	command := newPingCommand(t.Context(), IOStreams{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{})
	command.SetArgs([]string{"--server", "--show-addresses"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "only for peer ping") {
		t.Fatalf("server address error = %v", err)
	}
	help := command.Long + command.Flags().Lookup("show-addresses").Usage
	for _, warning := range []string{"public IPs", "private topology", "VPNs", "stable IPv6 identifiers"} {
		if !strings.Contains(help, warning) {
			t.Errorf("ping help missing %q", warning)
		}
	}
}

func TestVersionCommands(t *testing.T) {
	var stdout bytes.Buffer
	command, err := NewPXCommand(context.Background(), IOStreams{Out: &stdout, Err: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	command.SetArgs([]string{"version"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "px dev") {
		t.Fatalf("output = %q, want prefix %q", stdout.String(), "px dev")
	}
}

func TestWritePeerIsHumanFirst(t *testing.T) {
	peer := contextstate.Peer{Label: "build-vm", DeviceID: "full-device-id", Aliases: []string{"builder", "ci"}}
	var output bytes.Buffer
	if err := writePeer(&output, peer, false); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "@build-vm\tonline\taliases: builder,ci\n"; got != want || strings.Contains(got, peer.DeviceID) {
		t.Fatalf("peer output = %q, want %q", got, want)
	}
	output.Reset()
	if err := writePeer(&output, contextstate.Peer{Label: "phone", DeviceID: peer.DeviceID}, true); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "@phone\tonline\tfull-device-id\n"; got != want {
		t.Fatalf("wide peer output = %q, want %q", got, want)
	}
	output.Reset()
	if err := writePeers(&output, nil, false); err != nil || output.Len() != 0 {
		t.Fatalf("empty peers output = %q, %v", output.String(), err)
	}
	if err := writePeers(&output, []contextstate.Peer{{Label: "alpha"}, {Label: "beta", Aliases: []string{"b"}}}, false); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "@alpha\tonline\n@beta\tonline\taliases: b\n"; got != want {
		t.Fatalf("multiple peers output = %q, want %q", got, want)
	}
}

func TestTopLevelProbeIsHidden(t *testing.T) {
	command, err := NewPXCommand(t.Context(), IOStreams{})
	if err != nil {
		t.Fatal(err)
	}
	topLevelProbe, _, err := command.Find([]string{"probe"})
	if err != nil || !topLevelProbe.Hidden {
		t.Fatalf("top-level probe = %v, %v; want hidden command", topLevelProbe, err)
	}
	debug, _, err := command.Find([]string{"debug"})
	if err != nil {
		t.Fatal(err)
	}
	probe, _, err := debug.Find([]string{"probe"})
	if err != nil || probe.Name() != "probe" || probe.Hidden {
		t.Fatalf("debug probe = %v, %v; want visible command", probe, err)
	}
}

func TestValidateAgentIPCVersion(t *testing.T) {
	if err := validateAgentIPCVersion(agentapi.Version); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentIPCVersion(agentapi.Version + 1); err == nil || !strings.Contains(err.Error(), "upgrade or restart") {
		t.Fatalf("mismatched version error = %v", err)
	}
}

func TestRecentClearRequiresYesForJSONAndNoninteractiveInput(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "json", args: []string{"recent", "--json", "clear"}, want: "JSON recent clearing requires --yes"},
		{name: "noninteractive", args: []string{"recent", "clear"}, want: "requires --yes when input is not a terminal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, err := newPXCommand(t.Context(), IOStreams{In: strings.NewReader("yes\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &fakeCompletionSource{})
			if err != nil {
				t.Fatal(err)
			}
			command.PersistentPreRunE = nil
			command.SetArgs(test.args)
			if err := command.Execute(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestContextListStatusReportsPersistedAuthorityValidity(t *testing.T) {
	base := contextstate.State{State: "connected", Enabled: true}
	invalid := base
	invalid.OfferedRootScope = contextstate.OfferedRootScopeFilesystemRoot
	if got := contextListStatus(invalid); !strings.Contains(got, "FAILURE: inconsistent offered-root authority") || strings.Contains(got, "WARNING:") {
		t.Fatalf("invalid status = %q", got)
	}
	valid := invalid
	valid.OfferedRootAuthorityValid = true
	if got := contextListStatus(valid); !strings.Contains(got, "WARNING: filesystem-root authority") || strings.Contains(got, "FAILURE:") {
		t.Fatalf("valid filesystem-root status = %q", got)
	}
}

func TestContextRemovalPromptPreservesVisibleRoots(t *testing.T) {
	var output bytes.Buffer
	if err := writeContextRemovalPrompt(&output, "home"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`Remove context "home" locally?`, "Offered", "inbox", "put-root", "visible files remain unchanged", "[y/N]"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("context removal prompt missing %q: %q", want, output.String())
		}
	}
}

func TestReadInviteIsStrictAndBounded(t *testing.T) {
	token := "PXI1.rh6byqCJAHY_6BGAarjaNA.000102030405060708090a0b0c0d0e0f.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
	for _, suffix := range []string{"", "\n", "\r\n"} {
		got, err := readInvite(strings.NewReader(token + suffix))
		if err != nil || got != token {
			t.Fatalf("suffix %q = %q, %v", suffix, got, err)
		}
	}
	for _, value := range []string{token + "\n\n", " " + token, token + strings.Repeat("x", 3)} {
		if _, err := readInvite(strings.NewReader(value)); err == nil {
			t.Fatalf("invalid invite input accepted: %q", value)
		}
	}
}

func TestMemberInviteConfirmationAndMutationClassification(t *testing.T) {
	invite := inviteapi.Invite{InviteID: "000102030405060708090a0b0c0d0e0f", Label: "build-vm", IssuerType: "local", CreatedAt: "2026-07-31T10:00:00Z", ExpiresAt: "2026-07-31T11:00:00Z"}
	var output bytes.Buffer
	confirmed, err := confirmMemberInviteRevocation(bufio.NewReader(strings.NewReader("yes\n")), &output, invite)
	if err != nil || !confirmed || !strings.Contains(output.String(), invite.InviteID) || !strings.Contains(output.String(), "cannot be recovered") || !strings.Contains(output.String(), "[y/N]") {
		t.Fatalf("confirmation = %v, %v, %q", confirmed, err, output.String())
	}
	for _, action := range []string{"create", "revoke"} {
		trusted := []*localipc.Error{
			{Status: 400, Code: "invalid_request", Message: "invalid invite request"},
			{Status: 429, Code: agentapi.InviteCodeMemberOperationCapacity, Message: "context member-operation capacity reached"},
			{Status: 503, Code: agentapi.InviteCodeContextDisconnected, Message: "context is not connected"},
			{Status: 408, Code: agentapi.InviteCodeRequestTimeout, Message: "context deadline exceeded"},
			{Status: 404, Code: agentapi.InviteCodeContextNotFound, Message: "context not found"},
			{Status: 422, Code: agentapi.InviteCodeInvalidContext, Message: "invalid context state: context is disabled"},
			{Status: 502, Code: "outcome_unknown", Message: action + " outcome_unknown"},
		}
		if action == "create" {
			trusted = append(trusted,
				&localipc.Error{Status: 409, Code: "invite_label_unavailable", Message: "invite label is unavailable"},
				&localipc.Error{Status: 429, Code: "invite_capacity", Message: "invite capacity reached"},
			)
		} else {
			trusted = append(trusted, &localipc.Error{Status: 404, Code: "invite_unavailable", Message: "invite is unavailable"})
		}
		for _, response := range trusted {
			got := classifyMemberInviteMutation(action, invite.InviteID, response)
			if got != response || got.Error() != response.Message {
				t.Fatalf("%s structured %d/%s changed to %#v", action, response.Status, response.Code, got)
			}
			var preserved *localipc.Error
			if !errors.As(got, &preserved) || preserved.Code != response.Code || preserved.Message != response.Message {
				t.Fatalf("%s structured response fields changed: %#v", action, got)
			}
		}
		crossOperation := &localipc.Error{Status: 404, Code: "invite_unavailable", Message: "wrong operation"}
		if action == "revoke" {
			crossOperation = &localipc.Error{Status: 429, Code: "invite_capacity", Message: "wrong operation"}
		}
		malformedResponses := []*localipc.Error{
			{Status: 502, Message: "Bad Gateway"},
			{Status: 502, Code: "unknown", Message: "unknown outcome"},
			{Status: 503, Code: agentapi.InviteCodeRequestTimeout, Message: "mismatched status"},
			{Status: 408, Code: agentapi.InviteCodeContextDisconnected, Message: "mismatched code"},
			{Status: 429, Code: "invite_unavailable", Message: "cross-paired invite error"},
			crossOperation,
		}
		for _, malformed := range malformedResponses {
			got := classifyMemberInviteMutation(action, invite.InviteID, malformed)
			if got == malformed || !strings.Contains(got.Error(), "outcome_unknown") {
				t.Fatalf("%s malformed %d/%s was trusted: %v", action, malformed.Status, malformed.Code, got)
			}
		}
		transport := errors.New("local transport lost")
		got := classifyMemberInviteMutation(action, invite.InviteID, transport)
		if got == transport || !strings.Contains(got.Error(), "outcome_unknown") {
			t.Fatalf("%s transport uncertainty = %v", action, got)
		}
	}
	mismatch := errors.New(localipc.AgentVersionMismatchMessage)
	if got := classifyMemberInviteMutation("create", "", mismatch); got != mismatch || strings.Contains(got.Error(), "outcome_unknown") {
		t.Fatalf("agent protocol mismatch classification = %v", got)
	}
}

func TestOnboardInviteFlagsAreMutuallyExclusive(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"--invite", "token", "--invite-file", "file"}, want: "mutually exclusive"},
		{args: []string{"--invite=", "--invite-file="}, want: "mutually exclusive"},
		{args: []string{"--invite="}, want: "non-empty token"},
		{args: []string{"--invite-file="}, want: "non-empty path"},
	} {
		command := newOnboardCommand(t.Context(), IOStreams{}, &rootOptions{})
		command.SetArgs(test.args)
		if err := command.Execute(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("args %v error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestSpoolInputBoundsAndCleansProducerFailure(t *testing.T) {
	directory := t.TempDir()
	path, err := spoolInput(bytes.NewReader([]byte("pipeline")), directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "pipeline" {
		t.Fatalf("spool = %q, %v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode = %v", info.Mode())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := spoolInput(bytes.NewReader([]byte("too-large")), directory, 8); err == nil {
		t.Fatal("oversized stdin succeeded")
	}
	if _, err := spoolInput(failingReader{}, directory, 8); err == nil {
		t.Fatal("producer failure succeeded")
	}
	entries, err := filepath.Glob(filepath.Join(directory, ".stdin-*.spool"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed spools remain: %v, %v", entries, err)
	}
}

func TestTextDestinationName(t *testing.T) {
	name, err := textDestinationName(time.Date(2026, time.July, 31, 3, 8, 12, 0, time.FixedZone("local", 3600)), bytes.NewReader([]byte{0xa1, 0xb2, 0xc3, 0xd4}))
	if err != nil || name != "pxmsg-20260731T020812Z-a1b2c3d4.txt" {
		t.Fatalf("name = %q, %v", name, err)
	}
	if _, err := textDestinationName(time.Now(), bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("random failure succeeded")
	}
}

func TestErrorCodePreservesIPCSourceCategory(t *testing.T) {
	err := &localipc.Error{Status: 422, Code: transfer.SourceNotFoundCode, Message: "local source does not exist or is unavailable"}
	if got := errorCode(err); got != transfer.SourceNotFoundCode {
		t.Fatalf("error code = %q", got)
	}
}

func TestInboxRequiresAtSender(t *testing.T) {
	command := newInboxCommand(context.Background(), IOStreams{}, &rootOptions{})
	command.SetArgs([]string{"sender"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "@LABEL") {
		t.Fatalf("error = %v", err)
	}
}

func TestInboxSubcommandsValidatePathsAndResolveDirectoryDestination(t *testing.T) {
	for _, args := range [][]string{{"path", "alice"}, {"move", "alice", "destination"}} {
		command := newInboxCommand(context.Background(), IOStreams{}, &rootOptions{})
		command.SetArgs(args)
		if err := command.Execute(); !errors.Is(err, inbox.ErrInvalidPath) {
			t.Fatalf("args %v error = %v", args, err)
		}
	}
	directory := t.TempDir()
	resolved, err := resolveInboxDestination("alice/report.txt", directory)
	if err != nil || resolved != filepath.Join(directory, "report.txt") {
		t.Fatalf("directory destination = %q, %v", resolved, err)
	}
	exact := filepath.Join(directory, "renamed.txt")
	resolved, err = resolveInboxDestination("alice/report.txt", exact)
	if err != nil || resolved != exact {
		t.Fatalf("exact destination = %q, %v", resolved, err)
	}
}

func TestUncertainSendFailureRetainsSpool(t *testing.T) {
	request := agentapi.ContextSendRequest{Source: "spool", StdinSpool: true, Recoverable: true}
	if shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{}, errors.New("transport failed")) {
		t.Fatal("uncertain transport failure removed spool")
	}
	if !shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{}, &localipc.Error{Status: 422, Message: "rejected before streaming"}) {
		t.Fatal("pre-stream response retained unowned spool")
	}
	if !shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{State: "failed"}, nil) {
		t.Fatal("definitive pre-persistence failure retained unowned spool")
	}
	if shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{}, nil) {
		t.Fatal("ambiguous EOF removed spool")
	}
	if shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{TransferID: "persisted"}, &localipc.Error{Status: 422, Message: "failed"}) {
		t.Fatal("persisted spool was removable")
	}
}

func TestFastSendAlwaysRemovesStdinSpool(t *testing.T) {
	request := agentapi.ContextSendRequest{Source: "spool", StdinSpool: true}
	if !shouldRemoveUnsubmittedSpool(request, transfer.ResumeEvent{TransferID: "runtime-only"}, errors.New("transport failed")) {
		t.Fatal("fast send retained unowned stdin spool")
	}
}

func TestValidateBenchmarkResult(t *testing.T) {
	duration := 2 * time.Second
	result := benchmark.Result{
		Version: benchmark.Version, Reporter: benchmark.Identity{DeviceID: "reporter"}, Target: benchmark.Identity{DeviceID: "target"},
		RequestedDurationNS: duration.Nanoseconds(), SetupDurationNS: 10, RTTNS: 20,
		Upload:                     benchmark.Direction{Bytes: 1 << 20, DurationNS: int64(time.Second), MiBPerSecond: 1},
		Download:                   benchmark.Direction{Bytes: 2 << 20, DurationNS: int64(time.Second), MiBPerSecond: 2},
		SelectedLocalCandidateType: "host", SelectedRemoteCandidateType: "srflx",
	}
	if err := validateBenchmarkResult(result, duration); err != nil {
		t.Fatal(err)
	}
	result.Download.MiBPerSecond = 3
	if err := validateBenchmarkResult(result, duration); err == nil {
		t.Fatal("inconsistent throughput was accepted")
	}
}

func TestSendRetryRejectsPublicOverride(t *testing.T) {
	command := newIPCSendCommand(context.Background(), IOStreams{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{})
	command.SetArgs([]string{"vm", "--retry", strings.Repeat("a", 64), "--public"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "--public") {
		t.Fatalf("error = %v", err)
	}
}

func TestTransferHelpExplainsExclusivePublicationAndRecovery(t *testing.T) {
	tests := []struct {
		name  string
		cmd   *cobra.Command
		flags map[string]string
		want  []string
	}{
		{
			name: "get",
			cmd:  newGetOfferedCommand(context.Background(), IOStreams{}, &rootOptions{}),
			flags: map[string]string{
				"output": "must not already exist",
			},
			want: []string{"published exclusively", "never replaces", "another --output", "move or remove the local entry", "does not retain resume state", "rerunning starts at byte zero", "destination parent", "unsafe shared directories", "later get to the same parent", "startup only resets DB leases", ".px-<64 hex>.get", "64 cleanup rows", "4 GiB", "quota-charged"},
		},
		{
			name: "send",
			cmd:  newIPCSendCommand(context.Background(), IOStreams{}, &rootOptions{}),
			flags: map[string]string{
				"name":        "must not already exist",
				"public":      "publish exclusively",
				"recoverable": "verified atomic publication",
			},
			want: []string{"default fast mode", "visible destination", "without hashing", "partial file", "--recoverable", "namespaced inbox", "offered-root basename", "Neither mode replaces"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, want := range test.want {
				if !strings.Contains(test.cmd.Long, want) {
					t.Errorf("long help missing %q: %q", want, test.cmd.Long)
				}
			}
			for name, want := range test.flags {
				flag := test.cmd.Flags().Lookup(name)
				if flag == nil || !strings.Contains(flag.Usage, want) {
					t.Errorf("--%s help = %v, want text %q", name, flag, want)
				}
			}
		})
	}
}

func TestContextRemoveRequiresNoninteractiveConfirmation(t *testing.T) {
	command := newContextRemoveCommand(context.Background(), IOStreams{In: bytes.NewBufferString("yes\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{}, new(bool))
	command.SetArgs([]string{"home"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("error = %v", err)
	}
}

func TestTransferDeleteRequiresExplicitAutomationConfirmation(t *testing.T) {
	for _, args := range [][]string{{"delete", "transfer-id"}, {"delete", "transfer-id", "--json"}} {
		command := newTransferCommand(context.Background(), IOStreams{In: bytes.NewBufferString("yes\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{})
		command.SetArgs(args)
		err := command.Execute()
		if err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("args %v error = %v", args, err)
		}
	}
}

func TestTransferRetryHasNoManifestOverrideFlags(t *testing.T) {
	command := newTransferCommand(context.Background(), IOStreams{In: &bytes.Buffer{}, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{})
	retry, _, err := command.Find([]string{"retry"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"context", "peer", "name", "public", "source", "stdin", "max-file-bytes"} {
		if retry.Flags().Lookup(name) != nil {
			t.Fatalf("retry exposes manifest override --%s", name)
		}
	}
}

func TestTransferResolveRequiresExplicitActionAndConfirmation(t *testing.T) {
	for _, args := range [][]string{{"resolve", "transfer-id"}, {"resolve", "transfer-id", "--accept-current"}, {"resolve", "transfer-id", "--yes"}} {
		command := newTransferCommand(context.Background(), IOStreams{In: &bytes.Buffer{}, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}, &rootOptions{})
		command.SetArgs(args)
		err := command.Execute()
		if err == nil || !strings.Contains(err.Error(), "--accept-current and --yes") {
			t.Fatalf("args %v error = %v", args, err)
		}
	}
}

func TestTransferResolutionOutputDoesNotClaimRemoteSettlement(t *testing.T) {
	result := put.ResolutionResult{Version: put.ResolutionVersion, TransferID: strings.Repeat("a", 32), Context: "home", Destination: "portable/result", State: "resolved_accept_current"}
	for _, jsonOutput := range []bool{false, true} {
		var output bytes.Buffer
		if err := writeTransferResolution(&output, jsonOutput, result); err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{result.TransferID, result.Destination, "resolved"} {
			if !strings.Contains(output.String(), required) {
				t.Fatalf("json=%t output=%q missing %q", jsonOutput, output.String(), required)
			}
		}
		for _, forbidden := range []string{"native/private", ".px-stage", ".bak", "sha256", "durability", "created", "replaced", "peer_confirmation"} {
			if strings.Contains(output.String(), forbidden) {
				t.Fatalf("json=%t output exposed %q: %s", jsonOutput, forbidden, output.String())
			}
		}
	}
}

func TestPlainTransferOutputIncludesTimesAndCleanupOutcome(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	expires := created.Add(time.Hour)
	item := transfer.InventoryItem{ID: strings.Repeat("a", 64), Kind: "send", Context: "home", Peer: "peer", Name: "file", State: "retryable", CreatedAt: created, UpdatedAt: created.Add(time.Minute), ExpiresAt: &expires, CleanupPending: true}
	var output bytes.Buffer
	if err := writeTransferItem(&output, false, item); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"created_at\t2023-11-14T22:13:20Z", "updated_at\t2023-11-14T22:14:20Z", "expires_at\t2023-11-14T23:13:20Z", "cleanup_pending\ttrue"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("plain show missing %q: %s", value, output.String())
		}
	}
	output.Reset()
	if err := writeTransferListItem(&output, item); err != nil || !strings.Contains(output.String(), "2023-11-14T22:14:20Z\t2023-11-14T23:13:20Z") {
		t.Fatalf("plain list output = %q, %v", output.String(), err)
	}
	output.Reset()
	if err := writeTransferDelete(&output, false, item); err != nil || !strings.Contains(output.String(), "state deleted; private cleanup queued") {
		t.Fatalf("pending delete output = %q, %v", output.String(), err)
	}
}

func TestOnboardingDefaultsAndPrompts(t *testing.T) {
	offered, inbox := onboardingRoots("linux", "/home/user")
	if offered != filepath.Join("/home/user", ".local", "share", "px", "shared") || inbox != filepath.Join("/home/user", ".local", "share", "px", "inbox") {
		t.Fatalf("Unix roots = %q, %q", offered, inbox)
	}
	offered, inbox = onboardingRoots("windows", `C:\Users\user`)
	if offered != filepath.Join(`C:\Users\user`, "Documents", "PX", "shared") || inbox != filepath.Join(`C:\Users\user`, "Documents", "PX", "inbox") {
		t.Fatalf("Windows roots = %q, %q", offered, inbox)
	}
	var output bytes.Buffer
	confirmed, err := promptConfirm(context.Background(), bufio.NewReader(strings.NewReader("yes\n")), &output, "Continue?", false)
	if err != nil || !confirmed || output.String() != "Continue? [y/N] " {
		t.Fatalf("confirmation = %v, %v, %q", confirmed, err, output.String())
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := promptValue(cancelled, bufio.NewReader(strings.NewReader("value\n")), io.Discard, "Value", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prompt error = %v", err)
	}
}

func TestOnboardingSTUNPromptAndApprovalGuidance(t *testing.T) {
	for _, test := range []struct {
		input, fallback, want string
	}{
		{input: "\n", fallback: contextstate.DefaultSTUNURL, want: contextstate.DefaultSTUNURL},
		{input: "none\n", fallback: contextstate.DefaultSTUNURL, want: "none"},
		{input: " stun:first.example:3478, stun:second.example:3478 \n", fallback: contextstate.DefaultSTUNURL, want: "stun:first.example:3478, stun:second.example:3478"},
	} {
		var output bytes.Buffer
		got, err := promptOptionalValue(t.Context(), bufio.NewReader(strings.NewReader(test.input)), &output, "STUN URLs", test.fallback)
		if err != nil || got != test.want || !strings.Contains(output.String(), test.fallback) {
			t.Fatalf("optional prompt = %q, %v, output %q", got, err, output.String())
		}
	}
	if got := splitSTUNURLs(" stun:first.example:3478, ,stun:second.example:3478 "); len(got) != 2 || got[0] != "stun:first.example:3478" || got[1] != "stun:second.example:3478" {
		t.Fatalf("split STUN URLs = %v", got)
	}

	state := contextstate.State{Name: "lan", State: "pending", PendingCode: "F7K2-M9Q4"}
	var plain bytes.Buffer
	if err := writeContextState(IOStreams{Out: &plain}, false, state, true); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"px --context lan devices approve F7K2-M9Q4", "px-server devices approve F7K2-M9Q4"} {
		if !strings.Contains(plain.String(), value) {
			t.Fatalf("approval guidance missing %q: %q", value, plain.String())
		}
	}
	plain.Reset()
	if err := writeContextState(IOStreams{Out: &plain}, false, state, false); err != nil || strings.Contains(plain.String(), "devices approve") {
		t.Fatalf("repeated pending output = %q, %v", plain.String(), err)
	}
	var encoded bytes.Buffer
	if err := writeContextState(IOStreams{Out: &encoded}, true, state, true); err != nil || strings.Contains(encoded.String(), "devices approve") {
		t.Fatalf("JSON pending output = %q, %v", encoded.String(), err)
	}
}

func TestCreationCommandsRejectConflictingSTUNFlags(t *testing.T) {
	for _, args := range [][]string{
		{"join", "https://px.example", "--name", "vm", "--no-stun", "--stun", "stun:example.com:3478"},
		{"onboard", "https://px.example", "--no-stun", "--stun="},
	} {
		command, err := NewPXCommand(t.Context(), IOStreams{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		command.SetArgs(args)
		if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--no-stun and --stun cannot be combined") {
			t.Fatalf("execute %v = %v", args, err)
		}
	}
}

func TestJoinRequiresServerWithoutBuildDefault(t *testing.T) {
	original := DefaultServerURL
	DefaultServerURL = ""
	t.Cleanup(func() { DefaultServerURL = original })

	command := newJoinCommand(t.Context(), IOStreams{}, &rootOptions{})
	command.SetArgs([]string{"--name", "vm"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "required by this build") {
		t.Fatalf("missing server error = %v", err)
	}
}

func TestEnsurePrivateOnboardingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared")
	if err := ensurePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory = %v, %v", info, err)
	}
	existing := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(existing); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(existing); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("existing directory permissions changed: %v, %v", info, err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(file); err == nil {
		t.Fatal("file accepted as onboarding root")
	}
}

func TestPXErrorRendering(t *testing.T) {
	for _, test := range []struct {
		args []string
		want bool
	}{
		{args: []string{"child", "--json"}, want: true},
		{args: []string{"child", "--json=1"}, want: true},
		{args: []string{"child", "--json=t"}, want: true},
		{args: []string{"child", "--json=TRUE"}, want: true},
		{args: []string{"child", "--json=false"}, want: false},
		{args: []string{"child", "--json", "--json=false"}, want: false},
		{args: []string{"child", "--json=false", "--json=t"}, want: true},
		{args: []string{"child", "--label", "--json"}, want: false},
		{args: []string{"child", "--", "--json"}, want: false},
		{args: []string{"missing", "--json"}, want: false},
	} {
		root := &cobra.Command{Use: "root", SilenceErrors: true, SilenceUsage: true}
		child := &cobra.Command{Use: "child", RunE: func(*cobra.Command, []string) error { return errors.New("failed") }}
		child.Flags().Bool("json", false, "")
		child.Flags().String("label", "", "")
		root.AddCommand(child)
		root.SetArgs(test.args)
		executed, _ := root.ExecuteC()
		if got := JSONOutputEnabled(executed); got != test.want {
			t.Errorf("JSONOutputEnabled(%q) = %t, want %t", test.args, got, test.want)
		}
	}
	var output bytes.Buffer
	if err := WritePXError(&output, localipc.ErrAgentUnavailable, true); err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"error":{"code":"local_agent_unavailable","message":"PX agent is not reachable; run ` + "`px agent run` or `px startup install`" + `"}}` + "\n"
	if output.String() != want {
		t.Fatalf("JSON error = %q, want %q", output.String(), want)
	}
	output.Reset()
	if err := WritePXError(&output, errors.New("bad input"), false); err != nil {
		t.Fatal(err)
	}
	if output.String() != "px: bad input\n" {
		t.Fatalf("plain error = %q", output.String())
	}
}

type failingReader struct{}

func (failingReader) Read(buffer []byte) (int, error) {
	copy(buffer, "partial")
	return len("partial"), errors.New("producer failed")
}

var _ io.Reader = failingReader{}
