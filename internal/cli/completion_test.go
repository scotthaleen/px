package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/transfer"
	"github.com/spf13/cobra"
)

type fakeCompletionSource struct {
	contexts  []contextstate.State
	selected  string
	peers     []contextstate.Peer
	aliases   []contextstate.Alias
	invites   []string
	transfers transfer.Inventory
	err       error
	wait      bool
}

func TestValidCompletionTransferIDAcceptsPutIDs(t *testing.T) {
	if !validCompletionTransferID(strings.Repeat("a", 32)) {
		t.Fatal("32-hex put transfer ID rejected")
	}
	if validCompletionTransferID(strings.Repeat("a", 31)) || validCompletionTransferID(strings.Repeat("g", 32)) {
		t.Fatal("invalid put transfer ID accepted")
	}
}

func (s *fakeCompletionSource) finish(ctx context.Context) error {
	if s.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return s.err
}

func (s *fakeCompletionSource) DefaultContext(ctx context.Context) (string, error) {
	return s.selected, s.finish(ctx)
}

func (s *fakeCompletionSource) Complete(ctx context.Context, kind, _ string, prefix string) ([]string, error) {
	if err := s.finish(ctx); err != nil {
		return nil, err
	}
	var values []string
	switch kind {
	case "context":
		for _, value := range s.contexts {
			values = append(values, value.Name)
		}
	case "alias":
		for _, value := range s.aliases {
			values = append(values, value.Name)
		}
	case "peer", "peer_alias":
		for _, value := range s.peers {
			values = append(values, value.Label)
			if kind == "peer_alias" {
				values = append(values, value.Aliases...)
			}
		}
	case "invite":
		values = append(values, s.invites...)
	}
	return filterCandidates(values, prefix), nil
}

func (s *fakeCompletionSource) TransferIDs(ctx context.Context, _ string, action, peer, prefix string) ([]string, error) {
	if err := s.finish(ctx); err != nil {
		return nil, err
	}
	total := make(map[string]int)
	matches := make(map[string]int)
	for _, item := range s.transfers.Transfers {
		total[item.ID]++
		eligible := false
		switch action {
		case "show":
			eligible = true
		case "cancel":
			eligible = item.Active
		case "retry":
			eligible = item.Kind == "send" && item.State == "retryable" && item.Retryable && !item.Active && (peer == "" || strings.EqualFold(peer, item.Peer))
		case "delete":
			eligible = item.State == "retryable" && item.Retryable && !item.Active
		}
		if eligible {
			matches[item.ID]++
		}
	}
	values := make([]string, 0, len(matches))
	for id, count := range matches {
		if count == 1 && ((action != "show" && action != "delete") || total[id] == 1) {
			values = append(values, id)
		}
	}
	return filterCandidates(values, prefix), nil
}

func TestEntityCompletionAndPeerFirstRewrite(t *testing.T) {
	activeID := strings.Repeat("a", 64)
	retryID := strings.Repeat("b", 64)
	receiveID := strings.Repeat("c", 64)
	sharedActiveID := strings.Repeat("d", 64)
	sharedRetryID := strings.Repeat("e", 64)
	getID := "get-" + strings.Repeat("f", 32)
	source := &fakeCompletionSource{
		contexts: []contextstate.State{{Name: "work"}, {Name: "home"}},
		selected: "home",
		peers: []contextstate.Peer{
			{Label: "build-vm", DeviceID: "must-not-appear", Aliases: []string{"builder"}},
			{Label: "Alpha", Aliases: []string{"a"}},
		},
		aliases: []contextstate.Alias{{Name: "builder", Target: "build-vm"}, {Name: "offline", Target: "old-vm"}},
		invites: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		transfers: transfer.Inventory{Version: transfer.InventoryVersion, Transfers: []transfer.InventoryItem{
			{ID: activeID, Kind: "send", State: "active", Active: true},
			{ID: retryID, Kind: "send", Peer: "build-vm", State: "retryable", Retryable: true},
			{ID: receiveID, Kind: "receive", State: "retryable", Retryable: true},
			{ID: sharedActiveID, Kind: "send", State: "active", Active: true},
			{ID: sharedActiveID, Kind: "receive", State: "retryable", Retryable: true},
			{ID: sharedRetryID, Kind: "send", Peer: "build-vm", State: "retryable", Retryable: true},
			{ID: sharedRetryID, Kind: "receive", State: "retryable", Retryable: true},
			{ID: getID, Kind: "get", State: "active", Active: true},
		}},
	}
	tests := []struct {
		name string
		args []string
		want []string
		not  []string
		dir  string
	}{
		{name: "global context", args: []string{"__complete", "--context", "h"}, want: []string{"home"}, dir: ":4"},
		{name: "context position", args: []string{"__complete", "context", "disable", "w"}, want: []string{"work"}, dir: ":4"},
		{name: "peer and alias", args: []string{"__complete", "ls", "b"}, want: []string{"build-vm", "builder"}, not: []string{"must-not-appear"}, dir: ":4"},
		{name: "peer first", args: []string{"__complete", "@bu"}, want: []string{"@build-vm", "@builder"}, not: []string{"\"@builder\""}, dir: ":4"},
		{name: "peer first command", args: []string{"__complete", "@build-vm", "s"}, want: []string{"send"}, not: []string{"get"}, dir: ":4"},
		{name: "peer first text command", args: []string{"__complete", "@build-vm", "t"}, want: []string{"text"}, not: []string{"send"}, dir: ":4"},
		{name: "peer ping", args: []string{"__complete", "ping", "b"}, want: []string{"build-vm", "builder"}, dir: ":4"},
		{name: "remote path no files", args: []string{"__complete", "@build-vm", "get", ""}, dir: ":4"},
		{name: "send local path", args: []string{"__complete", "@build-vm", "send", ""}, dir: ":0"},
		{name: "text no files", args: []string{"__complete", "@build-vm", "text", ""}, dir: ":4"},
		{name: "offline alias management", args: []string{"__complete", "context", "alias", "remove", "o"}, want: []string{"offline"}, dir: ":4"},
		{name: "alias target canonical only", args: []string{"__complete", "context", "alias", "set", "ci", "b"}, want: []string{"build-vm"}, not: []string{"builder"}, dir: ":4"},
		{name: "show suppresses ambiguous", args: []string{"__complete", "transfer", "show", ""}, want: []string{activeID, retryID, receiveID, getID}, not: []string{sharedActiveID, sharedRetryID}, dir: ":4"},
		{name: "cancel active", args: []string{"__complete", "transfer", "cancel", ""}, want: []string{activeID, sharedActiveID, getID}, not: []string{retryID}, dir: ":4"},
		{name: "retry send", args: []string{"__complete", "transfer", "retry", ""}, want: []string{retryID, sharedRetryID}, not: []string{activeID, receiveID}, dir: ":4"},
		{name: "send retry flag", args: []string{"__complete", "send", "build-vm", "--retry", ""}, want: []string{retryID}, not: []string{activeID, receiveID}, dir: ":4"},
		{name: "send retry peer mismatch", args: []string{"__complete", "send", "other", "--retry", ""}, not: []string{retryID}, dir: ":4"},
		{name: "send retry incompatible public", args: []string{"__complete", "send", "build-vm", "--public", "--retry", ""}, not: []string{retryID}, dir: ":4"},
		{name: "delete retryable", args: []string{"__complete", "transfer", "delete", ""}, want: []string{retryID, receiveID}, not: []string{activeID, sharedActiveID, sharedRetryID}, dir: ":4"},
		{name: "active invite revoke", args: []string{"__complete", "invite", "revoke", "a"}, want: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, not: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, dir: ":4"},
		{name: "globals after peer rejected", args: []string{"__complete", "@build-vm", "--context", "home", "s"}, not: []string{"send"}, dir: ":4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := runCompletion(t, source, test.args...)
			for _, want := range test.want {
				if !containsLine(output, want) {
					t.Errorf("output missing %q: %q", want, output)
				}
			}
			for _, unwanted := range test.not {
				if strings.Contains(output, unwanted) {
					t.Errorf("output contains %q: %q", unwanted, output)
				}
			}
			if !containsLine(output, test.dir) {
				t.Errorf("output missing directive %q: %q", test.dir, output)
			}
		})
	}
}

func TestCompletionFailureIsSilentAndBounded(t *testing.T) {
	for _, source := range []*fakeCompletionSource{{err: errors.New("agent unavailable")}, {wait: true}} {
		started := time.Now()
		output := runCompletion(t, source, "__complete", "ls", "")
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("completion took %s", elapsed)
		}
		if strings.TrimSpace(output) != ":4" {
			t.Fatalf("completion output = %q", output)
		}
	}
}

func TestGeneratedCompletionScripts(t *testing.T) {
	markers := map[string][]string{
		"bash":       {"__complete", "complete"},
		"zsh":        {"#compdef px", "__complete"},
		"fish":       {"complete -c px", "__complete"},
		"powershell": {"Register-ArgumentCompleter", "$WordToComplete -like '@*'", "+ [char]96 + $WordToComplete", "Invoke-Expression"},
	}
	for shell, values := range markers {
		t.Run(shell, func(t *testing.T) {
			var output bytes.Buffer
			command, err := newPXCommand(context.Background(), IOStreams{Out: &output, Err: &bytes.Buffer{}}, &fakeCompletionSource{})
			if err != nil {
				t.Fatal(err)
			}
			command.SetArgs([]string{"completion", shell})
			if err := command.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				if !strings.Contains(output.String(), value) {
					t.Errorf("%s completion missing %q", shell, value)
				}
			}
		})
	}
}

func runCompletion(t *testing.T, source completionSource, args ...string) string {
	t.Helper()
	rewritten, err := RewritePXArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	command, err := newPXCommand(context.Background(), IOStreams{Out: &output, Err: &stderr}, source)
	if err != nil {
		t.Fatal(err)
	}
	command.SetArgs(rewritten)
	if err := command.Execute(); err != nil {
		t.Fatalf("completion failed: %v, stderr %q", err, stderr.String())
	}
	if stderr.Len() != 0 && !strings.HasPrefix(stderr.String(), "Completion ended with directive:") {
		t.Fatalf("completion stderr = %q", stderr.String())
	}
	return output.String()
}

func TestConfigureCompletionsReportsMissingCommand(t *testing.T) {
	root := &cobra.Command{Use: "px"}
	root.PersistentFlags().String("context", "", "context")
	err := configureCompletions(root, &rootOptions{}, &fakeCompletionSource{})
	if err == nil || !strings.Contains(err.Error(), "context default") {
		t.Fatalf("missing command error = %v", err)
	}
}

func containsLine(output, value string) bool {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == value {
			return true
		}
	}
	return false
}
