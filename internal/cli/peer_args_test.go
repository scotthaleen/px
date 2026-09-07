package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRewritePXArgs(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr string
	}{
		{name: "canonical", input: []string{"send", "vm", "file"}, want: []string{"send", "vm", "file"}},
		{name: "list", input: []string{"@vm", "ls", "releases"}, want: []string{"ls", "vm", "releases"}},
		{name: "get globals", input: []string{"--home", "/state", "-c", "work", "@build", "get", "app"}, want: []string{"--home", "/state", "-c", "work", "get", "build", "app"}},
		{name: "send inline globals", input: []string{"--context=work", "-vv", "@build", "send", "file", "--json"}, want: []string{"--context=work", "-vv", "send", "build", "file", "--json"}},
		{name: "text", input: []string{"@build", "text", "build is ready"}, want: []string{"text", "build", "build is ready"}},
		{name: "recent", input: []string{"@build", "recent", "--limit", "8"}, want: []string{"recent", "--peer-target", "build", "--limit", "8"}},
		{name: "ping", input: []string{"@build", "ping", "--count", "2"}, want: []string{"ping", "build", "--count", "2"}},
		{name: "ping addresses", input: []string{"@build", "ping", "--show-addresses"}, want: []string{"ping", "build", "--show-addresses"}},
		{name: "benchmark", input: []string{"@build", "benchmark", "--duration", "10s"}, want: []string{"benchmark", "build", "--duration", "10s"}},
		{name: "recent clear peer", input: []string{"@clear", "recent"}, want: []string{"recent", "--peer-target", "clear"}},
		{name: "recent clear peer ignores confirmation", input: []string{"@clear", "recent", "--yes"}, want: []string{"recent", "--peer-target", "clear"}},
		{name: "long verbosity", input: []string{"--verbose", "@build", "ls"}, want: []string{"--verbose", "ls", "build"}},
		{name: "clustered globals", input: []string{"-vvcwork", "@build", "ls"}, want: []string{"-vvcwork", "ls", "build"}},
		{name: "clustered context separate value", input: []string{"-vc", "work", "@build", "ls"}, want: []string{"-vc", "work", "ls", "build"}},
		{name: "clustered context completion", input: []string{"__complete", "-vc", "work", "@build", "s"}, want: []string{"__complete", "-vc", "work", "__peer_first", "s"}},
		{name: "doctor", input: []string{"@vm", "doctor", "--json"}, want: []string{"doctor", "--peer", "vm", "--json"}},
		{name: "completion commands", input: []string{cobra.ShellCompRequestCmd, "@vm", "s"}, want: []string{cobra.ShellCompRequestCmd, "__peer_first", "s"}},
		{name: "completion partial peer", input: []string{cobra.ShellCompRequestCmd, "@bu"}, want: []string{cobra.ShellCompRequestCmd, "__peer_first", "@bu"}},
		{name: "completion misplaced global", input: []string{cobra.ShellCompRequestCmd, "@vm", "--context", "home", "s"}, want: []string{cobra.ShellCompRequestCmd, "__peer_first", "--", "--context", "home", "s"}},
		{name: "completion send", input: []string{cobra.ShellCompRequestCmd, "@vm", "send", ""}, want: []string{cobra.ShellCompRequestCmd, "send", "vm", ""}},
		{name: "missing command", input: []string{"@vm"}, wantErr: `command required after @PEER; valid forms: px "@PEER" COMMAND`},
		{name: "empty peer", input: []string{"@", "ls"}, wantErr: "must be @LABEL"},
		{name: "invalid peer", input: []string{"@bad/peer", "ls"}, wantErr: "peer target: label must"},
		{name: "unsupported", input: []string{"@vm", "context", "list"}, wantErr: `command "context" does not support peer-first syntax; valid forms: px "@PEER" COMMAND`},
		{name: "ambiguous doctor", input: []string{"@vm", "doctor", "--peer", "other"}, wantErr: "cannot be combined"},
		{name: "after terminator", input: []string{"--", "@vm", "ls"}, wantErr: "before --"},
		{name: "unknown global", input: []string{"--unknown", "@vm", "ls"}, want: []string{"--unknown", "@vm", "ls"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := RewritePXArgs(test.input)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(actual, test.want) {
				t.Fatalf("rewrite = %v, %v; want %v", actual, err, test.want)
			}
		})
	}
}

func TestPXContextShorthand(t *testing.T) {
	command, err := NewPXCommand(t.Context(), IOStreams{})
	if err != nil {
		t.Fatal(err)
	}
	flag := command.PersistentFlags().Lookup("context")
	if flag == nil || flag.Shorthand != "c" {
		t.Fatalf("context flag = %+v", flag)
	}
}

func TestPeerFirstGuidanceIncludesEveryCommand(t *testing.T) {
	_, err := RewritePXArgs([]string{"@vm"})
	if err == nil {
		t.Fatal("missing peer-first command succeeded")
	}
	for _, command := range peerCommands {
		if !strings.Contains(err.Error(), command) {
			t.Errorf("guidance missing %q: %v", command, err)
		}
	}
}
