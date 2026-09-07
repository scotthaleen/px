package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/startup"
	"github.com/spf13/cobra"
)

func TestAgentCommandClassification(t *testing.T) {
	root, err := NewPXCommand(t.Context(), IOStreams{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		want bool
	}{
		{path: "status", want: true},
		{path: "peers", want: true},
		{path: "join", want: true},
		{path: "context list", want: true},
		{path: "context current", want: true},
		{path: "devices pending", want: true},
		{path: "ls", want: true},
		{path: "get", want: true},
		{path: "send", want: true},
		{path: "transfer list", want: true},
		{path: "probe", want: true},
		{path: "version"},
		{path: "agent status"},
		{path: "agent stop"},
		{path: "startup status"},
		{path: "onboard"},
		{path: "doctor"},
		{path: "debug probe"},
		{path: "completion bash"},
	} {
		command, _, findErr := root.Find(strings.Fields(test.path))
		if findErr != nil {
			t.Fatalf("find %q: %v", test.path, findErr)
		}
		if got := commandRequiresAgent(command, &rootOptions{}); got != test.want {
			t.Errorf("commandRequiresAgent(%q) = %t, want %t", test.path, got, test.want)
		}
	}
	current, _, err := root.Find([]string{"context", "current"})
	if err != nil {
		t.Fatal(err)
	}
	if commandRequiresAgent(current, &rootOptions{context: "home"}) {
		t.Fatal("context current with an explicit context requires the agent")
	}
}

func TestAgentRecoveryStartupPolicy(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     string
		input      string
		wantAction string
		wantErr    string
	}{
		{name: "installed defaults safe start", status: diagnostics.Pass, input: "\n", wantAction: "start"},
		{name: "missing accepts install", status: diagnostics.Skipped, input: "y\n", wantAction: "install"},
		{name: "missing defaults refuse", status: diagnostics.Skipped, input: "\n", wantErr: localipc.ErrAgentUnavailable.Error()},
		{name: "unsafe refuses repair", status: diagnostics.Fail, input: "y\n", wantErr: "startup upgrade"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := agentCommand(&cobra.Command{Use: "child"})
			var action string
			readyCalls := 0
			deps := agentRecoveryDeps{
				ready: func(context.Context, *localipc.Client) (bool, error) {
					readyCalls++
					if readyCalls == 1 {
						return false, nil
					}
					if action != "" {
						return true, nil
					}
					return false, localipc.ErrAgentUnavailable
				},
				currentPlan: func(string) (startup.Plan, error) { return startup.Plan{OS: "linux"}, nil },
				inspect: func(context.Context, startup.Plan, startup.Runner) (string, string) {
					return test.status, "inspection summary"
				},
				execute: func(_ context.Context, _ startup.Plan, got string, _ startup.Runner) (string, error) {
					action = got
					return "", nil
				},
				activate: func(context.Context, startup.Plan, startup.Runner) (string, error) {
					action = "start"
					return "", nil
				},
				terminal: func(io.Reader) bool { return true },
			}
			var stderr bytes.Buffer
			err := ensureAgentForCommandWith(t.Context(), command, IOStreams{In: strings.NewReader(test.input), Out: io.Discard, Err: &stderr}, &rootOptions{home: t.TempDir()}, deps)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("recovery error = %v, want %q", err, test.wantErr)
				}
				if action != "" {
					t.Fatalf("startup action = %q after refusal", action)
				}
				return
			}
			if err != nil || action != test.wantAction || readyCalls < 3 {
				t.Fatalf("recovery = action %q, ready calls %d, error %v", action, readyCalls, err)
			}
			if !strings.Contains(stderr.String(), "PX agent is ready") {
				t.Fatalf("recovery output = %q", stderr.String())
			}
		})
	}
}

func TestAgentRecoveryRevalidatesStartupAfterPrompt(t *testing.T) {
	command := agentCommand(&cobra.Command{Use: "child"})
	inspectCalls, executeCalls := 0, 0
	deps := agentRecoveryDeps{
		ready:       func(context.Context, *localipc.Client) (bool, error) { return false, localipc.ErrAgentUnavailable },
		currentPlan: func(string) (startup.Plan, error) { return startup.Plan{OS: "linux"}, nil },
		inspect: func(context.Context, startup.Plan, startup.Runner) (string, string) {
			inspectCalls++
			if inspectCalls == 1 {
				return diagnostics.Skipped, "not installed"
			}
			return diagnostics.Fail, "startup configuration is stale"
		},
		execute: func(context.Context, startup.Plan, string, startup.Runner) (string, error) {
			executeCalls++
			return "", nil
		},
		activate: func(context.Context, startup.Plan, startup.Runner) (string, error) {
			executeCalls++
			return "", nil
		},
		terminal: func(io.Reader) bool { return true },
	}
	err := ensureAgentForCommandWith(t.Context(), command, IOStreams{In: strings.NewReader("y\n"), Out: io.Discard, Err: io.Discard}, &rootOptions{home: t.TempDir()}, deps)
	if err == nil || !strings.Contains(err.Error(), "startup upgrade") || inspectCalls != 2 || executeCalls != 0 {
		t.Fatalf("revalidated recovery = inspections %d, executions %d, error %v", inspectCalls, executeCalls, err)
	}
}

func TestAgentRecoveryDoesNotPromptForAutomationOrReplayHandler(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		command := agentCommand(&cobra.Command{Use: "child"})
		command.Flags().Bool("json", false, "")
		if jsonOutput {
			if err := command.Flags().Set("json", "true"); err != nil {
				t.Fatal(err)
			}
		}
		inspected := false
		deps := agentRecoveryDeps{
			ready:       func(context.Context, *localipc.Client) (bool, error) { return false, localipc.ErrAgentUnavailable },
			currentPlan: func(string) (startup.Plan, error) { inspected = true; return startup.Plan{}, nil },
			terminal:    func(io.Reader) bool { return jsonOutput },
		}
		err := ensureAgentForCommandWith(t.Context(), command, IOStreams{In: strings.NewReader("y\n"), Out: io.Discard, Err: io.Discard}, &rootOptions{home: t.TempDir()}, deps)
		if !errors.Is(err, localipc.ErrAgentUnavailable) || inspected {
			t.Fatalf("automation recovery = %v, inspected %t", err, inspected)
		}
	}

	runCount, startupCount := 0, 0
	streams := IOStreams{In: strings.NewReader("\n"), Out: io.Discard, Err: io.Discard}
	opts := &rootOptions{home: t.TempDir()}
	deps := agentRecoveryDeps{
		ready: func(context.Context, *localipc.Client) (bool, error) {
			if startupCount > 0 {
				return true, nil
			}
			return false, localipc.ErrAgentUnavailable
		},
		currentPlan: func(string) (startup.Plan, error) { return startup.Plan{}, nil },
		inspect: func(context.Context, startup.Plan, startup.Runner) (string, string) {
			return diagnostics.Pass, "installed"
		},
		execute: func(context.Context, startup.Plan, string, startup.Runner) (string, error) {
			startupCount++
			return "", nil
		},
		activate: func(context.Context, startup.Plan, startup.Runner) (string, error) {
			startupCount++
			return "", nil
		},
		terminal: func(io.Reader) bool { return true },
	}
	root := &cobra.Command{Use: "root", SilenceErrors: true, SilenceUsage: true}
	root.PersistentPreRunE = func(command *cobra.Command, _ []string) error {
		return ensureAgentForCommandWith(t.Context(), command, streams, opts, deps)
	}
	child := agentCommand(&cobra.Command{Use: "child", RunE: func(*cobra.Command, []string) error {
		runCount++
		return localipc.ErrAgentUnavailable
	}})
	root.AddCommand(child)
	root.SetArgs([]string{"child"})
	if err := root.Execute(); !errors.Is(err, localipc.ErrAgentUnavailable) {
		t.Fatalf("execute error = %v", err)
	}
	if startupCount != 1 || runCount != 1 {
		t.Fatalf("startup count = %d, handler count = %d", startupCount, runCount)
	}
}
