package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/scotthaleen/go-toolbelt/processlock"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/startup"
	"github.com/spf13/cobra"
)

const requiresAgentAnnotation = "px.requires-agent"

type agentRecoveryDeps struct {
	ready       func(context.Context, *localipc.Client) (bool, error)
	currentPlan func(string) (startup.Plan, error)
	inspect     func(context.Context, startup.Plan, startup.Runner) (string, string)
	execute     func(context.Context, startup.Plan, string, startup.Runner) (string, error)
	activate    func(context.Context, startup.Plan, startup.Runner) (string, error)
	terminal    func(io.Reader) bool
}

func defaultAgentRecoveryDeps() agentRecoveryDeps {
	return agentRecoveryDeps{
		ready:       agentReady,
		currentPlan: startup.CurrentPlan,
		inspect:     startup.InspectRuntime,
		execute:     startup.Execute,
		activate:    startup.Activate,
		terminal:    inputIsTerminal,
	}
}

func agentCommand(command *cobra.Command) *cobra.Command {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[requiresAgentAnnotation] = "true"
	return command
}

func commandRequiresAgent(command *cobra.Command, opts *rootOptions) bool {
	if command.Name() == "current" && command.Parent() != nil && command.Parent().Name() == "context" && explicitContext(opts) != "" {
		return false
	}
	for current := command; current != nil; current = current.Parent() {
		if current.Annotations[requiresAgentAnnotation] == "true" {
			return true
		}
	}
	return false
}

func ensureAgentForCommand(ctx context.Context, command *cobra.Command, streams IOStreams, opts *rootOptions) error {
	return ensureAgentForCommandWith(ctx, command, streams, opts, defaultAgentRecoveryDeps())
}

func ensureAgentForCommandWith(ctx context.Context, command *cobra.Command, streams IOStreams, opts *rootOptions, deps agentRecoveryDeps) error {
	if !commandRequiresAgent(command, opts) {
		return nil
	}
	paths, _, err := prepare(streams, opts)
	if err != nil {
		return err
	}
	client := localipc.NewAgentClient(paths.AgentEndpoint)
	ready, err := deps.ready(ctx, client)
	if err == nil && ready {
		return nil
	}
	if err == nil {
		err = localipc.ErrAgentUnavailable
	}
	if !errors.Is(err, localipc.ErrAgentUnavailable) {
		return err
	}
	if !deps.terminal(streams.In) || JSONOutputEnabled(command) {
		return localipc.ErrAgentUnavailable
	}
	_, action, _, err := inspectAgentStartupWith(ctx, paths, deps)
	if err != nil {
		return err
	}
	prompt, defaultYes := "PX agent startup is not installed. Install it for this user and start it now?", false
	if action != "install" {
		prompt, defaultYes = "PX agent is not running. Start it?", true
	}
	confirmed, err := promptConfirm(ctx, bufio.NewReader(streams.In), streams.Err, prompt, defaultYes)
	if err != nil {
		return err
	}
	if !confirmed {
		return localipc.ErrAgentUnavailable
	}
	ready, err = deps.ready(ctx, client)
	if err == nil && ready {
		return nil
	}
	if err == nil {
		err = localipc.ErrAgentUnavailable
	}
	if err != nil && !errors.Is(err, localipc.ErrAgentUnavailable) {
		return err
	}
	if err := activateAgentStartupWith(ctx, paths, action, client, deps); err != nil {
		return err
	}
	_, err = fmt.Fprintln(streams.Err, "PX agent is ready.")
	return err
}

func inspectAgentStartup(ctx context.Context, paths apphome.Paths) (startup.Plan, string, string, error) {
	return inspectAgentStartupWith(ctx, paths, defaultAgentRecoveryDeps())
}

func inspectAgentStartupWith(ctx context.Context, paths apphome.Paths, deps agentRecoveryDeps) (startup.Plan, string, string, error) {
	plan, err := deps.currentPlan(paths.Root)
	if err != nil {
		return startup.Plan{}, "", "", err
	}
	status, summary := deps.inspect(ctx, plan, nil)
	switch status {
	case diagnostics.Pass:
		return plan, "start", summary, nil
	case diagnostics.Skipped:
		return plan, "install", summary, nil
	default:
		return startup.Plan{}, "", summary, fmt.Errorf("existing per-user startup cannot be started safely: %s; verify the selected PX home and executable, then run `px startup upgrade`", summary)
	}
}

func activateAgentStartup(ctx context.Context, paths apphome.Paths, action string, client *localipc.Client) error {
	return activateAgentStartupWith(ctx, paths, action, client, defaultAgentRecoveryDeps())
}

func activateAgentStartupWith(ctx context.Context, paths apphome.Paths, approvedAction string, client *localipc.Client, deps agentRecoveryDeps) error {
	lock, err := acquireStartupLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Stop(context.Background())

	ready, err := deps.ready(ctx, client)
	if err == nil && ready {
		return nil
	}
	if err != nil && !errors.Is(err, localipc.ErrAgentUnavailable) {
		return err
	}
	plan, action, _, err := inspectAgentStartupWith(ctx, paths, deps)
	if err != nil {
		return err
	}
	if approvedAction != "install" && action == "install" {
		return errors.New("per-user startup changed after confirmation; inspect it with `px startup status` and retry")
	}
	if action == "start" {
		_, err = deps.activate(ctx, plan, nil)
	} else {
		_, err = deps.execute(ctx, plan, action, nil)
	}
	if err != nil {
		return err
	}
	return waitForAgentReady(ctx, client, deps.ready, 10*time.Second, 100*time.Millisecond)
}

func acquireStartupLock(ctx context.Context) (*processlock.Lock, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(cache, "px")
	if err := apphome.EnsurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	lock := processlock.New(processlock.Config{Path: filepath.Join(directory, "startup.lock"), Name: "startup operation lock"})
	if err := lock.Start(ctx); err != nil {
		if errors.Is(err, processlock.ErrLocked) {
			return nil, fmt.Errorf("another PX startup operation is in progress: %w", err)
		}
		return nil, fmt.Errorf("acquire PX startup operation lock: %w", err)
	}
	return lock, nil
}

func waitForAgentReady(ctx context.Context, client *localipc.Client, readyFunc func(context.Context, *localipc.Client) (bool, error), timeout, interval time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ready, err := readyFunc(ctx, client)
		if err != nil && !errors.Is(err, localipc.ErrAgentUnavailable) {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("per-user startup completed but the PX agent did not become ready")
		case <-ticker.C:
		}
	}
}
