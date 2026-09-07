package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/direct"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/putroot"
	"github.com/scotthaleen/px/internal/startup"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type onboardOptions struct {
	server              string
	label               string
	offeredRoot         string
	inboxRoot           string
	putRoot             string
	stunURLs            []string
	defaultSTUN         bool
	noSTUN              bool
	installAgent        bool
	wait                bool
	yes                 bool
	allowFilesystemRoot bool
	allowPut            bool
	allowPutSet         bool
	jsonOutput          bool
	invite              string
	inviteFile          string
	inviteSet           bool
	inviteFileSet       bool
}

// DefaultServerURL may be set with -ldflags -X for deployment-specific client builds.
var DefaultServerURL string

func newOnboardCommand(ctx context.Context, streams IOStreams, root *rootOptions) *cobra.Command {
	options := onboardOptions{}
	command := &cobra.Command{
		Use:   "onboard [SERVER]",
		Short: "Configure the agent and join a trusted context",
		Args: func(command *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(command, args); err != nil {
				return err
			}
			if err := validateSTUNCreationFlags(command, options.noSTUN); err != nil {
				return err
			}
			options.inviteSet = command.Flags().Changed("invite")
			options.inviteFileSet = command.Flags().Changed("invite-file")
			if options.inviteSet && options.inviteFileSet {
				return errors.New("--invite and --invite-file are mutually exclusive")
			}
			if options.inviteSet && options.invite == "" {
				return errors.New("--invite requires a non-empty token")
			}
			if options.inviteFileSet && options.inviteFile == "" {
				return errors.New("--invite-file requires a non-empty path")
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			options.defaultSTUN = !options.noSTUN && !command.Flags().Changed("stun")
			captureOnboardPutFlag(command, &options)
			if len(args) == 1 {
				if options.server != "" {
					serverFlag, flagErr := normalizeOnboardServer(options.server)
					serverArg, argErr := normalizeOnboardServer(args[0])
					if flagErr != nil || argErr != nil || serverFlag != serverArg {
						return errors.New("SERVER and --server disagree")
					}
				}
				options.server = args[0]
			}
			if options.server == "" {
				options.server = DefaultServerURL
			}
			return runOnboard(ctx, streams, root, options, command.Flags().Changed("wait"))
		},
	}
	command.Flags().StringVar(&options.server, "server", "", "rendezvous server HTTP(S) origin")
	command.Flags().StringVar(&options.label, "name", "", "device label requested from the server")
	command.Flags().StringVar(&options.offeredRoot, "offered-root", "", "native root offered to remote peers")
	command.Flags().BoolVar(&options.allowFilesystemRoot, "allow-filesystem-root", false, "acknowledge dangerous filesystem-root exposure")
	command.Flags().StringVar(&options.inboxRoot, "inbox-root", "", "native root for received files")
	command.Flags().StringVar(&options.putRoot, "put-root", "", "existing canonical narrow root for remote put")
	command.Flags().BoolVar(&options.allowPut, "allow-put", false, "allow every authenticated context member to create files and request supported replacement beneath put root")
	command.Flags().StringSliceVar(&options.stunURLs, "stun", nil, "context STUN URL (repeatable, maximum four)")
	command.Flags().BoolVar(&options.noSTUN, "no-stun", false, "create the context without a STUN service")
	command.Flags().BoolVar(&options.installAgent, "install-agent", false, "install and start per-user agent startup if needed")
	command.Flags().BoolVar(&options.wait, "wait", false, "wait for approval and agent connection")
	command.Flags().BoolVar(&options.yes, "yes", false, "confirm trust and filesystem changes noninteractively")
	command.Flags().BoolVar(&options.jsonOutput, "json", false, "emit context states and diagnostics as JSON lines")
	command.Flags().StringVar(&options.invite, "invite", "", "one-time enrollment invite (may be visible in process inspection)")
	command.Flags().StringVar(&options.inviteFile, "invite-file", "", "read one-time enrollment invite from PATH, or - for stdin")
	return command
}

func captureOnboardPutFlag(command *cobra.Command, options *onboardOptions) {
	options.allowPutSet = command.Flags().Changed("allow-put")
}

func runOnboard(ctx context.Context, streams IOStreams, root *rootOptions, options onboardOptions, waitSet bool) error {
	paths, _, err := prepare(streams, root)
	if err != nil {
		return err
	}
	interactive := inputIsTerminal(streams.In)
	reader := bufio.NewReader(streams.In)
	client := localipc.NewAgentClient(paths.AgentEndpoint)
	ready, readyErr := agentReady(ctx, client)
	if readyErr != nil && !errors.Is(readyErr, localipc.ErrAgentUnavailable) {
		return readyErr
	}
	if !ready {
		install := options.installAgent
		if !install && interactive {
			install, err = promptConfirm(ctx, reader, streams.Err, "The PX agent is not reachable. Install and start per-user startup now?", false)
			if err != nil {
				return err
			}
		}
		if !install {
			return localipc.ErrAgentUnavailable
		}
		if err := installOnboardAgent(ctx, paths, client); err != nil {
			return err
		}
	}
	if options.inviteFileSet {
		input := streams.In
		var file *os.File
		if options.inviteFile != "-" {
			file, err = os.Open(options.inviteFile)
			if err != nil {
				return fmt.Errorf("read invite file: %w", err)
			}
			defer file.Close()
			input = file
		}
		options.invite, err = readInvite(input)
		if err != nil {
			return err
		}
	}
	if options.inviteSet || options.inviteFileSet {
		if _, err := membership.ParseInviteToken(options.invite); err != nil {
			return errors.New("invalid enrollment invite token")
		}
	}
	if err := completeOnboardOptions(ctx, reader, streams.Err, root, &options, interactive && !options.yes); err != nil {
		return err
	}
	if !interactive && !options.yes {
		return errors.New("noninteractive onboarding requires --yes to confirm trust and filesystem changes")
	}
	contextName := root.context
	if contextName == "" {
		contextName = os.Getenv("PX_CONTEXT")
	}
	if contextName == "" {
		contextName = "default"
	}
	serverURL, err := normalizeOnboardServer(options.server)
	if err != nil {
		return err
	}
	if err := membership.ValidateLabel(contextName); err != nil {
		return fmt.Errorf("context name: %w", err)
	}
	if err := membership.ValidateLabel(options.label); err != nil {
		return fmt.Errorf("device label: %w", err)
	}
	if err := direct.ValidateSTUNURLs(options.stunURLs); err != nil {
		return err
	}
	if err := contextstate.ValidateOfferedRootPath(options.offeredRoot); err != nil {
		return fmt.Errorf("offered root: %w", err)
	}
	options.offeredRoot, err = filepath.Abs(options.offeredRoot)
	if err != nil {
		return fmt.Errorf("offered root: %w", err)
	}
	offeredScope, err := contextstate.OfferedRootScope(options.offeredRoot)
	if err != nil {
		return fmt.Errorf("offered root: %w", err)
	}
	if offeredScope == contextstate.OfferedRootScopeFilesystemRoot && !options.allowFilesystemRoot {
		return errors.New("offered root is a filesystem root; --allow-filesystem-root is required (generic --yes does not acknowledge this exposure)")
	}
	if offeredScope == contextstate.OfferedRootScopeNarrow && options.allowFilesystemRoot {
		return errors.New("--allow-filesystem-root is only valid for a filesystem root")
	}
	options.inboxRoot, err = filepath.Abs(options.inboxRoot)
	if err != nil {
		return fmt.Errorf("inbox root: %w", err)
	}
	if options.allowPut && options.putRoot == "" {
		return errors.New("--allow-put requires --put-root")
	}
	if options.putRoot != "" {
		options.putRoot, err = filepath.Abs(options.putRoot)
		if err != nil {
			return fmt.Errorf("put root: %w", err)
		}
		options.putRoot = filepath.Clean(options.putRoot)
	}
	for _, root := range []*string{&options.offeredRoot, &options.inboxRoot} {
		canonical, canonicalErr := filepath.EvalSymlinks(*root)
		if canonicalErr == nil {
			*root = filepath.Clean(canonical)
		} else if !errors.Is(canonicalErr, os.ErrNotExist) {
			return fmt.Errorf("canonicalize root: %w", canonicalErr)
		}
	}
	if options.putRoot != "" {
		canonical, canonicalErr := putroot.Canonical(options.putRoot)
		if canonicalErr != nil {
			return fmt.Errorf("put root: %w", canonicalErr)
		}
		options.putRoot = canonical
	}
	existing, err := ensureOnboardContextUnchanged(ctx, client, contextName, serverURL, options)
	if err != nil {
		return err
	}
	if !options.jsonOutput {
		if _, err := fmt.Fprintf(streams.Err, "Context: %s\nServer: %s\nDevice: %s\nOffered root (readable by trusted members): %s\nInbox root (receives trusted-member sends): %s\n", contextName, serverURL, options.label, options.offeredRoot, options.inboxRoot); err != nil {
			return err
		}
		if options.allowFilesystemRoot {
			if _, err := fmt.Fprintln(streams.Err, "WARNING: DANGER: every authenticated context member can browse and retrieve every reachable regular file beneath this filesystem root."); err != nil {
				return err
			}
		}
		if options.putRoot != "" {
			if _, err := fmt.Fprintf(streams.Err, "Put root (remote create authority): %s\nPut enabled: %t\n", options.putRoot, options.allowPut); err != nil {
				return err
			}
		}
	}
	if interactive && !options.yes {
		confirmed, err := promptConfirm(ctx, reader, streams.Err, "Create these roots if needed and join this trust pool?", false)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("onboarding cancelled")
		}
	}
	for _, path := range []string{options.offeredRoot, options.inboxRoot} {
		if err := ensurePrivateDirectory(path); err != nil {
			return err
		}
	}
	request := contextstate.JoinRequest{Name: contextName, ServerURL: serverURL, Label: options.label, OfferedRoot: options.offeredRoot, InboxRoot: options.inboxRoot, STUNURLs: options.stunURLs, DefaultSTUN: options.defaultSTUN, NoSTUN: options.noSTUN, RequireUnchanged: true, RequireExisting: existing, Invite: options.invite, AllowFilesystemRoot: options.allowFilesystemRoot, AllowPut: options.allowPut, AllowPutSet: options.allowPutSet}
	if options.putRoot != "" {
		request.PutRoot = &options.putRoot
	}
	var state contextstate.State
	if err := client.JSON(ctx, "POST", "/v1/contexts/join", request, &state); err != nil {
		return err
	}
	if err := writeContextState(streams, options.jsonOutput, state, true); err != nil {
		return err
	}
	wait := options.wait
	if interactive && !waitSet {
		wait = true
	}
	if wait {
		state, err = waitOnboardContext(ctx, client, streams, options.jsonOutput, state)
		if err != nil {
			return err
		}
	}
	if state.State == "pending" {
		return nil
	}
	if err := terminalJoinError(state); err != nil {
		return err
	}
	return writeOnboardDiagnostics(ctx, streams, paths, client, state, options.jsonOutput)
}

func readInvite(input io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(input, membership.InviteTokenLength+3))
	if err != nil {
		return "", errors.New("read enrollment invite")
	}
	if len(data) > membership.InviteTokenLength+2 {
		return "", errors.New("enrollment invite input exceeds size limit")
	}
	value := string(data)
	if strings.HasSuffix(value, "\r\n") {
		value = strings.TrimSuffix(value, "\r\n")
	} else if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if _, err := membership.ParseInviteToken(value); err != nil {
		return "", errors.New("invalid enrollment invite token")
	}
	return value, nil
}

func completeOnboardOptions(ctx context.Context, reader *bufio.Reader, output io.Writer, root *rootOptions, options *onboardOptions, interactive bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	defaultOffered, defaultInbox := currentOnboardingRoots(home)
	hostname, _ := os.Hostname()
	if membership.ValidateLabel(hostname) != nil {
		hostname = "device"
	}
	if !interactive {
		if options.server == "" {
			return errors.New("SERVER or --server is required for noninteractive onboarding")
		}
		if options.label == "" {
			options.label = hostname
		}
		if options.offeredRoot == "" {
			options.offeredRoot = defaultOffered
		}
		if options.inboxRoot == "" {
			options.inboxRoot = defaultInbox
		}
		return nil
	}
	contextName := root.context
	if contextName == "" {
		contextName = os.Getenv("PX_CONTEXT")
	}
	if contextName == "" {
		contextName = "default"
	}
	if options.server, err = promptValue(ctx, reader, output, "Server URL", options.server); err != nil {
		return err
	}
	if root.context, err = promptValue(ctx, reader, output, "Context name", contextName); err != nil {
		return err
	}
	if options.label, err = promptValue(ctx, reader, output, "Device name", firstNonempty(options.label, hostname)); err != nil {
		return err
	}
	if options.offeredRoot, err = promptValue(ctx, reader, output, "Offered root", firstNonempty(options.offeredRoot, defaultOffered)); err != nil {
		return err
	}
	if options.inboxRoot, err = promptValue(ctx, reader, output, "Inbox root", firstNonempty(options.inboxRoot, defaultInbox)); err != nil {
		return err
	}
	if !options.noSTUN {
		stunDefault := strings.Join(options.stunURLs, ",")
		if options.defaultSTUN {
			stunDefault = contextstate.DefaultSTUNURL
		}
		stun, promptErr := promptOptionalValue(ctx, reader, output, `STUN URLs (comma-separated; "none" to disable)`, stunDefault)
		if promptErr != nil {
			return promptErr
		}
		if strings.EqualFold(stun, "none") {
			options.defaultSTUN, options.noSTUN, options.stunURLs = false, true, nil
		} else if stun != contextstate.DefaultSTUNURL || !options.defaultSTUN {
			options.defaultSTUN, options.stunURLs = false, splitSTUNURLs(stun)
		}
	}
	return nil
}

func onboardingRoots(goos, home string) (string, string) {
	base := filepath.Join(home, ".local", "share", "px")
	if goos == "windows" {
		base = filepath.Join(home, "Documents", "PX")
	}
	return filepath.Join(base, "shared"), filepath.Join(base, "inbox")
}

func installOnboardAgent(ctx context.Context, paths apphome.Paths, client *localipc.Client) error {
	_, action, _, err := inspectAgentStartup(ctx, paths)
	if err != nil {
		return err
	}
	return activateAgentStartup(ctx, paths, action, client)
}

func agentReady(ctx context.Context, client *localipc.Client) (bool, error) {
	requestContext, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var status agentapi.Status
	if err := client.JSON(requestContext, "GET", "/v1/status", nil, &status); err != nil {
		return false, err
	}
	if err := validateAgentIPCVersion(status.Version); err != nil {
		return false, err
	}
	return true, nil
}

func waitOnboardContext(ctx context.Context, client *localipc.Client, streams IOStreams, jsonOutput bool, state contextstate.State) (contextstate.State, error) {
	lastState, lastCode := state.State, state.PendingCode
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for state.State == "pending" || state.State == "enrolled" || state.State == "disconnected" {
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		case <-ticker.C:
			if err := client.JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(state.Name), nil, &state); err != nil {
				return state, err
			}
			if !state.Enabled {
				return state, errors.New("context was disabled during onboarding")
			}
			if state.State != lastState || state.PendingCode != lastCode {
				if err := writeContextState(streams, jsonOutput, state, false); err != nil {
					return state, err
				}
				lastState, lastCode = state.State, state.PendingCode
			}
		}
	}
	return state, terminalJoinError(state)
}

func writeOnboardDiagnostics(ctx context.Context, streams IOStreams, paths apphome.Paths, client *localipc.Client, state contextstate.State, jsonOutput bool) error {
	ready, readyErr := agentReady(ctx, client)
	if readyErr != nil {
		return readyErr
	}
	roots := []diagnostics.Root{{Context: state.Name, Kind: "offered", Path: state.OfferedRoot, Scope: state.OfferedRootScope, Revision: state.OfferedRootRevision, FilesystemRootAcknowledged: state.FilesystemRootAcknowledged, AuthorityValid: state.OfferedRootAuthorityValid}, {Context: state.Name, Kind: "inbox", Path: state.InboxRoot}}
	if state.PutRoot != nil {
		roots = append(roots, diagnostics.Root{Context: state.Name, Kind: "put", Path: *state.PutRoot, Revision: state.PutRootRevision, AuthorityValid: state.PutRootAuthorityValid})
	}
	checks := diagnostics.Local(paths, ready, roots)
	plan, err := startup.CurrentPlan(paths.Root)
	if err != nil {
		checks = append(checks, diagnostics.Check{ID: "local.startup", Layer: "local", Status: diagnostics.Fail, Summary: "per-user startup configuration could not be inspected"})
	} else {
		status, summary := startup.InspectRuntime(ctx, plan, nil)
		checks = append(checks, diagnostics.Check{ID: "local.startup", Layer: "local", Status: status, Summary: summary})
	}
	var contextChecks []diagnostics.Check
	if err := client.JSON(ctx, "POST", "/v1/doctor/contexts", agentapi.ContextDiagnosticsRequest{Context: state.Name}, &contextChecks); err != nil {
		checks = append(checks, diagnostics.Check{ID: "context.request", Layer: "context", Context: state.Name, Status: diagnostics.Fail, Summary: "context diagnostics request failed"})
	} else {
		checks = append(checks, contextChecks...)
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
			if _, err := fmt.Fprintf(streams.Out, "[%s] %s %s: %s\n", check.Status, check.Layer, check.ID, check.Summary); err != nil {
				return err
			}
		}
	}
	if report.Status == diagnostics.Fail {
		return errors.New("onboarding completed but diagnostic checks failed")
	}
	return nil
}

func ensureOnboardContextUnchanged(ctx context.Context, client *localipc.Client, name, serverURL string, options onboardOptions) (bool, error) {
	var existing contextstate.State
	err := client.JSON(ctx, "GET", "/v1/contexts/"+url.PathEscape(name), nil, &existing)
	if err != nil {
		var response *localipc.Error
		if errors.As(err, &response) && response.Status == 404 {
			return false, nil
		}
		return false, err
	}
	if !existing.Enabled {
		return true, fmt.Errorf("context %q is disabled; use `px context enable %s` before resuming onboarding", name, name)
	}
	if existing.State == "revoked" {
		return true, fmt.Errorf("context %q membership is %s and cannot be resumed", name, existing.State)
	}
	requestedSTUN := options.stunURLs
	if options.noSTUN {
		requestedSTUN = []string{}
	}
	if existing.ServerURL != serverURL || existing.Label != options.label || existing.OfferedRoot != options.offeredRoot || existing.InboxRoot != options.inboxRoot || options.allowPutSet && existing.AllowPut != options.allowPut || options.putRoot != "" && (existing.PutRoot == nil || *existing.PutRoot != options.putRoot) || !options.defaultSTUN && !slices.Equal(existing.STUNURLs, requestedSTUN) {
		return true, fmt.Errorf("context %q already exists with different settings; use explicit context commands to inspect or change it", name)
	}
	return true, nil
}

func normalizeOnboardServer(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("server URL must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("onboarding root %q is not a directory", path)
		}
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect onboarding root %q: %w", path, err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create onboarding root %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect onboarding root %q: %w", path, err)
	}
	return nil
}

func inputIsTerminal(input io.Reader) bool {
	file, ok := input.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func promptValue(ctx context.Context, reader *bufio.Reader, output io.Writer, label, defaultValue string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if defaultValue == "" {
		if _, err := fmt.Fprintf(output, "%s: ", label); err != nil {
			return "", err
		}
	} else {
		if _, err := fmt.Fprintf(output, "%s [%s]: ", label, defaultValue); err != nil {
			return "", err
		}
	}
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultValue
	}
	if value == "" {
		return "", fmt.Errorf("%s is required", strings.ToLower(label))
	}
	return value, nil
}

func promptOptionalValue(ctx context.Context, reader *bufio.Reader, output io.Writer, label, defaultValue string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(output, "%s [%s]: ", label, defaultValue); err != nil {
		return "", err
	}
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func splitSTUNURLs(value string) []string {
	values := make([]string, 0, 1)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func validateSTUNCreationFlags(command *cobra.Command, noSTUN bool) error {
	if noSTUN && command.Flags().Changed("stun") {
		return errors.New("--no-stun and --stun cannot be combined")
	}
	return nil
}

func promptConfirm(ctx context.Context, reader *bufio.Reader, output io.Writer, message string, defaultYes bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	defaultLabel := "y/N"
	if defaultYes {
		defaultLabel = "Y/n"
	}
	if _, err := fmt.Fprintf(output, "%s [%s] ", message, defaultLabel); err != nil {
		return false, err
	}
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultYes, nil
	}
	switch strings.ToLower(value) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, errors.New("answer must be yes or no")
	}
}

func firstNonempty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
