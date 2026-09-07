package servercli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/scotthaleen/go-toolbelt/logging"
	"github.com/scotthaleen/px/internal/adapterapi"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/securefile"
	"github.com/scotthaleen/px/internal/serveradmin"
	"github.com/scotthaleen/px/internal/serverhost"
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
	verbosity int
	logFormat string
}

func NewCommand(ctx context.Context, streams IOStreams) *cobra.Command {
	opts := &rootOptions{}
	root := &cobra.Command{Use: "px-server", Short: "PX rendezvous and STUN server", SilenceErrors: true, SilenceUsage: true}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.PersistentFlags().StringVar(&opts.home, "home", "", "PX application home (overrides PX_HOME)")
	root.PersistentFlags().CountVarP(&opts.verbosity, "verbose", "v", "increase log verbosity")
	root.PersistentFlags().StringVar(&opts.logFormat, "log-format", string(logging.FormatAuto), "log format: auto, text, tint, or json")
	root.AddCommand(
		newVersionCommand(streams),
		newInitCommand(streams, opts),
		newServeCommand(ctx, streams, opts),
		newStatusCommand(ctx, streams, opts),
		newStopCommand(ctx, streams, opts),
		newDevicesCommand(ctx, streams, opts),
		newInviteCommand(ctx, streams, opts),
		newAdaptersCommand(ctx, streams, opts),
		newAuditCommand(ctx, streams, opts),
		newDebugCommand(ctx, streams, opts),
	)
	return root
}

func newVersionCommand(streams IOStreams) *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print build information", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		_, err := fmt.Fprintln(streams.Out, versioninfo.String("px-server"))
		return err
	}}
}

func newServeCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var listenAddress, stunAddress string
	var trustedProxyCIDRs []string
	command := &cobra.Command{Use: "serve", Short: "Run the PX rendezvous server", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		paths, logger, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		return serverhost.RunServer(ctx, paths, listenAddress, stunAddress, trustedProxyCIDRs, logger)
	}}
	command.Flags().StringVar(&listenAddress, "listen", "127.0.0.1:8080", "HTTP rendezvous listen address")
	command.Flags().StringVar(&stunAddress, "stun-listen", "", "optional UDP STUN listen address")
	command.Flags().StringArrayVar(&trustedProxyCIDRs, "trusted-proxy", nil, "trusted HTTP reverse-proxy CIDR (repeatable, maximum 16)")
	return command
}

func newDebugCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	debug := &cobra.Command{Use: "debug", Short: "Run experimental server diagnostics"}
	var listenAddress string
	signal := &cobra.Command{Use: "signal", Short: "Run the bounded probe signaling service", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		_, logger, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		return serverhost.RunSignalServer(ctx, listenAddress, logger)
	}}
	signal.Flags().StringVar(&listenAddress, "listen", "127.0.0.1:8090", "probe signaling listen address")
	debug.AddCommand(signal)
	return debug
}

func newInitCommand(streams IOStreams, opts *rootOptions) *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Initialize the rendezvous server authority", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		paths, _, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		if err := paths.EnsureServer(); err != nil {
			return err
		}
		if err := membership.Initialize(paths.ServerAuthorityKey, paths.ServerIdentity); err != nil {
			return err
		}
		authority, err := membership.Load(paths.ServerAuthorityKey, paths.ServerIdentity)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(streams.Out, authority.ServerID())
		return err
	}}
}

func newStatusCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{Use: "status", Short: "Inspect bounded rendezvous operational status", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		var status serveradmin.Status
		if err := adminRequest(ctx, streams, opts, http.MethodGet, "/v1/status", nil, &status); err != nil {
			return err
		}
		if status.Version != serveradmin.Version {
			return localipc.ErrServerAdminVersionMismatch
		}
		status.Build = serveradmin.SanitizeBuildStatus(status.Build)
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(status)
		}
		return writeStatus(streams.Out, status)
	}}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	return command
}

func writeStatus(output io.Writer, status serveradmin.Status) error {
	status.Build = serveradmin.SanitizeBuildStatus(status.Build)
	fields := []struct {
		name  string
		value any
	}{
		{"build_version", status.Build.Version},
		{"build_commit", status.Build.Commit},
		{"build_date", status.Build.Date},
		{"ready", status.Ready},
		{"authority_available", status.AuthorityAvailable},
		{"database_healthy", status.DatabaseHealthy},
		{"http_listener_ready", status.HTTPListenerReady},
		{"authenticated_connections", status.AuthenticatedConnections},
		{"pending_enrollments", status.PendingEnrollments},
		{"signaling_queue_queued", status.SignalingQueue.Queued},
		{"signaling_queue_capacity", status.SignalingQueue.Capacity},
		{"signaling_queue_max_depth", status.SignalingQueue.MaxDepth},
		{"signaling_queue_per_client_capacity", status.SignalingQueue.PerClientCapacity},
		{"enrollment_rejected", status.Counters.EnrollmentRejected},
		{"authentication_failed", status.Counters.AuthenticationFailed},
		{"signaling_rejected", status.Counters.SignalingRejected},
		{"queue_overflow", status.Counters.QueueOverflow},
		{"authenticated_connected", status.Counters.AuthenticatedConnected},
		{"authenticated_disconnected", status.Counters.AuthenticatedDisconnected},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(output, "%s\t%v\n", field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

func newStopCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	return &cobra.Command{Use: "stop", Short: "Stop the local PX rendezvous server", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		var result struct {
			Stopping bool `json:"stopping"`
		}
		if err := adminRequest(ctx, streams, opts, http.MethodPost, "/v1/shutdown", nil, &result); err != nil {
			return err
		}
		if !result.Stopping {
			return errors.New("PX server did not accept shutdown request")
		}
		_, err := fmt.Fprintln(streams.Out, "PX server is stopping")
		return err
	}}
}

func newAdaptersCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	adapters := &cobra.Command{Use: "adapters", Short: "Administer enrollment adapter identities"}
	adapters.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit sensitive JSON where applicable")
	endpoint := &cobra.Command{Use: "endpoint", Short: "Print the resolved protected adapter IPC endpoint", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		paths, _, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(struct {
				Version  int    `json:"version"`
				Endpoint string `json:"endpoint"`
			}{serveradmin.Version, paths.ServerAdapterEndpoint})
		}
		_, err = fmt.Fprintln(streams.Out, paths.ServerAdapterEndpoint)
		return err
	}}
	newCredential := func(action string) *cobra.Command {
		var credentialFile string
		command := &cobra.Command{Use: action + " ADAPTER_ID", Short: map[string]string{"provision": "Provision an enrollment adapter", "rotate": "Rotate an adapter credential"}[action], Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			adapterID := args[0]
			var output *os.File
			if credentialFile != "" {
				var err error
				output, err = securefile.CreateExclusive(credentialFile)
				if err != nil {
					return fmt.Errorf("create adapter credential file: %w", err)
				}
			}
			keep := false
			defer func() {
				if output != nil {
					_ = output.Close()
					if !keep {
						_ = os.Remove(credentialFile)
					}
				}
			}()
			var result serveradmin.AdapterProvisioning
			if err := adminRequest(ctx, streams, opts, http.MethodPost, "/v1/adapters/"+action, serveradmin.AdapterRequest{AdapterID: adapterID}, &result); err != nil {
				return classifyCredentialError(action, adapterID, err)
			}
			if result.Version != serveradmin.Version || result.AdapterID != adapterID || action == "provision" && !result.Active {
				return credentialOutcomeUnknown(action, adapterID)
			}
			if _, err := adapterapi.DecodeCredential(result.Credential); err != nil {
				return credentialOutcomeUnknown(action, adapterID)
			}
			if output != nil {
				if err := writeCredential(output, result.Credential); err != nil {
					return credentialOutcomeUnknown(action, adapterID)
				}
				output, keep, result.Credential = nil, true, ""
				if _, err := fmt.Fprintf(streams.Err, "Adapter credential written once to %s\n", credentialFile); err != nil {
					return credentialOutcomeUnknown(action, adapterID)
				}
			} else if _, err := fmt.Fprintln(streams.Err, "Warning: adapter credential is sensitive and is shown only once"); err != nil {
				return credentialOutcomeUnknown(action, adapterID)
			}
			if jsonOutput {
				if result.Credential == "" {
					return json.NewEncoder(streams.Out).Encode(result.AdapterStatus)
				}
				return writeOneTimeCredential(streams.Out, result, true, action, adapterID)
			}
			if result.Credential != "" {
				return writeOneTimeCredential(streams.Out, result, false, action, adapterID)
			}
			_, err := fmt.Fprintf(streams.Out, "%s\tactive=%t\n", result.AdapterID, result.Active)
			return err
		}}
		command.Flags().StringVar(&credentialFile, "credential-file", "", "create a new platform-owner-only credential file")
		return command
	}
	status := &cobra.Command{Use: "status ADAPTER_ID", Short: "Inspect one redacted adapter identity", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		var result serveradmin.AdapterStatus
		if err := adminRequest(ctx, streams, opts, http.MethodGet, "/v1/adapters/status?adapter_id="+url.QueryEscape(args[0]), nil, &result); err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err := fmt.Fprintf(streams.Out, "%s\tactive=%t\tlast_command_id=%s\n", result.AdapterID, result.Active, result.LastCommandID)
		return err
	}}
	setActive := func(action string, active bool) *cobra.Command {
		return &cobra.Command{Use: action + " ADAPTER_ID", Short: action + " an enrollment adapter", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			var result serveradmin.AdapterStatus
			if err := adminRequest(ctx, streams, opts, http.MethodPost, "/v1/adapters/"+action, serveradmin.AdapterRequest{AdapterID: args[0]}, &result); err != nil {
				return err
			}
			if result.Active != active {
				return errors.New("adapter active state did not change")
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			_, err := fmt.Fprintf(streams.Out, "%s\tactive=%t\n", result.AdapterID, result.Active)
			return err
		}}
	}
	adapters.AddCommand(endpoint, newCredential("provision"), status, setActive("activate", true), setActive("deactivate", false), newCredential("rotate"))
	return adapters
}

type credentialOutput interface {
	io.Writer
	Sync() error
	Close() error
}

func writeCredential(file credentialOutput, credential string) error {
	if _, err := io.WriteString(file, credential+"\n"); err != nil {
		return fmt.Errorf("write adapter credential file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync adapter credential file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close adapter credential file: %w", err)
	}
	return nil
}

func writeOneTimeCredential(output io.Writer, result serveradmin.AdapterProvisioning, jsonOutput bool, action, adapterID string) error {
	var err error
	if jsonOutput {
		err = json.NewEncoder(output).Encode(result)
	} else {
		_, err = fmt.Fprintln(output, result.Credential)
	}
	if err != nil {
		return credentialOutcomeUnknown(action, adapterID)
	}
	return nil
}

func classifyCredentialError(action, adapterID string, err error) error {
	var responseError *localipc.Error
	if errors.As(err, &responseError) && responseError.Status >= 400 && responseError.Status < 500 {
		return err
	}
	return credentialOutcomeUnknown(action, adapterID)
}

func credentialOutcomeUnknown(action, adapterID string) error {
	if action == "provision" {
		return fmt.Errorf("adapter credential outcome_unknown: issuance may have committed; inspect `px-server adapters status %s`; if the identity exists, rotate it again and securely replace the credential file; if status clearly reports that provisioning did not occur, retry provisioning", adapterID)
	}
	return fmt.Errorf("adapter credential outcome_unknown: issuance may have committed; inspect `px-server adapters status %s`; rotation may have committed, so rotate again and securely replace the credential file", adapterID)
}

func newInviteCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput, yes bool
	invites := &cobra.Command{Use: "invite", Short: "Administer one-time enrollment invites"}
	invites.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit a JSON result; creation output contains a sensitive token")

	lifetime := membership.DefaultInviteLifetime
	create := &cobra.Command{Use: "create LABEL", Short: "Create a label-bound enrollment invite", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if err := membership.ValidateLabel(args[0]); err != nil {
			return err
		}
		if lifetime < membership.MinInviteLifetime || lifetime > membership.MaxInviteLifetime || lifetime%time.Second != 0 {
			return errors.New("--expires must be a whole-second duration from 1m through 168h")
		}
		paths, _, err := prepare(streams, opts)
		if err != nil {
			return err
		}
		serverKey, err := identity.LoadPublic(paths.ServerIdentity)
		if err != nil {
			return errors.New("load local server identity for invite validation")
		}
		request := serveradmin.CreateInviteRequest{Version: serveradmin.InviteVersion, Label: args[0], LifetimeSeconds: int64(lifetime / time.Second)}
		var result serveradmin.InviteCreation
		if err := inviteAdminRequest(ctx, streams, opts, http.MethodPost, "/v1/invites", request, &result); err != nil {
			return classifyInviteMutationError("create", "", err)
		}
		if err := validateInviteCreation(result, identity.ID(serverKey), args[0], lifetime); err != nil {
			return inviteOutcomeUnknown("create", "")
		}
		if _, err := fmt.Fprintf(streams.Err, "Created invite %s for %s; expires %s UTC. Warning: the enrollment token is sensitive and is shown only once.\n", result.InviteID, result.Label, result.ExpiresAt); err != nil {
			return inviteOutcomeUnknown("create", result.InviteID)
		}
		if jsonOutput {
			if err := json.NewEncoder(streams.Out).Encode(result); err != nil {
				return inviteOutcomeUnknown("create", result.InviteID)
			}
			return nil
		}
		if _, err := fmt.Fprintln(streams.Out, result.Token); err != nil {
			return inviteOutcomeUnknown("create", result.InviteID)
		}
		return nil
	}}
	create.Flags().DurationVar(&lifetime, "expires", membership.DefaultInviteLifetime, "invite lifetime from 1m through 168h")

	list := &cobra.Command{Use: "list", Short: "List active enrollment invites without tokens", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		result, err := listServerInvites(ctx, streams, opts)
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
		if err := membership.ValidateInviteID(args[0]); err != nil {
			return err
		}
		if jsonOutput && !yes {
			return errors.New("JSON invite revocation requires --yes")
		}
		if !yes && !inputIsTerminal(streams.In) {
			return errors.New("invite revocation requires --yes when input is not a terminal")
		}
		listed, err := listServerInvites(ctx, streams, opts)
		if err != nil {
			return err
		}
		var selected serveradmin.Invite
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
				if err := writeInviteRevocationPreview(streams.Err, selected); err != nil {
					return err
				}
			} else {
				confirmed, err := confirmInviteRevocation(bufio.NewReader(streams.In), streams.Err, selected)
				if err != nil {
					return err
				}
				if !confirmed {
					return errors.New("invite revocation cancelled")
				}
			}
		}
		var result serveradmin.InviteRevocation
		if err := inviteAdminRequest(ctx, streams, opts, http.MethodDelete, "/v1/invites/"+args[0], nil, &result); err != nil {
			return classifyInviteMutationError("revoke", args[0], err)
		}
		if result.Version != serveradmin.InviteVersion || result.State != "revoked" || result.Invite != selected || validateInviteDTO(result.Invite) != nil {
			return inviteOutcomeUnknown("revoke", args[0])
		}
		return writeInviteRevocationResult(streams.Out, result, jsonOutput)
	}}
	revoke.Flags().BoolVar(&yes, "yes", false, "confirm invite revocation")
	invites.AddCommand(create, list, revoke)
	return invites
}

func listServerInvites(ctx context.Context, streams IOStreams, opts *rootOptions) (serveradmin.InviteList, error) {
	var result serveradmin.InviteList
	if err := inviteAdminRequest(ctx, streams, opts, http.MethodGet, "/v1/invites", nil, &result); err != nil {
		return serveradmin.InviteList{}, err
	}
	if inviteapi.ValidateList(result) != nil {
		return serveradmin.InviteList{}, errors.New("PX server returned an invalid invite list")
	}
	return result, nil
}

func validateInviteCreation(result serveradmin.InviteCreation, serverID, label string, lifetime time.Duration) error {
	return inviteapi.ValidateCreation(result, serverID, label, "local", "", lifetime)
}

func validateInviteDTO(invite serveradmin.Invite) error {
	return inviteapi.Validate(invite)
}

func writeInviteRevocationPreview(output io.Writer, invite serveradmin.Invite) error {
	_, err := fmt.Fprintf(output, "Revoke invite %s for %s, expiring %s UTC?\nThe one-time token will immediately stop authorizing enrollment and cannot be recovered.\n", invite.InviteID, invite.Label, invite.ExpiresAt)
	return err
}

func confirmInviteRevocation(reader *bufio.Reader, output io.Writer, invite serveradmin.Invite) (bool, error) {
	if err := writeInviteRevocationPreview(output, invite); err != nil {
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

func writeInviteRevocationResult(output io.Writer, result serveradmin.InviteRevocation, jsonOutput bool) error {
	if jsonOutput {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return fmt.Errorf("write invite revocation result: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(output, "revoked %s (%s)\n", result.Invite.Label, result.Invite.InviteID); err != nil {
		return fmt.Errorf("write invite revocation result: %w", err)
	}
	return nil
}

func classifyInviteMutationError(action, inviteID string, err error) error {
	if errors.Is(err, localipc.ErrServerAdminVersionMismatch) {
		return err
	}
	var responseError *localipc.Error
	if errors.As(err, &responseError) {
		deterministic := responseError.Status == http.StatusBadRequest && responseError.Code == "invalid_request"
		if action == "create" {
			deterministic = deterministic || responseError.Status == http.StatusConflict && responseError.Code == string(membership.CodeInviteLabelUnavailable) ||
				responseError.Status == http.StatusTooManyRequests && responseError.Code == string(membership.CodeInviteCapacity)
		} else if action == "revoke" {
			deterministic = deterministic || responseError.Status == http.StatusNotFound && responseError.Code == string(membership.CodeInviteUnavailable)
		}
		if deterministic {
			return err
		}
	}
	return inviteOutcomeUnknown(action, inviteID)
}

func inviteOutcomeUnknown(action, inviteID string) error {
	if action == "create" {
		return errors.New("invite creation outcome_unknown: issuance may have committed but the one-time token cannot be recovered; list active invites, revoke the unrecoverable invite, and create a replacement")
	}
	return fmt.Errorf("invite revocation outcome_unknown: revocation of %s may have committed; list active invites before deciding whether another action is needed", inviteID)
}

func newDevicesCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput, yes, listActive, listAll bool
	var listLimit int
	var listCursor string
	devices := &cobra.Command{Use: "devices", Short: "Administer rendezvous memberships"}
	devices.PersistentFlags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	pending := &cobra.Command{Use: "pending", Short: "List pending enrollment requests", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		var result []membership.Pending
		if err := adminRequest(ctx, streams, opts, http.MethodGet, "/v1/devices/pending", nil, &result); err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		for _, item := range result {
			if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%s\n", item.Code, item.Label, item.DeviceID); err != nil {
				return err
			}
		}
		return nil
	}}
	list := &cobra.Command{Use: "list", Short: "List enrolled and revoked members", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if listLimit <= 0 || listLimit > membership.MaxMemberListLimit {
			return fmt.Errorf("--limit must be between 1 and %d", membership.MaxMemberListLimit)
		}
		if listAll && !listActive {
			return errors.New("--all requires --active; use --cursor to page unbounded membership history")
		}
		if listAll && listCursor != "" {
			return errors.New("--all and --cursor cannot be combined")
		}
		cursor := listCursor
		result := serveradmin.ListDevicesResponse{Version: serveradmin.Version, Devices: make([]membership.Member, 0)}
		for {
			query := url.Values{"limit": {fmt.Sprint(listLimit)}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			if listActive {
				query.Set("active", "true")
			}
			var page serveradmin.ListDevicesResponse
			if err := adminRequest(ctx, streams, opts, http.MethodGet, "/v1/devices?"+query.Encode(), nil, &page); err != nil {
				return err
			}
			if page.Version != serveradmin.Version {
				return localipc.ErrServerAdminVersionMismatch
			}
			result.Devices = append(result.Devices, page.Devices...)
			result.NextCursor = page.NextCursor
			if len(result.Devices) > membership.MaxMembers {
				return errors.New("active member capacity exceeded while listing all members")
			}
			if !listAll || page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
		if listAll {
			result.NextCursor = ""
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		for _, member := range result.Devices {
			state := "active"
			if member.RevokedAt != nil {
				state = "revoked"
			}
			if _, err := fmt.Fprintf(streams.Out, "%s\t%s\t%d\t%s\n", member.Label, member.DeviceID, member.Revision, state); err != nil {
				return err
			}
		}
		if result.NextCursor != "" {
			_, err := fmt.Fprintf(streams.Err, "More members are available; continue with --cursor %s\n", result.NextCursor)
			return err
		}
		return nil
	}}
	list.Flags().IntVar(&listLimit, "limit", membership.DefaultMemberListLimit, "maximum members to return")
	list.Flags().StringVar(&listCursor, "cursor", "", "continue membership history from an earlier page")
	list.Flags().BoolVar(&listActive, "active", false, "list active members only")
	list.Flags().BoolVar(&listAll, "all", false, "list all active members across bounded pages")
	approve := &cobra.Command{Use: "approve CODE", Short: "Approve one pending enrollment", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		var result membership.Member
		if err := adminRequest(ctx, streams, opts, http.MethodPost, "/v1/devices/approve", serveradmin.ApproveRequest{Code: args[0]}, &result); err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err := fmt.Fprintf(streams.Out, "approved %s (%s)\n", result.Label, result.DeviceID)
		return err
	}}
	revoke := &cobra.Command{Use: "revoke DEVICE_ID", Short: "Revoke one enrolled device", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if jsonOutput && !yes {
			return errors.New("JSON revocation requires --yes")
		}
		if !yes && !inputIsTerminal(streams.In) {
			return errors.New("device revocation requires --yes when input is not a terminal")
		}
		var inspected membership.Member
		if err := adminRequest(ctx, streams, opts, http.MethodGet, "/v1/devices/inspect?device_id="+url.QueryEscape(args[0]), nil, &inspected); err != nil {
			return err
		}
		if !jsonOutput {
			if yes {
				if err := writeRevocationPreview(streams.Err, inspected); err != nil {
					return err
				}
			} else {
				confirmed, err := confirmRevocation(bufio.NewReader(streams.In), streams.Err, inspected)
				if err != nil {
					return err
				}
				if !confirmed {
					return errors.New("device revocation cancelled")
				}
			}
		}
		var result membership.Member
		request := serveradmin.RevokeRequest{DeviceID: inspected.DeviceID, ExpectedRevision: inspected.Revision}
		if err := adminRequest(ctx, streams, opts, http.MethodPost, "/v1/devices/revoke", request, &result); err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		_, err := fmt.Fprintf(streams.Out, "revoked %s (%s)\n", result.Label, result.DeviceID)
		return err
	}}
	revoke.Flags().BoolVar(&yes, "yes", false, "confirm device revocation")
	devices.AddCommand(pending, list, approve, revoke)
	return devices
}

func writeRevocationPreview(output io.Writer, member membership.Member) error {
	_, err := fmt.Fprintf(output, "Revoke %s (%s), revision %d?\nThis closes current presence and prevents reauthentication. It does not delete remote files or local contexts.\n", member.Label, member.DeviceID, member.Revision)
	return err
}

func confirmRevocation(reader *bufio.Reader, output io.Writer, member membership.Member) (bool, error) {
	if err := writeRevocationPreview(output, member); err != nil {
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

func newAuditCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	limit := membership.DefaultAuditLimit
	audit := &cobra.Command{Use: "audit", Short: "Inspect redacted server administration history"}
	list := &cobra.Command{Use: "list", Short: "List newest audit events first", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if limit <= 0 || limit > membership.MaxAuditLimit {
			return fmt.Errorf("--limit must be between 1 and %d", membership.MaxAuditLimit)
		}
		result := make([]membership.AuditEvent, 0)
		if err := adminRequest(ctx, streams, opts, http.MethodGet, fmt.Sprintf("/v1/audit?limit=%d", limit), nil, &result); err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(streams.Out).Encode(result)
		}
		for _, event := range result {
			actor := event.ActorType
			if event.ActorDeviceID != "" {
				actor += ":" + event.ActorDeviceID
			}
			revision := "-"
			if event.TargetRevision != nil {
				revision = fmt.Sprint(*event.TargetRevision)
			}
			if _, err := fmt.Fprintf(streams.Out, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", event.ID, event.OccurredAt.UTC().Format(time.RFC3339), actor, event.Action, event.TargetDeviceID, event.TargetLabel, revision); err != nil {
				return err
			}
		}
		return nil
	}}
	list.Flags().IntVar(&limit, "limit", membership.DefaultAuditLimit, "maximum events to return")
	list.Flags().BoolVar(&jsonOutput, "json", false, "emit a JSON result")
	audit.AddCommand(list)
	return audit
}

func adminRequest(ctx context.Context, streams IOStreams, opts *rootOptions, method, path string, input, output any) error {
	paths, _, err := prepare(streams, opts)
	if err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return localipc.NewServerAdminClient(paths.ServerAdminEndpoint, serveradmin.Version).JSON(requestContext, method, path, input, output)
}

func inviteAdminRequest(ctx context.Context, streams IOStreams, opts *rootOptions, method, path string, input, output any) error {
	paths, _, err := prepare(streams, opts)
	if err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return localipc.NewServerAdminClient(paths.ServerAdminEndpoint, serveradmin.Version).JSONStrict(requestContext, method, path, input, output)
}

func prepare(streams IOStreams, opts *rootOptions) (apphome.Paths, *slog.Logger, error) {
	paths, err := apphome.Resolve(opts.home)
	if err != nil {
		return apphome.Paths{}, nil, err
	}
	logger, err := logging.NewLogger(logging.Config{Verbosity: opts.verbosity, Output: streams.Err, Format: logging.Format(opts.logFormat)})
	if err != nil {
		return apphome.Paths{}, nil, err
	}
	return paths, logger, nil
}

func inputIsTerminal(input io.Reader) bool {
	file, ok := input.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}
