package cli

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/spf13/cobra"
)

const completionTimeout = 250 * time.Millisecond

type completionSource interface {
	Complete(context.Context, string, string, string) ([]string, error)
	DefaultContext(context.Context) (string, error)
	TransferIDs(context.Context, string, string, string, string) ([]string, error)
}

type ipcCompletionSource struct {
	opts *rootOptions
}

func (s *ipcCompletionSource) client() (*localipc.Client, error) {
	paths, err := apphome.Resolve(s.opts.home)
	if err != nil {
		return nil, err
	}
	return localipc.NewAgentClient(paths.AgentEndpoint), nil
}

func (s *ipcCompletionSource) Complete(ctx context.Context, kind, contextName, prefix string) ([]string, error) {
	client, err := s.client()
	if err != nil {
		return nil, err
	}
	query := url.Values{"kind": {kind}, "prefix": {prefix}}
	if contextName != "" {
		query.Set("context", contextName)
	}
	var result agentapi.Completion
	err = client.JSON(ctx, "GET", "/v1/completions?"+query.Encode(), nil, &result)
	if err == nil && result.Version != agentapi.CompletionVersion {
		err = errors.New("unsupported completion response")
	}
	if err == nil && len(result.Values) > agentapi.MaxCompletionValues {
		err = errors.New("completion response exceeds value limit")
	}
	if err == nil {
		for _, value := range result.Values {
			if kind == "invite" && membership.ValidateInviteID(value) != nil || kind != "invite" && membership.ValidateLabel(value) != nil {
				return nil, errors.New("completion response contains an invalid entity")
			}
		}
	}
	return result.Values, err
}

func (s *ipcCompletionSource) DefaultContext(ctx context.Context) (string, error) {
	client, err := s.client()
	if err != nil {
		return "", err
	}
	var value struct {
		Name string `json:"name"`
	}
	err = client.JSON(ctx, "GET", "/v1/default-context", nil, &value)
	return value.Name, err
}

func (s *ipcCompletionSource) TransferIDs(ctx context.Context, contextName, action, peer, prefix string) ([]string, error) {
	client, err := s.client()
	if err != nil {
		return nil, err
	}
	query := url.Values{"kind": {"transfer_" + action}, "context": {contextName}, "prefix": {prefix}}
	if peer != "" {
		query.Set("peer", peer)
	}
	var result agentapi.Completion
	err = client.JSON(ctx, "GET", "/v1/completions?"+query.Encode(), nil, &result)
	if err == nil && (result.Version != agentapi.CompletionVersion || len(result.Values) > agentapi.MaxCompletionValues) {
		err = errors.New("unsupported transfer completion response")
	}
	if err == nil {
		for _, value := range result.Values {
			if !validCompletionTransferID(value) {
				return nil, errors.New("transfer completion response contains an invalid ID")
			}
		}
	}
	return result.Values, err
}

func configureCompletions(root *cobra.Command, opts *rootOptions, source completionSource) error {
	if err := root.RegisterFlagCompletionFunc("context", completeWith(source, func(ctx context.Context, _ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		values, err := source.Complete(ctx, "context", "", prefix)
		return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
	})); err != nil {
		return err
	}

	for _, path := range [][]string{{"context", "default"}, {"context", "enable"}, {"context", "disable"}, {"context", "remove"}, {"context", "show"}, {"context", "configure"}} {
		command, err := commandAt(root, path...)
		if err != nil {
			return err
		}
		command.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp, nil
			}
			values, err := source.Complete(ctx, "context", "", prefix)
			return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
		})
	}

	peerCompletion := func(remotePath bool) cobra.CompletionFunc {
		return completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
			if len(args) != 0 {
				if remotePath {
					return nil, cobra.ShellCompDirectiveNoFileComp, nil
				}
				return nil, cobra.ShellCompDirectiveDefault, nil
			}
			values, err := onlinePeerNames(ctx, opts, source, true, prefix)
			return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
		})
	}
	for _, value := range []struct {
		path       string
		remotePath bool
	}{{"ls", true}, {"get", true}, {"send", false}, {"text", true}, {"recent", true}, {"ping", true}} {
		command, err := commandAt(root, value.path)
		if err != nil {
			return err
		}
		command.ValidArgsFunction = peerCompletion(value.remotePath)
	}
	putCommand, err := commandAt(root, "put")
	if err != nil {
		return err
	}
	putCommand.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		switch len(args) {
		case 0:
			values, err := onlinePeerNames(ctx, opts, source, true, prefix)
			return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
		case 1:
			return nil, cobra.ShellCompDirectiveDefault, nil
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp, nil
		}
	})

	doctor, err := commandAt(root, "doctor")
	if err != nil {
		return err
	}
	if err := doctor.RegisterFlagCompletionFunc("peer", completeWith(source, func(ctx context.Context, _ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		values, err := onlinePeerNames(ctx, opts, source, true, prefix)
		return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
	})); err != nil {
		return err
	}

	aliasSet, err := commandAt(root, "context", "alias", "set")
	if err != nil {
		return err
	}
	aliasSet.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		if len(args) != 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp, nil
		}
		values, err := onlinePeerNames(ctx, opts, source, false, prefix)
		return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
	})
	for _, action := range []string{"show", "remove"} {
		command, err := commandAt(root, "context", "alias", action)
		if err != nil {
			return err
		}
		command.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp, nil
			}
			contextName, err := completionContext(ctx, opts, source)
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp, err
			}
			values, err := source.Complete(ctx, "alias", contextName, prefix)
			return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
		})
	}

	for _, action := range []string{"show", "cancel", "retry", "delete", "resolve"} {
		action := action
		command, err := commandAt(root, "transfer", action)
		if err != nil {
			return err
		}
		command.ValidArgsFunction = transferCompletion(opts, source, action, "")
	}
	inviteRevoke, err := commandAt(root, "invite", "revoke")
	if err != nil {
		return err
	}
	inviteRevoke.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp, nil
		}
		contextName, err := completionContext(ctx, opts, source)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp, err
		}
		values, err := source.Complete(ctx, "invite", contextName, prefix)
		return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
	})
	send, err := commandAt(root, "send")
	if err != nil {
		return err
	}
	if err := send.RegisterFlagCompletionFunc("retry", transferCompletion(opts, source, "retry", "send")); err != nil {
		return err
	}

	peerFirst, err := commandAt(root, "__peer_first")
	if err != nil {
		return err
	}
	peerFirst.ValidArgsFunction = completeWith(source, func(ctx context.Context, _ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp, nil
		}
		if strings.HasPrefix(prefix, "@") {
			values, err := onlinePeerNames(ctx, opts, source, true, strings.TrimPrefix(prefix, "@"))
			for index := range values {
				values[index] = "@" + values[index]
			}
			return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
		}
		return filterCandidates([]string{"ls", "get", "put", "send", "text", "recent", "ping", "doctor"}, prefix), cobra.ShellCompDirectiveNoFileComp, nil
	})
	return nil
}

func completeWith(_ completionSource, lookup func(context.Context, *cobra.Command, []string, string) ([]string, cobra.ShellCompDirective, error)) cobra.CompletionFunc {
	return func(command *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(command.Context(), completionTimeout)
		defer cancel()
		values, directive, err := lookup(ctx, command, args, prefix)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return values, directive
	}
}

func completionContext(ctx context.Context, opts *rootOptions, source completionSource) (string, error) {
	if selected := explicitContext(opts); selected != "" {
		return selected, nil
	}
	return source.DefaultContext(ctx)
}

func onlinePeerNames(ctx context.Context, opts *rootOptions, source completionSource, includeAliases bool, prefix string) ([]string, error) {
	contextName, err := completionContext(ctx, opts, source)
	if err != nil {
		return nil, err
	}
	kind := "peer"
	if includeAliases {
		kind = "peer_alias"
	}
	return source.Complete(ctx, kind, contextName, prefix)
}

func transferCompletion(opts *rootOptions, source completionSource, action, kind string) cobra.CompletionFunc {
	return completeWith(source, func(ctx context.Context, command *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective, error) {
		if len(args) != 0 && kind == "" {
			return nil, cobra.ShellCompDirectiveNoFileComp, nil
		}
		peer := ""
		if kind == "send" {
			if len(args) != 1 {
				return nil, cobra.ShellCompDirectiveNoFileComp, nil
			}
			stdinInput, _ := command.Flags().GetBool("stdin")
			name, _ := command.Flags().GetString("name")
			public, _ := command.Flags().GetBool("public")
			if stdinInput || name != "" || public {
				return nil, cobra.ShellCompDirectiveNoFileComp, nil
			}
			peer = args[0]
		}
		contextName, err := completionContext(ctx, opts, source)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp, err
		}
		values, err := source.TransferIDs(ctx, contextName, action, peer, prefix)
		return filterCandidates(values, prefix), cobra.ShellCompDirectiveNoFileComp, err
	})
}

func filterCandidates(values []string, prefix string) []string {
	unique := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validCompletionCandidate(value) || !strings.HasPrefix(value, prefix) {
			continue
		}
		if _, exists := unique[value]; exists {
			continue
		}
		unique[value] = struct{}{}
		result = append(result, value)
	}
	slices.SortFunc(result, func(a, b string) int {
		if order := strings.Compare(strings.ToLower(a), strings.ToLower(b)); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	return result
}

func validCompletionCandidate(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e || value[index] == '\t' || value[index] == '\n' || value[index] == '\r' {
			return false
		}
	}
	return true
}

func validCompletionTransferID(value string) bool {
	digits := value
	if strings.HasPrefix(value, "get-") {
		digits = strings.TrimPrefix(value, "get-")
		if len(digits) != 32 {
			return false
		}
	} else if len(digits) != 32 && len(digits) != 64 {
		return false
	}
	for index := range len(digits) {
		if !strings.ContainsRune("0123456789abcdef", rune(digits[index])) {
			return false
		}
	}
	return true
}

func commandAt(root *cobra.Command, path ...string) (*cobra.Command, error) {
	command, remaining, err := root.Find(path)
	if err != nil || len(remaining) != 0 || command == root && len(path) != 0 {
		return nil, errors.New("PX completion command is not registered: " + strings.Join(path, " "))
	}
	return command, nil
}
