package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/spf13/cobra"
)

func explicitContext(opts *rootOptions) string {
	if opts.context != "" {
		return opts.context
	}
	return os.Getenv("PX_CONTEXT")
}

func newStatusCommand(ctx context.Context, streams IOStreams, opts *rootOptions) *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "status",
		Short: "Summarize local PX readiness",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			paths, _, err := prepare(streams, opts)
			if err != nil {
				return err
			}
			query := url.Values{}
			if selected := explicitContext(opts); selected != "" {
				query.Set("context", selected)
			}
			path := "/v1/summary"
			if len(query) != 0 {
				path += "?" + query.Encode()
			}
			requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var result agentapi.Summary
			if err := localipc.NewAgentClient(paths.AgentEndpoint).JSON(requestContext, "GET", path, nil, &result); err != nil {
				var responseError *localipc.Error
				if errors.As(err, &responseError) && responseError.Status == 404 && responseError.Message == "404 Not Found" {
					return errors.New("running PX agent does not support daily status; restart it with this PX release")
				}
				return err
			}
			if result.Version != agentapi.SummaryVersion {
				return fmt.Errorf("PX agent summary version %d is unsupported", result.Version)
			}
			if jsonOutput {
				return json.NewEncoder(streams.Out).Encode(result)
			}
			return writeStatus(streams, result)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "emit deterministic JSON output")
	return command
}

func writeStatus(streams IOStreams, result agentapi.Summary) error {
	title := "PX needs attention"
	if result.Status == "ok" {
		title = "PX is ready"
	}
	rows := [][2]string{{"Agent", "running | version " + result.Build.Version}}
	if result.Context == nil {
		rows = append(rows,
			[2]string{"Context", "not configured"},
			[2]string{"Peers", "unknown"},
			[2]string{"Transfers", "unknown"},
		)
	} else {
		state := result.Context.State
		if !result.Context.Enabled {
			state = "disabled"
		}
		peers := "unknown"
		if result.Context.OnlinePeers != nil {
			peers = fmt.Sprintf("%d online", *result.Context.OnlinePeers)
		}
		transfers := "unknown"
		if result.Transfers != nil {
			if result.Transfers.Active == 0 && result.Transfers.Retryable == 0 {
				transfers = "none"
			} else {
				transfers = fmt.Sprintf("%d active | %d retryable", result.Transfers.Active, result.Transfers.Retryable)
			}
		}
		rows = append(rows,
			[2]string{"Context", result.Context.Name + " | " + state},
			[2]string{"Peers", peers},
			[2]string{"Transfers", transfers},
		)
	}
	if result.Next != "" {
		rows = append(rows, [2]string{"Next", result.Next})
	}
	for _, warning := range result.Warnings {
		rows = append(rows, [2]string{"Warning", warning})
	}
	if _, err := fmt.Fprintf(streams.Out, "%s\n\n", title); err != nil {
		return err
	}
	writer := tabwriter.NewWriter(streams.Out, 0, 4, 2, ' ', 0)
	for _, row := range rows {
		if _, err := fmt.Fprintf(writer, "%s\t%s\n", row[0], row[1]); err != nil {
			return err
		}
	}
	return writer.Flush()
}
