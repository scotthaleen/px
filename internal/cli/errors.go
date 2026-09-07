package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/scotthaleen/px/internal/localipc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const ErrorEnvelopeVersion = 1

type errorEnvelope struct {
	Version int             `json:"version"`
	Error   errorEnvelopeV1 `json:"error"`
}

type errorEnvelopeV1 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type reportedError struct {
	cause error
}

func (e *reportedError) Error() string { return e.cause.Error() }

func (e *reportedError) Unwrap() error { return e.cause }

// JSONOutputEnabled reads the effective value parsed by Cobra for the command
// that ran. Unknown commands and pre-parse failures conservatively return false.
func JSONOutputEnabled(command *cobra.Command) bool {
	if command == nil {
		return false
	}
	var flag *pflag.Flag
	for _, flags := range []*pflag.FlagSet{command.Flags(), command.PersistentFlags(), command.InheritedFlags()} {
		if flag = flags.Lookup("json"); flag != nil {
			break
		}
	}
	if flag == nil {
		return false
	}
	value, err := strconv.ParseBool(flag.Value.String())
	return err == nil && value
}

// WritePXError writes one CLI error without contaminating command stdout.
func WritePXError(output io.Writer, err error, jsonOutput bool) error {
	var reported *reportedError
	if errors.As(err, &reported) {
		return nil
	}
	if !jsonOutput {
		_, writeErr := fmt.Fprintln(output, "px:", err)
		return writeErr
	}
	envelope := errorEnvelope{
		Version: ErrorEnvelopeVersion,
		Error: errorEnvelopeV1{
			Code:    errorCode(err),
			Message: err.Error(),
		},
	}
	return json.NewEncoder(output).Encode(envelope)
}

func markErrorReported(err error) error {
	return &reportedError{cause: err}
}

func errorCode(err error) string {
	var responseError *localipc.Error
	switch {
	case errors.Is(err, localipc.ErrAgentUnavailable):
		return "local_agent_unavailable"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.As(err, &responseError):
		if responseError.Code != "" {
			return responseError.Code
		}
		return "local_ipc_error"
	default:
		return "command_failed"
	}
}
