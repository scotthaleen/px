package localipc

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// ErrAgentUnavailable means the local agent endpoint does not exist or is not
// accepting connections. It does not include permission, protocol, or remote
// API failures.
var ErrAgentUnavailable = errors.New("PX agent is not reachable; run `px agent run` or `px startup install`")

var errLocalDialTimeout = errors.New("local endpoint dial timed out")

type redactedTransportError struct {
	message string
	cause   error
}

func (e *redactedTransportError) Error() string { return e.message }

func (e *redactedTransportError) Unwrap() error { return e.cause }

func redactAgentTransportError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case isLocalEndpointUnavailable(err):
		return ErrAgentUnavailable
	case errors.Is(err, os.ErrPermission):
		return &redactedTransportError{message: "PX agent local transport permission denied", cause: err}
	default:
		return &redactedTransportError{message: "PX agent local transport failed", cause: err}
	}
}

func redactServerAdminTransportError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case isLocalEndpointUnavailable(err):
		return &redactedTransportError{message: "PX server administration endpoint is not reachable", cause: err}
	case errors.Is(err, os.ErrPermission):
		return &redactedTransportError{message: "PX server administration transport permission denied", cause: err}
	default:
		return &redactedTransportError{message: "PX server administration transport failed", cause: err}
	}
}

func redactLocalTransportError(err error) error {
	return redactTransportError(err, "local endpoint is not reachable", "local transport permission denied", "local transport failed")
}

func redactTransportError(err error, unavailable, permission, other string) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case isLocalEndpointUnavailable(err):
		return &redactedTransportError{message: unavailable, cause: err}
	case errors.Is(err, os.ErrPermission):
		return &redactedTransportError{message: permission, cause: err}
	default:
		return &redactedTransportError{message: other, cause: err}
	}
}

func isLocalEndpointUnavailable(err error) bool {
	if errors.Is(err, errLocalDialTimeout) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && isWindowsPipeUnavailableCode(uintptr(errno))
}

// Keep Windows classification platform-neutral so all builders exercise the
// named-pipe error policy.
func isWindowsPipeUnavailableCode(code uintptr) bool {
	switch code {
	case 2, // ERROR_FILE_NOT_FOUND
		3,     // ERROR_PATH_NOT_FOUND
		230,   // ERROR_BAD_PIPE
		231,   // ERROR_PIPE_BUSY
		232,   // ERROR_NO_DATA
		233,   // ERROR_PIPE_NOT_CONNECTED
		1225,  // ERROR_CONNECTION_REFUSED
		10061: // WSAECONNREFUSED
		return true
	default:
		return false
	}
}
