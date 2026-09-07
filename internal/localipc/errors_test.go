package localipc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAgentTransportErrorClassificationAndRedaction(t *testing.T) {
	endpoint := "/private/user/run/agent.sock"
	tests := []struct {
		name        string
		err         error
		unavailable bool
		is          error
	}{
		{name: "missing Unix socket", err: &os.PathError{Op: "dial", Path: endpoint, Err: syscall.ENOENT}, unavailable: true},
		{name: "refused Unix socket", err: &os.PathError{Op: "dial", Path: endpoint, Err: syscall.ECONNREFUSED}, unavailable: true},
		{name: "missing Windows pipe", err: fmt.Errorf("dial pipe: %w", syscall.Errno(2)), unavailable: true},
		{name: "busy Windows pipe", err: fmt.Errorf("dial pipe: %w", syscall.Errno(231)), unavailable: true},
		{name: "refused Windows pipe", err: fmt.Errorf("dial pipe: %w", syscall.Errno(1225)), unavailable: true},
		{name: "access denied", err: &os.PathError{Op: "dial", Path: endpoint, Err: syscall.EACCES}, is: os.ErrPermission},
		{name: "Windows access denied", err: fmt.Errorf("dial pipe: %w", syscall.Errno(5))},
		{name: "cancelled", err: fmt.Errorf("dial: %w", context.Canceled), is: context.Canceled},
		{name: "deadline", err: fmt.Errorf("dial: %w", context.DeadlineExceeded), is: context.DeadlineExceeded},
		{name: "other", err: errors.New("network is down")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := redactAgentTransportError(test.err)
			if errors.Is(classified, ErrAgentUnavailable) != test.unavailable {
				t.Fatalf("error = %v, unavailable = %t", classified, test.unavailable)
			}
			if test.is != nil && !errors.Is(classified, test.is) {
				t.Fatalf("error = %v, want category %v", classified, test.is)
			}
			if strings.Contains(classified.Error(), endpoint) || strings.Contains(classified.Error(), `\\.\pipe`) {
				t.Fatalf("error leaks endpoint: %v", classified)
			}
		})
	}
}

func TestGenericLocalTransportErrorsAreRedactedWithoutAgentClassification(t *testing.T) {
	endpoint := `\\.\pipe\private-px-admin`
	err := redactLocalTransportError(&os.PathError{Op: "dial", Path: endpoint, Err: syscall.ENOENT})
	if errors.Is(err, ErrAgentUnavailable) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generic endpoint error classification = %v", err)
	}
	if strings.Contains(err.Error(), endpoint) {
		t.Fatalf("generic endpoint error leaks path: %v", err)
	}
}

func TestServerAdminTransportErrorsRemainDistinct(t *testing.T) {
	endpoint := `\\.\pipe\private-px-admin`
	cause := &os.PathError{Op: "dial", Path: endpoint, Err: syscall.ENOENT}
	err := (&Client{kind: serverAdminClient}).transportError(cause)
	if errors.Is(err, ErrAgentUnavailable) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("server-admin classification = %v", err)
	}
	if !strings.Contains(err.Error(), "server administration endpoint") || strings.Contains(err.Error(), endpoint) {
		t.Fatalf("server-admin error = %q", err)
	}
}

func TestDialTimeoutPolicy(t *testing.T) {
	if localDialTimeout <= 0 || localDialTimeout > time.Second {
		t.Fatalf("local dial timeout = %s", localDialTimeout)
	}
	if err := normalizeDialError(context.Background(), context.DeadlineExceeded); !errors.Is(err, errLocalDialTimeout) || !isLocalEndpointUnavailable(err) {
		t.Fatalf("child dial deadline = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := normalizeDialError(cancelled, context.DeadlineExceeded); !errors.Is(err, context.Canceled) || errors.Is(err, errLocalDialTimeout) {
		t.Fatalf("caller cancellation = %v", err)
	}
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	if err := normalizeDialError(deadline, context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errLocalDialTimeout) {
		t.Fatalf("caller deadline = %v", err)
	}
}

func TestWindowsPipeUnavailableCodesExcludeAccessDenied(t *testing.T) {
	for _, code := range []uintptr{2, 3, 230, 231, 232, 233, 1225, 10061} {
		if !isWindowsPipeUnavailableCode(code) {
			t.Errorf("code %d was not classified unavailable", code)
		}
	}
	if isWindowsPipeUnavailableCode(5) {
		t.Fatal("ERROR_ACCESS_DENIED was classified unavailable")
	}
}
