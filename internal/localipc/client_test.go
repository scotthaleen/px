package localipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingResponseBody struct {
	err error
}

func (b failingResponseBody) Read([]byte) (int, error) { return 0, b.err }

func (failingResponseBody) Close() error { return nil }

type partialResponseBody struct {
	data []byte
	err  error
}

func (b *partialResponseBody) Read(data []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(data, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (*partialResponseBody) Close() error { return nil }

type contextResponseBody struct {
	ctx     context.Context
	started chan struct{}
}

func (b *contextResponseBody) Read([]byte) (int, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*contextResponseBody) Close() error { return nil }

func TestAgentResponseReadErrorsAreRedacted(t *testing.T) {
	endpoint := `\\.\pipe\private-agent`
	cause := &os.PathError{Op: "read", Path: endpoint, Err: syscall.EACCES}
	for _, test := range []struct {
		name   string
		status int
		call   func(*Client) error
	}{
		{name: "JSON response", status: http.StatusOK, call: func(client *Client) error {
			return client.JSON(context.Background(), http.MethodGet, "/v1/status", nil, nil)
		}},
		{name: "JSON error response", status: http.StatusBadGateway, call: func(client *Client) error {
			return client.JSON(context.Background(), http.MethodGet, "/v1/status", nil, nil)
		}},
		{name: "stream response", status: http.StatusOK, call: func(client *Client) error {
			return client.StreamJSON(context.Background(), http.MethodPost, "/v1/stream", struct{}{}, func(json.RawMessage) error { return nil })
		}},
		{name: "stream error response", status: http.StatusBadGateway, call: func(client *Client) error {
			return client.StreamJSON(context.Background(), http.MethodPost, "/v1/stream", struct{}{}, func(json.RawMessage) error { return nil })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{kind: agentClient, client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Status: http.StatusText(test.status), Body: failingResponseBody{err: cause}}, nil
			})}}
			err := test.call(client)
			if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrAgentUnavailable) {
				t.Fatalf("response read error = %v", err)
			}
			if strings.Contains(err.Error(), endpoint) {
				t.Fatalf("response read error leaks endpoint: %v", err)
			}
		})
	}
}

func TestAgentHTTPErrorPreservesApprovalUncertainty(t *testing.T) {
	body := `{"status":502,"message":"approval outcome unknown; inspect devices list or devices pending before retrying"}`
	client := &Client{kind: agentClient, client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	err := client.JSON(context.Background(), http.MethodPost, "/v1/approve", struct{}{}, nil)
	var responseError *Error
	if !errors.As(err, &responseError) || responseError.Status != http.StatusBadGateway || responseError.Message != "approval outcome unknown; inspect devices list or devices pending before retrying" {
		t.Fatalf("approval uncertainty error = %#v, %v", responseError, err)
	}
}

func TestIPCClientVersionsRemainSeparate(t *testing.T) {
	for _, test := range []struct {
		name        string
		client      *Client
		wantVersion string
	}{
		{name: "agent", client: &Client{kind: agentClient}, wantVersion: "13"},
		{name: "generic", client: &Client{kind: genericClient}, wantVersion: "13"},
		{name: "server admin", client: &Client{kind: serverAdminClient, ipcVersion: "5"}, wantVersion: "5"},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.client.client = &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				if got := request.Header.Get("X-PX-IPC-Version"); got != test.wantVersion {
					t.Fatalf("IPC version = %q, want %q", got, test.wantVersion)
				}
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			if err := test.client.JSON(context.Background(), http.MethodGet, "/v1/status", nil, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStrictJSONRejectsUnknownAndTrailingSuccessData(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"unknown":true}`,
		`{"version":1} {"version":1}`,
	} {
		client := &Client{kind: serverAdminClient, ipcVersion: "5", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		var result struct {
			Version int `json:"version"`
		}
		if err := client.JSONStrict(context.Background(), http.MethodGet, "/v1/invites", nil, &result); err == nil {
			t.Fatalf("strict response accepted %q", body)
		}
	}
}

func TestStrictNDJSONPreservesRawFramingAndRejectsContentType(t *testing.T) {
	const body = "{\"version\":1,\"value\":\"first\"}\n{\"version\":1,\"value\":\"second\"}\n"
	var records []string
	client := &Client{kind: agentClient, ipcVersion: "11", client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.Body != nil || request.Header.Get("Accept") != "application/x-ndjson" {
			t.Fatalf("stream request = %s, body=%v, accept=%q", request.Method, request.Body, request.Header.Get("Accept"))
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/x-ndjson"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	if err := client.StreamNDJSON(context.Background(), http.MethodGet, "/v1/watch", nil, func(data json.RawMessage) error {
		records = append(records, string(data))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(records, "\n") + "\n"; got != body {
		t.Fatalf("raw framing = %q", got)
	}
	client.client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := client.StreamNDJSON(context.Background(), http.MethodGet, "/v1/watch", nil, func(json.RawMessage) error { return nil }); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Fatalf("invalid content type error = %v", err)
	}
}

func TestStrictNDJSONReportsMalformedAndTransportFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		body io.ReadCloser
	}{
		{name: "malformed", body: io.NopCloser(strings.NewReader("not-json\n"))},
		{name: "transport", body: failingResponseBody{err: errors.New("read failed")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{kind: agentClient, ipcVersion: "11", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/x-ndjson"}}, Body: test.body}, nil
			})}}
			if err := client.StreamNDJSON(context.Background(), http.MethodGet, "/v1/watch", nil, func(json.RawMessage) error { return nil }); err == nil {
				t.Fatal("strict NDJSON accepted malformed/failed body")
			}
		})
	}
}

func TestFiniteStreamReportsFailureAfterPartialResponse(t *testing.T) {
	cause := errors.New("stream failed")
	body := &partialResponseBody{data: []byte("{\"version\":1}\n"), err: cause}
	client := &Client{kind: agentClient, ipcVersion: "11", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/x-ndjson"}}, Body: body}, nil
	})}}
	records := 0
	err := client.StreamJSON(t.Context(), http.MethodPost, "/v1/stream", struct{}{}, func(json.RawMessage) error {
		records++
		return nil
	})
	if err == nil || records != 1 {
		t.Fatalf("partial stream error = %v, records = %d", err, records)
	}
}

func TestFiniteStreamPreservesWholeOperationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	client := &Client{kind: agentClient, ipcVersion: "11", client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/x-ndjson"}}, Body: &contextResponseBody{ctx: request.Context(), started: started}}, nil
	})}}
	done := make(chan error, 1)
	go func() {
		done <- client.StreamJSON(ctx, http.MethodPost, "/v1/stream", struct{}{}, func(json.RawMessage) error { return nil })
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled stream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled finite stream did not return")
	}
}

func TestAgentClientMakesVersionMismatchActionableForJSONAndStreams(t *testing.T) {
	for _, stream := range []bool{false, true} {
		client := &Client{kind: agentClient, ipcVersion: "2", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUpgradeRequired,
				Status:     "426 Upgrade Required",
				Body:       io.NopCloser(strings.NewReader(`{"status":426,"message":"old agent"}`)),
			}, nil
		})}}
		var err error
		if stream {
			err = client.StreamJSON(context.Background(), http.MethodPost, "/v1/stream", struct{}{}, func(json.RawMessage) error { return nil })
		} else {
			err = client.JSON(context.Background(), http.MethodGet, "/v1/status", nil, nil)
		}
		if err == nil || err.Error() != AgentVersionMismatchMessage {
			t.Fatalf("stream=%v mismatch error = %v", stream, err)
		}
	}
}

func TestServerAdminClientMakesOldServerMismatchActionable(t *testing.T) {
	client := &Client{kind: serverAdminClient, ipcVersion: "5", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUpgradeRequired,
			Status:     "426 Upgrade Required",
			Body:       io.NopCloser(strings.NewReader(`{"status":426,"message":"unsupported or missing PX IPC version"}`)),
		}, nil
	})}}
	err := client.JSON(context.Background(), http.MethodGet, "/v1/devices", nil, nil)
	if err == nil || !errors.Is(err, ErrServerAdminVersionMismatch) || err.Error() != ServerAdminVersionMismatchMessage || !strings.Contains(err.Error(), "administration protocol") {
		t.Fatalf("version mismatch error = %v", err)
	}
}

func TestServerAdminClientPreservesTypedErrorCode(t *testing.T) {
	client := &Client{kind: serverAdminClient, ipcVersion: "5", client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Status:     "409 Conflict",
			Body:       io.NopCloser(strings.NewReader(`{"status":409,"code":"adapter_capacity","message":"adapter capacity reached"}`)),
		}, nil
	})}}
	err := client.JSON(context.Background(), http.MethodPost, "/v1/adapters/provision", struct{}{}, nil)
	var responseError *Error
	if !errors.As(err, &responseError) || responseError.Status != http.StatusConflict || responseError.Code != "adapter_capacity" || responseError.Message != "adapter capacity reached" {
		t.Fatalf("typed server admin error = %+v, %v", responseError, err)
	}
}
