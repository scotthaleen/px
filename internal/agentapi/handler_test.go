package agentapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/transfer"
)

func TestWatchPreflightInitialFlushCancellationAndDeadline(t *testing.T) {
	events := make(chan contextwatch.Event, 1)
	events <- watchTestEvent(contextwatch.ContextConnected, true)
	handler := New(nil, nil, nil)
	unsubscribed := make(chan struct{})
	handler.watchSubscribe = func(context.Context, string) (<-chan contextwatch.Event, func(), error) {
		return events, func() { close(unsubscribed) }, nil
	}
	requestContext, cancel := context.WithCancel(t.Context())
	request := httptest.NewRequest(http.MethodGet, "/v1/contexts/home/watch", nil).WithContext(requestContext)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-response.flushed
	if response.code != http.StatusOK || response.Header().Get("Content-Type") != "application/x-ndjson" || response.deadlines < 2 {
		t.Fatalf("watch response = status %d, content-type %q, deadlines %d", response.code, response.Header().Get("Content-Type"), response.deadlines)
	}
	data := bytes.TrimSpace(response.body.Bytes())
	event, err := contextwatch.DecodeStrict(data)
	if err != nil || !event.Snapshot || event.Type != contextwatch.ContextConnected {
		t.Fatalf("initial event = %s, %v", data, err)
	}
	cancel()
	<-done
	<-unsubscribed

	for _, deadlineErr := range []error{errors.New("deadline failed"), http.ErrNotSupported} {
		failing := newWatchResponseWriter()
		failing.deadlineErr = deadlineErr
		events = make(chan contextwatch.Event, 1)
		events <- watchTestEvent(contextwatch.ContextDisconnected, true)
		request = httptest.NewRequest(http.MethodGet, "/v1/contexts/home/watch", nil)
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		handler.watchSubscribe = func(context.Context, string) (<-chan contextwatch.Event, func(), error) {
			return events, func() {}, nil
		}
		handler.ServeHTTP(failing, request)
		if failing.code != http.StatusInternalServerError {
			t.Fatalf("deadline preflight error %v status = %d", deadlineErr, failing.code)
		}
	}
}

func TestWatchRejectsMalformedRequestBeforeSubscribe(t *testing.T) {
	handler := New(nil, nil, nil)
	called := false
	handler.watchSubscribe = func(context.Context, string) (<-chan contextwatch.Event, func(), error) {
		called = true
		return nil, nil, nil
	}
	for _, target := range []string{"/v1/contexts/home/watch?extra=true", "/v1/contexts/home/watch?"} {
		request := httptest.NewRequest(http.MethodGet, target, strings.NewReader("unexpected"))
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || called {
			t.Fatalf("malformed watch = %d, subscribed=%t", response.Code, called)
		}
	}
}

func TestWatchHasNoIdleDeadline(t *testing.T) {
	events := make(chan contextwatch.Event, 1)
	events <- watchTestEvent(contextwatch.ContextConnected, true)
	handler := New(nil, nil, nil)
	handler.watchSubscribe = func(context.Context, string) (<-chan contextwatch.Event, func(), error) {
		return events, func() {}, nil
	}
	requestContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/v1/contexts/home/watch", nil).WithContext(requestContext)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-response.flushed
	time.Sleep(20 * time.Millisecond)
	if response.deadlines != 2 {
		t.Fatalf("idle watch deadline resets = %d, want 2", response.deadlines)
	}
	select {
	case <-done:
		t.Fatal("healthy idle watch ended")
	default:
	}
	cancel()
	<-done
}

func TestWatchHandlerDrainsTerminalGapAfterBlockedWriter(t *testing.T) {
	hub := contextwatch.NewHub()
	hub.Connect("home", nil)
	handler := New(nil, nil, nil)
	handler.watchSubscribe = func(context.Context, string) (<-chan contextwatch.Event, func(), error) {
		subscription, err := hub.Subscribe("home")
		if err != nil {
			return nil, nil, err
		}
		return subscription.Events, subscription.Close, nil
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/contexts/home/watch", nil)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	response.blockWrite = 2
	response.writeBlocked = make(chan struct{})
	response.releaseWrite = make(chan struct{})
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-response.flushed
	peer := contextwatch.Peer{DeviceID: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Label: "peer"}
	hub.Join("home", peer)
	<-response.writeBlocked
	for range contextwatch.OrdinaryQueueDepth {
		hub.Leave("home", peer.DeviceID)
		hub.Join("home", peer)
	}
	close(response.releaseWrite)
	<-done
	lines := bytes.Split(bytes.TrimSpace(response.body.Bytes()), []byte{'\n'})
	if len(lines) < 2 {
		t.Fatalf("watch lines = %d", len(lines))
	}
	last, err := contextwatch.DecodeStrict(lines[len(lines)-1])
	if err != nil || last.Type != contextwatch.StreamGap || !last.ResyncRequired {
		t.Fatalf("terminal gap = %s, %v", lines[len(lines)-1], err)
	}
}

type watchResponseWriter struct {
	header       http.Header
	body         bytes.Buffer
	code         int
	flushed      chan struct{}
	flushOnce    sync.Once
	deadlines    int
	deadlineErr  error
	deadlineAt   int
	blockWrite   int
	writeCount   int
	writeErr     error
	writeErrAt   int
	flushErr     error
	writeBlocked chan struct{}
	releaseWrite chan struct{}
}

func newWatchResponseWriter() *watchResponseWriter {
	return &watchResponseWriter{header: make(http.Header), flushed: make(chan struct{})}
}

func (w *watchResponseWriter) Header() http.Header { return w.header }

func (w *watchResponseWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

func (w *watchResponseWriter) Write(data []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	w.writeCount++
	if w.blockWrite == w.writeCount {
		close(w.writeBlocked)
		<-w.releaseWrite
	}
	if w.writeErr != nil && (w.writeErrAt == 0 || w.writeErrAt == w.writeCount) {
		return 0, w.writeErr
	}
	return w.body.Write(data)
}

func (w *watchResponseWriter) Flush() { _ = w.FlushError() }

func (w *watchResponseWriter) FlushError() error {
	w.flushOnce.Do(func() { close(w.flushed) })
	return w.flushErr
}

func (w *watchResponseWriter) SetWriteDeadline(time.Time) error {
	w.deadlines++
	if w.deadlineAt != 0 && w.deadlineAt != w.deadlines {
		return nil
	}
	return w.deadlineErr
}

func TestNDJSONResponsePreflightEncodeFlushAndDeadlineErrors(t *testing.T) {
	if _, err := prepareNDJSONResponse(httptest.NewRecorder()); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("unsupported response writer error = %v", err)
	}

	for _, test := range []struct {
		name      string
		configure func(*watchResponseWriter)
		value     any
	}{
		{name: "write deadline", configure: func(w *watchResponseWriter) { w.deadlineErr, w.deadlineAt = errors.New("deadline failed"), 2 }, value: map[string]int{"value": 1}},
		{name: "encode", configure: func(*watchResponseWriter) {}, value: map[string]any{"value": make(chan int)}},
		{name: "write", configure: func(w *watchResponseWriter) { w.writeErr = errors.New("write failed") }, value: map[string]int{"value": 1}},
		{name: "flush", configure: func(w *watchResponseWriter) { w.flushErr = errors.New("flush failed") }, value: map[string]int{"value": 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := newWatchResponseWriter()
			test.configure(response)
			stream, err := prepareNDJSONResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			stream.commit(response)
			if err := stream.write(test.value); err == nil {
				t.Fatal("stream write succeeded")
			}
			if response.code != http.StatusOK || response.deadlines < 2 {
				t.Fatalf("stream response = status %d, deadlines %d", response.code, response.deadlines)
			}
		})
	}
}

func watchTestEvent(eventType string, snapshot bool) contextwatch.Event {
	deviceID := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	event := contextwatch.Event{Version: contextwatch.Version, StreamID: strings.Repeat("a", 32), Sequence: 1, ObservedAt: time.Unix(1, 0).UTC(), Context: "home", Type: eventType, Snapshot: snapshot}
	if eventType == contextwatch.ContextConnected {
		event.Peers = []contextwatch.Peer{{DeviceID: deviceID, Label: "peer"}}
	}
	return event
}

func TestStatusRequiresVersionAndEmptyBody(t *testing.T) {
	handler := New(nil, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	request.Header.Set("X-PX-IPC-Version", "2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("IPC v2 status = %d, want 426", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/status", strings.NewReader("unexpected"))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestPingRequestIsStrictBoundedAndAdmitted(t *testing.T) {
	handler := New(nil, nil, &contextstate.Manager{})
	for _, body := range []string{
		`{"version":1,"context":"home","peer":"vm","count":4}`,
		`{"version":2,"context":"home","peer":"vm","count":0}`,
		`{"version":2,"context":"home","peer":"vm","server":true,"count":4}`,
		`{"version":2,"context":"home","server":true,"show_addresses":true,"count":4}`,
		`{"version":2,"context":"home","count":4}`,
		`{"version":2,"context":"home","peer":"vm","count":4,"payload":"x"}`,
		`{"version":2,"context":"home","peer":"vm","count":4} {}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/ping", strings.NewReader(body))
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("ping %s = %d: %s", body, response.Code, response.Body.String())
		}
	}
	for range 4 {
		handler.operations <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ping", bytes.NewReader(mustJSON(t, PingRequest{Version: ping.Version, Context: "home", Server: true, Count: 4})))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity ping = %d: %s", response.Code, response.Body.String())
	}
}

func TestBenchmarkRequestIsStrictAndBounded(t *testing.T) {
	handler := New(nil, nil, &contextstate.Manager{})
	for _, body := range []string{
		`{"version":0,"context":"home","peer":"vm","duration":1000000000}`,
		`{"version":1,"context":"home","peer":"vm","duration":999000000}`,
		`{"version":1,"context":"home","peer":"vm","duration":31000000000}`,
		`{"version":1,"context":"home","peer":"vm","duration":1000000000,"extra":true}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/benchmark", strings.NewReader(body))
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("benchmark %s = %d: %s", body, response.Code, response.Body.String())
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSummaryVersionThreeReportsFilesystemAuthority(t *testing.T) {
	online := 1
	for _, test := range []struct {
		name       string
		context    contextstate.StatusContext
		wantStatus string
		warning    string
	}{
		{name: "narrow", context: contextstate.StatusContext{Name: "home", State: "connected", Enabled: true, OnlinePeers: &online, OfferedRootScope: contextstate.OfferedRootScopeNarrow, OfferedRootAuthorityValid: true}, wantStatus: "ok"},
		{name: "filesystem root", context: contextstate.StatusContext{Name: "home", State: "connected", Enabled: true, OnlinePeers: &online, OfferedRootScope: contextstate.OfferedRootScopeFilesystemRoot, OfferedRootAuthorityValid: true}, wantStatus: "ok", warning: "DANGER"},
		{name: "put authority", context: contextstate.StatusContext{Name: "home", State: "connected", Enabled: true, OnlinePeers: &online, OfferedRootScope: contextstate.OfferedRootScopeNarrow, OfferedRootAuthorityValid: true, AllowPut: true, PutRootAuthorityValid: true}, wantStatus: "ok", warning: "supported replacement"},
		{name: "inconsistent", context: contextstate.StatusContext{Name: "home", State: "connected", Enabled: true, OnlinePeers: &online, OfferedRootScope: contextstate.OfferedRootScopeNarrow}, wantStatus: "degraded", warning: "FAILURE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := summaryFromSnapshot(time.Unix(1, 0), contextstate.StatusSnapshot{Context: &test.context, Transfers: &transfer.Counts{}})
			if result.Version != 3 || result.Status != test.wantStatus {
				t.Fatalf("summary = %+v", result)
			}
			if test.warning == "" && len(result.Warnings) != 0 || test.warning != "" && (len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], test.warning)) {
				t.Fatalf("summary warnings = %v", result.Warnings)
			}
		})
	}
}

func TestTransferErrorStatus(t *testing.T) {
	handler := New(nil, nil, nil)
	for _, test := range []struct {
		err  error
		want int
	}{
		{err: transfer.ErrTransferNotFound, want: http.StatusNotFound},
		{err: transfer.ErrTransferNotActive, want: http.StatusConflict},
		{err: transfer.ErrTransferActive, want: http.StatusConflict},
		{err: transfer.ErrTransferAmbiguous, want: http.StatusConflict},
		{err: put.ErrNotResolvable, want: http.StatusConflict},
		{err: put.ErrResolutionUnsafe, want: http.StatusConflict},
		{err: put.ErrAuthority, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrContextDisconnected, want: http.StatusServiceUnavailable},
		{err: contextstate.ErrInvalidContextState, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrPeerUnknown, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrPeerOffline, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrPeerSelf, want: http.StatusUnprocessableEntity},
		{err: context.Canceled, want: http.StatusRequestTimeout},
		{err: errors.New("database failed"), want: http.StatusInternalServerError},
	} {
		response := httptest.NewRecorder()
		handler.writeTransferError(response, test.err)
		if response.Code != test.want {
			t.Fatalf("error %v status = %d, want %d", test.err, response.Code, test.want)
		}
	}
}

func TestTransferRoutesRequireContextAndDeleteConfirmation(t *testing.T) {
	handler := New(nil, nil, &contextstate.Manager{})
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/v1/transfers"},
		{method: http.MethodGet, path: "/v1/transfers/id"},
		{method: http.MethodPost, path: "/v1/transfers/id/cancel"},
		{method: http.MethodPost, path: "/v1/transfers/id/retry", body: `{}`},
		{method: http.MethodPost, path: "/v1/transfers/id/resolve", body: `{}`},
		{method: http.MethodPost, path: "/v1/transfers/id/resolve", body: `{"context":"home","accept_current":true}`},
		{method: http.MethodPost, path: "/v1/transfers/id/resolve", body: `{"context":"home","accept_current":true,"confirmed":true,"unknown":1}`},
		{method: http.MethodDelete, path: "/v1/transfers/id", body: `{"context":"home"}`},
		{method: http.MethodDelete, path: "/v1/transfers/id", body: `{"context":"home","confirmed":false}`},
		{method: http.MethodDelete, path: "/v1/transfers/id", body: `{"context":"home","confirmed":true,"unknown":1}`},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s %s status = %d: %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
}

func TestResolveTransferReturnsOnlyRedactedLocalResolutionResult(t *testing.T) {
	id := strings.Repeat("a", 32)
	handler := New(nil, nil, &contextstate.Manager{})
	handler.resolveCurrent = func(_ context.Context, contextName, transferID string) (put.ResolutionResult, error) {
		if contextName != "home" || transferID != id {
			t.Fatalf("resolve context=%q id=%q", contextName, transferID)
		}
		return put.ResolutionResult{Version: put.ResolutionVersion, TransferID: id, Context: "home", Destination: "portable/result", State: "resolved_accept_current"}, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+id+"/resolve", strings.NewReader(`{"context":"home","accept_current":true,"confirmed":true}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "transfer_id", "context", "destination", "state"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("missing key %q in %v", key, result)
		}
	}
	if len(result) != 5 {
		t.Fatalf("unexpected resolution fields: %v", result)
	}
	for _, forbidden := range []string{"native/private", ".px-stage", ".bak", "sha256", "durability", "created", "replaced", "peer_confirmation"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("resolution response exposed %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestInviteRoutesAreStrictAndErrorsAreCoded(t *testing.T) {
	handler := New(nil, nil, &contextstate.Manager{})
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/v1/contexts/home/invites", body: `{}`},
		{method: http.MethodPost, path: "/v1/contexts/home/invites", body: `{"version":2,"label":"valid","lifetime_seconds":3600}`},
		{method: http.MethodPost, path: "/v1/contexts/home/invites", body: `{"version":1,"label":"valid","lifetime_seconds":3600,"extra":true}`},
		{method: http.MethodPost, path: "/v1/contexts/home/invites?extra=1", body: `{"version":1,"label":"valid","lifetime_seconds":3600}`},
		{method: http.MethodGet, path: "/v1/contexts/home/invites", body: `{}`},
		{method: http.MethodDelete, path: "/v1/contexts/home/invites/INVALID"},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var responseError localipc.Error
		if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != http.StatusBadRequest || responseError.Code != "invalid_request" {
			t.Fatalf("%s %s = %d %+v, %v: %s", test.method, test.path, response.Code, responseError, err, response.Body.String())
		}
	}

	for _, test := range []struct {
		err     error
		status  int
		code    string
		message string
	}{
		{err: &contextstate.InviteError{Code: "invalid_request", Message: "invalid invite request"}, status: http.StatusBadRequest, code: "invalid_request", message: "invalid invite request"},
		{err: &contextstate.InviteError{Code: string(membership.CodeInviteLabelUnavailable), Message: "invite label is unavailable"}, status: http.StatusConflict, code: string(membership.CodeInviteLabelUnavailable), message: "invite label is unavailable"},
		{err: &contextstate.InviteError{Code: string(membership.CodeInviteCapacity), Message: "invite capacity reached"}, status: http.StatusTooManyRequests, code: string(membership.CodeInviteCapacity), message: "invite capacity reached"},
		{err: &contextstate.InviteError{Code: string(membership.CodeInviteUnavailable), Message: "invite is unavailable"}, status: http.StatusNotFound, code: string(membership.CodeInviteUnavailable), message: "invite is unavailable"},
		{err: contextstate.ErrInviteCreateOutcomeUnknown, status: http.StatusBadGateway, code: "outcome_unknown", message: contextstate.ErrInviteCreateOutcomeUnknown.Error()},
		{err: sql.ErrNoRows, status: http.StatusNotFound, code: InviteCodeContextNotFound, message: "context not found"},
		{err: contextstate.ErrMemberOperationCapacity, status: http.StatusTooManyRequests, code: InviteCodeMemberOperationCapacity, message: contextstate.ErrMemberOperationCapacity.Error()},
		{err: contextstate.ErrContextDisconnected, status: http.StatusServiceUnavailable, code: InviteCodeContextDisconnected, message: contextstate.ErrContextDisconnected.Error()},
		{err: context.DeadlineExceeded, status: http.StatusRequestTimeout, code: InviteCodeRequestTimeout, message: context.DeadlineExceeded.Error()},
		{err: fmt.Errorf("%w: context is disabled", contextstate.ErrInvalidContextState), status: http.StatusUnprocessableEntity, code: InviteCodeInvalidContext, message: "invalid context state: context is disabled"},
		{err: fmt.Errorf("%w: rejected by rendezvous", contextstate.ErrOperationRejected), status: http.StatusUnprocessableEntity, code: InviteCodeInvalidContext, message: "context operation rejected: rejected by rendezvous"},
	} {
		response := httptest.NewRecorder()
		handler.writeInviteError(response, test.err)
		var responseError localipc.Error
		if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != test.status || responseError.Code != test.code || responseError.Message != test.message {
			t.Fatalf("error %v = %d %+v, %v", test.err, response.Code, responseError, err)
		}
	}
}

func TestTransferRetryRoutePreflightsBeforeStreaming(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "missing or expired", err: transfer.ErrTransferNotFound, want: http.StatusNotFound},
		{name: "active", err: transfer.ErrTransferActive, want: http.StatusConflict},
		{name: "context mismatch", err: transfer.ErrTransferContextMismatch, want: http.StatusConflict},
		{name: "peer mismatch", err: transfer.ErrTransferPeerMismatch, want: http.StatusConflict},
		{name: "context disconnected", err: contextstate.ErrContextDisconnected, want: http.StatusServiceUnavailable},
		{name: "peer offline", err: contextstate.ErrPeerOffline, want: http.StatusUnprocessableEntity},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := New(nil, nil, &contextstate.Manager{})
			handler.prepareRetry = func(context.Context, string, string) (transferRetryOperation, error) {
				return nil, test.err
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("a", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
			request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || response.Header().Get("Content-Type") == "application/x-ndjson" {
				t.Fatalf("status = %d, content type = %q, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
			}
		})
	}
}

func TestPutRetryRouteMaps32CharacterPreflightErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "missing", err: put.ErrNotFound, want: http.StatusNotFound},
		{name: "committed", err: put.ErrNotFound, want: http.StatusNotFound},
		{name: "active", err: put.ErrActive, want: http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := New(nil, nil, &contextstate.Manager{})
			handler.prepareRetry = func(context.Context, string, string) (transferRetryOperation, error) {
				return nil, test.err
			}
			id := strings.Repeat("a", 32)
			request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+id+"/retry", strings.NewReader(`{"context":"home"}`))
			request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || response.Header().Get("Content-Type") == "application/x-ndjson" {
				t.Fatalf("status=%d content-type=%q body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
			}
		})
	}
}

func TestTransferRetryRouteStreamsPreparedOperation(t *testing.T) {
	operation := &fakeRetryOperation{events: []transfer.ResumeEvent{
		{Version: transfer.ResumeEventVersion, State: "resumed", TransferID: strings.Repeat("b", 32), Bytes: 8, Total: 20},
		{Version: transfer.ResumeEventVersion, State: "committed", TransferID: strings.Repeat("b", 32), Bytes: 20, Total: 20, Name: "path/result", Created: true, Outcome: "created", Durability: "durability_confirmed"},
	}}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(context.Context, string, string) (transferRetryOperation, error) {
		return operation, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	handler.ServeHTTP(response, request)
	if response.code != http.StatusOK || response.Header().Get("Content-Type") != "application/x-ndjson" || !operation.closed {
		t.Fatalf("status = %d, content type = %q, closed = %v", response.code, response.Header().Get("Content-Type"), operation.closed)
	}
	decoder := json.NewDecoder(&response.body)
	for _, want := range operation.events {
		var event transfer.ResumeEvent
		if err := decoder.Decode(&event); err != nil || event != want {
			t.Fatalf("event = %+v, %v, want %+v", event, err, want)
		}
	}
}

type fakeRetryOperation struct {
	events   []transfer.ResumeEvent
	err      error
	ctx      context.Context
	run      func(func(transfer.ResumeEvent)) error
	canceled bool
	closed   bool
}

func (o *fakeRetryOperation) Run(progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	if o.run != nil {
		err := o.run(progress)
		o.canceled = o.ctx != nil && o.ctx.Err() != nil
		return transfer.Result{}, err
	}
	for _, event := range o.events {
		progress(event)
	}
	if o.ctx != nil {
		o.canceled = o.ctx.Err() != nil
	}
	if o.err != nil {
		return transfer.Result{}, o.err
	}
	return transfer.Result{Bytes: o.events[len(o.events)-1].Bytes}, nil
}

func (o *fakeRetryOperation) Close() { o.closed = true }

func TestTransferRetryStreamsSourceErrorCode(t *testing.T) {
	operation := &fakeRetryOperation{err: &transfer.SourceError{Code: transfer.SourceNotFoundCode, Message: "local source does not exist or is unavailable"}}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(context.Context, string, string) (transferRetryOperation, error) {
		return operation, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	handler.ServeHTTP(response, request)
	var event transfer.ResumeEvent
	if err := json.NewDecoder(&response.body).Decode(&event); err != nil || event.State != "failed" || event.ErrorCode != transfer.SourceNotFoundCode || !operation.closed {
		t.Fatalf("event = %+v, closed = %v, error = %v", event, operation.closed, err)
	}
}

func TestTransferRetryWriteFailureCancelsAndReleasesOperation(t *testing.T) {
	operation := &fakeRetryOperation{events: []transfer.ResumeEvent{{Version: transfer.ResumeEventVersion, State: "resumed", TransferID: strings.Repeat("b", 64)}}}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(ctx context.Context, _, _ string) (transferRetryOperation, error) {
		operation.ctx = ctx
		return operation, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	response.writeErr = errors.New("client disconnected")
	response.blockWrite = 1
	response.writeBlocked = make(chan struct{})
	response.releaseWrite = make(chan struct{})
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-response.writeBlocked
	close(response.releaseWrite)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed blocked stream did not return")
	}
	if response.code != http.StatusOK || !operation.canceled || !operation.closed || len(handler.operations) != 0 {
		t.Fatalf("status = %d, canceled = %v, closed = %v, operation slots = %d", response.code, operation.canceled, operation.closed, len(handler.operations))
	}
	if response.body.Len() != 0 {
		t.Fatalf("committed stream contains second error body: %q", response.body.String())
	}
}

func TestTransferRetryDeadlineFailureAfterCommitCancelsOperation(t *testing.T) {
	operation := &fakeRetryOperation{events: []transfer.ResumeEvent{{Version: transfer.ResumeEventVersion, State: "resumed", TransferID: strings.Repeat("b", 64)}}}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(ctx context.Context, _, _ string) (transferRetryOperation, error) {
		operation.ctx = ctx
		return operation, nil
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	response.deadlineErr = errors.New("deadline failed")
	response.deadlineAt = 2
	handler.ServeHTTP(response, request)
	if response.code != http.StatusOK || !operation.canceled || !operation.closed || response.body.Len() != 0 {
		t.Fatalf("status = %d, canceled = %v, closed = %v, body = %q", response.code, operation.canceled, operation.closed, response.body.String())
	}
}

func TestTransferRetryUnsupportedDeadlineClosesPreparedOperation(t *testing.T) {
	operation := &fakeRetryOperation{}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(context.Context, string, string) (transferRetryOperation, error) { return operation, nil }
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	response.deadlineErr = http.ErrNotSupported
	handler.ServeHTTP(response, request)
	if response.code != http.StatusInternalServerError || !operation.closed || len(handler.operations) != 0 || response.Header().Get("Content-Type") == "application/x-ndjson" {
		t.Fatalf("status = %d, closed = %v, operation slots = %d, content type = %q", response.code, operation.closed, len(handler.operations), response.Header().Get("Content-Type"))
	}
}

func TestTransferRetryClientCancellationClosesPreparedOperation(t *testing.T) {
	started := make(chan struct{})
	operation := &fakeRetryOperation{}
	handler := New(nil, nil, &contextstate.Manager{})
	handler.prepareRetry = func(ctx context.Context, _, _ string) (transferRetryOperation, error) {
		operation.ctx = ctx
		operation.run = func(func(transfer.ResumeEvent)) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return operation, nil
	}
	requestContext, cancel := context.WithCancel(t.Context())
	request := httptest.NewRequest(http.MethodPost, "/v1/transfers/"+strings.Repeat("b", 64)+"/retry", strings.NewReader(`{"context":"home"}`)).WithContext(requestContext)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := newWatchResponseWriter()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled retry handler did not return")
	}
	if !operation.canceled || !operation.closed || len(handler.operations) != 0 {
		t.Fatalf("canceled = %v, closed = %v, operation slots = %d", operation.canceled, operation.closed, len(handler.operations))
	}
}

func TestPublicTransferErrorRedactsPathsAndBoundsMessages(t *testing.T) {
	if message := publicTransferError(errors.New("inspect source path: /private/source: denied")); message != "transfer operation failed" {
		t.Fatalf("path error = %q", message)
	}
	if message := publicTransferError(errors.New(strings.Repeat("x", 257))); message != "transfer operation failed" {
		t.Fatalf("long error = %q", message)
	}
	if message := publicTransferError(transfer.ErrTransferContextMismatch); message != transfer.ErrTransferContextMismatch.Error() {
		t.Fatalf("safe error = %q", message)
	}
	sourceErr := &transfer.SourceError{Code: transfer.SourceNotFoundCode, Message: "local source does not exist or is unavailable"}
	if message := publicTransferError(sourceErr); message != sourceErr.Message {
		t.Fatalf("source error = %q", message)
	}
}

func TestContextSendRejectsInvalidSourceBeforeStreaming(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	handler := New(nil, nil, &contextstate.Manager{})
	body, err := json.Marshal(ContextSendRequest{Context: "home", Peer: "vm", Source: missing, MaxFileBytes: transfer.DefaultMaxFileBytes})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/context/send", bytes.NewReader(body))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var responseErr localipc.Error
	if err := json.Unmarshal(response.Body.Bytes(), &responseErr); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnprocessableEntity || response.Header().Get("Content-Type") == "application/x-ndjson" || responseErr.Code != transfer.SourceNotFoundCode || strings.Contains(response.Body.String(), missing) {
		t.Fatalf("status = %d, content type = %q, error = %+v, body = %s", response.Code, response.Header().Get("Content-Type"), responseErr, response.Body.String())
	}
}

func TestContextOperationErrorStatus(t *testing.T) {
	handler := New(nil, nil, nil)
	for _, test := range []struct {
		err  error
		want int
	}{
		{err: contextstate.ErrMemberOperationCapacity, want: http.StatusTooManyRequests},
		{err: contextstate.ErrContextDisconnected, want: http.StatusServiceUnavailable},
		{err: contextstate.ErrContextActive, want: http.StatusConflict},
		{err: contextstate.ErrContextCapacity, want: http.StatusConflict},
		{err: contextstate.ErrAliasCapacity, want: http.StatusConflict},
		{err: contextstate.ErrContextProjection, want: http.StatusConflict},
		{err: context.Canceled, want: http.StatusRequestTimeout},
		{err: context.DeadlineExceeded, want: http.StatusRequestTimeout},
		{err: contextstate.ErrApprovalOutcomeUnknown, want: http.StatusBadGateway},
		{err: contextstate.ErrInvalidConfiguration, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrInvalidAlias, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrInvalidContextState, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrOperationRejected, want: http.StatusUnprocessableEntity},
		{err: contextstate.ErrPeerOffline, want: http.StatusUnprocessableEntity},
		{err: errors.New("database failed"), want: http.StatusInternalServerError},
	} {
		response := httptest.NewRecorder()
		handler.writeContextOperationError(response, test.err)
		if response.Code != test.want {
			t.Fatalf("error %v status = %d, want %d", test.err, response.Code, test.want)
		}
	}
}

func TestWriteJSONRejectsOversizedAgentResponseBeforeSuccess(t *testing.T) {
	exactResponse := httptest.NewRecorder()
	overhead := len(`{"value":""}`) + 1
	writeJSON(exactResponse, http.StatusOK, map[string]string{"value": strings.Repeat("x", localipc.MaxResponseBytes-overhead)})
	if exactResponse.Code != http.StatusOK || exactResponse.Body.Len() != localipc.MaxResponseBytes {
		t.Fatalf("exact response status = %d, bytes = %d", exactResponse.Code, exactResponse.Body.Len())
	}

	response := httptest.NewRecorder()
	writeJSON(response, http.StatusOK, map[string]string{"value": strings.Repeat("x", localipc.MaxResponseBytes)})
	if response.Code != http.StatusInternalServerError || response.Body.Len() > localipc.MaxResponseBytes {
		t.Fatalf("status = %d, bytes = %d", response.Code, response.Body.Len())
	}
	var result localipc.Error
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Message != "agent response exceeds size limit" {
		t.Fatalf("response = %+v, %v", result, err)
	}
}

func TestContextConfigurationAndAliasErrorStatuses(t *testing.T) {
	handler := New(nil, nil, nil)
	for _, test := range []struct {
		write func(http.ResponseWriter, error)
		err   error
		want  int
	}{
		{write: handler.writeContextConfigurationError, err: sql.ErrNoRows, want: http.StatusNotFound},
		{write: handler.writeContextConfigurationError, err: contextstate.ErrContextActive, want: http.StatusConflict},
		{write: handler.writeContextConfigurationError, err: contextstate.ErrInvalidConfiguration, want: http.StatusUnprocessableEntity},
		{write: handler.writeContextConfigurationError, err: errors.New("database failed"), want: http.StatusInternalServerError},
		{write: handler.writeAliasError, err: sql.ErrNoRows, want: http.StatusNotFound},
		{write: handler.writeAliasError, err: contextstate.ErrAliasNotFound, want: http.StatusNotFound},
		{write: handler.writeAliasError, err: contextstate.ErrInvalidAlias, want: http.StatusUnprocessableEntity},
		{write: handler.writeAliasError, err: errors.New("database failed"), want: http.StatusInternalServerError},
	} {
		response := httptest.NewRecorder()
		test.write(response, test.err)
		if response.Code != test.want {
			t.Fatalf("error %v status = %d, want %d", test.err, response.Code, test.want)
		}
	}
}

func TestLegacyAliasSetRouteRemainsRegistered(t *testing.T) {
	handler := New(nil, nil, nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/contexts/alias", strings.NewReader(`{"context":"home","alias":"build","target":"vm"}`))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy alias route status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestStatusAndShutdown(t *testing.T) {
	shutdown := make(chan struct{}, 1)
	handler := New(func() { shutdown <- struct{}{} }, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var status Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Version != Version || status.PID == 0 {
		t.Fatalf("status = %+v", status)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/shutdown", nil)
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("shutdown was not requested")
	}
}

func TestCompletionPrefixValidation(t *testing.T) {
	for _, value := range []string{"", "build-vm", "@peer"} {
		if !validCompletionPrefix(value) {
			t.Fatalf("valid prefix %q rejected", value)
		}
	}
	for _, value := range []string{"bad\nvalue", "bad/path", `bad\path`, strings.Repeat("a", 129)} {
		if validCompletionPrefix(value) {
			t.Fatalf("invalid prefix %q accepted", value)
		}
	}
}

func TestRequestBodyIsBounded(t *testing.T) {
	handler := New(nil, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/status", bytes.NewReader(make([]byte, localipc.MaxRequestBytes+1)))
	request.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestOperationCapacityIsBounded(t *testing.T) {
	handler := New(nil, nil, nil)
	for range cap(handler.operations) {
		if !handler.beginOperation(httptest.NewRecorder()) {
			t.Fatal("operation capacity rejected early")
		}
	}
	response := httptest.NewRecorder()
	if handler.beginOperation(response) {
		t.Fatal("operation capacity exceeded")
	}
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", response.Code)
	}
	for range cap(handler.operations) {
		handler.endOperation()
	}
}
