package adapterapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
)

func TestVersionOneResponseBoundsAreDerivedFromActualDTOs(t *testing.T) {
	maxTime := "9999-12-31T23:59:59Z"
	pendingFact := Fact{Seq: math.MaxInt64, Kind: membership.FactPendingAdmitted, EnrollmentID: strings.Repeat("f", 32), OccurredAt: maxTime, DeviceID: strings.Repeat("z", 43), Label: strings.Repeat("z", 63), ExpiresAt: maxTime}
	memberFact := pendingFact
	memberFact.Kind = membership.FactMemberApproved
	memberFact.ExpiresAt = ""
	memberFact.MemberRevision = math.MaxInt64
	if encodedSize(memberFact) > encodedSize(pendingFact) {
		pendingFact = memberFact
	}
	maximum := FactPage{Version: Version, Floor: math.MaxInt64, HighWater: math.MaxInt64, Facts: make([]Fact, MaxFactPage)}
	for index := range maximum.Facts {
		maximum.Facts[index] = pendingFact
	}
	if size := encodedSize(maximum) + 1; size > localipc.MaxResponseBytes {
		t.Fatalf("maximum replay page = %d bytes, limit %d", size, localipc.MaxResponseBytes)
	}
	maximum.Facts = append(maximum.Facts, pendingFact)
	if size := encodedSize(maximum) + 1; size <= localipc.MaxResponseBytes {
		t.Fatalf("MaxFactPage is not the derived maximum: max+1 = %d bytes", size)
	}

	pending := PendingSnapshot{Version: Version, HighWater: math.MaxInt64, Pending: make([]Pending, membership.DefaultMaxPending)}
	for index := range pending.Pending {
		pending.Pending[index] = Pending{EnrollmentID: strings.Repeat("f", 32), DeviceID: strings.Repeat("z", 43), Label: strings.Repeat("z", 63), CreatedAt: maxTime, ExpiresAt: maxTime}
	}
	if size := encodedSize(pending) + 1; size > localipc.MaxResponseBytes {
		t.Fatalf("maximum pending snapshot = %d bytes, limit %d", size, localipc.MaxResponseBytes)
	}
}

func TestHandlerAuthenticationStrictnessRedactionAndApproval(t *testing.T) {
	store := newAdapterStore(t)
	now := time.UnixMilli(1_700_000_000_123).UTC()
	provisioning, err := store.ProvisionAdapter(context.Background(), "fixture", now)
	if err != nil {
		t.Fatal(err)
	}
	credential := EncodeCredential(provisioning.Credential)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), publicKey, "fixture-device", "192.0.2.99", now); err != nil {
		t.Fatal(err)
	}
	handler := New(store, nil)
	handler.now = func() time.Time { return now }

	for _, authorization := range []string{"", "Bearer " + credential + "=", "Bearer " + strings.ToUpper(credential), "Basic " + credential} {
		response := adapterRequest(handler, http.MethodGet, "/v1/pending", "fixture", authorization, nil)
		if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"version\":1,\"code\":\"adapter_unauthorized\",\"message\":\"adapter authorization failed\"}\n" {
			t.Fatalf("collapsed authorization = %d %s", response.Code, response.Body.String())
		}
	}
	snapshotResponse := adapterRequest(handler, http.MethodGet, "/v1/pending", "fixture", "Bearer "+credential, nil)
	var snapshot PendingSnapshot
	if err := json.Unmarshal(snapshotResponse.Body.Bytes(), &snapshot); err != nil || len(snapshot.Pending) != 1 || snapshot.Pending == nil {
		t.Fatalf("snapshot = %+v, %v: %s", snapshot, err, snapshotResponse.Body.String())
	}
	for _, forbidden := range []string{"192.0.2.99", "credential", "device_key", "source_ip", "code", credential} {
		if strings.Contains(snapshotResponse.Body.String(), forbidden) {
			t.Fatalf("snapshot contains %q: %s", forbidden, snapshotResponse.Body.String())
		}
	}

	commandID := uuidV7(now)
	request := ApprovalRequest{SchemaVersion: 1, Action: membership.ApprovalCommandAction, CommandID: commandID, EnrollmentID: snapshot.Pending[0].EnrollmentID}
	response := adapterRequest(handler, http.MethodPost, "/v1/commands", "fixture", "Bearer "+credential, request)
	var command Command
	if err := json.Unmarshal(response.Body.Bytes(), &command); err != nil || response.Code != http.StatusOK || command.State != membership.ReceiptCommitted || command.Result == nil {
		t.Fatalf("approval = %+v, %v, status %d: %s", command, err, response.Code, response.Body.String())
	}
	response = adapterRequest(handler, http.MethodPost, "/v1/commands", "fixture", "Bearer "+credential, request)
	if err := json.Unmarshal(response.Body.Bytes(), &command); err != nil || command.State != membership.ReceiptCommitted {
		t.Fatalf("exact retry = %+v, %v: %s", command, err, response.Body.String())
	}
	request.EnrollmentID = strings.Repeat("0", 32)
	response = adapterRequest(handler, http.MethodPost, "/v1/commands", "fixture", "Bearer "+credential, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"request_conflict"`) {
		t.Fatalf("changed retry = %d: %s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/v1/status", "/v1/devices", "/v1/audit", "/v1/shutdown", "/v1/adapters/status"} {
		response = adapterRequest(handler, http.MethodGet, path, "fixture", "Bearer "+credential, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("forbidden route %s = %d", path, response.Code)
		}
	}
}

func TestHandlerRejectsMalformedQueriesAndBodies(t *testing.T) {
	store := newAdapterStore(t)
	provisioning, err := store.ProvisionAdapter(context.Background(), "strict", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	authorization := "Bearer " + EncodeCredential(provisioning.Credential)
	handler := New(store, nil)
	for _, target := range []string{
		"/v1/facts?cursor=0&high_water=0&limit=1&extra=1",
		"/v1/facts?cursor=0&cursor=1&high_water=0&limit=1",
		"/v1/facts?cursor=-1&high_water=0&limit=1",
		"/v1/facts?cursor=0&high_water=0&limit=0",
		fmt.Sprintf("/v1/facts?cursor=0&high_water=0&limit=%d", MaxFactPage+1),
		"/v1/facts?cursor=2&high_water=1&limit=1",
		"/v1/facts?cursor=0&high_water=999&limit=1",
		"/v1/facts?cursor=0&high_water=0&limit=" + strings.Repeat("9", 20),
		"/v1/pending?extra=1",
		"/v1/commands/not/a-command",
	} {
		response := adapterRequest(handler, http.MethodGet, target, "strict", authorization, nil)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("malformed %q = %d: %s", target, response.Code, response.Body.String())
		}
	}
	response := adapterRawRequest(handler, http.MethodPost, "/v1/commands", "strict", authorization, `{"schema_version":1,"action":"enrollment.approve","command_id":"x","enrollment_id":"x","extra":true}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unknown body field = %d: %s", response.Code, response.Body.String())
	}
	for _, rawQuery := range []string{"cursor=0&high_water=0&limit=%31", "cursor=0&high_water=0&limit=1%", "limit=1&cursor=0&high_water=0", "cursor=%30&high_water=0&limit=1", "cursor=&high_water=0&limit=1", "cursor=0&high_water=&limit=1", "cursor=0&high_water=0&limit=", "cursor=0&high_water=0&page_size=1"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/facts", nil)
		request.URL.RawQuery = rawQuery
		request.Header.Set(VersionHeader, "1")
		request.Header.Set(AdapterHeader, "strict")
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("raw query %q = %d: %s", rawQuery, response.Code, response.Body.String())
		}
	}
	for _, target := range []string{"/v1/facts", "/v1/pending", "/v1/commands", "/v1/doorbell"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if target == "/v1/commands" {
			request.Method = http.MethodPost
			request.Body = io.NopCloser(strings.NewReader(`{"schema_version":1,"action":"enrollment.approve","command_id":"018bcfe5-687b-7000-8000-000000000001","enrollment_id":"` + strings.Repeat("f", 32) + `"}`))
		}
		request.URL.ForceQuery = true
		request.Header.Set(VersionHeader, "1")
		request.Header.Set(AdapterHeader, "strict")
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("dangling query %q = %d: %s", target, response.Code, response.Body.String())
		}
	}
	for _, rawPath := range []string{"/v1/commands/018bcfe5-687b-7000-8000-000000000001", "/v1/commands/018bcfe5%2D687b-7000-8000-000000000001", "/v1%2Fcommands/018bcfe5-687b-7000-8000-000000000001"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/commands/018bcfe5-687b-7000-8000-000000000001", nil)
		if strings.Contains(rawPath, "%") {
			request.URL.RawPath = rawPath
			decoded, _ := url.PathUnescape(rawPath)
			request.URL.Path = decoded
		}
		request.Header.Set(VersionHeader, "1")
		request.Header.Set(AdapterHeader, "strict")
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if strings.Contains(rawPath, "%") && response.Code != http.StatusBadRequest {
			t.Fatalf("escaped path %q = %d: %s", rawPath, response.Code, response.Body.String())
		}
	}
}

func TestUnexpectedApprovalFailuresAreOutcomeUnknown(t *testing.T) {
	store := newAdapterStore(t)
	now := time.UnixMilli(1_700_000_000_123).UTC()
	provisioning, err := store.ProvisionAdapter(context.Background(), "unknown", now)
	if err != nil {
		t.Fatal(err)
	}
	request := ApprovalRequest{SchemaVersion: 1, Action: membership.ApprovalCommandAction, CommandID: uuidV7(now), EnrollmentID: strings.Repeat("f", 32)}
	for _, stage := range []string{"admit", "approve"} {
		handler := New(store, nil)
		handler.now = func() time.Time { return now }
		if stage == "admit" {
			handler.admit = func(context.Context, string, membership.AdapterCredential, membership.ApprovalCommand, time.Time) (membership.CommandReceipt, error) {
				return membership.CommandReceipt{}, errors.New("private database failure")
			}
		} else {
			handler.admit = func(context.Context, string, membership.AdapterCredential, membership.ApprovalCommand, time.Time) (membership.CommandReceipt, error) {
				return membership.CommandReceipt{State: membership.ReceiptAdmitted}, nil
			}
			handler.approve = func(context.Context, string, string, time.Time) (membership.CommandReceipt, error) {
				return membership.CommandReceipt{}, errors.New("private execution failure")
			}
		}
		response := adapterRequest(handler, http.MethodPost, "/v1/commands", "unknown", "Bearer "+EncodeCredential(provisioning.Credential), request)
		var responseError Error
		if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != http.StatusServiceUnavailable || responseError.Code != CodeOutcomeUnknown || responseError.CommandID != request.CommandID || responseError.Message != OutcomeUnknownMessage || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("%s failure = %+v, %v, status %d: %s", stage, responseError, err, response.Code, response.Body.String())
		}
	}
}

func TestDurableRejectionUsesHTTP200AndWriterRejectsBeforeOutput(t *testing.T) {
	store := newAdapterStore(t)
	now := time.UnixMilli(1_700_000_000_123).UTC()
	provisioning, err := store.ProvisionAdapter(context.Background(), "reject", now)
	if err != nil {
		t.Fatal(err)
	}
	request := ApprovalRequest{SchemaVersion: 1, Action: membership.ApprovalCommandAction, CommandID: uuidV7(now), EnrollmentID: strings.Repeat("f", 32)}
	handler := New(store, nil)
	handler.now = func() time.Time { return now }
	response := adapterRequest(handler, http.MethodPost, "/v1/commands", "reject", "Bearer "+EncodeCredential(provisioning.Credential), request)
	var result Command
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK || result.State != membership.ReceiptRejected || result.RejectionCode != string(membership.RejectionNotPending) {
		t.Fatalf("durable rejection = %+v, %v, status %d: %s", result, err, response.Code, response.Body.String())
	}

	oversized := httptest.NewRecorder()
	writeJSON(oversized, strings.Repeat("x", localipc.MaxResponseBytes))
	if oversized.Code != http.StatusInternalServerError || strings.Contains(oversized.Body.String(), strings.Repeat("x", 100)) || !strings.Contains(oversized.Body.String(), `"code":"internal_error"`) {
		t.Fatalf("oversized response was partially written: %d %s", oversized.Code, oversized.Body.String())
	}
}

func TestDoorbellReplacementAndCredentialReauthorization(t *testing.T) {
	store := newAdapterStore(t)
	provisioning, err := store.ProvisionAdapter(context.Background(), "bell", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(nil)
	broker.cancel = func() {}
	handler := New(store, broker)
	handler.doorbellReauthorize = 20 * time.Millisecond
	server := httptest.NewServer(handler)
	defer server.Close()
	open := func(credential membership.AdapterCredential) (*http.Response, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/doorbell", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(VersionHeader, "1")
		request.Header.Set(AdapterHeader, "bell")
		request.Header.Set("Authorization", "Bearer "+EncodeCredential(credential))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response, cancel
	}
	first, cancelFirst := open(provisioning.Credential)
	defer cancelFirst()
	second, cancelSecond := open(provisioning.Credential)
	defer cancelSecond()
	if data, err := io.ReadAll(first.Body); err != nil || len(data) != 0 {
		t.Fatalf("replaced stream = %q, %v", data, err)
	}
	first.Body.Close()
	if _, err := store.RotateAdapterCredential(context.Background(), "bell", time.Now()); err != nil {
		t.Fatal(err)
	}
	broker.fanout()
	closed := make(chan error, 1)
	go func() { _, readErr := io.ReadAll(second.Body); closed <- readErr }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale doorbell remained open after rotation")
	}
	second.Body.Close()
}

func TestDoorbellAuthorizationAndReplacementAreAtomicWithRotation(t *testing.T) {
	store := newAdapterStore(t)
	provisioning, err := store.ProvisionAdapter(context.Background(), "atomic-bell", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(nil)
	broker.cancel = func() {}
	callbackStarted := make(chan struct{})
	allowStaleSubscribe := make(chan struct{})
	staleSubscribed := make(chan (<-chan struct{}), 1)
	staleError := make(chan error, 1)
	go func() {
		staleError <- store.WithAuthorizedAdapter(context.Background(), "atomic-bell", provisioning.Credential, func() error {
			close(callbackStarted)
			<-allowStaleSubscribe
			subscriber, _, subscribeErr := broker.Subscribe("atomic-bell")
			if subscribeErr == nil {
				staleSubscribed <- subscriber
			}
			return subscribeErr
		})
	}()
	<-callbackStarted
	rotation := make(chan membership.AdapterProvisioning, 1)
	rotationError := make(chan error, 1)
	go func() {
		result, rotateErr := store.RotateAdapterCredential(context.Background(), "atomic-bell", time.Now())
		rotation <- result
		rotationError <- rotateErr
	}()
	select {
	case err := <-rotationError:
		t.Fatalf("rotation crossed authorized subscription callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowStaleSubscribe)
	if err := <-staleError; err != nil {
		t.Fatal(err)
	}
	stale := <-staleSubscribed
	rotated := <-rotation
	if err := <-rotationError; err != nil {
		t.Fatal(err)
	}
	var current <-chan struct{}
	if err := store.WithAuthorizedAdapter(context.Background(), "atomic-bell", rotated.Credential, func() error {
		var subscribeErr error
		current, _, subscribeErr = broker.Subscribe("atomic-bell")
		return subscribeErr
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-stale:
		if ok {
			t.Fatal("stale pre-rotation subscription survived valid replacement")
		}
	case <-time.After(time.Second):
		t.Fatal("valid post-rotation subscription did not replace stale stream")
	}
	broker.fanout()
	select {
	case _, ok := <-current:
		if !ok {
			t.Fatal("valid post-rotation stream was closed")
		}
	case <-time.After(time.Second):
		t.Fatal("valid post-rotation stream did not receive marker")
	}
}

func encodedSize(value any) int {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return len(data)
}

func adapterRequest(handler http.Handler, method, target, adapterID, authorization string, body any) *httptest.ResponseRecorder {
	var data io.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		data = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, target, data)
	request.Header.Set(VersionHeader, "1")
	request.Header.Set(AdapterHeader, adapterID)
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func adapterRawRequest(handler http.Handler, method, target, adapterID, authorization, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set(VersionHeader, "1")
	request.Header.Set(AdapterHeader, adapterID)
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func uuidV7(now time.Time) string {
	milliseconds := now.UnixMilli()
	return fmt.Sprintf("%08x-%04x-7000-8000-000000000001", uint32(milliseconds>>16), uint16(milliseconds))
}

func newAdapterStore(t *testing.T) *membership.Store {
	t.Helper()
	directory := t.TempDir()
	privatePath, publicPath := filepath.Join(directory, "authority.key"), filepath.Join(directory, "server.pub")
	if err := membership.Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	authority, err := membership.Load(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := database.Config(database.KindServer, filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(config)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Stop(context.Background()) })
	return membership.NewStore(databaseStore.DB(), authority, membership.DefaultMaxPending)
}
