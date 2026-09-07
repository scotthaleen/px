package serveradmin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/adapterapi"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/versioninfo"
)

func TestAuditAndMemberInspectionRoutesAreBoundedAndRedacted(t *testing.T) {
	store := newTestStore(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	pending, err := store.RequestEnrollment(context.Background(), publicKey, "handler-device", "192.0.2.99", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := store.Approve(context.Background(), pending.Code, "local", "", now)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(store, rendezvousapi.NewHub(), nil)

	inspect := request(t, handler, http.MethodGet, "/v1/devices/inspect?device_id="+member.DeviceID, nil)
	if inspect.Code != http.StatusOK {
		t.Fatalf("inspect status = %d: %s", inspect.Code, inspect.Body.String())
	}
	partial := request(t, handler, http.MethodGet, "/v1/devices/inspect?device_id="+member.DeviceID[:12], nil)
	if partial.Code != http.StatusBadRequest || !strings.Contains(partial.Body.String(), "complete enrolled device ID") {
		t.Fatalf("partial selector = %d: %s", partial.Code, partial.Body.String())
	}

	audit := request(t, handler, http.MethodGet, "/v1/audit?limit=1", nil)
	if audit.Code != http.StatusOK {
		t.Fatalf("audit status = %d: %s", audit.Code, audit.Body.String())
	}
	var events []membership.AuditEvent
	if err := json.Unmarshal(audit.Body.Bytes(), &events); err != nil || len(events) != 1 || events[0].Action != "member.approved" {
		t.Fatalf("audit events = %+v, %v: %s", events, err, audit.Body.String())
	}
	for _, forbidden := range []string{"192.0.2.99", "credential", "device_key", "nonce", "source_ip", "request_body", "signaling"} {
		if strings.Contains(audit.Body.String(), forbidden) {
			t.Fatalf("audit response contains %q: %s", forbidden, audit.Body.String())
		}
	}
	oversized := request(t, handler, http.MethodGet, "/v1/audit?limit=129", nil)
	if oversized.Code != http.StatusBadRequest || !strings.Contains(oversized.Body.String(), "must not exceed") {
		t.Fatalf("oversized limit = %d: %s", oversized.Code, oversized.Body.String())
	}
	oversized = request(t, handler, http.MethodGet, "/v1/devices?limit=129", nil)
	if oversized.Code != http.StatusBadRequest || !strings.Contains(oversized.Body.String(), "must not exceed") {
		t.Fatalf("oversized member limit = %d: %s", oversized.Code, oversized.Body.String())
	}
	for _, target := range []string{"/v1/audit?limit=128", "/v1/devices?limit=128"} {
		maximum := request(t, handler, http.MethodGet, target, nil)
		if maximum.Code != http.StatusOK {
			t.Fatalf("advertised maximum %s = %d: %s", target, maximum.Code, maximum.Body.String())
		}
	}
}

func TestAdapterAdministrationRoutesReturnCredentialOnceAndRedactStatus(t *testing.T) {
	handler := New(newTestStore(t), rendezvousapi.NewHub(), nil)
	provision := request(t, handler, http.MethodPost, "/v1/adapters/provision", AdapterRequest{AdapterID: "example"})
	var created AdapterProvisioning
	if err := json.Unmarshal(provision.Body.Bytes(), &created); err != nil || provision.Code != http.StatusOK || created.Version != Version || created.AdapterID != "example" || !created.Active {
		t.Fatalf("provision = %+v, %v, status %d: %s", created, err, provision.Code, provision.Body.String())
	}
	if _, err := adapterapi.DecodeCredential(created.Credential); err != nil {
		t.Fatalf("credential is not canonical: %v", err)
	}
	status := request(t, handler, http.MethodGet, "/v1/adapters/status?adapter_id=example", nil)
	var inspected AdapterStatus
	if err := json.Unmarshal(status.Body.Bytes(), &inspected); err != nil || inspected.AdapterID != "example" || !inspected.Active {
		t.Fatalf("status = %+v, %v: %s", inspected, err, status.Body.String())
	}
	for _, forbidden := range []string{created.Credential, "credential", "verifier", "credential_hash"} {
		if strings.Contains(status.Body.String(), forbidden) {
			t.Fatalf("status contains %q: %s", forbidden, status.Body.String())
		}
	}
	deactivated := request(t, handler, http.MethodPost, "/v1/adapters/deactivate", AdapterRequest{AdapterID: "example"})
	if err := json.Unmarshal(deactivated.Body.Bytes(), &inspected); err != nil || inspected.Active {
		t.Fatalf("deactivate = %+v, %v: %s", inspected, err, deactivated.Body.String())
	}
	rotated := request(t, handler, http.MethodPost, "/v1/adapters/rotate", AdapterRequest{AdapterID: "example"})
	var rotation AdapterProvisioning
	if err := json.Unmarshal(rotated.Body.Bytes(), &rotation); err != nil || rotation.Credential == created.Credential || rotation.Active {
		t.Fatalf("rotation = %+v, %v: %s", rotation, err, rotated.Body.String())
	}
	activated := request(t, handler, http.MethodPost, "/v1/adapters/activate", AdapterRequest{AdapterID: "example"})
	if err := json.Unmarshal(activated.Body.Bytes(), &inspected); err != nil || !inspected.Active {
		t.Fatalf("activate = %+v, %v: %s", inspected, err, activated.Body.String())
	}
}

func TestInviteAdministrationRoutesAreStrictBoundedAndRedacted(t *testing.T) {
	handler := New(newTestStore(t), rendezvousapi.NewHub(), nil)
	createdResponse := request(t, handler, http.MethodPost, "/v1/invites", CreateInviteRequest{Version: InviteVersion, Label: "bootstrap", LifetimeSeconds: 3600})
	var created InviteCreation
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &created); err != nil || createdResponse.Code != http.StatusOK || created.Version != InviteVersion || created.Label != "bootstrap" || created.IssuerType != "local" || created.IssuerDeviceID != "" {
		t.Fatalf("create response invalid: decode_error=%v status=%d version=%d label_matches=%t issuer_type=%q issuer_id_empty=%t body_bytes=%d token_length=%d", err, createdResponse.Code, created.Version, created.Label == "bootstrap", created.IssuerType, created.IssuerDeviceID == "", createdResponse.Body.Len(), len(created.Token))
	}
	parsed, err := membership.ParseInviteToken(created.Token)
	if err != nil {
		t.Fatalf("creation token is invalid: %v", err)
	}
	listedResponse := request(t, handler, http.MethodGet, "/v1/invites", nil)
	var listed InviteList
	listedDecodeErr := json.Unmarshal(listedResponse.Body.Bytes(), &listed)
	listedTokenLeak := strings.Contains(listedResponse.Body.String(), created.Token)
	listedSecretLeak := strings.Contains(listedResponse.Body.String(), base64.RawURLEncoding.EncodeToString(parsed.Secret[:]))
	listedForbiddenField := strings.Contains(listedResponse.Body.String(), "token") || strings.Contains(listedResponse.Body.String(), "verifier") || strings.Contains(listedResponse.Body.String(), "secret")
	if listedDecodeErr != nil || listedResponse.Code != http.StatusOK || listed.Version != InviteVersion || len(listed.Invites) != 1 || listed.Invites[0] != created.Invite || listedTokenLeak || listedSecretLeak || listedForbiddenField {
		t.Fatalf("list response invalid: decode_error=%v status=%d version=%d count=%d invite_matches=%t body_bytes=%d token_leak=%t secret_leak=%t forbidden_field=%t", listedDecodeErr, listedResponse.Code, listed.Version, len(listed.Invites), len(listed.Invites) == 1 && listed.Invites[0] == created.Invite, listedResponse.Body.Len(), listedTokenLeak, listedSecretLeak, listedForbiddenField)
	}
	revokedResponse := request(t, handler, http.MethodDelete, "/v1/invites/"+created.InviteID, nil)
	var revoked InviteRevocation
	revokedDecodeErr := json.Unmarshal(revokedResponse.Body.Bytes(), &revoked)
	revokedTokenLeak := strings.Contains(revokedResponse.Body.String(), created.Token)
	revokedSecretLeak := strings.Contains(revokedResponse.Body.String(), base64.RawURLEncoding.EncodeToString(parsed.Secret[:]))
	if revokedDecodeErr != nil || revokedResponse.Code != http.StatusOK || revoked.Version != InviteVersion || revoked.State != "revoked" || revoked.Invite != created.Invite || revokedTokenLeak || revokedSecretLeak {
		t.Fatalf("revoke response invalid: decode_error=%v status=%d version=%d state_matches=%t invite_matches=%t body_bytes=%d token_leak=%t secret_leak=%t", revokedDecodeErr, revokedResponse.Code, revoked.Version, revoked.State == "revoked", revoked.Invite == created.Invite, revokedResponse.Body.Len(), revokedTokenLeak, revokedSecretLeak)
	}
	missing := request(t, handler, http.MethodDelete, "/v1/invites/"+created.InviteID, nil)
	var missingError localipc.Error
	if err := json.Unmarshal(missing.Body.Bytes(), &missingError); err != nil || missing.Code != http.StatusNotFound || missingError.Code != string(membership.CodeInviteUnavailable) || missingError.Message != "invite is unavailable" {
		t.Fatalf("missing = %+v, %v, status %d: %s", missingError, err, missing.Code, missing.Body.String())
	}
	assertEncodedResponseFits(t, "invites", listed)
}

func TestInviteAdministrationRejectsNoncanonicalWire(t *testing.T) {
	handler := New(newTestStore(t), rendezvousapi.NewHub(), nil)
	requests := []struct {
		method string
		target string
		body   string
	}{
		{http.MethodPost, "/v1/invites", `{}`},
		{http.MethodPost, "/v1/invites", `{"version":2,"label":"valid","lifetime_seconds":3600}`},
		{http.MethodPost, "/v1/invites", `{"version":1,"label":"valid","lifetime_seconds":59}`},
		{http.MethodPost, "/v1/invites", `{"version":1,"label":"valid","lifetime_seconds":3600,"extra":true}`},
		{http.MethodPost, "/v1/invites?extra=1", `{"version":1,"label":"valid","lifetime_seconds":3600}`},
		{http.MethodGet, "/v1/invites?extra=1", ``},
		{http.MethodDelete, "/v1/invites/INVALID", ``},
		{http.MethodDelete, "/v1/invites/00000000000000000000000000000000?extra=1", ``},
		{http.MethodDelete, "/v1/invites/00000000000000000000000000000000", `{}`},
	}
	for _, test := range requests {
		req := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
		req.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		var responseError localipc.Error
		if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != http.StatusBadRequest || responseError.Code != "invalid_request" {
			t.Fatalf("%s %s body %q = %+v, %v, status %d: %s", test.method, test.target, test.body, responseError, err, response.Code, response.Body.String())
		}
	}
}

func TestInviteAdministrationUsesStableErrorCodes(t *testing.T) {
	handler := New(newTestStore(t), rendezvousapi.NewHub(), nil, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	tests := []struct {
		err    error
		status int
		code   string
		text   string
	}{
		{&membership.StoreError{Code: membership.CodeMembershipInvalid, Message: "private invalid detail"}, http.StatusBadRequest, "invalid_request", "invalid invite request"},
		{&membership.StoreError{Code: membership.CodeInviteLabelUnavailable, Message: "private conflict detail"}, http.StatusConflict, "invite_label_unavailable", "invite label is unavailable"},
		{&membership.StoreError{Code: membership.CodeInviteCapacity, Message: "private capacity detail"}, http.StatusTooManyRequests, "invite_capacity", "invite capacity reached"},
		{&membership.StoreError{Code: membership.CodeInviteUnavailable, Message: "private terminal detail"}, http.StatusNotFound, "invite_unavailable", "invite is unavailable"},
		{errors.New("private database detail"), http.StatusInternalServerError, "internal_error", "invite administration failed"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		handler.writeInviteError(response, test.err)
		var responseError localipc.Error
		if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != test.status || responseError.Code != test.code || responseError.Message != test.text || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("error %v = %+v, %v, status %d: %s", test.err, responseError, err, response.Code, response.Body.String())
		}
	}
}

func TestMembershipStoreFailuresAreRedactedFromAdministrationResponses(t *testing.T) {
	var logs bytes.Buffer
	store := membership.NewStoreProvider(func() *sql.DB { return nil }, nil, membership.DefaultMaxPending)
	handler := New(store, rendezvousapi.NewHub(), nil, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	response := request(t, handler, http.MethodGet, "/v1/devices/pending", nil)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "membership administration failed") {
		t.Fatalf("administration store failure = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "database") {
		t.Fatalf("administration store failure disclosed database detail: %s", response.Body.String())
	}
	if !strings.Contains(logs.String(), "membership database is not ready") {
		t.Fatalf("detailed store failure was not logged: %s", logs.String())
	}
}

func TestAdapterAdministrationStrictWireAndTypedCapacity(t *testing.T) {
	store := newTestStore(t)
	handler := New(store, rendezvousapi.NewHub(), nil)
	for _, target := range []string{
		"/v1/adapters/status?adapter_id=%61",
		"/v1/adapters/status?adapter_id=a&adapter_id=b",
		"/v1/adapters/status?adapter_id=a%",
		"/v1/adapters/status?extra=a",
	} {
		response := request(t, handler, http.MethodGet, target, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("malformed adapter query %q = %d: %s", target, response.Code, response.Body.String())
		}
	}
	response := request(t, handler, http.MethodPost, "/v1/adapters/provision?extra=1", AdapterRequest{AdapterID: "query"})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST query = %d: %s", response.Code, response.Body.String())
	}
	forceQuery := httptest.NewRequest(http.MethodGet, "/v1/adapters/status", nil)
	forceQuery.URL.ForceQuery = true
	forceQuery.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	forceResponse := httptest.NewRecorder()
	handler.ServeHTTP(forceResponse, forceQuery)
	if forceResponse.Code != http.StatusBadRequest {
		t.Fatalf("dangling adapter status query = %d: %s", forceResponse.Code, forceResponse.Body.String())
	}
	forcePost := httptest.NewRequest(http.MethodPost, "/v1/adapters/provision", strings.NewReader(`{"adapter_id":"query"}`))
	forcePost.URL.ForceQuery = true
	forcePost.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	forcePostResponse := httptest.NewRecorder()
	handler.ServeHTTP(forcePostResponse, forcePost)
	if forcePostResponse.Code != http.StatusBadRequest {
		t.Fatalf("dangling adapter POST query = %d: %s", forcePostResponse.Code, forcePostResponse.Body.String())
	}
	escapedRequest := httptest.NewRequest(http.MethodGet, "/v1/adapters/status?adapter_id=a", nil)
	escapedRequest.URL.RawPath = "/v1/%61dapters/status"
	escapedRequest.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	escapedResponse := httptest.NewRecorder()
	handler.ServeHTTP(escapedResponse, escapedRequest)
	if escapedResponse.Code != http.StatusBadRequest {
		t.Fatalf("escaped admin path = %d: %s", escapedResponse.Code, escapedResponse.Body.String())
	}

	for index := range membership.MaxAdapters {
		response := request(t, handler, http.MethodPost, "/v1/adapters/provision", AdapterRequest{AdapterID: fmt.Sprintf("capacity-%02d", index)})
		if response.Code != http.StatusOK {
			t.Fatalf("provision adapter %d = %d: %s", index, response.Code, response.Body.String())
		}
	}
	response = request(t, handler, http.MethodPost, "/v1/adapters/provision", AdapterRequest{AdapterID: "overflow"})
	var responseError localipc.Error
	if err := json.Unmarshal(response.Body.Bytes(), &responseError); err != nil || response.Code != http.StatusConflict || responseError.Code != string(membership.CodeAdapterCapacity) || responseError.Message != "adapter capacity reached" {
		t.Fatalf("adapter capacity = %+v, %v, status %d: %s", responseError, err, response.Code, response.Body.String())
	}
}

func TestMaximumListResponsesFitIPCResponseLimit(t *testing.T) {
	maximumTime := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	revokedAt := maximumTime
	members := make([]membership.Member, membership.MaxMemberListLimit)
	for index := range members {
		members[index] = membership.Member{
			DeviceID:  strings.Repeat("z", 43),
			Label:     strings.Repeat("z", 63),
			Revision:  1<<63 - 1,
			CreatedAt: maximumTime,
			RevokedAt: &revokedAt,
		}
	}
	assertEncodedResponseFits(t, "members", ListDevicesResponse{Version: Version, Devices: members, NextCursor: strings.Repeat("z", 84)})

	revision := int64(1<<63 - 1)
	events := make([]membership.AuditEvent, membership.MaxAuditLimit)
	for index := range events {
		events[index] = membership.AuditEvent{
			ID:             1<<63 - 1,
			OccurredAt:     maximumTime,
			ActorType:      "member",
			ActorDeviceID:  strings.Repeat("z", 43),
			Action:         "enrollment.requested",
			TargetDeviceID: strings.Repeat("z", 43),
			TargetLabel:    strings.Repeat("z", 63),
			TargetRevision: &revision,
		}
	}
	assertEncodedResponseFits(t, "audit", events)

	invites := make([]Invite, membership.MaxActiveInvites)
	for index := range invites {
		invites[index] = Invite{
			InviteID: strings.Repeat("f", 32), Label: strings.Repeat("z", 63), IssuerType: "member", IssuerDeviceID: strings.Repeat("z", 43),
			CreatedAt: "9999-12-31T23:59:59Z", ExpiresAt: "9999-12-31T23:59:59Z",
		}
	}
	assertEncodedResponseFits(t, "invites", InviteList{Version: InviteVersion, Invites: invites})
}

func TestMemberPagesRouteUsesStableCursor(t *testing.T) {
	store := newTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	for index := range 2 {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := store.RequestEnrollment(context.Background(), publicKey, fmt.Sprintf("page-%d", index), "192.0.2.1", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Approve(context.Background(), pending.Code, "local", "", now); err != nil {
			t.Fatal(err)
		}
	}
	handler := New(store, rendezvousapi.NewHub(), nil)
	first := request(t, handler, http.MethodGet, "/v1/devices?active=true&limit=1", nil)
	var firstPage ListDevicesResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstPage); err != nil || first.Code != http.StatusOK || len(firstPage.Devices) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first page = %+v, %v, status %d", firstPage, err, first.Code)
	}
	second := request(t, handler, http.MethodGet, "/v1/devices?active=true&limit=1&cursor="+firstPage.NextCursor, nil)
	var secondPage ListDevicesResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondPage); err != nil || second.Code != http.StatusOK || len(secondPage.Devices) != 1 || secondPage.NextCursor != "" || secondPage.Devices[0].DeviceID == firstPage.Devices[0].DeviceID {
		t.Fatalf("second page = %+v, %v, status %d", secondPage, err, second.Code)
	}
	invalid := request(t, handler, http.MethodGet, "/v1/devices?cursor=invalid", nil)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "invalid member list cursor") {
		t.Fatalf("invalid cursor = %d: %s", invalid.Code, invalid.Body.String())
	}
}

func TestServerAdminVersionMismatchIsActionable(t *testing.T) {
	handler := New(newTestStore(t), rendezvousapi.NewHub(), nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	req.Header.Set("X-PX-IPC-Version", "4")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUpgradeRequired || !strings.Contains(response.Body.String(), "administration protocol") || !strings.Contains(response.Body.String(), "upgrade the older") {
		t.Fatalf("version mismatch = %d: %s", response.Code, response.Body.String())
	}
}

func TestStatusIsFixedAndReportsDependencyDegradation(t *testing.T) {
	store := newTestStore(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestEnrollment(context.Background(), publicKey, "status-device", "192.0.2.9", time.Now()); err != nil {
		t.Fatal(err)
	}
	operational := rendezvousapi.NewOperationalState()
	operational.SetHTTPReady(true)
	operational.SetLifecycleReady(true)
	hub := rendezvousapi.NewHub()
	hub.EnrollmentRejected()
	handler := New(store, hub, nil, WithOperationalState(operational))
	response := request(t, handler, http.MethodGet, "/v1/status", nil)
	var status Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || status.Version != Version || !status.Ready || !status.AuthorityAvailable || !status.DatabaseHealthy || !status.HTTPListenerReady || status.PendingEnrollments != 1 || status.SignalingQueue.PerClientCapacity != 32 || status.Counters.EnrollmentRejected != 1 {
		t.Fatalf("status = %+v, HTTP %d", status, response.Code)
	}
	for _, forbidden := range []string{"status-device", "192.0.2.9", "code", "address", "candidate", "credential", "nonce", "path", "error"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("status contains %q: %s", forbidden, response.Body.String())
		}
	}

	degradedStore := membership.NewStoreProvider(func() *sql.DB { return nil }, nil, membership.DefaultMaxPending)
	degraded := New(degradedStore, hub, nil, WithOperationalState(operational))
	response = request(t, degraded, http.MethodGet, "/v1/status", nil)
	status = Status{}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil || response.Code != http.StatusOK || status.Ready || status.DatabaseHealthy || status.PendingEnrollments != 0 {
		t.Fatalf("degraded status = %+v, %v, HTTP %d", status, err, response.Code)
	}
}

func TestStatusSanitizesAndBoundsBuildMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate := versioninfo.Version, versioninfo.Commit, versioninfo.Date
	t.Cleanup(func() {
		versioninfo.Version, versioninfo.Commit, versioninfo.Date = originalVersion, originalCommit, originalDate
	})
	versioninfo.Version = strings.Repeat("v", versioninfo.MaxBuildMetadataBytes+100)
	versioninfo.Commit = "commit\nsecret"
	versioninfo.Date = string([]byte{'2', '0', '2', '6', 0xff})
	operational := rendezvousapi.NewOperationalState()
	operational.SetHTTPReady(true)
	operational.SetLifecycleReady(true)
	response := request(t, New(newTestStore(t), rendezvousapi.NewHub(), nil, WithOperationalState(operational)), http.MethodGet, "/v1/status", nil)
	var status Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Build.Version) != versioninfo.MaxBuildMetadataBytes || status.Build.Commit != "invalid" || status.Build.Date != "invalid" {
		t.Fatalf("sanitized build = %+v", status.Build)
	}
	for _, value := range []string{status.Build.Version, status.Build.Commit, status.Build.Date} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
			t.Fatalf("unsafe build metadata = %q", value)
		}
	}
	if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "\\n") {
		t.Fatalf("unsafe status JSON = %s", response.Body.String())
	}
}

func TestMaximumStatusResponseIsComfortablyBounded(t *testing.T) {
	maximum := uint64(math.MaxUint64)
	status := Status{
		Version: Version,
		Build: BuildStatus{
			Version: strings.Repeat("v", versioninfo.MaxBuildMetadataBytes),
			Commit:  strings.Repeat("c", versioninfo.MaxBuildMetadataBytes),
			Date:    strings.Repeat("d", versioninfo.MaxBuildMetadataBytes),
		},
		Ready: true, AuthorityAvailable: true, DatabaseHealthy: true, HTTPListenerReady: true,
		AuthenticatedConnections: maximum, PendingEnrollments: maximum,
		SignalingQueue: rendezvousapi.QueueSnapshot{Queued: maximum, Capacity: maximum, MaxDepth: maximum, PerClientCapacity: maximum},
		Counters: rendezvousapi.CounterSnapshot{
			EnrollmentRejected: maximum, AuthenticationFailed: maximum, SignalingRejected: maximum,
			QueueOverflow: maximum, AuthenticatedConnected: maximum, AuthenticatedDisconnected: maximum,
		},
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 >= 4<<10 {
		t.Fatalf("maximum status response = %d bytes, want below 4096", len(encoded)+1)
	}
	assertEncodedResponseFits(t, "status", status)
}

func assertEncodedResponseFits(t *testing.T, name string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > localipc.MaxResponseBytes {
		t.Fatalf("maximum %s response = %d bytes, limit %d", name, len(encoded)+1, localipc.MaxResponseBytes)
	}
}

func request(t *testing.T, handler http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, target, &encoded)
	req.Header.Set("X-PX-IPC-Version", strconv.Itoa(Version))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func newTestStore(t *testing.T) *membership.Store {
	t.Helper()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "authority.key")
	publicPath := filepath.Join(dir, "server.pub")
	if err := membership.Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	authority, err := membership.Load(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := database.Config(database.KindServer, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	databaseStore := sqlite.New(cfg)
	if err := databaseStore.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := databaseStore.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return membership.NewStore(databaseStore.DB(), authority, membership.DefaultMaxPending)
}
