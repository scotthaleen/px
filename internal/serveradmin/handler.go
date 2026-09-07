package serveradmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/adapterapi"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/versioninfo"
)

const (
	Version       = 5
	InviteVersion = inviteapi.Version
)

type Handler struct {
	store              *membership.Store
	hub                *rendezvousapi.Hub
	requestShutdown    func()
	operational        *rendezvousapi.OperationalState
	authorityAvailable bool
	logger             *slog.Logger
}

type Status struct {
	Version                  int                           `json:"version"`
	Build                    BuildStatus                   `json:"build"`
	Ready                    bool                          `json:"ready"`
	AuthorityAvailable       bool                          `json:"authority_available"`
	DatabaseHealthy          bool                          `json:"database_healthy"`
	HTTPListenerReady        bool                          `json:"http_listener_ready"`
	AuthenticatedConnections uint64                        `json:"authenticated_connections"`
	PendingEnrollments       uint64                        `json:"pending_enrollments"`
	SignalingQueue           rendezvousapi.QueueSnapshot   `json:"signaling_queue"`
	Counters                 rendezvousapi.CounterSnapshot `json:"counters"`
}

type BuildStatus struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func SanitizeBuildStatus(build BuildStatus) BuildStatus {
	return BuildStatus{
		Version: versioninfo.SanitizeBuildMetadata(build.Version),
		Commit:  versioninfo.SanitizeBuildMetadata(build.Commit),
		Date:    versioninfo.SanitizeBuildMetadata(build.Date),
	}
}

type Option func(*Handler)

func WithOperationalState(state *rendezvousapi.OperationalState) Option {
	return func(handler *Handler) {
		handler.operational = state
	}
}

func WithAuthorityAvailable(available bool) Option {
	return func(handler *Handler) {
		handler.authorityAvailable = available
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(handler *Handler) {
		if logger != nil {
			handler.logger = logger
		}
	}
}

type ApproveRequest struct {
	Code string `json:"code"`
}

type RevokeRequest struct {
	DeviceID         string `json:"device_id"`
	ExpectedRevision int64  `json:"expected_revision"`
}

type AdapterRequest struct {
	AdapterID string `json:"adapter_id"`
}

type AdapterStatus struct {
	Version       int    `json:"version"`
	AdapterID     string `json:"adapter_id"`
	Active        bool   `json:"active"`
	LastCommandID string `json:"last_command_id,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type AdapterProvisioning struct {
	AdapterStatus
	Credential string `json:"credential"`
}

type ListDevicesResponse struct {
	Version    int                 `json:"version"`
	Devices    []membership.Member `json:"devices"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type (
	CreateInviteRequest = inviteapi.CreateRequest
	Invite              = inviteapi.Invite
	InviteCreation      = inviteapi.Creation
	InviteList          = inviteapi.List
	InviteRevocation    = inviteapi.Revocation
)

func New(store *membership.Store, hub *rendezvousapi.Hub, requestShutdown func(), options ...Option) *Handler {
	if requestShutdown == nil {
		requestShutdown = func() {}
	}
	handler := &Handler{store: store, hub: hub, requestShutdown: requestShutdown, authorityAvailable: true, logger: slog.Default()}
	for _, option := range options {
		option(handler)
	}
	return handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-PX-IPC-Version") != strconv.Itoa(Version) {
		writeError(w, http.StatusUpgradeRequired, localipc.ServerAdminVersionMismatchMessage)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, localipc.MaxRequestBytes)
	if strings.HasPrefix(r.URL.Path, "/v1/invites") && !canonicalInviteAdminPath(r) {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite administration path")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/adapters") && !canonicalAdapterAdminPath(r) {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid adapter administration path")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
		h.status(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/pending":
		pending, err := h.store.ListPending(r.Context(), time.Now())
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, pending)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices":
		limit, err := boundedLimit(r, membership.DefaultMemberListLimit, membership.MaxMemberListLimit, "member list")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		activeOnly := false
		if value := r.URL.Query().Get("active"); value != "" {
			if value != "true" {
				writeError(w, http.StatusBadRequest, "active must be true when provided")
				return
			}
			activeOnly = true
		}
		page, err := h.store.ListMembers(r.Context(), limit, r.URL.Query().Get("cursor"), activeOnly)
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, ListDevicesResponse{Version: Version, Devices: page.Members, NextCursor: page.NextCursor})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/devices/inspect":
		member, err := h.store.ActiveMember(r.Context(), r.URL.Query().Get("device_id"))
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/audit":
		limit, err := boundedLimit(r, membership.DefaultAuditLimit, membership.MaxAuditLimit, "audit")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		events, err := h.store.ListAudit(r.Context(), limit)
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, events)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/invites":
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invite request query must be empty")
			return
		}
		var request CreateInviteRequest
		if err := decode(r, &request); err != nil || request.Version != InviteVersion || request.LifetimeSeconds < int64(membership.MinInviteLifetime/time.Second) || request.LifetimeSeconds > int64(membership.MaxInviteLifetime/time.Second) {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite creation request")
			return
		}
		created, err := h.store.CreateInvite(r.Context(), request.Label, time.Duration(request.LifetimeSeconds)*time.Second, "local", "", time.Now())
		if err != nil {
			h.writeInviteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, inviteCreationDTO(created))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/invites":
		if r.URL.RawQuery != "" || r.URL.ForceQuery || requireEmpty(r) != nil {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invite list request must be empty")
			return
		}
		invites, err := h.store.ListInvites(r.Context(), "local", "", time.Now())
		if err != nil {
			h.writeInviteError(w, err)
			return
		}
		result := InviteList{Version: InviteVersion, Invites: make([]Invite, 0, len(invites))}
		for _, invite := range invites {
			result.Invites = append(result.Invites, inviteDTO(invite))
		}
		writeJSON(w, http.StatusOK, result)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/invites/"):
		if r.URL.RawQuery != "" || r.URL.ForceQuery || requireEmpty(r) != nil {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invite revocation request must be empty")
			return
		}
		inviteID := strings.TrimPrefix(r.URL.Path, "/v1/invites/")
		if err := membership.ValidateInviteID(inviteID); err != nil {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite ID")
			return
		}
		invite, err := h.store.RevokeInvite(r.Context(), inviteID, "local", "", time.Now())
		if err != nil {
			h.writeInviteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, InviteRevocation{Version: InviteVersion, State: "revoked", Invite: inviteDTO(invite)})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/adapters/provision":
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "adapter request query must be empty")
			return
		}
		var request AdapterRequest
		if err := decode(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid adapter request")
			return
		}
		provisioning, err := h.store.ProvisionAdapter(r.Context(), request.AdapterID, time.Now())
		if err != nil {
			h.writeAdapterError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, adapterProvisioningDTO(provisioning))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/adapters/status":
		if r.URL.ForceQuery {
			writeError(w, http.StatusBadRequest, "invalid adapter status query")
			return
		}
		query, err := strictAdminQuery(r.URL.RawQuery, "adapter_id")
		if err != nil || query.Get("adapter_id") == "" {
			writeError(w, http.StatusBadRequest, "invalid adapter status query")
			return
		}
		authority, err := h.store.Adapter(r.Context(), query.Get("adapter_id"))
		if err != nil {
			h.writeAdapterError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, adapterStatusDTO(authority))
	case r.Method == http.MethodPost && (r.URL.Path == "/v1/adapters/activate" || r.URL.Path == "/v1/adapters/deactivate"):
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "adapter request query must be empty")
			return
		}
		var request AdapterRequest
		if err := decode(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid adapter request")
			return
		}
		authority, err := h.store.SetAdapterActive(r.Context(), request.AdapterID, r.URL.Path == "/v1/adapters/activate", time.Now())
		if err != nil {
			h.writeAdapterError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, adapterStatusDTO(authority))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/adapters/rotate":
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "adapter request query must be empty")
			return
		}
		var request AdapterRequest
		if err := decode(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid adapter request")
			return
		}
		provisioning, err := h.store.RotateAdapterCredential(r.Context(), request.AdapterID, time.Now())
		if err != nil {
			h.writeAdapterError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, adapterProvisioningDTO(provisioning))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/approve":
		var request ApproveRequest
		if err := decode(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		member, err := h.store.Approve(r.Context(), request.Code, "local", "", time.Now())
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/devices/revoke":
		var request RevokeRequest
		if err := decode(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		member, err := h.store.Revoke(r.Context(), request.DeviceID, request.ExpectedRevision, "local", "", time.Now())
		if err != nil {
			h.writeMembershipError(w, err)
			return
		}
		h.hub.Revoke(member.DeviceID)
		writeJSON(w, http.StatusOK, member)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/shutdown":
		if err := requireEmpty(r); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Stopping bool `json:"stopping"`
		}{Stopping: true})
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		h.requestShutdown()
	default:
		http.NotFound(w, r)
	}
}

func adapterStatusDTO(authority membership.AdapterAuthority) AdapterStatus {
	return AdapterStatus{
		Version: Version, AdapterID: authority.ID, Active: authority.Active,
		LastCommandID: authority.LastCommandID,
		CreatedAt:     authority.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		UpdatedAt:     authority.UpdatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
}

func adapterProvisioningDTO(provisioning membership.AdapterProvisioning) AdapterProvisioning {
	return AdapterProvisioning{AdapterStatus: adapterStatusDTO(provisioning.Authority), Credential: adapterapi.EncodeCredential(provisioning.Credential)}
}

func inviteDTO(invite membership.Invite) Invite {
	return inviteapi.FromMembership(invite)
}

func inviteCreationDTO(created membership.InviteCreation) InviteCreation {
	return inviteapi.CreationFromMembership(created)
}

func (h *Handler) writeInviteError(w http.ResponseWriter, err error) {
	switch {
	case membership.HasCode(err, membership.CodeMembershipInvalid):
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite request")
	case membership.HasCode(err, membership.CodeInviteLabelUnavailable):
		writeErrorCode(w, http.StatusConflict, string(membership.CodeInviteLabelUnavailable), "invite label is unavailable")
	case membership.HasCode(err, membership.CodeInviteCapacity):
		writeErrorCode(w, http.StatusTooManyRequests, string(membership.CodeInviteCapacity), "invite capacity reached")
	case membership.HasCode(err, membership.CodeInviteUnavailable):
		writeErrorCode(w, http.StatusNotFound, string(membership.CodeInviteUnavailable), "invite is unavailable")
	default:
		h.logger.Error("invite administration failed", "reason", err)
		writeErrorCode(w, http.StatusInternalServerError, "internal_error", "invite administration failed")
	}
}

func (h *Handler) writeAdapterError(w http.ResponseWriter, err error) {
	if membership.HasCode(err, membership.CodeAdapterCapacity) {
		writeErrorCode(w, http.StatusConflict, string(membership.CodeAdapterCapacity), "adapter capacity reached")
		return
	}
	message := err.Error()
	if message != "adapter ID is already provisioned" && message != "adapter not found" && message != "invalid adapter ID" {
		h.logger.Error("adapter administration failed", "reason", err)
		writeError(w, http.StatusInternalServerError, "adapter administration failed")
		return
	}
	writeError(w, http.StatusConflict, message)
}

func (h *Handler) writeMembershipError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "membership administration failed"
	switch {
	case membership.HasCode(err, membership.CodeMembershipInvalid):
		status, message = http.StatusBadRequest, err.Error()
	case membership.HasCode(err, membership.CodeMembershipNotFound):
		status, message = http.StatusNotFound, err.Error()
	case membership.HasCode(err, membership.CodeMembershipConflict), membership.HasCode(err, membership.CodeMembershipRevoked):
		status, message = http.StatusConflict, err.Error()
	case membership.HasCode(err, membership.CodeMembershipCapacity), membership.HasCode(err, membership.CodeFactCapacity):
		status, message = http.StatusConflict, "membership capacity reached"
	default:
		h.logger.Error("membership administration failed", "reason", err)
	}
	writeError(w, status, message)
}

func canonicalAdapterAdminPath(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	switch escaped {
	case "/v1/adapters/provision", "/v1/adapters/status", "/v1/adapters/activate", "/v1/adapters/deactivate", "/v1/adapters/rotate":
		return r.URL.Path == escaped
	default:
		return false
	}
}

func canonicalInviteAdminPath(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	if escaped == "/v1/invites" {
		return r.URL.Path == escaped
	}
	if !strings.HasPrefix(escaped, "/v1/invites/") || r.URL.Path != escaped {
		return false
	}
	return membership.ValidateInviteID(strings.TrimPrefix(escaped, "/v1/invites/")) == nil
}

func strictAdminQuery(raw string, allowed ...string) (url.Values, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		want[key] = true
	}
	for key, values := range query {
		if !want[key] || len(values) != 1 || values[0] == "" {
			return nil, errors.New("invalid query parameter")
		}
	}
	for key := range want {
		if len(query[key]) != 1 || query[key][0] == "" {
			return nil, errors.New("missing query parameter")
		}
	}
	if query.Encode() != raw {
		return nil, errors.New("noncanonical query encoding")
	}
	return query, nil
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	snapshot := h.hub.Snapshot()
	result := Status{
		Version:                  Version,
		Build:                    SanitizeBuildStatus(BuildStatus{Version: versioninfo.Version, Commit: versioninfo.Commit, Date: versioninfo.Date}),
		AuthorityAvailable:       h.authorityAvailable,
		HTTPListenerReady:        h.operational.HTTPReady(),
		AuthenticatedConnections: snapshot.AuthenticatedConnections,
		SignalingQueue:           snapshot.Queue,
		Counters:                 snapshot.Counters,
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	count, err := h.store.PendingCount(ctx, time.Now())
	if err == nil {
		result.DatabaseHealthy = true
		result.PendingEnrollments = count
	}
	result.Ready = h.operational.LifecycleReady() && result.AuthorityAvailable && result.DatabaseHealthy && result.HTTPListenerReady
	writeJSON(w, http.StatusOK, result)
}

func boundedLimit(r *http.Request, defaultLimit, maxLimit int, name string) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return defaultLimit, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("%s limit must be a positive integer", name)
	}
	if limit > maxLimit {
		return 0, fmt.Errorf("%s limit must not exceed %d", name, maxLimit)
	}
	return limit, nil
}

func requireEmpty(r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(data) != 0 {
		return errors.New("request body must be empty")
	}
	return nil
}

func decode(r *http.Request, output any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("request has trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, localipc.Error{Status: status, Message: message})
}

func writeErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, localipc.Error{Status: status, Code: code, Message: message})
}
