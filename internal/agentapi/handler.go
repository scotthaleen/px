package agentapi

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/benchmark"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/direct"
	"github.com/scotthaleen/px/internal/getcleanup"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/ipcversion"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/offered"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/probe"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/transfer"
	"github.com/scotthaleen/px/internal/versioninfo"
)

const (
	Version             = ipcversion.Agent
	SummaryVersion      = 3
	CompletionVersion   = 1
	MaxCompletionValues = 64
	maxOperationTimeout = 10 * time.Minute
	streamWriteTimeout  = 5 * time.Second
)

const (
	InviteCodeContextNotFound         = "context_not_found"
	InviteCodeMemberOperationCapacity = "member_operation_capacity"
	InviteCodeContextDisconnected     = "context_disconnected"
	InviteCodeRequestTimeout          = "request_timeout"
	InviteCodeInvalidContext          = "invalid_context"
)

type Status struct {
	Version   int       `json:"version"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

type Summary struct {
	Version   int              `json:"version"`
	Build     Build            `json:"build"`
	StartedAt time.Time        `json:"started_at"`
	Context   *SummaryContext  `json:"context,omitempty"`
	Transfers *transfer.Counts `json:"transfers,omitempty"`
	Status    string           `json:"status"`
	Next      string           `json:"next,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type SummaryContext struct {
	Name                      string `json:"name"`
	State                     string `json:"state"`
	Enabled                   bool   `json:"enabled"`
	OnlinePeers               *int   `json:"online_peers"`
	OfferedRootScope          string `json:"offered_root_scope"`
	OfferedRootAuthorityValid bool   `json:"offered_root_authority_valid"`
	AllowPut                  bool   `json:"allow_put"`
	PutRootAuthorityValid     bool   `json:"put_root_authority_valid"`
}

type Completion struct {
	Version int      `json:"version"`
	Values  []string `json:"values"`
}

type Handler struct {
	startedAt       time.Time
	requestShutdown func()
	logger          *slog.Logger
	operations      chan struct{}
	contexts        *contextstate.Manager
	prepareRetry    func(context.Context, string, string) (transferRetryOperation, error)
	resolveCurrent  func(context.Context, string, string) (put.ResolutionResult, error)
	watchSubscribe  func(context.Context, string) (<-chan contextwatch.Event, func(), error)
	handler         http.Handler
}

type transferRetryOperation interface {
	Run(func(transfer.ResumeEvent)) (transfer.Result, error)
	Close()
}

type ndjsonResponse struct {
	controller *http.ResponseController
	encoder    *json.Encoder
}

func prepareNDJSONResponse(w http.ResponseWriter) (*ndjsonResponse, error) {
	if _, ok := w.(http.Flusher); !ok {
		return nil, http.ErrNotSupported
	}
	controller := http.NewResponseController(w)
	if err := setStreamWriteDeadline(controller); err != nil {
		return nil, err
	}
	return &ndjsonResponse{controller: controller, encoder: json.NewEncoder(w)}, nil
}

func (s *ndjsonResponse) commit(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
}

func (s *ndjsonResponse) write(value any) error {
	if err := setStreamWriteDeadline(s.controller); err != nil {
		return err
	}
	if err := s.encoder.Encode(value); err != nil {
		return err
	}
	return s.controller.Flush()
}

func setStreamWriteDeadline(controller *http.ResponseController) error {
	return controller.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
}

type ConnectionRequest struct {
	SignalURL      string        `json:"signal_url"`
	Session        string        `json:"session"`
	PrivatePath    string        `json:"private_path"`
	PeerPublicPath string        `json:"peer_public_path"`
	Timeout        time.Duration `json:"timeout"`
	AllowLoopback  bool          `json:"allow_loopback"`
	STUNURLs       []string      `json:"stun_urls,omitempty"`
}

type ProbeRequest struct {
	ConnectionRequest
	Offer bool `json:"offer"`
}

type SendFileRequest struct {
	ConnectionRequest
	Source       string `json:"source"`
	Name         string `json:"name,omitempty"`
	MaxFileBytes int64  `json:"max_file_bytes"`
}

type ReceiveFileRequest struct {
	ConnectionRequest
	Inbox        string `json:"inbox"`
	Context      string `json:"context"`
	Sender       string `json:"sender"`
	MaxFileBytes int64  `json:"max_file_bytes"`
}

type TransferResult struct {
	transfer.Result
	LocalAddress  string   `json:"local_address"`
	RemoteAddress string   `json:"remote_address"`
	CandidateType string   `json:"candidate_type"`
	RemoteType    string   `json:"remote_candidate_type"`
	GatheredTypes []string `json:"gathered_candidate_types"`
}

type ListOfferedRequest struct {
	Context string `json:"context"`
	Peer    string `json:"peer"`
	Path    string `json:"path"`
}

type GetOfferedRequest struct {
	Context      string `json:"context"`
	Peer         string `json:"peer"`
	Path         string `json:"path"`
	Destination  string `json:"destination"`
	MaxFileBytes int64  `json:"max_file_bytes"`
}

type ContextSendRequest struct {
	Context      string `json:"context"`
	Peer         string `json:"peer"`
	Source       string `json:"source,omitempty"`
	Name         string `json:"name,omitempty"`
	TransferID   string `json:"transfer_id,omitempty"`
	StdinSpool   bool   `json:"stdin_spool,omitempty"`
	Public       bool   `json:"public,omitempty"`
	Recoverable  bool   `json:"recoverable,omitempty"`
	MaxFileBytes int64  `json:"max_file_bytes"`
}

type ContextPutRequest struct {
	Context      string `json:"context"`
	Peer         string `json:"peer"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Replace      bool   `json:"replace,omitempty"`
	ExpectSHA256 string `json:"expect_sha256,omitempty"`
}

type TransferContextRequest struct {
	Context string `json:"context"`
}

type DeleteTransferRequest struct {
	Context   string `json:"context"`
	Confirmed bool   `json:"confirmed"`
}

type ResolveTransferRequest struct {
	Context       string `json:"context"`
	AcceptCurrent bool   `json:"accept_current"`
	Confirmed     bool   `json:"confirmed"`
}

type RecentPeerRequest struct {
	Context string `json:"context"`
	Peer    string `json:"peer"`
	Limit   int    `json:"limit"`
}

type ClearRecentRequest struct {
	Context   string `json:"context"`
	Confirmed bool   `json:"confirmed"`
}

type InboxPathRequest struct {
	Path string `json:"path"`
}

type InboxMoveRequest struct {
	Path        string `json:"path"`
	Destination string `json:"destination"`
}

type ContextDiagnosticsRequest struct {
	Context string `json:"context,omitempty"`
}

type PeerDiagnosticRequest struct {
	Context string        `json:"context"`
	Peer    string        `json:"peer"`
	Timeout time.Duration `json:"timeout"`
}

type PingRequest struct {
	Version       int    `json:"version"`
	Context       string `json:"context"`
	Peer          string `json:"peer,omitempty"`
	Server        bool   `json:"server,omitempty"`
	ShowAddresses bool   `json:"show_addresses,omitempty"`
	Count         int    `json:"count"`
}

type BenchmarkRequest struct {
	Version  int           `json:"version"`
	Context  string        `json:"context"`
	Peer     string        `json:"peer"`
	Duration time.Duration `json:"duration"`
}

type ApproveDeviceRequest struct {
	Code string `json:"code"`
}

func New(requestShutdown func(), logger *slog.Logger, contextManager *contextstate.Manager) *Handler {
	if requestShutdown == nil {
		requestShutdown = func() {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{
		startedAt:       time.Now().UTC(),
		requestShutdown: requestShutdown,
		logger:          logger,
		operations:      make(chan struct{}, 4),
		contexts:        contextManager,
	}
	if contextManager != nil {
		h.prepareRetry = func(ctx context.Context, contextName, id string) (transferRetryOperation, error) {
			return contextManager.PrepareRetry(ctx, contextName, id)
		}
		h.resolveCurrent = contextManager.ResolveTransferAcceptCurrent
		h.watchSubscribe = func(ctx context.Context, contextName string) (<-chan contextwatch.Event, func(), error) {
			subscription, err := contextManager.Watch(ctx, contextName)
			if err != nil {
				return nil, nil, err
			}
			return subscription.Events, subscription.Close, nil
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", h.status)
	mux.HandleFunc("GET /v1/summary", h.summary)
	mux.HandleFunc("GET /v1/completions", h.completions)
	mux.HandleFunc("POST /v1/shutdown", h.shutdown)
	mux.HandleFunc("POST /v1/probe", h.probe)
	mux.HandleFunc("POST /v1/ping", h.ping)
	mux.HandleFunc("POST /v1/benchmark", h.benchmark)
	mux.HandleFunc("POST /v1/send-file", h.sendFile)
	mux.HandleFunc("POST /v1/receive-file", h.receiveFile)
	mux.HandleFunc("POST /v1/offered/list", h.listOffered)
	mux.HandleFunc("POST /v1/offered/get", h.getOffered)
	mux.HandleFunc("POST /v1/context/send", h.sendContextFile)
	mux.HandleFunc("POST /v1/context/put", h.putContextFile)
	mux.HandleFunc("GET /v1/transfers", h.listTransfers)
	mux.HandleFunc("GET /v1/recent", h.listRecent)
	mux.HandleFunc("POST /v1/recent/peer", h.listPeerRecent)
	mux.HandleFunc("DELETE /v1/recent", h.clearRecent)
	mux.HandleFunc("GET /v1/transfers/{id}", h.showTransfer)
	mux.HandleFunc("POST /v1/transfers/{id}/retry", h.retryTransfer)
	mux.HandleFunc("POST /v1/transfers/{id}/cancel", h.cancelTransfer)
	mux.HandleFunc("POST /v1/transfers/{id}/resolve", h.resolveTransfer)
	mux.HandleFunc("DELETE /v1/transfers/{id}", h.deleteTransfer)
	mux.HandleFunc("POST /v1/doctor/contexts", h.diagnoseContexts)
	mux.HandleFunc("POST /v1/doctor/peer", h.diagnosePeer)
	mux.HandleFunc("POST /v1/contexts/join", h.joinContext)
	mux.HandleFunc("GET /v1/contexts", h.listContexts)
	mux.HandleFunc("GET /v1/contexts/{name}", h.getContext)
	mux.HandleFunc("GET /v1/contexts/{name}/configuration", h.getContextConfiguration)
	mux.HandleFunc("GET /v1/contexts/{name}/inbox", h.listInbox)
	mux.HandleFunc("POST /v1/contexts/{name}/inbox/path", h.inboxPath)
	mux.HandleFunc("POST /v1/contexts/{name}/inbox/move", h.moveInbox)
	mux.HandleFunc("PUT /v1/contexts/{name}/configuration", h.updateContextConfiguration)
	mux.HandleFunc("POST /v1/contexts/{name}/disable", h.disableContext)
	mux.HandleFunc("POST /v1/contexts/{name}/enable", h.enableContext)
	mux.HandleFunc("DELETE /v1/contexts/{name}", h.removeContext)
	mux.HandleFunc("GET /v1/default-context", h.getDefaultContext)
	mux.HandleFunc("POST /v1/default-context", h.setDefaultContext)
	mux.HandleFunc("GET /v1/contexts/{name}/aliases", h.listContextAliases)
	mux.HandleFunc("GET /v1/contexts/{name}/aliases/{alias}", h.getContextAlias)
	mux.HandleFunc("PUT /v1/contexts/{name}/aliases/{alias}", h.setContextAlias)
	mux.HandleFunc("DELETE /v1/contexts/{name}/aliases/{alias}", h.removeContextAlias)
	mux.HandleFunc("POST /v1/contexts/alias", h.setLegacyContextAlias)
	mux.HandleFunc("GET /v1/contexts/{name}/peers", h.listPeers)
	mux.HandleFunc("GET /v1/contexts/{name}/watch", h.watchContext)
	mux.HandleFunc("GET /v1/contexts/{name}/members", h.listMembers)
	mux.HandleFunc("GET /v1/contexts/{name}/devices/pending", h.listPendingDevices)
	mux.HandleFunc("POST /v1/contexts/{name}/devices/approve", h.approveDevice)
	mux.HandleFunc("POST /v1/contexts/{name}/invites", h.createInvite)
	mux.HandleFunc("GET /v1/contexts/{name}/invites", h.listInvites)
	mux.HandleFunc("DELETE /v1/contexts/{name}/invites/{invite_id}", h.revokeInvite)
	h.handler = h.validate(mux)
	return h
}

func (h *Handler) listRecent(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if requireEmptyBody(r) != nil {
		writeError(w, http.StatusBadRequest, "invalid recent observation request")
		return
	}
	query := r.URL.Query()
	if len(query) < 1 || len(query) > 2 || len(query) == 2 && !query.Has("limit") || len(query["context"]) != 1 || query.Get("context") == "" || len(query["limit"]) > 1 {
		writeError(w, http.StatusBadRequest, "invalid recent observation query")
		return
	}
	limit := recent.DefaultLimit
	var err error
	if query.Has("limit") {
		limit, err = strconv.Atoi(query.Get("limit"))
	}
	if err != nil || limit <= 0 || limit > recent.MaxLimit {
		writeError(w, http.StatusBadRequest, "recent limit must be between 1 and 64")
		return
	}
	snapshot, err := h.contexts.Recent(r.Context(), query.Get("context"), limit)
	if err != nil {
		h.writeRecentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) listPeerRecent(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request RecentPeerRequest
	if !decodeRecentRequest(w, r, &request) {
		return
	}
	if request.Context == "" || request.Peer == "" || request.Limit <= 0 || request.Limit > recent.MaxLimit {
		writeError(w, http.StatusBadRequest, "invalid peer recent observation request")
		return
	}
	snapshot, err := h.contexts.RecentPeer(r.Context(), request.Context, request.Peer, request.Limit)
	if err != nil {
		h.writeRecentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) clearRecent(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "invalid recent observation clear request")
		return
	}
	var request ClearRecentRequest
	if !decodeRecentRequest(w, r, &request) {
		return
	}
	if request.Context == "" || !request.Confirmed {
		writeError(w, http.StatusBadRequest, "recent observation clear requires context and confirmation")
		return
	}
	result, err := h.contexts.ClearRecent(r.Context(), request.Context)
	if err != nil {
		h.writeRecentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeRecentRequest(w http.ResponseWriter, r *http.Request, output any) bool {
	data, err := io.ReadAll(r.Body)
	if err != nil || recent.DecodeStrict(data, output) != nil {
		writeError(w, http.StatusBadRequest, "invalid recent observation request")
		return false
	}
	return true
}

func (h *Handler) writeRecentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "context not found")
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, contextstate.ErrPeerUnknown), errors.Is(err, contextstate.ErrPeerOffline), errors.Is(err, contextstate.ErrPeerSelf), errors.Is(err, contextstate.ErrOperationRejected):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "recent observation request timed out")
	default:
		h.logger.Error("recent observation operation failed", "event", "recent.failed", "error", err)
		writeError(w, http.StatusInternalServerError, "recent observation operation failed")
	}
}

func (h *Handler) putContextFile(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request ContextPutRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" || request.Peer == "" || request.Source == "" || request.Destination == "" {
		writeError(w, http.StatusBadRequest, "context, peer, source, and destination are required")
		return
	}
	if request.ExpectSHA256 != "" && !request.Replace {
		writeError(w, http.StatusBadRequest, "expect_sha256 requires replacement mode")
		return
	}
	if err := put.ValidateExpectedSHA256(request.ExpectSHA256); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := transfer.ValidateSource(request.Source, put.MaxFileBytes); err != nil {
		writeError(w, http.StatusUnprocessableEntity, publicTransferError(err))
		return
	}
	if err := put.ValidateDestination(request.Destination); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	stream, err := prepareNDJSONResponse(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent stream transport is unavailable")
		return
	}
	operationContext, cancelOperation := context.WithCancel(r.Context())
	defer cancelOperation()
	stream.commit(w)
	terminal := false
	transferID := ""
	emit := func(event put.Event) {
		if operationContext.Err() != nil {
			return
		}
		if event.TransferID != "" {
			transferID = event.TransferID
		}
		if event.State == "committed" || event.State == "failed" {
			terminal = true
		}
		if err := stream.write(event); err != nil {
			cancelOperation()
		}
	}
	_, err = h.contexts.PutRemote(operationContext, request.Context, request.Peer, request.Source, request.Destination, request.Replace, request.ExpectSHA256, emit)
	if err != nil && !terminal && operationContext.Err() == nil {
		emit(put.Event{Version: put.EventVersion, State: "failed", TransferID: transferID, Error: publicTransferError(err)})
	}
}

func (h *Handler) listInbox(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if requireEmptyBody(r) != nil {
		writeError(w, http.StatusBadRequest, "invalid inbox request")
		return
	}
	query := r.URL.Query()
	if len(query) > 1 || len(query) == 1 && (!query.Has("sender") || len(query["sender"]) != 1) {
		writeError(w, http.StatusBadRequest, "invalid inbox query")
		return
	}
	entries, err := h.contexts.Inbox(r.Context(), r.PathValue("name"), query.Get("sender"))
	if err != nil {
		h.writeInboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handler) inboxPath(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "invalid inbox path request")
		return
	}
	var request InboxPathRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Path == "" {
		writeError(w, http.StatusBadRequest, "inbox path is required")
		return
	}
	result, err := h.contexts.InboxPath(r.Context(), r.PathValue("name"), request.Path)
	if err != nil {
		h.writeInboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) moveInbox(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "invalid inbox move request")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request InboxMoveRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Path == "" || request.Destination == "" {
		writeError(w, http.StatusBadRequest, "inbox path and destination are required")
		return
	}
	result, err := h.contexts.MoveInbox(r.Context(), r.PathValue("name"), request.Path, request.Destination)
	if err != nil {
		h.writeInboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writeInboxError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, inbox.ErrInvalidPath), errors.Is(err, inbox.ErrInvalidDestination), errors.Is(err, inbox.ErrUnavailable), errors.Is(err, inbox.ErrEntryChanged), errors.Is(err, getcleanup.ErrUnsafeParent), errors.Is(err, getcleanup.ErrUnsafeState):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, getcleanup.ErrDestinationExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, getcleanup.ErrCapacity):
		writeError(w, http.StatusInsufficientStorage, err.Error())
	default:
		h.writeContextOperationError(w, err)
	}
}

func (h *Handler) listPeers(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	peers, err := h.contexts.Peers(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (h *Handler) watchContext(w http.ResponseWriter, r *http.Request) {
	if h.watchSubscribe == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || requireEmptyBody(r) != nil {
		writeError(w, http.StatusBadRequest, "invalid context watch request")
		return
	}
	events, unsubscribe, err := h.watchSubscribe(r.Context(), r.PathValue("name"))
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, "context not found")
		case errors.Is(err, contextwatch.ErrSubscriberCapacity):
			writeError(w, http.StatusTooManyRequests, err.Error())
		default:
			writeError(w, http.StatusServiceUnavailable, "context watch is unavailable")
		}
		return
	}
	defer unsubscribe()
	initial, ok := <-events
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "context watch is unavailable")
		return
	}
	stream, err := prepareNDJSONResponse(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "context watch transport is unavailable")
		return
	}
	stream.commit(w)
	if err := stream.write(initial); err != nil {
		h.logger.DebugContext(r.Context(), "context watch stream ended", "reason", err)
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-events:
			if !open {
				return
			}
			if err := stream.write(event); err != nil {
				h.logger.DebugContext(r.Context(), "context watch stream ended", "reason", err)
				return
			}
		}
	}
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	members, err := h.contexts.Members(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

func (h *Handler) listPendingDevices(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	pending, err := h.contexts.PendingDevices(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pending)
}

func (h *Handler) approveDevice(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request ApproveDeviceRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	member, err := h.contexts.ApproveDevice(r.Context(), r.PathValue("name"), request.Code)
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (h *Handler) createInvite(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite request")
		return
	}
	var request inviteapi.CreateRequest
	if !decodeInviteRequest(w, r, &request) {
		return
	}
	if request.Version != inviteapi.Version || request.LifetimeSeconds < int64(membership.MinInviteLifetime/time.Second) || request.LifetimeSeconds > int64(membership.MaxInviteLifetime/time.Second) {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite request")
		return
	}
	result, err := h.contexts.CreateInvite(r.Context(), r.PathValue("name"), request.Label, time.Duration(request.LifetimeSeconds)*time.Second)
	if err != nil {
		h.writeInviteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeInviteRequest(w http.ResponseWriter, r *http.Request, output any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite request")
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite request")
		return false
	}
	return true
}

func (h *Handler) listInvites(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || requireEmptyBody(r) != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite list request")
		return
	}
	result, err := h.contexts.ListInvites(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeInviteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || requireEmptyBody(r) != nil || membership.ValidateInviteID(r.PathValue("invite_id")) != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid invite revocation request")
		return
	}
	result, err := h.contexts.RevokeInvite(r.Context(), r.PathValue("name"), r.PathValue("invite_id"))
	if err != nil {
		h.writeInviteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writeInviteError(w http.ResponseWriter, err error) {
	var inviteErr *contextstate.InviteError
	switch {
	case errors.As(err, &inviteErr):
		switch inviteErr.Code {
		case "invalid_request":
			writeErrorCode(w, http.StatusBadRequest, inviteErr.Code, inviteErr.Message)
		case string(membership.CodeInviteLabelUnavailable):
			writeErrorCode(w, http.StatusConflict, inviteErr.Code, inviteErr.Message)
		case string(membership.CodeInviteCapacity):
			writeErrorCode(w, http.StatusTooManyRequests, inviteErr.Code, inviteErr.Message)
		case string(membership.CodeInviteUnavailable):
			writeErrorCode(w, http.StatusNotFound, inviteErr.Code, inviteErr.Message)
		default:
			writeError(w, http.StatusInternalServerError, "internal context operation failed")
		}
	case errors.Is(err, contextstate.ErrInviteCreateOutcomeUnknown), errors.Is(err, contextstate.ErrInviteRevokeOutcomeUnknown):
		writeErrorCode(w, http.StatusBadGateway, "outcome_unknown", err.Error())
	case errors.Is(err, sql.ErrNoRows):
		writeErrorCode(w, http.StatusNotFound, InviteCodeContextNotFound, "context not found")
	case errors.Is(err, contextstate.ErrMemberOperationCapacity):
		writeErrorCode(w, http.StatusTooManyRequests, InviteCodeMemberOperationCapacity, err.Error())
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeErrorCode(w, http.StatusServiceUnavailable, InviteCodeContextDisconnected, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeErrorCode(w, http.StatusRequestTimeout, InviteCodeRequestTimeout, err.Error())
	case errors.Is(err, contextstate.ErrInvalidContextState), errors.Is(err, contextstate.ErrOperationRejected):
		writeErrorCode(w, http.StatusUnprocessableEntity, InviteCodeInvalidContext, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal context operation failed")
	}
}

func (h *Handler) writeContextOperationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "context not found")
	case errors.Is(err, contextstate.ErrMemberOperationCapacity):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, contextstate.ErrContextActive), errors.Is(err, contextstate.ErrContextAuthorityBlocked):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, contextstate.ErrContextCapacity), errors.Is(err, contextstate.ErrAliasCapacity), errors.Is(err, contextstate.ErrContextProjection):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, err.Error())
	case errors.Is(err, contextstate.ErrApprovalOutcomeUnknown):
		writeError(w, http.StatusBadGateway, err.Error())
	case errors.Is(err, contextstate.ErrAliasNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, contextstate.ErrInvalidConfiguration), errors.Is(err, contextstate.ErrInvalidAlias), errors.Is(err, contextstate.ErrInvalidContextState),
		errors.Is(err, contextstate.ErrOperationRejected), errors.Is(err, contextstate.ErrPeerUnknown), errors.Is(err, inbox.ErrInvalidSender),
		errors.Is(err, contextstate.ErrPeerOffline), errors.Is(err, contextstate.ErrPeerSelf):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal context operation failed")
	}
}

func (h *Handler) sendContextFile(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request ContextSendRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" || request.Peer == "" || (request.TransferID == "" && request.Source == "") || (request.TransferID != "" && request.Source != "") {
		writeError(w, http.StatusBadRequest, "context, peer, and exactly one source or transfer ID are required")
		return
	}
	if request.Public && request.TransferID != "" {
		writeError(w, http.StatusBadRequest, "public visibility is persisted and cannot be changed during retry")
		return
	}
	if request.MaxFileBytes <= 0 || request.MaxFileBytes > transfer.DefaultMaxFileBytes {
		writeError(w, http.StatusBadRequest, "max file bytes must be within the agent limit")
		return
	}
	if request.Source != "" {
		if err := transfer.ValidateSource(request.Source, request.MaxFileBytes); err != nil {
			var sourceErr *transfer.SourceError
			if errors.As(err, &sourceErr) {
				writeErrorCode(w, http.StatusUnprocessableEntity, sourceErr.Code, sourceErr.Message)
			} else {
				writeError(w, http.StatusInternalServerError, "internal transfer operation failed")
			}
			return
		}
	}
	stream, err := prepareNDJSONResponse(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent stream transport is unavailable")
		return
	}
	operationContext, cancelOperation := context.WithCancel(r.Context())
	defer cancelOperation()
	stream.commit(w)
	terminal := false
	transferID := request.TransferID
	emit := func(event transfer.ResumeEvent) {
		if operationContext.Err() != nil {
			return
		}
		if event.TransferID != "" {
			transferID = event.TransferID
		}
		if event.State == "committed" || event.State == "rejected" || event.State == "failed" {
			terminal = true
		}
		if err := stream.write(event); err != nil {
			cancelOperation()
		}
	}
	_, err = h.contexts.SendRemote(operationContext, request.Context, request.Peer, request.Source, request.Name, request.TransferID, request.StdinSpool, request.Public, request.Recoverable || request.TransferID != "", request.MaxFileBytes, emit)
	if err != nil && !terminal && operationContext.Err() == nil {
		event := transfer.ResumeEvent{Version: transfer.ResumeEventVersion, State: "failed", TransferID: transferID, Error: publicTransferError(err)}
		var sourceErr *transfer.SourceError
		if errors.As(err, &sourceErr) {
			event.ErrorCode = sourceErr.Code
		} else if errors.Is(err, transfer.ErrFastOutcomeUnknown) {
			event.ErrorCode = transfer.FastOutcomeUnknownCode
			event.Outcome = transfer.FastOutcomeUnknownCode
		}
		emit(event)
	}
}

func (h *Handler) listTransfers(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	limit := transfer.DefaultInventoryLimit
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "transfer limit must be an integer")
			return
		}
		limit = parsed
	}
	if limit <= 0 || limit > transfer.MaxInventoryLimit {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("transfer limit must be between 1 and %d", transfer.MaxInventoryLimit))
		return
	}
	contextName := r.URL.Query().Get("context")
	if contextName == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	inventory, err := h.contexts.ListTransfers(r.Context(), contextName, limit)
	if err != nil {
		h.writeTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (h *Handler) showTransfer(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	contextName := r.URL.Query().Get("context")
	if contextName == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	item, err := h.contexts.ShowTransfer(r.Context(), contextName, r.PathValue("id"))
	if err != nil {
		h.writeTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) retryTransfer(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request TransferContextRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	operationContext, cancelOperation := context.WithCancel(r.Context())
	defer cancelOperation()
	prepared, err := h.prepareRetry(operationContext, request.Context, r.PathValue("id"))
	if err != nil {
		h.writeTransferError(w, err)
		return
	}
	defer prepared.Close()
	stream, err := prepareNDJSONResponse(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent stream transport is unavailable")
		return
	}
	stream.commit(w)
	terminal := false
	emit := func(event transfer.ResumeEvent) {
		if operationContext.Err() != nil {
			return
		}
		if event.State == "committed" || event.State == "rejected" || event.State == "failed" {
			terminal = true
		}
		if err := stream.write(event); err != nil {
			cancelOperation()
		}
	}
	result, err := prepared.Run(emit)
	if err != nil && !terminal && operationContext.Err() == nil {
		event := transfer.ResumeEvent{Version: transfer.ResumeEventVersion, State: "failed", TransferID: r.PathValue("id"), Error: publicTransferError(err)}
		var sourceErr *transfer.SourceError
		if errors.As(err, &sourceErr) {
			event.ErrorCode = sourceErr.Code
		}
		emit(event)
		return
	}
	_ = result
}

func (h *Handler) cancelTransfer(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	contextName := r.URL.Query().Get("context")
	if contextName == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	if err := h.contexts.CancelTransfer(r.Context(), contextName, r.PathValue("id")); err != nil {
		h.writeTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "state": "cancel_requested"})
}

func (h *Handler) deleteTransfer(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request DeleteTransferRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	if !request.Confirmed {
		writeError(w, http.StatusBadRequest, "transfer deletion requires explicit confirmation")
		return
	}
	item, err := h.contexts.DeleteTransfer(r.Context(), request.Context, r.PathValue("id"))
	if err != nil {
		h.writeTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) resolveTransfer(w http.ResponseWriter, r *http.Request) {
	if h.resolveCurrent == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request ResolveTransferRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" {
		writeError(w, http.StatusBadRequest, transfer.ErrTransferContextRequired.Error())
		return
	}
	if !request.AcceptCurrent || !request.Confirmed {
		writeError(w, http.StatusBadRequest, "accept-current resolution requires explicit action and confirmation")
		return
	}
	result, err := h.resolveCurrent(r.Context(), request.Context, r.PathValue("id"))
	if err != nil {
		h.writeTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writeTransferError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, transfer.ErrTransferContextRequired):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, sql.ErrNoRows), errors.Is(err, transfer.ErrTransferNotFound), errors.Is(err, put.ErrNotFound):
		writeError(w, http.StatusNotFound, "transfer or context not found")
	case errors.Is(err, transfer.ErrTransferNotActive), errors.Is(err, transfer.ErrTransferActive), errors.Is(err, transfer.ErrTransferAmbiguous), errors.Is(err, transfer.ErrTransferNotDeletable), errors.Is(err, transfer.ErrTransferContextMismatch), errors.Is(err, transfer.ErrTransferPeerMismatch), errors.Is(err, contextstate.ErrContextActive), errors.Is(err, put.ErrActive):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, put.ErrNotResolvable):
		writeError(w, http.StatusConflict, "transfer is not eligible for accept-current resolution")
	case errors.Is(err, put.ErrResolutionUnsafe):
		writeError(w, http.StatusConflict, "current destination or recovery artifacts cannot be verified safely")
	case errors.Is(err, put.ErrAuthority):
		writeError(w, http.StatusUnprocessableEntity, "put authority is unavailable")
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, contextstate.ErrInvalidContextState), errors.Is(err, contextstate.ErrOperationRejected), errors.Is(err, contextstate.ErrPeerUnknown), errors.Is(err, contextstate.ErrPeerOffline), errors.Is(err, contextstate.ErrPeerSelf):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal transfer operation failed")
	}
}

func publicTransferError(err error) string {
	if err == nil {
		return ""
	}
	var sourceErr *transfer.SourceError
	if errors.As(err, &sourceErr) {
		return sourceErr.Message
	}
	message := err.Error()
	if len(message) > 256 || strings.ContainsAny(message, `/\\`) {
		return "transfer operation failed"
	}
	return message
}

func (h *Handler) diagnoseContexts(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request ContextDiagnosticsRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	writeJSON(w, http.StatusOK, h.contexts.DiagnoseContexts(r.Context(), request.Context))
}

func (h *Handler) diagnosePeer(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request PeerDiagnosticRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Timeout <= 0 || request.Timeout > 30*time.Second {
		writeError(w, http.StatusBadRequest, "peer diagnostic timeout must be positive and at most 30 seconds")
		return
	}
	result, err := h.contexts.ProbeRemote(r.Context(), request.Context, request.Peer, request.Timeout)
	check := diagnostics.Check{ID: "peer.direct", Layer: "peer", Context: request.Context, Peer: request.Peer, Status: diagnostics.Pass, Summary: "authenticated direct peer probe succeeded"}
	if err != nil {
		check.Status, check.Summary = diagnostics.Fail, "authenticated direct peer probe failed"
	} else {
		relayUsed := result.RelayUsed
		check.SetupDuration = result.SetupDuration
		check.LocalCandidateType = result.CandidateType
		check.RemoteCandidateType = result.RemoteType
		check.LocalAddress = result.LocalAddress
		check.RemoteAddress = result.RemoteAddress
		check.GatheredTypes = result.GatheredTypes
		check.RelayUsed = &relayUsed
	}
	writeJSON(w, http.StatusOK, check)
}

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request PingRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Version != ping.Version || request.Context == "" || ping.ValidateCount(request.Count) != nil || request.Server == (request.Peer != "") || request.Server && request.ShowAddresses {
		writeError(w, http.StatusBadRequest, "ping requires a context, count from 1 through 10, and exactly one peer or server target")
		return
	}
	operationContext, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var (
		result ping.Result
		err    error
	)
	if request.Server {
		result, err = h.contexts.PingServer(operationContext, request.Context, request.Count)
	} else {
		result, err = h.contexts.PingPeer(operationContext, request.Context, request.Peer, request.Count, request.ShowAddresses)
	}
	if err != nil {
		h.writePingError(w, err)
		return
	}
	hasLocalAddress := result.SelectedLocalAddress != ""
	hasRemoteAddress := result.SelectedRemoteAddress != ""
	if hasLocalAddress != hasRemoteAddress || request.ShowAddresses != (hasLocalAddress && hasRemoteAddress) {
		h.logger.Error("ping operation returned invalid address fields", "event", "ping.invalid_result")
		writeError(w, http.StatusInternalServerError, "ping operation returned an invalid result")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writePingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "context not found")
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeError(w, http.StatusServiceUnavailable, "selected context is disconnected")
	case errors.Is(err, contextstate.ErrMemberOperationCapacity):
		writeError(w, http.StatusTooManyRequests, "context operation capacity reached")
	case errors.Is(err, contextstate.ErrPeerUnknown), errors.Is(err, contextstate.ErrPeerOffline), errors.Is(err, contextstate.ErrPeerSelf), errors.Is(err, contextstate.ErrOperationRejected):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "ping operation timed out or was canceled")
	default:
		h.logger.Error("ping operation failed", "event", "ping.failed")
		writeError(w, http.StatusUnprocessableEntity, "ping operation failed")
	}
}

func (h *Handler) benchmark(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request BenchmarkRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Version != benchmark.Version || request.Context == "" || request.Peer == "" || benchmark.ValidateDuration(request.Duration) != nil {
		writeError(w, http.StatusBadRequest, "benchmark requires a context, peer, and duration from 1s through 30s")
		return
	}
	operationContext, cancel := context.WithTimeout(r.Context(), 30*time.Second+2*request.Duration)
	defer cancel()
	result, err := h.contexts.BenchmarkPeer(operationContext, request.Context, request.Peer, request.Duration)
	if err != nil {
		h.writeBenchmarkError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writeBenchmarkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "context not found")
	case errors.Is(err, contextstate.ErrContextDisconnected):
		writeError(w, http.StatusServiceUnavailable, "selected context is disconnected")
	case errors.Is(err, contextstate.ErrMemberOperationCapacity):
		writeError(w, http.StatusTooManyRequests, "context operation capacity reached")
	case errors.Is(err, contextstate.ErrPeerUnknown), errors.Is(err, contextstate.ErrPeerOffline), errors.Is(err, contextstate.ErrPeerSelf), errors.Is(err, contextstate.ErrOperationRejected):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "benchmark operation timed out or was canceled")
	default:
		h.logger.Error("benchmark operation failed", "event", "benchmark.failed")
		writeError(w, http.StatusUnprocessableEntity, "benchmark operation failed")
	}
}

func (h *Handler) listOffered(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request ListOfferedRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	entries, err := h.contexts.ListRemote(r.Context(), request.Context, request.Peer, request.Path)
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *Handler) getOffered(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request GetOfferedRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.MaxFileBytes <= 0 || request.MaxFileBytes > offered.DefaultMaxFileBytes {
		writeError(w, http.StatusBadRequest, "max file bytes must be within the agent limit")
		return
	}
	stream, err := prepareNDJSONResponse(w)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent stream transport is unavailable")
		return
	}
	operationContext, cancelOperation := context.WithCancel(r.Context())
	defer cancelOperation()
	stream.commit(w)
	terminal := false
	emit := func(event offered.GetEvent) {
		if operationContext.Err() != nil {
			return
		}
		if event.State == "committed" || event.State == "failed" {
			terminal = true
		}
		if err := stream.write(event); err != nil {
			cancelOperation()
		}
	}
	emit(offered.GetEvent{Version: offered.GetEventVersion, State: "submitted"})
	if operationContext.Err() != nil {
		return
	}
	_, err = h.contexts.GetRemoteProgress(operationContext, request.Context, request.Peer, request.Path, request.Destination, request.MaxFileBytes, emit)
	if err != nil && !terminal && operationContext.Err() == nil {
		emit(offered.GetEvent{Version: offered.GetEventVersion, State: "failed", Error: publicTransferError(err)})
	}
}

type defaultContextRequest struct {
	Name string `json:"name"`
}

type aliasRequest struct {
	Context string `json:"context,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Target  string `json:"target"`
}

type aliasTargetRequest struct {
	Target string `json:"target"`
}

func (h *Handler) joinContext(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request contextstate.JoinRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	state, err := h.contexts.Join(r.Context(), request)
	if err != nil {
		if errors.Is(err, contextstate.ErrContextCapacity) || errors.Is(err, contextstate.ErrContextProjection) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *Handler) listContexts(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	states, err := h.contexts.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, states)
}

func (h *Handler) getContext(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	state, err := h.contexts.Get(r.Context(), r.PathValue("name"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "context not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *Handler) getContextConfiguration(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	configuration, err := h.contexts.Configuration(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeContextConfigurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, configuration)
}

func (h *Handler) updateContextConfiguration(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request contextstate.UpdateRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	configuration, err := h.contexts.Update(r.Context(), r.PathValue("name"), request)
	if err != nil {
		h.writeContextConfigurationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, configuration)
}

func (h *Handler) writeContextConfigurationError(w http.ResponseWriter, err error) {
	h.writeContextOperationError(w, err)
}

func (h *Handler) disableContext(w http.ResponseWriter, r *http.Request) {
	h.setContextEnabled(w, r, false)
}

func (h *Handler) enableContext(w http.ResponseWriter, r *http.Request) {
	h.setContextEnabled(w, r, true)
}

func (h *Handler) setContextEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var (
		state contextstate.State
		err   error
	)
	if enabled {
		state, err = h.contexts.Enable(r.Context(), r.PathValue("name"))
	} else {
		state, err = h.contexts.Disable(r.Context(), r.PathValue("name"))
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "context not found")
		return
	}
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *Handler) removeContext(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PathValue("name")
	if err := h.contexts.Remove(r.Context(), name); err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, defaultContextRequest{Name: name})
}

func (h *Handler) getDefaultContext(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	name, err := h.contexts.Default(r.Context())
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, defaultContextRequest{Name: name})
}

func (h *Handler) setDefaultContext(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request defaultContextRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if err := h.contexts.SetDefault(r.Context(), request.Name); err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (h *Handler) setContextAlias(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request aliasTargetRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if err := h.contexts.SetAlias(r.Context(), r.PathValue("name"), r.PathValue("alias"), request.Target); err != nil {
		h.writeAliasError(w, err)
		return
	}
	value, err := h.contexts.GetAlias(r.Context(), r.PathValue("name"), r.PathValue("alias"))
	if err != nil {
		h.writeAliasError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (h *Handler) setLegacyContextAlias(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	var request aliasRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.Context == "" || request.Alias == "" {
		writeError(w, http.StatusBadRequest, "context and alias are required")
		return
	}
	if err := h.contexts.SetAlias(r.Context(), request.Context, request.Alias, request.Target); err != nil {
		h.writeAliasError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (h *Handler) listContextAliases(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	values, err := h.contexts.ListAliases(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeAliasError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (h *Handler) getContextAlias(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	value, err := h.contexts.GetAlias(r.Context(), r.PathValue("name"), r.PathValue("alias"))
	if err != nil {
		h.writeAliasError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (h *Handler) removeContextAlias(w http.ResponseWriter, r *http.Request) {
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	value, err := h.contexts.RemoveAlias(r.Context(), r.PathValue("name"), r.PathValue("alias"))
	if err != nil {
		h.writeAliasError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (h *Handler) writeAliasError(w http.ResponseWriter, err error) {
	h.writeContextOperationError(w, err)
}

func (h *Handler) probe(w http.ResponseWriter, r *http.Request) {
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request ProbeRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if err := validateConnection(request.ConnectionRequest); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	privateKey, peerKey, err := loadKeys(request.ConnectionRequest)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	result, err := probe.Run(r.Context(), probe.Config{
		SignalURL:     request.SignalURL,
		Session:       request.Session,
		PrivateKey:    privateKey,
		PeerKey:       peerKey,
		Offer:         request.Offer,
		Timeout:       request.Timeout,
		AllowLoopback: request.AllowLoopback,
		STUNURLs:      request.STUNURLs,
		Logger:        h.logger,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) sendFile(w http.ResponseWriter, r *http.Request) {
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request SendFileRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.MaxFileBytes <= 0 || request.MaxFileBytes > transfer.DefaultMaxFileBytes {
		writeError(w, http.StatusBadRequest, "max file bytes must be within the agent limit")
		return
	}
	session, cancel, err := h.connect(r.Context(), request.ConnectionRequest, true)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer cancel()
	defer session.Close()
	result, err := transfer.Send(session.Context(), transfer.NewDirectChannel(session), transfer.SendConfig{
		Source:       request.Source,
		Name:         request.Name,
		MaxFileBytes: request.MaxFileBytes,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, transferResult(result, session))
}

func (h *Handler) receiveFile(w http.ResponseWriter, r *http.Request) {
	if !h.beginOperation(w) {
		return
	}
	defer h.endOperation()
	var request ReceiveFileRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if request.MaxFileBytes <= 0 || request.MaxFileBytes > transfer.DefaultMaxFileBytes {
		writeError(w, http.StatusBadRequest, "max file bytes must be within the agent limit")
		return
	}
	if err := os.MkdirAll(request.Inbox, 0o700); err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("create inbox root: %v", err))
		return
	}
	session, cancel, err := h.connect(r.Context(), request.ConnectionRequest, false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	defer cancel()
	defer session.Close()
	result, err := transfer.Receive(session.Context(), transfer.NewDirectChannel(session), transfer.ReceiveConfig{
		InboxRoot:    request.Inbox,
		Context:      request.Context,
		Sender:       request.Sender,
		MaxFileBytes: request.MaxFileBytes,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, transferResult(result, session))
}

func (h *Handler) beginOperation(w http.ResponseWriter) bool {
	select {
	case h.operations <- struct{}{}:
		return true
	default:
		writeError(w, http.StatusTooManyRequests, "agent operation capacity reached")
		return false
	}
}

func (h *Handler) endOperation() {
	<-h.operations
}

func decodeRequest(w http.ResponseWriter, r *http.Request, output any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request has trailing data")
		return false
	}
	return true
}

func (h *Handler) connect(parent context.Context, request ConnectionRequest, offer bool) (*direct.Session, context.CancelFunc, error) {
	if err := validateConnection(request); err != nil {
		return nil, nil, err
	}
	privateKey, peerKey, err := loadKeys(request)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, request.Timeout)
	session, err := direct.Connect(ctx, direct.Config{
		SignalURL:        request.SignalURL,
		Session:          request.Session,
		PrivateKey:       privateKey,
		PeerKey:          peerKey,
		Offer:            offer,
		AllowLoopback:    request.AllowLoopback,
		STUNURLs:         request.STUNURLs,
		ChannelLabel:     "px-transfer",
		ChannelProtocol:  transfer.Protocol,
		MaxMessageBytes:  transfer.MaxMessageBytes,
		MessageQueue:     transfer.DefaultQueueDepth,
		MaxBufferedBytes: transfer.DefaultBufferedBytes,
		Logger:           h.logger,
	})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return session, cancel, nil
}

func validateConnection(request ConnectionRequest) error {
	if request.SignalURL == "" || request.Session == "" || request.PrivatePath == "" || request.PeerPublicPath == "" {
		return errors.New("signal URL, session, private path, and peer public path are required")
	}
	if request.Timeout <= 0 || request.Timeout > maxOperationTimeout {
		return errors.New("operation timeout must be positive and at most 10 minutes")
	}
	return nil
}

func loadKeys(request ConnectionRequest) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateKey, err := identity.LoadPrivate(request.PrivatePath)
	if err != nil {
		return nil, nil, err
	}
	peerKey, err := identity.LoadPublic(request.PeerPublicPath)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, peerKey, nil
}

func transferResult(result transfer.Result, session *direct.Session) TransferResult {
	pair := session.CandidatePair()
	return TransferResult{
		Result:        result,
		LocalAddress:  pair.LocalAddress,
		RemoteAddress: pair.RemoteAddress,
		CandidateType: pair.LocalType,
		RemoteType:    pair.RemoteType,
		GatheredTypes: session.GatheredCandidateTypes(),
	}
}

func (h *Handler) shutdown(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(r); err != nil {
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
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *Handler) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PX-IPC-Version") != strconv.Itoa(Version) {
			writeError(w, http.StatusUpgradeRequired, localipc.AgentVersionMismatchMessage)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, localipc.MaxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Status{Version: Version, PID: os.Getpid(), StartedAt: h.startedAt})
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	snapshot, err := h.contexts.StatusSnapshot(r.Context(), r.URL.Query().Get("context"))
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summaryFromSnapshot(h.startedAt, snapshot))
}

func summaryFromSnapshot(startedAt time.Time, snapshot contextstate.StatusSnapshot) Summary {
	result := Summary{
		Version: SummaryVersion,
		Build: Build{
			Version: versioninfo.SanitizeBuildMetadata(versioninfo.Version),
			Commit:  versioninfo.SanitizeBuildMetadata(versioninfo.Commit),
			Date:    versioninfo.SanitizeBuildMetadata(versioninfo.Date),
		},
		StartedAt: startedAt,
		Transfers: snapshot.Transfers,
		Status:    "ok",
	}
	if snapshot.Context != nil {
		result.Context = &SummaryContext{Name: snapshot.Context.Name, State: snapshot.Context.State, Enabled: snapshot.Context.Enabled, OnlinePeers: snapshot.Context.OnlinePeers, OfferedRootScope: snapshot.Context.OfferedRootScope, OfferedRootAuthorityValid: snapshot.Context.OfferedRootAuthorityValid, AllowPut: snapshot.Context.AllowPut, PutRootAuthorityValid: snapshot.Context.PutRootAuthorityValid}
	}
	if result.Context != nil {
		if !result.Context.OfferedRootAuthorityValid {
			result.Warnings = append(result.Warnings, "FAILURE: offered-root authority is inconsistent; offered-root and incoming-send service is blocked until explicit repair")
		} else if result.Context.OfferedRootScope == contextstate.OfferedRootScopeFilesystemRoot {
			result.Warnings = append(result.Warnings, "DANGER: this context offers the filesystem root to every authenticated member")
		}
		if result.Context.AllowPut && !result.Context.PutRootAuthorityValid {
			result.Warnings = append(result.Warnings, "FAILURE: put authority is enabled but invalid; incoming put is blocked")
		} else if result.Context.AllowPut {
			result.Warnings = append(result.Warnings, "WARNING: every authenticated context member may create files and request supported replacement beneath the configured put root")
		}
	}
	if result.Context == nil || !result.Context.Enabled || result.Context.State != "connected" || result.Context.OnlinePeers == nil || !result.Context.OfferedRootAuthorityValid || result.Context.AllowPut && !result.Context.PutRootAuthorityValid {
		result.Status = "degraded"
		result.Next = "px doctor"
	}
	return result
}

func (h *Handler) completions(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.contexts == nil {
		writeError(w, http.StatusServiceUnavailable, "context manager is unavailable")
		return
	}
	prefix := r.URL.Query().Get("prefix")
	if !validCompletionPrefix(prefix) {
		writeError(w, http.StatusBadRequest, "completion prefix is invalid")
		return
	}
	kind := r.URL.Query().Get("kind")
	contextName := r.URL.Query().Get("context")
	var values []string
	var err error
	switch kind {
	case "context":
		values, err = h.contexts.CompletionContexts(r.Context(), prefix, MaxCompletionValues)
	case "alias":
		if contextName == "" {
			writeError(w, http.StatusBadRequest, "completion context is required")
			return
		}
		values, err = h.contexts.CompletionAliases(r.Context(), contextName, prefix, MaxCompletionValues)
	case "peer", "peer_alias":
		if contextName == "" {
			writeError(w, http.StatusBadRequest, "completion context is required")
			return
		}
		values, err = h.contexts.CompletionPeers(r.Context(), contextName, prefix, kind == "peer_alias", MaxCompletionValues)
	case "invite":
		if contextName == "" {
			writeError(w, http.StatusBadRequest, "completion context is required")
			return
		}
		values, err = h.contexts.CompletionInviteIDs(r.Context(), contextName, prefix, MaxCompletionValues)
	case "transfer_show", "transfer_cancel", "transfer_retry", "transfer_delete", "transfer_resolve":
		if contextName == "" {
			writeError(w, http.StatusBadRequest, "completion context is required")
			return
		}
		peer := r.URL.Query().Get("peer")
		if kind == "transfer_retry" && peer != "" {
			peer, err = h.contexts.CompletionPeerTarget(r.Context(), contextName, peer)
			if err != nil {
				h.writeContextOperationError(w, err)
				return
			}
		}
		values, err = h.contexts.CompletionTransferIDs(r.Context(), contextName, strings.TrimPrefix(kind, "transfer_"), peer, prefix, MaxCompletionValues)
	default:
		writeError(w, http.StatusBadRequest, "completion kind is invalid")
		return
	}
	if err != nil {
		h.writeContextOperationError(w, err)
		return
	}
	if values == nil {
		values = []string{}
	}
	writeJSON(w, http.StatusOK, Completion{Version: CompletionVersion, Values: values})
}

func validCompletionPrefix(value string) bool {
	if len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e || value[index] == '\t' || value[index] == '/' || value[index] == '\\' {
			return false
		}
	}
	return true
}

func requireEmptyBody(r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(data) != 0 {
		return errors.New("request body must be empty")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > localipc.MaxResponseBytes {
		status = http.StatusInternalServerError
		data, _ = json.Marshal(localipc.Error{Status: status, Message: "agent response exceeds size limit"})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, localipc.Error{Status: status, Message: message})
}

func writeErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, localipc.Error{Status: status, Code: code, Message: message})
}
