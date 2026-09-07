package adapterapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
)

const (
	Version       = 1
	VersionHeader = "X-PX-IPC-Version"
	AdapterHeader = "X-PX-Adapter-ID"

	CodeUnauthorized       = "adapter_unauthorized"
	CodeInvalidRequest     = "invalid_request"
	CodeInternal           = "internal_error"
	CodeOutcomeUnknown     = "outcome_unknown"
	CodeCursorExpired      = "cursor_expired"
	CodeReceiptExpired     = "receipt_expired"
	CodeReceiptNotFound    = "receipt_not_found"
	CodeRequestConflict    = "request_conflict"
	CodeCommandTimeInvalid = "command_time_invalid"
	CodeCommandCapacity    = "command_capacity"
	CodeReceiptCapacity    = "receipt_capacity"

	OutcomeUnknownMessage = "approval outcome unknown; query or resubmit the exact unchanged adapter ID, command ID, and request"
)

// MaxFactPage is derived from the worst-case version 1 fact DTO and the 64 KiB
// local IPC response limit. The bound is proved in api_test.go.
const MaxFactPage = 203

var (
	adapterIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	commandIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	enrollmentIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

var ErrDoorbellDisconnected = errors.New("adapter doorbell disconnected; replay is required before reconnecting")

type Error struct {
	Version      int    `json:"version"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	CommandID    string `json:"command_id,omitempty"`
	Floor        int64  `json:"floor,omitempty"`
	HighWater    int64  `json:"high_water,omitempty"`
	Status       int    `json:"-"`
	hasCommandID bool
	hasFloor     bool
	hasHighWater bool
}

func (e *Error) Error() string { return e.Message }

func (e *Error) UnmarshalJSON(data []byte) error {
	raw, err := strictObject(data, []string{"version", "code", "message", "command_id", "floor", "high_water"}, []string{"version", "code", "message"})
	if err != nil {
		return err
	}
	type errorAlias Error
	var value errorAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*e = Error(value)
	_, e.hasCommandID = raw["command_id"]
	_, e.hasFloor = raw["floor"]
	_, e.hasHighWater = raw["high_water"]
	if err := rejectNullFields(raw, "command_id", "floor", "high_water"); err != nil {
		return err
	}
	if e.Code == CodeCursorExpired && (!e.hasFloor || !e.hasHighWater) {
		return errors.New("cursor_expired response requires floor and high_water")
	}
	if e.Code == CodeOutcomeUnknown && !e.hasCommandID {
		return errors.New("outcome_unknown response requires command_id")
	}
	return nil
}

type Fact struct {
	Seq            int64  `json:"seq"`
	Kind           string `json:"kind"`
	EnrollmentID   string `json:"enrollment_id"`
	OccurredAt     string `json:"occurred_at"`
	DeviceID       string `json:"device_id"`
	Label          string `json:"label"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	MemberRevision int64  `json:"member_revision,omitempty"`
	hasExpiresAt   bool
	hasRevision    bool
}

func (f *Fact) UnmarshalJSON(data []byte) error {
	raw, err := strictObject(data, []string{"seq", "kind", "enrollment_id", "occurred_at", "device_id", "label", "expires_at", "member_revision"}, []string{"seq", "kind", "enrollment_id", "occurred_at", "device_id", "label"})
	if err != nil {
		return err
	}
	type factAlias Fact
	var value factAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*f = Fact(value)
	_, f.hasExpiresAt = raw["expires_at"]
	_, f.hasRevision = raw["member_revision"]
	return rejectNullFields(raw, "expires_at", "member_revision")
}

type FactPage struct {
	Version   int    `json:"version"`
	Floor     int64  `json:"floor"`
	HighWater int64  `json:"high_water"`
	Facts     []Fact `json:"facts"`
}

func (p *FactPage) UnmarshalJSON(data []byte) error {
	if _, err := strictObject(data, []string{"version", "floor", "high_water", "facts"}, []string{"version", "floor", "high_water", "facts"}); err != nil {
		return err
	}
	type pageAlias FactPage
	var value pageAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = FactPage(value)
	return nil
}

type Pending struct {
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	Label        string `json:"label"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
}

func (p *Pending) UnmarshalJSON(data []byte) error {
	if _, err := strictObject(data, []string{"enrollment_id", "device_id", "label", "created_at", "expires_at"}, []string{"enrollment_id", "device_id", "label", "created_at", "expires_at"}); err != nil {
		return err
	}
	type pendingAlias Pending
	var value pendingAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = Pending(value)
	return nil
}

type PendingSnapshot struct {
	Version   int       `json:"version"`
	HighWater int64     `json:"high_water"`
	Pending   []Pending `json:"pending"`
}

func (p *PendingSnapshot) UnmarshalJSON(data []byte) error {
	if _, err := strictObject(data, []string{"version", "high_water", "pending"}, []string{"version", "high_water", "pending"}); err != nil {
		return err
	}
	type snapshotAlias PendingSnapshot
	var value snapshotAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = PendingSnapshot(value)
	return nil
}

type ApprovalRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	CommandID     string `json:"command_id"`
	EnrollmentID  string `json:"enrollment_id"`
}

type ApprovalResult struct {
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	Label        string `json:"label"`
	Revision     int64  `json:"revision"`
}

func (r *ApprovalResult) UnmarshalJSON(data []byte) error {
	if _, err := strictObject(data, []string{"enrollment_id", "device_id", "label", "revision"}, []string{"enrollment_id", "device_id", "label", "revision"}); err != nil {
		return err
	}
	type resultAlias ApprovalResult
	var result resultAlias
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	*r = ApprovalResult(result)
	return nil
}

type Command struct {
	Version       int             `json:"version"`
	SchemaVersion int             `json:"schema_version"`
	Action        string          `json:"action"`
	CommandID     string          `json:"command_id"`
	EnrollmentID  string          `json:"enrollment_id"`
	State         string          `json:"state"`
	AdmittedAt    string          `json:"admitted_at"`
	SettledAt     string          `json:"settled_at,omitempty"`
	RejectionCode string          `json:"rejection_code,omitempty"`
	Result        *ApprovalResult `json:"result,omitempty"`
	hasSettledAt  bool
	hasRejection  bool
	hasResult     bool
}

func (c *Command) UnmarshalJSON(data []byte) error {
	raw, err := strictObject(data, []string{"version", "schema_version", "action", "command_id", "enrollment_id", "state", "admitted_at", "settled_at", "rejection_code", "result"}, []string{"version", "schema_version", "action", "command_id", "enrollment_id", "state", "admitted_at"})
	if err != nil {
		return err
	}
	type wireCommand struct {
		Version       int             `json:"version"`
		SchemaVersion int             `json:"schema_version"`
		Action        string          `json:"action"`
		CommandID     string          `json:"command_id"`
		EnrollmentID  string          `json:"enrollment_id"`
		State         string          `json:"state"`
		AdmittedAt    string          `json:"admitted_at"`
		SettledAt     string          `json:"settled_at"`
		RejectionCode string          `json:"rejection_code"`
		Result        *ApprovalResult `json:"result"`
	}
	var wire wireCommand
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*c = Command{
		Version: wire.Version, SchemaVersion: wire.SchemaVersion, Action: wire.Action,
		CommandID: wire.CommandID, EnrollmentID: wire.EnrollmentID, State: wire.State,
		AdmittedAt: wire.AdmittedAt, SettledAt: wire.SettledAt,
		RejectionCode: wire.RejectionCode, Result: wire.Result,
	}
	_, c.hasSettledAt = raw["settled_at"]
	_, c.hasRejection = raw["rejection_code"]
	_, c.hasResult = raw["result"]
	return rejectNullFields(raw, "settled_at", "rejection_code", "result")
}

type Doorbell struct {
	Version        int  `json:"version"`
	ReplayRequired bool `json:"replay_required"`
}

func (d *Doorbell) UnmarshalJSON(data []byte) error {
	if _, err := strictObject(data, []string{"version", "replay_required"}, []string{"version", "replay_required"}); err != nil {
		return err
	}
	type doorbellAlias Doorbell
	var value doorbellAlias
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*d = Doorbell(value)
	return nil
}

func strictObject(data []byte, allowed, required []string) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, errors.New("adapter response value must be an object")
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = true
	}
	for key := range raw {
		if !allowedSet[key] {
			return nil, errors.New("unknown adapter response field")
		}
	}
	for _, key := range required {
		value, exists := raw[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("missing or null adapter response field")
		}
	}
	return raw, nil
}

func rejectNullFields(raw map[string]json.RawMessage, fields ...string) error {
	for _, key := range fields {
		if value, exists := raw[key]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null optional adapter response field")
		}
	}
	return nil
}

type Handler struct {
	store               *membership.Store
	broker              *Broker
	now                 func() time.Time
	doorbellReauthorize time.Duration
	admit               func(context.Context, string, membership.AdapterCredential, membership.ApprovalCommand, time.Time) (membership.CommandReceipt, error)
	approve             func(context.Context, string, string, time.Time) (membership.CommandReceipt, error)
}

func New(store *membership.Store, broker *Broker) *Handler {
	return &Handler{
		store: store, broker: broker, now: time.Now, doorbellReauthorize: 5 * time.Second,
		admit: store.AdmitApprovalCommand, approve: store.ApproveAdapterCommand,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values(VersionHeader)) != 1 || r.Header.Get(VersionHeader) != strconv.Itoa(Version) {
		writeError(w, http.StatusUpgradeRequired, CodeInvalidRequest, "unsupported or missing adapter IPC version", nil)
		return
	}
	adapterID, credential, ok := authenticateHeaders(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "adapter authorization failed", nil)
		return
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, localipc.MaxRequestBytes)
	if !canonicalAdapterPath(r) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid adapter path", nil)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/facts":
		h.replay(w, r, adapterID, credential)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/pending":
		h.pending(w, r, adapterID, credential)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/commands":
		h.submit(w, r, adapterID, credential)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/commands/"):
		h.query(w, r, adapterID, credential)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/doorbell":
		h.doorbell(w, r, adapterID, credential)
	default:
		writeError(w, http.StatusNotFound, CodeInvalidRequest, "adapter route not found", nil)
	}
}

func authenticateHeaders(r *http.Request) (string, membership.AdapterCredential, bool) {
	adapterID := r.Header.Get(AdapterHeader)
	value := r.Header.Get("Authorization")
	if len(r.Header.Values(AdapterHeader)) != 1 || len(r.Header.Values("Authorization")) != 1 || !adapterIDPattern.MatchString(adapterID) || !strings.HasPrefix(value, "Bearer ") || strings.Count(value, " ") != 1 {
		return "", membership.AdapterCredential{}, false
	}
	credential, err := DecodeCredential(strings.TrimPrefix(value, "Bearer "))
	if err != nil {
		return "", membership.AdapterCredential{}, false
	}
	return adapterID, credential, true
}

func EncodeCredential(credential membership.AdapterCredential) string {
	return base64.RawURLEncoding.EncodeToString(credential[:])
}

func DecodeCredential(value string) (membership.AdapterCredential, error) {
	var credential membership.AdapterCredential
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(credential) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return credential, errors.New("invalid adapter credential")
	}
	copy(credential[:], decoded)
	return credential, nil
}

func (h *Handler) replay(w http.ResponseWriter, r *http.Request, adapterID string, credential membership.AdapterCredential) {
	if !emptyBody(r) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid fact replay query", nil)
		return
	}
	if r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid fact replay query", nil)
		return
	}
	values, err := strictRawQuery(r.URL.RawQuery, "cursor", "high_water", "limit")
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid fact replay query", nil)
		return
	}
	cursor, cursorOK := parseInt(values.Get("cursor"))
	highWater, highWaterOK := parseInt(values.Get("high_water"))
	limit, limitOK := parseInt(values.Get("limit"))
	if !cursorOK || !highWaterOK || !limitOK || limit <= 0 || limit > MaxFactPage || highWater != 0 && cursor > highWater {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid fact replay query", nil)
		return
	}
	page, err := h.store.ReplayFacts(r.Context(), adapterID, credential, cursor, highWater, int(limit))
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	facts := make([]Fact, len(page.Facts))
	for index, fact := range page.Facts {
		facts[index] = factDTO(fact)
	}
	writeJSON(w, FactPage{Version: Version, Floor: page.Floor, HighWater: page.HighWater, Facts: facts})
}

func (h *Handler) pending(w http.ResponseWriter, r *http.Request, adapterID string, credential membership.AdapterCredential) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !emptyBody(r) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "pending snapshot request must be empty", nil)
		return
	}
	page, err := h.store.CurrentPendingSnapshot(r.Context(), adapterID, credential, h.now())
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	pending := make([]Pending, len(page.Pending))
	for index, item := range page.Pending {
		pending[index] = Pending{EnrollmentID: item.EnrollmentID, DeviceID: item.DeviceID, Label: item.Label, CreatedAt: formatTime(item.CreatedAt), ExpiresAt: formatTime(item.ExpiresAt)}
	}
	writeJSON(w, PendingSnapshot{Version: Version, HighWater: page.HighWater, Pending: pending})
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request, adapterID string, credential membership.AdapterCredential) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "approval request query must be empty", nil)
		return
	}
	var request ApprovalRequest
	if !decodeStrict(r, &request) || request.SchemaVersion != membership.ApprovalCommandSchemaVersion || request.Action != membership.ApprovalCommandAction {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid approval request", nil)
		return
	}
	receipt, err := h.admit(r.Context(), adapterID, credential, membership.ApprovalCommand{CommandID: request.CommandID, EnrollmentID: request.EnrollmentID}, h.now())
	if err != nil {
		h.writeSubmitError(w, request.CommandID, err)
		return
	}
	if receipt.State == membership.ReceiptAdmitted {
		receipt, err = h.approve(r.Context(), adapterID, request.CommandID, h.now())
		if err != nil {
			writeOutcomeUnknown(w, request.CommandID)
			return
		}
	}
	writeJSON(w, commandDTO(receipt))
}

func (h *Handler) writeSubmitError(w http.ResponseWriter, commandID string, err error) {
	var storeError *membership.StoreError
	if errors.As(err, &storeError) {
		h.writeStoreError(w, err)
		return
	}
	writeOutcomeUnknown(w, commandID)
}

func (h *Handler) query(w http.ResponseWriter, r *http.Request, adapterID string, credential membership.AdapterCredential) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !emptyBody(r) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "command query must be empty", nil)
		return
	}
	commandID := strings.TrimPrefix(r.URL.Path, "/v1/commands/")
	if !commandIDPattern.MatchString(commandID) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid command query", nil)
		return
	}
	receipt, err := h.store.QueryCommand(r.Context(), adapterID, credential, commandID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	writeJSON(w, commandDTO(receipt))
}

func (h *Handler) doorbell(w http.ResponseWriter, r *http.Request, adapterID string, credential membership.AdapterCredential) {
	if h.broker == nil || r.URL.RawQuery != "" || r.URL.ForceQuery || !emptyBody(r) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid doorbell request", nil)
		return
	}
	var subscriber <-chan struct{}
	var cancel func()
	err := h.store.WithAuthorizedAdapter(r.Context(), adapterID, credential, func() error {
		var subscribeErr error
		subscriber, cancel, subscribeErr = h.broker.Subscribe(adapterID)
		return subscribeErr
	})
	if err != nil {
		if cancel != nil {
			cancel()
		}
		if membership.HasCode(err, membership.CodeAdapterUnauthorized) || membership.HasCode(err, membership.CodeAdapterInvalid) {
			h.writeStoreError(w, err)
		} else {
			writeError(w, http.StatusConflict, CodeInvalidRequest, "doorbell subscription unavailable", nil)
		}
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	ticker := time.NewTicker(h.doorbellReauthorize)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := h.store.AuthorizeAdapter(r.Context(), adapterID, credential); err != nil {
				return
			}
		case _, ok := <-subscriber:
			if !ok {
				return
			}
			release, err := h.store.AuthorizeAdapterMarker(r.Context(), adapterID, credential)
			if err != nil {
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := json.NewEncoder(w).Encode(Doorbell{Version: Version, ReplayRequired: true}); err != nil {
				release()
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			release()
		}
	}
}

func factDTO(fact membership.EnrollmentFact) Fact {
	result := Fact{Seq: fact.Seq, Kind: fact.Kind, EnrollmentID: fact.EnrollmentID, OccurredAt: formatTime(fact.OccurredAt), DeviceID: fact.DeviceID, Label: fact.Label, MemberRevision: fact.MemberRevision}
	if fact.ExpiresAt != nil {
		result.ExpiresAt = formatTime(*fact.ExpiresAt)
	}
	return result
}

func commandDTO(receipt membership.CommandReceipt) Command {
	result := Command{Version: Version, SchemaVersion: membership.ApprovalCommandSchemaVersion, Action: membership.ApprovalCommandAction, CommandID: receipt.CommandID, EnrollmentID: receipt.EnrollmentID, State: receipt.State, AdmittedAt: formatTime(receipt.AdmittedAt), RejectionCode: string(receipt.RejectionCode)}
	if receipt.SettledAt != nil {
		result.SettledAt = formatTime(*receipt.SettledAt)
	}
	if receipt.Result != nil {
		result.Result = &ApprovalResult{EnrollmentID: receipt.Result.EnrollmentID, DeviceID: receipt.Result.DeviceID, Label: receipt.Result.Label, Revision: receipt.Result.Revision}
	}
	return result
}

func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func strictRawQuery(raw string, allowed ...string) (url.Values, error) {
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

func canonicalAdapterPath(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	switch escaped {
	case "/v1/facts", "/v1/pending", "/v1/commands", "/v1/doorbell":
		return r.URL.Path == escaped
	}
	const prefix = "/v1/commands/"
	if !strings.HasPrefix(escaped, prefix) || r.URL.Path != escaped {
		return false
	}
	return commandIDPattern.MatchString(strings.TrimPrefix(escaped, prefix))
}

func parseInt(value string) (int64, bool) {
	if value == "" || strings.HasPrefix(value, "+") || len(value) > 19 {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed >= 0 && strconv.FormatInt(parsed, 10) == value
}

func decodeStrict(r *http.Request, output any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func emptyBody(r *http.Request) bool {
	data, err := io.ReadAll(r.Body)
	return err == nil && len(data) == 0
}

func (h *Handler) writeStoreError(w http.ResponseWriter, err error) {
	var storeError *membership.StoreError
	if !errors.As(err, &storeError) {
		writeError(w, http.StatusInternalServerError, CodeInternal, "adapter request failed", nil)
		return
	}
	if storeError.Code == membership.CodeAdapterUnauthorized || storeError.Code == membership.CodeAdapterInvalid {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "adapter authorization failed", nil)
		return
	}
	if storeError.Code == membership.CodeFactReplayInvalid {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid fact replay request", nil)
		return
	}
	status := http.StatusConflict
	message := map[membership.ErrorCode]string{
		membership.CodeCursorExpired:      "fact replay cursor expired; rebuild from the current pending snapshot",
		membership.CodeReceiptExpired:     "command result expired and command ID cannot be reused",
		membership.CodeReceiptNotFound:    "command receipt not found",
		membership.CodeRequestConflict:    "command ID was already used for a different request",
		membership.CodeCommandTimeInvalid: "command ID time is outside the accepted window",
		membership.CodeCommandCapacity:    "admitted command capacity reached",
		membership.CodeReceiptCapacity:    "command receipt capacity reached",
	}[storeError.Code]
	if message == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid adapter request", nil)
		return
	}
	writeError(w, status, string(storeError.Code), message, storeError)
}

func writeJSON(w http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > localipc.MaxResponseBytes {
		writeError(w, http.StatusInternalServerError, CodeInternal, "adapter response exceeds size limit", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, status int, code, message string, storeError *membership.StoreError) {
	result := Error{Version: Version, Code: code, Message: message}
	if storeError != nil {
		result.Floor, result.HighWater = storeError.Floor, storeError.HighWater
	}
	data, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

func writeOutcomeUnknown(w http.ResponseWriter, commandID string) {
	result := Error{Version: Version, Code: CodeOutcomeUnknown, Message: OutcomeUnknownMessage, CommandID: commandID}
	data, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(append(data, '\n'))
}
