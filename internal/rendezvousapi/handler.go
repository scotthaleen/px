package rendezvousapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/rendezvousproto"
)

const (
	rateWindow        = time.Minute
	rateRequests      = 5
	MaxTrustedProxies = 16
	maxForwardedBytes = 4 << 10
	maxForwardedHops  = 32
)

type Handler struct {
	store          *membership.Store
	authority      *membership.Authority
	hub            *Hub
	logger         *slog.Logger
	rateMu         sync.Mutex
	rates          map[string]rateEntry
	inviteRateMu   sync.Mutex
	inviteRates    map[string]rateEntry
	authSlots      chan struct{}
	inviteSlots    chan struct{}
	trustedProxies []netip.Prefix
	operational    *OperationalState
	readiness      *readinessProbe
}

type Option func(*Handler)

func WithTrustedProxies(prefixes []netip.Prefix) Option {
	return func(handler *Handler) {
		handler.trustedProxies = append([]netip.Prefix(nil), prefixes...)
	}
}

func WithOperationalState(state *OperationalState) Option {
	return func(handler *Handler) {
		handler.operational = state
	}
}

func ParseTrustedProxyCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) > MaxTrustedProxies {
		return nil, fmt.Errorf("at most %d trusted proxy CIDRs may be configured", MaxTrustedProxies)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q", value)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

type rateEntry struct {
	window time.Time
	count  int
}

type authenticationRejectedError struct {
	message string
}

func (e *authenticationRejectedError) Error() string { return e.message }

type inviteControlError struct {
	code    string
	message string
}

func (e *inviteControlError) Error() string { return e.message }

func New(store *membership.Store, authority *membership.Authority, hub *Hub, logger *slog.Logger, options ...Option) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	handler := &Handler{
		store:       store,
		authority:   authority,
		hub:         hub,
		logger:      logger,
		rates:       make(map[string]rateEntry),
		inviteRates: make(map[string]rateEntry),
		authSlots:   make(chan struct{}, 128),
		inviteSlots: make(chan struct{}, 64),
		readiness:   newReadinessProbe(store),
	}
	for _, option := range options {
		option(handler)
	}
	return handler
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", h.ready)
	mux.HandleFunc("GET /v1/server", h.serverInfo)
	mux.HandleFunc("POST /v1/enrollments", h.enroll)
	mux.HandleFunc("POST /v1/enrollments/status", h.enrollmentStatus)
	mux.HandleFunc("POST /v1/invites/redeem", h.redeemInvite)
	mux.HandleFunc("GET /v1/connect", h.connect)
	return mux
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if !h.operational.LifecycleReady() || !h.operational.HTTPReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !h.readiness.ready(r.Context()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serverInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ServerInfo{Version: Version, AuthenticationVersion: AuthenticationVersion, ControlVersion: Version, InviteVersion: 1, ServerID: h.authority.ServerID(), Authority: identity.ID(h.authority.PublicKey())})
}

func (h *Handler) redeemInvite(w http.ResponseWriter, r *http.Request) {
	sourceIP, err := h.clientIP(r)
	if err != nil {
		writePublicError(w, http.StatusBadRequest, "invalid_request", "invalid invite redemption request")
		return
	}
	if !allowRate(&h.inviteRateMu, h.inviteRates, sourceIP, time.Now(), 10) {
		writePublicError(w, http.StatusTooManyRequests, "rate_limited", "invite redemption rate limit exceeded")
		return
	}
	select {
	case h.inviteSlots <- struct{}{}:
		defer func() { <-h.inviteSlots }()
	default:
		writePublicError(w, http.StatusServiceUnavailable, "service_unavailable", "invite redemption capacity reached")
		return
	}
	var request InviteRedemptionRequest
	if decodeJSON(w, r, &request, MaxRequestBytes) != nil || request.Version != 1 {
		writePublicError(w, http.StatusBadRequest, "invalid_request", "invalid invite redemption request")
		return
	}
	if _, err := membership.ParseInviteToken(request.Token); err != nil {
		writePublicError(w, http.StatusBadRequest, "invalid_request", "invalid invite redemption request")
		return
	}
	deviceKey, err := identity.ParseID(request.DeviceKey)
	if err != nil || identity.ID(deviceKey) != request.DeviceKey || membership.ValidateLabel(request.Label) != nil {
		writePublicError(w, http.StatusBadRequest, "invalid_request", "invalid invite redemption request")
		return
	}
	redemption, err := h.store.RedeemInvite(r.Context(), request.Token, deviceKey, request.Label, time.Now())
	if err != nil {
		switch {
		case membership.HasCode(err, membership.CodeInviteUnavailable):
			writePublicError(w, http.StatusNotFound, "invite_unavailable", "invite is invalid, unavailable, expired, revoked, used, or does not match this enrollment")
		case membership.HasCode(err, membership.CodeEnrollmentUnavailable):
			writePublicError(w, http.StatusConflict, "enrollment_unavailable", "enrollment is unavailable")
		default:
			h.logger.Error("invite redemption failed", "reason", err)
			writePublicError(w, http.StatusInternalServerError, "internal_error", "invite redemption service unavailable")
		}
		return
	}
	writeJSON(w, http.StatusOK, InviteRedemption{Version: 1, State: "enrolled", Credential: redemption.Credential})
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	sourceIP, err := h.clientIP(r)
	if err != nil {
		h.rejectEnrollment(w, http.StatusBadRequest, "invalid forwarded client address")
		return
	}
	if !h.allowEnrollment(sourceIP, time.Now()) {
		h.rejectEnrollment(w, http.StatusTooManyRequests, "enrollment rate limit exceeded")
		return
	}
	var request EnrollmentRequest
	if err := decodeJSON(w, r, &request, MaxRequestBytes); err != nil {
		h.rejectEnrollment(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceKey, err := identity.ParseID(request.DeviceKey)
	if err != nil {
		h.rejectEnrollment(w, http.StatusBadRequest, "invalid enrollment device key")
		return
	}
	result, err := h.store.RequestEnrollment(r.Context(), deviceKey, request.Label, sourceIP, time.Now())
	if err != nil {
		h.writeMembershipError(w, err, true)
		return
	}
	writeJSON(w, http.StatusOK, enrollmentResponse(result))
}

func (h *Handler) rejectEnrollment(w http.ResponseWriter, status int, message string) {
	h.hub.EnrollmentRejected()
	writeError(w, status, message)
}

func (h *Handler) enrollmentStatus(w http.ResponseWriter, r *http.Request) {
	var request EnrollmentRequest
	if err := decodeJSON(w, r, &request, MaxRequestBytes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceKey, err := identity.ParseID(request.DeviceKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid enrollment device key")
		return
	}
	result, err := h.store.EnrollmentStatus(r.Context(), deviceKey, request.Label, time.Now())
	if err != nil {
		h.writeMembershipError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, enrollmentResponse(result))
}

func enrollmentResponse(value membership.Enrollment) rendezvousproto.Enrollment {
	return rendezvousproto.Enrollment{
		State: value.State, Code: value.Code, ExpiresAt: value.ExpiresAt, Credential: value.Credential,
	}
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	authSlotHeld := false
	select {
	case h.authSlots <- struct{}{}:
		authSlotHeld = true
	default:
		h.hub.AuthenticationFailed()
		writeError(w, http.StatusServiceUnavailable, "authentication capacity reached")
		return
	}
	defer func() {
		if authSlotHeld {
			<-h.authSlots
		}
	}()
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxControlBytes)
	defer conn.CloseNow()
	authContext, cancelAuth := context.WithTimeout(r.Context(), authenticationLimit)
	challenge, err := h.challenge(time.Now())
	if err != nil {
		cancelAuth()
		_ = conn.Close(websocket.StatusInternalError, "create authentication challenge")
		return
	}
	if err := writeWebSocket(authContext, conn, challenge); err != nil {
		cancelAuth()
		return
	}
	messageType, data, err := conn.Read(authContext)
	cancelAuth()
	if err != nil {
		if authenticationReadRejected(err) {
			h.hub.AuthenticationFailed()
		}
		return
	}
	if messageType != websocket.MessageText {
		h.hub.AuthenticationFailed()
		_ = conn.Close(websocket.StatusUnsupportedData, "text authentication required")
		return
	}
	member, authentication, err := h.authenticate(r.Context(), challenge, data, time.Now())
	if err != nil {
		h.hub.AuthenticationFailed()
		var mismatch *rendezvousproto.ProtocolMismatch
		if errors.As(err, &mismatch) {
			h.logger.Warn("unsupported client protocol", "event", "protocol.unsupported", "boundary", mismatch.Boundary, "expected_version", mismatch.Expected, "received_version", mismatch.Actual)
			_ = conn.Close(websocket.StatusPolicyViolation, "unsupported_protocol")
			return
		}
		if expectedAuthenticationError(err) {
			_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		} else {
			h.logger.Error("membership authentication failed", "reason", err)
			_ = conn.Close(websocket.StatusInternalError, "authentication unavailable")
		}
		return
	}
	<-h.authSlots
	authSlotHeld = false
	proof, err := h.authenticatedProof(challenge, member, authentication)
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "create authenticated proof")
		return
	}

	sessionContext, cancelSession := context.WithCancel(r.Context())
	defer cancelSession()
	value := &client{member: member, send: make(chan outbound, clientQueueSize), cancel: cancelSession}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-sessionContext.Done():
				return
			case message := <-value.send:
				if err := conn.Write(sessionContext, websocket.MessageText, message.data); err != nil {
					cancelSession()
					return
				}
				if message.closeAfter {
					cancelSession()
					return
				}
			}
		}
	}()
	peers, err := h.hub.register(value)
	if err != nil {
		cancelSession()
		<-writerDone
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer func() {
		h.hub.unregister(value)
		h.logger.Info("context disconnected", "peer", "@"+member.Label)
		cancelSession()
		<-writerDone
	}()
	if err := h.hub.enqueue(value, wireMessage{Version: Version, Type: "authenticated", Member: &member, Members: peers, AuthenticationProof: &proof}, false); err != nil {
		return
	}
	h.logger.Info("context connected", "peer", "@"+member.Label)

	for {
		messageType, data, err := conn.Read(sessionContext)
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			if h.hub.enqueue(value, wireMessage{Version: Version, Type: "error", Error: "text control messages required"}, false) != nil {
				return
			}
			continue
		}
		if operation, requestID, err := h.handleMemberMessage(sessionContext, value, data); err != nil {
			var mismatch *rendezvousproto.ProtocolMismatch
			if errors.As(err, &mismatch) {
				h.logger.Warn("unsupported client protocol", "event", "protocol.unsupported", "boundary", mismatch.Boundary, "expected_version", mismatch.Expected, "received_version", mismatch.Actual)
				_ = conn.Close(websocket.StatusPolicyViolation, "unsupported_protocol")
				return
			}
			var inviteErr *inviteControlError
			if errors.As(err, &inviteErr) {
				if h.hub.enqueue(value, inviteapi.ControlError{Type: "invite.error", RequestID: requestID, Version: inviteapi.Version, Code: inviteErr.code, Message: inviteErr.message}, false) != nil {
					return
				}
				continue
			}
			if operation == "" {
				_ = conn.Close(websocket.StatusPolicyViolation, "invalid_control")
				return
			}
			if h.hub.enqueue(value, wireMessage{Version: Version, Type: operation + ".error", RequestID: requestID, Error: err.Error()}, false) != nil {
				return
			}
		}
	}
}

func authenticationReadRejected(err error) bool {
	if errors.Is(err, websocket.ErrMessageTooBig) {
		return true
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusProtocolError, websocket.StatusUnsupportedData, websocket.StatusInvalidFramePayloadData, websocket.StatusMessageTooBig:
		return true
	default:
		return false
	}
}

func (h *Handler) handleMemberMessage(ctx context.Context, sender *client, data []byte) (string, string, error) {
	if len(data) > MaxControlBytes {
		return "", "", errors.New("control request exceeds bounds")
	}
	var envelope struct {
		Version   int    `json:"version"`
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return "", "", errors.New("invalid control request")
	}
	if strings.HasPrefix(envelope.Type, "invite.") {
		return h.handleInviteMessage(ctx, sender, data, envelope)
	}
	if envelope.Version != Version {
		return "", "", &rendezvousproto.ProtocolMismatch{Boundary: "control", Expected: Version, Actual: envelope.Version, Remote: "client"}
	}
	if envelope.Type == "" {
		return "", "", errors.New("invalid control request")
	}
	if envelope.Type == "ping.request" {
		var request rendezvousproto.PingControl
		if decodeBytes(data, &request, MaxControlBytes) != nil || request.Version != Version || request.Type != envelope.Type || rendezvousproto.ValidateRequestID(request.RequestID) != nil {
			return envelope.Type, validRequestID(envelope.RequestID), errors.New("invalid ping request")
		}
		response := rendezvousproto.PingControl{Version: Version, Type: "ping.response", RequestID: request.RequestID}
		return request.Type, request.RequestID, h.hub.enqueue(sender, response, false)
	}
	var message wireMessage
	if err := decodeBytes(data, &message, MaxControlBytes); err != nil {
		return envelope.Type, validRequestID(envelope.RequestID), err
	}
	switch message.Type {
	case "signal":
		if message.To == "" || message.To == sender.member.DeviceID || len(message.Payload) == 0 || len(message.Payload) > MaxSignalBytes {
			h.hub.SignalingRejected()
			return message.Type, validRequestID(message.RequestID), errors.New("invalid signaling message")
		}
		return message.Type, validRequestID(message.RequestID), h.hub.forward(sender.member.DeviceID, message.To, message.Payload)
	case "members.list":
		if message.Version != Version {
			return message.Type, "", errors.New("members.list requires control protocol version 2")
		}
		if err := rendezvousproto.ValidateRequestID(message.RequestID); err != nil {
			return message.Type, "", err
		}
		members, err := h.store.ListActiveMembers(ctx)
		if err != nil {
			return message.Type, message.RequestID, h.controlStoreError(err)
		}
		return message.Type, message.RequestID, h.hub.enqueue(sender, wireMessage{Version: Version, Type: message.Type, RequestID: message.RequestID, Members: members}, false)
	case "pending.list":
		if err := rendezvousproto.ValidateRequestID(message.RequestID); err != nil {
			return message.Type, "", err
		}
		pending, err := h.store.ListPending(ctx, time.Now())
		if err != nil {
			return message.Type, message.RequestID, h.controlStoreError(err)
		}
		return message.Type, message.RequestID, h.hub.enqueue(sender, wireMessage{Version: Version, Type: message.Type, RequestID: message.RequestID, Pending: pending}, false)
	case "pending.approve":
		if err := rendezvousproto.ValidateRequestID(message.RequestID); err != nil {
			return message.Type, "", err
		}
		code, err := membership.NormalizeApprovalCode(message.Code)
		if err != nil {
			return message.Type, message.RequestID, err
		}
		member, err := h.store.Approve(ctx, code, "member", sender.member.DeviceID, time.Now())
		if err != nil {
			return message.Type, message.RequestID, h.controlStoreError(err)
		}
		return message.Type, message.RequestID, h.hub.enqueue(sender, wireMessage{Version: Version, Type: "pending.approved", RequestID: message.RequestID, Member: &member}, false)
	default:
		return message.Type, validRequestID(message.RequestID), fmt.Errorf("unsupported member message %q", message.Type)
	}
}

func validRequestID(value string) string {
	if rendezvousproto.ValidateRequestID(value) != nil {
		return ""
	}
	return value
}

func (h *Handler) handleInviteMessage(ctx context.Context, sender *client, data []byte, envelope struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
},
) (string, string, error) {
	requestID := envelope.RequestID
	invalid := func() (string, string, error) {
		if rendezvousproto.ValidateRequestID(requestID) != nil {
			requestID = ""
		}
		return envelope.Type, requestID, &inviteControlError{code: "invalid_request", message: "invalid invite request"}
	}
	if envelope.Version != inviteapi.Version || rendezvousproto.ValidateRequestID(requestID) != nil {
		return invalid()
	}
	switch envelope.Type {
	case "invite.create":
		var request inviteapi.ControlCreateRequest
		if decodeBytes(data, &request, MaxControlBytes) != nil || request.Type != envelope.Type || request.RequestID != requestID || request.Version != inviteapi.Version || request.LifetimeSeconds < int64(membership.MinInviteLifetime/time.Second) || request.LifetimeSeconds > int64(membership.MaxInviteLifetime/time.Second) {
			return invalid()
		}
		created, err := h.store.CreateInvite(ctx, request.Label, time.Duration(request.LifetimeSeconds)*time.Second, "member", sender.member.DeviceID, time.Now())
		if err != nil {
			return envelope.Type, requestID, h.inviteControlStoreError(err)
		}
		response := inviteapi.ControlCreation{Type: "invite.created", RequestID: requestID, Creation: inviteapi.CreationFromMembership(created)}
		return envelope.Type, requestID, h.hub.enqueue(sender, response, false)
	case "invite.list":
		var request inviteapi.ControlListRequest
		if decodeBytes(data, &request, MaxControlBytes) != nil || request.Type != envelope.Type || request.RequestID != requestID || request.Version != inviteapi.Version {
			return invalid()
		}
		invites, err := h.store.ListInvites(ctx, "member", sender.member.DeviceID, time.Now())
		if err != nil {
			return envelope.Type, requestID, h.inviteControlStoreError(err)
		}
		result := inviteapi.List{Version: inviteapi.Version, Invites: make([]inviteapi.Invite, 0, len(invites))}
		for _, invite := range invites {
			result.Invites = append(result.Invites, inviteapi.FromMembership(invite))
		}
		return envelope.Type, requestID, h.hub.enqueue(sender, inviteapi.ControlList{Type: "invite.listed", RequestID: requestID, List: result}, false)
	case "invite.revoke":
		var request inviteapi.ControlRevokeRequest
		if decodeBytes(data, &request, MaxControlBytes) != nil || request.Type != envelope.Type || request.RequestID != requestID || request.Version != inviteapi.Version || membership.ValidateInviteID(request.InviteID) != nil {
			return invalid()
		}
		invite, err := h.store.RevokeInvite(ctx, request.InviteID, "member", sender.member.DeviceID, time.Now())
		if err != nil {
			return envelope.Type, requestID, h.inviteControlStoreError(err)
		}
		result := inviteapi.Revocation{Version: inviteapi.Version, State: "revoked", Invite: inviteapi.FromMembership(invite)}
		return envelope.Type, requestID, h.hub.enqueue(sender, inviteapi.ControlRevocation{Type: "invite.revoked", RequestID: requestID, Revocation: result}, false)
	default:
		return invalid()
	}
}

func (h *Handler) inviteControlStoreError(err error) error {
	switch {
	case membership.HasCode(err, membership.CodeMembershipInvalid):
		return &inviteControlError{code: "invalid_request", message: "invalid invite request"}
	case membership.HasCode(err, membership.CodeInviteLabelUnavailable):
		return &inviteControlError{code: string(membership.CodeInviteLabelUnavailable), message: "invite label is unavailable"}
	case membership.HasCode(err, membership.CodeInviteCapacity):
		return &inviteControlError{code: string(membership.CodeInviteCapacity), message: "invite capacity reached"}
	case membership.HasCode(err, membership.CodeInviteUnavailable):
		return &inviteControlError{code: string(membership.CodeInviteUnavailable), message: "invite is unavailable"}
	default:
		h.logger.Error("member invite control operation failed", "reason", err)
		return &inviteControlError{code: "internal_error", message: "invite administration failed"}
	}
}

func (h *Handler) writeMembershipError(w http.ResponseWriter, err error, enrollmentRejected bool) {
	status, message, expected := membershipHTTPError(err)
	if !expected {
		h.logger.Error("membership request failed", "reason", err)
	}
	if enrollmentRejected {
		h.rejectEnrollment(w, status, message)
		return
	}
	writeError(w, status, message)
}

func membershipHTTPError(err error) (int, string, bool) {
	switch {
	case membership.HasCode(err, membership.CodeMembershipInvalid):
		return http.StatusBadRequest, err.Error(), true
	case membership.HasCode(err, membership.CodeMembershipNotFound):
		return http.StatusNotFound, err.Error(), true
	case membership.HasCode(err, membership.CodeMembershipConflict), membership.HasCode(err, membership.CodeMembershipRevoked):
		return http.StatusConflict, err.Error(), true
	case membership.HasCode(err, membership.CodeMembershipCapacity):
		return http.StatusConflict, err.Error(), true
	case membership.HasCode(err, membership.CodeFactCapacity):
		return http.StatusConflict, "enrollment capacity reached", true
	default:
		return http.StatusInternalServerError, "membership service unavailable", false
	}
}

func expectedAuthenticationError(err error) bool {
	var rejected *authenticationRejectedError
	if errors.As(err, &rejected) {
		return true
	}
	_, _, expected := membershipHTTPError(err)
	return expected
}

func (h *Handler) controlStoreError(err error) error {
	if _, message, expected := membershipHTTPError(err); expected {
		return errors.New(message)
	}
	h.logger.Error("member control operation failed", "reason", err)
	return errors.New("member operation failed")
}

func (h *Handler) challenge(now time.Time) (Challenge, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}
	challenge := Challenge{
		Version:   AuthenticationVersion,
		Type:      "challenge",
		ServerID:  h.authority.ServerID(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		ExpiresAt: now.Add(authenticationLimit).Unix(),
	}
	canonical, err := rendezvousproto.ServerChallengeBytes(challenge)
	if err != nil {
		return Challenge{}, err
	}
	challenge.AuthoritySignature = base64.RawURLEncoding.EncodeToString(h.authority.Sign(canonical))
	return challenge, nil
}

func (h *Handler) authenticate(ctx context.Context, challenge Challenge, data []byte, now time.Time) (membership.Member, Authentication, error) {
	if err := rendezvousproto.VerifyServerChallenge(challenge, h.authority.ServerID(), now); err != nil {
		return membership.Member{}, Authentication{}, &authenticationRejectedError{message: "authentication challenge expired or mismatched"}
	}
	var authentication Authentication
	if err := decodeBytes(data, &authentication, MaxControlBytes); err != nil {
		return membership.Member{}, Authentication{}, &authenticationRejectedError{message: "invalid authentication response"}
	}
	if authentication.Version != AuthenticationVersion {
		if authentication.Version != 0 {
			return membership.Member{}, Authentication{}, &rendezvousproto.ProtocolMismatch{Boundary: "authentication", Expected: AuthenticationVersion, Actual: authentication.Version, Remote: "client"}
		}
		return membership.Member{}, Authentication{}, &authenticationRejectedError{message: "invalid authentication response"}
	}
	if authentication.Type != "authenticate" {
		return membership.Member{}, Authentication{}, &authenticationRejectedError{message: "invalid authentication response"}
	}
	member, err := h.store.Authenticate(ctx, authentication.Credential)
	if err != nil {
		return membership.Member{}, Authentication{}, err
	}
	deviceKey, err := identity.ParseID(authentication.Credential.Claims.DeviceKey)
	if err != nil {
		return membership.Member{}, Authentication{}, err
	}
	if err := rendezvousproto.VerifyChallengeSignature(deviceKey, challenge, authentication.Signature); err != nil {
		return membership.Member{}, Authentication{}, &authenticationRejectedError{message: err.Error()}
	}
	return member, authentication, nil
}

func (h *Handler) authenticatedProof(challenge Challenge, member membership.Member, authentication Authentication) (AuthenticatedProof, error) {
	proof, err := rendezvousproto.NewAuthenticatedProof(challenge, member.DeviceID, authentication.Credential.Claims.DeviceKey, member.Revision, authentication.Signature)
	if err != nil {
		return AuthenticatedProof{}, err
	}
	canonical, err := rendezvousproto.AuthenticatedProofBytes(proof)
	if err != nil {
		return AuthenticatedProof{}, err
	}
	proof.AuthoritySignature = base64.RawURLEncoding.EncodeToString(h.authority.Sign(canonical))
	return proof, nil
}

func (h *Handler) allowEnrollment(sourceIP string, now time.Time) bool {
	return allowRate(&h.rateMu, h.rates, sourceIP, now, rateRequests)
}

func allowRate(mu *sync.Mutex, rates map[string]rateEntry, sourceIP string, now time.Time, limit int) bool {
	mu.Lock()
	defer mu.Unlock()
	entry, exists := rates[sourceIP]
	if !exists && len(rates) >= 1024 {
		for key, value := range rates {
			if now.Sub(value.window) >= rateWindow {
				delete(rates, key)
			}
		}
		if len(rates) >= 1024 {
			return false
		}
	}
	if entry.window.IsZero() || now.Sub(entry.window) >= rateWindow {
		entry = rateEntry{window: now}
	}
	if entry.count >= limit {
		return false
	}
	entry.count++
	rates[sourceIP] = entry
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, output any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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

func decodeBytes(data []byte, output any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("control message exceeds bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode control message: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("control message has trailing data")
	}
	return nil
}

func writeWebSocket(ctx context.Context, conn *websocket.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func writePublicError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}{Code: code, Error: message})
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return strings.TrimSpace(address)
}

func (h *Handler) clientIP(request *http.Request) (string, error) {
	immediate, err := parseAddress(remoteIP(request.RemoteAddr))
	if err != nil {
		return "", err
	}
	if !h.isTrustedProxy(immediate) {
		return immediate.String(), nil
	}

	var derived []netip.Addr
	for _, header := range []string{"Forwarded", "X-Forwarded-For"} {
		values := request.Header.Values(header)
		if len(values) == 0 {
			continue
		}
		chain, err := forwardedAddresses(header, values)
		if err != nil {
			return "", err
		}
		derived = append(derived, h.rightmostUntrusted(immediate, chain))
	}
	if len(derived) == 0 {
		return immediate.String(), nil
	}
	for _, address := range derived[1:] {
		if address != derived[0] {
			return "", errors.New("forwarded client address headers disagree")
		}
	}
	return derived[0].String(), nil
}

func (h *Handler) rightmostUntrusted(immediate netip.Addr, chain []netip.Addr) netip.Addr {
	current := immediate
	for index := len(chain) - 1; index >= 0; index-- {
		if !h.isTrustedProxy(current) {
			return current
		}
		current = chain[index]
	}
	return current
}

func (h *Handler) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range h.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func forwardedAddresses(header string, values []string) ([]netip.Addr, error) {
	joined := strings.Join(values, ",")
	if len(joined) == 0 || len(joined) > maxForwardedBytes {
		return nil, errors.New("forwarded address chain exceeds bounds")
	}
	elements := strings.Split(joined, ",")
	if len(elements) > maxForwardedHops {
		return nil, errors.New("forwarded address chain exceeds bounds")
	}
	addresses := make([]netip.Addr, 0, len(elements))
	for _, element := range elements {
		value := strings.TrimSpace(element)
		if header == "Forwarded" {
			value = ""
			found := false
			for _, parameter := range strings.Split(element, ";") {
				name, candidate, ok := strings.Cut(parameter, "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(name), "for") {
					continue
				}
				if found {
					return nil, errors.New("forwarded element has multiple for parameters")
				}
				found = true
				value = strings.TrimSpace(candidate)
			}
			if !found || value == "" {
				return nil, errors.New("forwarded element has no for parameter")
			}
		}
		if strings.HasPrefix(value, `"`) {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				return nil, errors.New("invalid quoted forwarded address")
			}
			value = unquoted
		}
		address, err := parseAddress(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func parseAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, errors.New("invalid forwarded IP address")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("invalid forwarded IP address")
	}
	return address.Unmap(), nil
}
