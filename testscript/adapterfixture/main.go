package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/securefile"
)

const (
	wireVersion       = 1
	wireVersionHeader = "X-PX-IPC-Version"
	wireAdapterHeader = "X-PX-Adapter-ID"
	actionApprove     = "enrollment.approve"
	maxFactPage       = 203

	stateAdmitted  = "admitted"
	stateCommitted = "committed"
	stateRejected  = "rejected"

	codeCursorExpired  = "cursor_expired"
	codeReceiptExpired = "receipt_expired"
	codeReceiptMissing = "receipt_not_found"
	codeConflict       = "request_conflict"
	codeOutcomeUnknown = "outcome_unknown"
)

var (
	commandIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	enrollmentPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	adapterPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	labelPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	errMarkerReceived = errors.New("doorbell marker received")
)

type state struct {
	Version         int                `json:"version"`
	Cursor          int64              `json:"cursor"`
	HighWater       int64              `json:"high_water"`
	LastCommandID   string             `json:"last_command_id,omitempty"`
	AppliedFactIDs  map[string]bool    `json:"applied_fact_ids"`
	Pending         map[string]pending `json:"pending"`
	ProviderEffects map[string]string  `json:"provider_effects"`
	PendingCommand  *approvalRequest   `json:"pending_command,omitempty"`
	ResponseStarted bool               `json:"response_started,omitempty"`
}

type apiError struct {
	Version   int    `json:"version"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	CommandID string `json:"command_id,omitempty"`
	Floor     int64  `json:"floor,omitempty"`
	HighWater int64  `json:"high_water,omitempty"`
	Status    int    `json:"-"`
}

func (e *apiError) Error() string { return e.Message }

type fact struct {
	Seq            int64   `json:"seq"`
	Kind           string  `json:"kind"`
	EnrollmentID   string  `json:"enrollment_id"`
	OccurredAt     string  `json:"occurred_at"`
	DeviceID       string  `json:"device_id"`
	Label          string  `json:"label"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
	MemberRevision *int64  `json:"member_revision,omitempty"`
}

type factPage struct {
	Version   int    `json:"version"`
	Floor     int64  `json:"floor"`
	HighWater int64  `json:"high_water"`
	Facts     []fact `json:"facts"`
}

type pending struct {
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	Label        string `json:"label"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
}

type pendingSnapshot struct {
	Version   int       `json:"version"`
	HighWater int64     `json:"high_water"`
	Pending   []pending `json:"pending"`
}

type approvalRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Action        string `json:"action"`
	CommandID     string `json:"command_id"`
	EnrollmentID  string `json:"enrollment_id"`
}

type approvalResult struct {
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	Label        string `json:"label"`
	Revision     int64  `json:"revision"`
}

type command struct {
	Version       int             `json:"version"`
	SchemaVersion int             `json:"schema_version"`
	Action        string          `json:"action"`
	CommandID     string          `json:"command_id"`
	EnrollmentID  string          `json:"enrollment_id"`
	State         string          `json:"state"`
	AdmittedAt    string          `json:"admitted_at"`
	SettledAt     *string         `json:"settled_at,omitempty"`
	RejectionCode *string         `json:"rejection_code,omitempty"`
	Result        *approvalResult `json:"result,omitempty"`
}

type doorbell struct {
	Version        int  `json:"version"`
	ReplayRequired bool `json:"replay_required"`
}

type wireClient struct {
	http       *http.Client
	endpoint   string
	adapterID  string
	credential string
}

func main() {
	endpoint := flag.String("endpoint", "", "adapter IPC endpoint")
	adapterID := flag.String("adapter", "", "permanent adapter ID")
	credentialFile := flag.String("credential-file", "", "owner-only adapter credential file")
	stateFile := flag.String("state", "", "durable fixture state")
	enrollmentID := flag.String("enrollment", "", "enrollment ID")
	commandID := flag.String("command-id", "", "command ID for conformance")
	duration := flag.Duration("duration", time.Second, "doorbell duration")
	readyFile := flag.String("ready-file", "", "write after the doorbell stream is established")
	flag.Parse()
	if flag.NArg() != 1 || *endpoint == "" || !adapterPattern.MatchString(*adapterID) || *credentialFile == "" || *stateFile == "" {
		fatal(errors.New("usage: adapter-fixture [flags] sync|approve|approve-drop|conflict|expect-expired|doorbell|stall-doorbell"))
	}
	mutating := flag.Arg(0) == "sync" || flag.Arg(0) == "approve" || flag.Arg(0) == "approve-drop"
	var lock *stateFileLock
	var err error
	if mutating {
		lock, err = acquireStateFileLock(*stateFile, 10*time.Second)
		if err != nil {
			fatal(err)
		}
		defer lock.Close()
	}
	credential, err := readCredential(*credentialFile)
	if err != nil {
		fatal(err)
	}
	client := newWireClient(*endpoint, *adapterID, credential)
	current, err := loadState(*stateFile)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	switch flag.Arg(0) {
	case "sync":
		err = syncFacts(ctx, client, *stateFile, &current)
	case "approve", "approve-drop":
		if !enrollmentPattern.MatchString(*enrollmentID) {
			err = errors.New("--enrollment must be one canonical enrollment ID")
			break
		}
		if flag.Arg(0) == "approve-drop" {
			err = approveDrop(ctx, client, *stateFile, &current, *enrollmentID)
		} else {
			err = approve(ctx, client, *stateFile, &current, *enrollmentID)
		}
	case "conflict", "expect-expired":
		if !enrollmentPattern.MatchString(*enrollmentID) || !commandIDPattern.MatchString(*commandID) {
			err = errors.New("--enrollment and --command-id must be canonical")
			break
		}
		want := codeConflict
		if flag.Arg(0) == "expect-expired" {
			want = codeReceiptExpired
		}
		if want == codeReceiptExpired {
			_, queryErr := client.query(ctx, *commandID)
			var queryResponseError *apiError
			if !errors.As(queryErr, &queryResponseError) || queryResponseError.Code != codeReceiptExpired {
				err = fmt.Errorf("command query returned %v, require %s", queryErr, codeReceiptExpired)
				break
			}
		}
		_, submitErr := client.submit(ctx, approvalRequest{SchemaVersion: 1, Action: actionApprove, CommandID: *commandID, EnrollmentID: *enrollmentID})
		var responseError *apiError
		if !errors.As(submitErr, &responseError) || responseError.Code != want {
			err = fmt.Errorf("command returned %v, require %s", submitErr, want)
		}
	case "doorbell":
		err = client.doorbell(ctx, func() error { return reportReady(*readyFile) }, func(doorbell) error { return errMarkerReceived })
		if errors.Is(err, errMarkerReceived) {
			err = nil
		}
	case "stall-doorbell":
		err = client.stallDoorbell(ctx, *duration, *readyFile)
	default:
		err = errors.New("unknown fixture command")
	}
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(current); err != nil {
		fatal(err)
	}
}

func newWireClient(endpoint, adapterID, credential string) *wireClient {
	return &wireClient{http: localipc.NewClient(endpoint).HTTPClient(), endpoint: endpoint, adapterID: adapterID, credential: credential}
}

func (c *wireClient) replay(ctx context.Context, cursor, highWater int64) (factPage, error) {
	path := fmt.Sprintf("/v1/facts?cursor=%d&high_water=%d&limit=%d", cursor, highWater, maxFactPage)
	var page factPage
	if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return page, err
	}
	if page.Version != wireVersion || page.Facts == nil || page.Floor < 0 || page.Floor > cursor || page.HighWater < cursor || highWater != 0 && page.HighWater != highWater || len(page.Facts) > maxFactPage {
		return factPage{}, errors.New("invalid fact page envelope")
	}
	previous := cursor
	seen := make(map[string]bool, len(page.Facts))
	for _, item := range page.Facts {
		identity := item.Kind + "\x00" + item.EnrollmentID
		if item.Seq <= previous || item.Seq > page.HighWater || seen[identity] || !validFact(item) {
			return factPage{}, errors.New("invalid fact page item")
		}
		seen[identity] = true
		previous = item.Seq
	}
	return page, nil
}

func (c *wireClient) snapshot(ctx context.Context) (pendingSnapshot, error) {
	var snapshot pendingSnapshot
	if err := c.do(ctx, http.MethodGet, "/v1/pending", nil, &snapshot); err != nil {
		return snapshot, err
	}
	if snapshot.Version != wireVersion || snapshot.Pending == nil || snapshot.HighWater < 0 || len(snapshot.Pending) > 64 {
		return pendingSnapshot{}, errors.New("invalid pending snapshot envelope")
	}
	enrollments := make(map[string]bool, len(snapshot.Pending))
	devices := make(map[string]bool, len(snapshot.Pending))
	labels := make(map[string]bool, len(snapshot.Pending))
	for _, item := range snapshot.Pending {
		labelKey := strings.ToLower(item.Label)
		if !validPending(item) || enrollments[item.EnrollmentID] || devices[item.DeviceID] || labels[labelKey] {
			return pendingSnapshot{}, errors.New("invalid pending snapshot item")
		}
		enrollments[item.EnrollmentID] = true
		devices[item.DeviceID] = true
		labels[labelKey] = true
	}
	return snapshot, nil
}

func (c *wireClient) submit(ctx context.Context, request approvalRequest) (command, error) {
	var result command
	if err := c.do(ctx, http.MethodPost, "/v1/commands", request, &result); err != nil {
		return result, err
	}
	if !validCommand(result, request.CommandID, request.EnrollmentID) {
		return command{}, &apiError{Version: 1, Code: codeOutcomeUnknown, Message: "approval outcome unknown", CommandID: request.CommandID}
	}
	return result, nil
}

func (c *wireClient) query(ctx context.Context, commandID string) (command, error) {
	var result command
	if err := c.do(ctx, http.MethodGet, "/v1/commands/"+commandID, nil, &result); err != nil {
		return result, err
	}
	if !validCommand(result, commandID, "") {
		return command{}, errors.New("invalid command query response")
	}
	return result, nil
}

func (c *wireClient) do(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://px.local"+path, body)
	if err != nil {
		return err
	}
	c.setHeaders(request)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, localipc.MaxResponseBytes+1))
	if err != nil || len(data) > localipc.MaxResponseBytes {
		return errors.New("adapter response unavailable or oversized")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var responseError apiError
		if strictDecode(data, &responseError) != nil || responseError.Version != wireVersion || responseError.Code == "" || responseError.Message == "" {
			return errors.New("invalid adapter error response")
		}
		responseError.Status = response.StatusCode
		return &responseError
	}
	return strictDecode(data, output)
}

func (c *wireClient) setHeaders(request *http.Request) {
	request.Header.Set(wireVersionHeader, "1")
	request.Header.Set(wireAdapterHeader, c.adapterID)
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Accept", "application/json")
	if request.Body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
}

func (c *wireClient) submitAndDrop(ctx context.Context, request approvalRequest) error {
	connection, err := localipc.Dial(ctx, c.endpoint)
	if err != nil {
		return err
	}
	defer connection.Close()
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://px.local/v1/commands", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	c.setHeaders(httpRequest)
	if err := httpRequest.Write(connection); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), httpRequest)
	if err != nil {
		return fmt.Errorf("read approval response status and headers: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("approval response started with %s", response.Status)
	}
	// Deliberately close the transport without reading or accepting the body.
	return nil
}

func (c *wireClient) doorbell(ctx context.Context, ready func() error, event func(doorbell) error) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://px.local/v1/doorbell", nil)
	if err != nil {
		return err
	}
	c.setHeaders(request)
	request.Header.Set("Accept", "application/x-ndjson")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("doorbell rejected")
	}
	if err := ready(); err != nil {
		return err
	}
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	for {
		var marker doorbell
		if err := decoder.Decode(&marker); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("doorbell disconnected; replay required")
		}
		if marker.Version != wireVersion || !marker.ReplayRequired {
			return errors.New("invalid doorbell marker")
		}
		if err := event(marker); err != nil {
			return err
		}
	}
}

func (c *wireClient) stallDoorbell(ctx context.Context, duration time.Duration, readyFile string) error {
	stallContext, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	connection, err := localipc.Dial(stallContext, c.endpoint)
	if err != nil {
		return err
	}
	defer connection.Close()
	if bufferSetter, ok := connection.(interface{ SetReadBuffer(int) error }); ok {
		if err := bufferSetter.SetReadBuffer(1); err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(stallContext, http.MethodGet, "http://px.local/v1/doorbell", nil)
	if err != nil {
		return err
	}
	c.setHeaders(request)
	request.Header.Set("Accept", "application/x-ndjson")
	if err := request.Write(connection); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return errors.New("doorbell rejected")
	}
	if err := reportReady(readyFile); err != nil {
		return err
	}
	<-stallContext.Done()
	if deadlineSetter, ok := connection.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineSetter.SetReadDeadline(time.Now().Add(time.Second))
	}
	buffer := make([]byte, 4096)
	for {
		if _, err := connection.Read(buffer); err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				return errors.New("stalled doorbell was not disconnected")
			}
			return nil
		}
	}
}

func reportReady(path string) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, nil, 0o600)
}

func syncFacts(ctx context.Context, client *wireClient, path string, current *state) error {
	for {
		page, err := client.replay(ctx, current.Cursor, current.HighWater)
		var responseError *apiError
		if errors.As(err, &responseError) && responseError.Code == codeCursorExpired {
			if responseError.Floor <= current.Cursor || responseError.HighWater < responseError.Floor {
				return errors.New("incoherent cursor_expired metadata")
			}
			snapshot, snapshotErr := client.snapshot(ctx)
			if snapshotErr != nil {
				return snapshotErr
			}
			if snapshot.HighWater < responseError.HighWater || snapshot.HighWater < responseError.Floor {
				return errors.New("pending snapshot high-water precedes cursor expiry metadata")
			}
			current.Pending = make(map[string]pending, len(snapshot.Pending))
			for _, item := range snapshot.Pending {
				current.Pending[item.EnrollmentID] = item
			}
			current.Cursor, current.HighWater = snapshot.HighWater, 0
			if err := saveState(path, current); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		current.HighWater = page.HighWater
		for _, item := range page.Facts {
			identity := item.Kind + ":" + item.EnrollmentID
			if !current.AppliedFactIDs[identity] {
				current.AppliedFactIDs[identity] = true
				if item.Kind == "enrollment.pending_admitted" {
					current.Pending[item.EnrollmentID] = pending{EnrollmentID: item.EnrollmentID, DeviceID: item.DeviceID, Label: item.Label, CreatedAt: item.OccurredAt, ExpiresAt: *item.ExpiresAt}
				} else {
					delete(current.Pending, item.EnrollmentID)
				}
			}
			current.Cursor = item.Seq
		}
		if err := saveState(path, current); err != nil {
			return err
		}
		if current.Cursor == page.HighWater {
			current.HighWater = 0
			return saveState(path, current)
		}
	}
}

func approveDrop(ctx context.Context, client *wireClient, path string, current *state, enrollmentID string) error {
	request, err := ownCommand(path, current, enrollmentID)
	if err != nil {
		return err
	}
	if err := client.submitAndDrop(ctx, *request); err != nil {
		return err
	}
	current.ResponseStarted = true
	if err := saveState(path, current); err != nil {
		return err
	}
	return &apiError{Version: 1, Code: codeOutcomeUnknown, Message: "approval outcome unknown; restart and query or resubmit the exact unchanged request", CommandID: request.CommandID}
}

func approve(ctx context.Context, client *wireClient, path string, current *state, enrollmentID string) error {
	request := current.PendingCommand
	var result command
	var err error
	if request != nil {
		if request.EnrollmentID != enrollmentID {
			return errors.New("another exact approval command requires recovery")
		}
		result, err = client.query(ctx, request.CommandID)
		var responseError *apiError
		if errors.As(err, &responseError) && responseError.Code == codeReceiptMissing {
			if current.ResponseStarted {
				return errors.New("response-started command receipt is unexpectedly missing")
			}
			result, err = client.submit(ctx, *request)
		}
	} else {
		request, err = ownCommand(path, current, enrollmentID)
		if err == nil {
			result, err = client.submit(ctx, *request)
		}
	}
	if err != nil {
		return err
	}
	if result.State == stateAdmitted {
		result, err = client.submit(ctx, *request)
		if err != nil {
			return err
		}
	}
	if result.State == stateCommitted {
		current.ProviderEffects[request.CommandID] = result.EnrollmentID
	}
	current.PendingCommand = nil
	current.ResponseStarted = false
	return saveState(path, current)
}

func ownCommand(path string, current *state, enrollmentID string) (*approvalRequest, error) {
	if current.PendingCommand != nil {
		return current.PendingCommand, nil
	}
	commandID, err := nextUUIDv7(current.LastCommandID, time.Now())
	if err != nil {
		return nil, err
	}
	current.LastCommandID = commandID
	current.PendingCommand = &approvalRequest{SchemaVersion: 1, Action: actionApprove, CommandID: commandID, EnrollmentID: enrollmentID}
	if err := saveState(path, current); err != nil {
		return nil, err
	}
	return current.PendingCommand, nil
}

func validFact(item fact) bool {
	if item.Seq <= 0 || !enrollmentPattern.MatchString(item.EnrollmentID) || !validDeviceID(item.DeviceID) || !labelPattern.MatchString(item.Label) || !validWireTime(item.OccurredAt) {
		return false
	}
	switch item.Kind {
	case "enrollment.pending_admitted":
		if item.ExpiresAt == nil || item.MemberRevision != nil || !validWireTime(*item.ExpiresAt) {
			return false
		}
		expires, _ := time.Parse(time.RFC3339, *item.ExpiresAt)
		occurred, _ := time.Parse(time.RFC3339, item.OccurredAt)
		return expires.After(occurred)
	case "enrollment.pending_expired":
		return item.ExpiresAt == nil && item.MemberRevision == nil
	case "enrollment.member_approved":
		return item.ExpiresAt == nil && item.MemberRevision != nil && *item.MemberRevision == 1
	case "enrollment.member_revoked":
		return item.ExpiresAt == nil && item.MemberRevision != nil && *item.MemberRevision > 1
	default:
		return false
	}
}

func validPending(item pending) bool {
	if !enrollmentPattern.MatchString(item.EnrollmentID) || !validDeviceID(item.DeviceID) || !labelPattern.MatchString(item.Label) || !validWireTime(item.CreatedAt) || !validWireTime(item.ExpiresAt) {
		return false
	}
	created, _ := time.Parse(time.RFC3339, item.CreatedAt)
	expires, _ := time.Parse(time.RFC3339, item.ExpiresAt)
	return created.Before(expires)
}

func validCommand(result command, commandID, enrollmentID string) bool {
	if result.Version != wireVersion || result.SchemaVersion != 1 || result.Action != actionApprove || result.CommandID != commandID || !commandIDPattern.MatchString(result.CommandID) || !enrollmentPattern.MatchString(result.EnrollmentID) || enrollmentID != "" && result.EnrollmentID != enrollmentID || !validWireTime(result.AdmittedAt) {
		return false
	}
	switch result.State {
	case stateAdmitted:
		return result.SettledAt == nil && result.RejectionCode == nil && result.Result == nil
	case stateCommitted:
		return validSettlement(result) && result.RejectionCode == nil && result.Result != nil && result.Result.EnrollmentID == result.EnrollmentID && validDeviceID(result.Result.DeviceID) && labelPattern.MatchString(result.Result.Label) && result.Result.Revision == 1
	case stateRejected:
		return validSettlement(result) && result.RejectionCode != nil && validRejection(*result.RejectionCode) && result.Result == nil
	default:
		return false
	}
}

func validSettlement(result command) bool {
	if result.SettledAt == nil || !validWireTime(*result.SettledAt) {
		return false
	}
	admitted, _ := time.Parse(time.RFC3339, result.AdmittedAt)
	settled, _ := time.Parse(time.RFC3339, *result.SettledAt)
	return !settled.Before(admitted)
}

func validDeviceID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validRejection(code string) bool {
	switch code {
	case "enrollment_expired", "settled_elsewhere", "not_pending", "member_capacity", "invalid_enrollment_key":
		return true
	default:
		return false
	}
}

func validWireTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Nanosecond() == 0 && parsed.Format(time.RFC3339) == value
}

func strictDecode(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("response has trailing data")
	}
	return validateWirePresence(data, output)
}

func validateWirePresence(data []byte, output any) error {
	fields, err := requiredObject(data)
	if err != nil {
		return err
	}
	require := func(names ...string) error {
		for _, name := range names {
			value, exists := fields[name]
			if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("missing or null required field %q", name)
			}
		}
		return nil
	}
	rejectOptionalNull := func(names ...string) error {
		for _, name := range names {
			if value, exists := fields[name]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("null optional field %q", name)
			}
		}
		return nil
	}
	switch value := output.(type) {
	case *factPage:
		if err := require("version", "floor", "high_water", "facts"); err != nil {
			return err
		}
		var facts []json.RawMessage
		if err := json.Unmarshal(fields["facts"], &facts); err != nil {
			return err
		}
		for _, raw := range facts {
			factFields, err := requiredObject(raw)
			if err != nil {
				return err
			}
			for _, name := range []string{"seq", "kind", "enrollment_id", "occurred_at", "device_id", "label"} {
				item, exists := factFields[name]
				if !exists || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return fmt.Errorf("missing or null fact field %q", name)
				}
			}
			for _, name := range []string{"expires_at", "member_revision"} {
				if item, exists := factFields[name]; exists && bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return fmt.Errorf("null optional fact field %q", name)
				}
			}
		}
	case *pendingSnapshot:
		if err := require("version", "high_water", "pending"); err != nil {
			return err
		}
		var pendingItems []json.RawMessage
		if err := json.Unmarshal(fields["pending"], &pendingItems); err != nil {
			return err
		}
		for _, raw := range pendingItems {
			itemFields, err := requiredObject(raw)
			if err != nil {
				return err
			}
			for _, name := range []string{"enrollment_id", "device_id", "label", "created_at", "expires_at"} {
				item, exists := itemFields[name]
				if !exists || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return fmt.Errorf("missing or null pending field %q", name)
				}
			}
		}
	case *command:
		if err := require("version", "schema_version", "action", "command_id", "enrollment_id", "state", "admitted_at"); err != nil {
			return err
		}
		if err := rejectOptionalNull("settled_at", "rejection_code", "result"); err != nil {
			return err
		}
		if _, exists := fields["result"]; exists {
			resultFields, err := requiredObject(fields["result"])
			if err != nil {
				return err
			}
			for _, name := range []string{"enrollment_id", "device_id", "label", "revision"} {
				item, exists := resultFields[name]
				if !exists || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return fmt.Errorf("missing or null result field %q", name)
				}
			}
		}
	case *apiError:
		if err := require("version", "code", "message"); err != nil {
			return err
		}
		if err := rejectOptionalNull("command_id", "floor", "high_water"); err != nil {
			return err
		}
		if value.Code == codeCursorExpired {
			if err := require("floor", "high_water"); err != nil {
				return err
			}
		}
		if value.Code == codeOutcomeUnknown {
			return require("command_id")
		}
	case *doorbell:
		return require("version", "replay_required")
	case *state:
		if err := require("version", "cursor", "high_water", "applied_fact_ids", "pending", "provider_effects"); err != nil {
			return err
		}
		return rejectOptionalNull("last_command_id", "pending_command", "response_started")
	}
	return nil
}

func requiredObject(data []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errors.New("JSON value must be an object")
	}
	return fields, nil
}

func nextUUIDv7(previous string, now time.Time) (string, error) {
	milliseconds := uint64(now.UnixMilli())
	sequence := uint64(1)
	if previous != "" {
		if !commandIDPattern.MatchString(previous) {
			return "", errors.New("invalid persisted UUIDv7 high-water")
		}
		previousMilliseconds, _ := strconv.ParseUint(previous[:8]+previous[9:13], 16, 48)
		previousSequence, _ := strconv.ParseUint(previous[24:], 16, 48)
		if previousMilliseconds > milliseconds {
			milliseconds = previousMilliseconds
		}
		if previousMilliseconds == milliseconds {
			sequence = previousSequence + 1
		}
	}
	if milliseconds >= 1<<48 || sequence >= 1<<48 {
		return "", errors.New("monotonic UUIDv7 sequence exhausted")
	}
	return fmt.Sprintf("%08x-%04x-7000-8000-%012x", uint32(milliseconds>>16), uint16(milliseconds), sequence), nil
}

func readCredential(path string) (string, error) {
	data, err := securefile.ReadOwnerOnly(path)
	if err != nil {
		return "", fmt.Errorf("insecure adapter credential file: %w", err)
	}
	credential := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(credential, "\r\n") {
		return "", errors.New("adapter credential file must contain one credential")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != credential {
		return "", errors.New("invalid adapter credential")
	}
	return credential, nil
}

func loadState(path string) (state, error) {
	result := state{Version: 1, AppliedFactIDs: map[string]bool{}, Pending: map[string]pending{}, ProviderEffects: map[string]string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return state{}, err
	}
	if err := strictDecode(data, &result); err != nil || result.Version != 1 || result.AppliedFactIDs == nil || result.Pending == nil || result.ProviderEffects == nil {
		return state{}, errors.New("invalid adapter fixture state")
	}
	return result, nil
}

func saveState(path string, value *state) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := path + ".tmp-" + hex.EncodeToString(random)
	file, err := securefile.CreateExclusive(temporary)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	if err := json.NewEncoder(file).Encode(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceState(temporary, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "adapter-fixture:", err)
	os.Exit(1)
}
