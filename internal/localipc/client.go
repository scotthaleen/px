package localipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/scotthaleen/go-toolbelt/localgateway"
	"github.com/scotthaleen/px/internal/ipcversion"
)

const localDialTimeout = 250 * time.Millisecond

const (
	ServerAdminVersionMismatchMessage = "PX server administration protocol is incompatible; upgrade the older px-server or command so both support the same administration protocol"
)

var (
	AgentVersionMismatchMessage   = fmt.Sprintf("PX agent IPC is incompatible; upgrade or restart the older PX agent or command so both support agent IPC version %d", ipcversion.Agent)
	ErrServerAdminVersionMismatch = errors.New(ServerAdminVersionMismatchMessage)
)

type clientKind uint8

const (
	genericClient clientKind = iota
	agentClient
	serverAdminClient
)

type Client struct {
	client     *http.Client
	kind       clientKind
	ipcVersion string
}

func (c *Client) StreamJSON(ctx context.Context, method, path string, input any, event func(json.RawMessage) error) error {
	return c.streamJSON(ctx, method, path, input, false, event)
}

// StreamNDJSON reads a strict NDJSON response while preserving each raw record
// for callers that relay the versioned framing unchanged.
func (c *Client) StreamNDJSON(ctx context.Context, method, path string, input any, event func(json.RawMessage) error) error {
	return c.streamJSON(ctx, method, path, input, true, event)
}

func (c *Client) streamJSON(ctx context.Context, method, path string, input any, strict bool, event func(json.RawMessage) error) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > MaxRequestBytes {
			return errors.New("encode bounded agent stream request")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, localgateway.BaseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/x-ndjson")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("X-PX-IPC-Version", c.version())
	response, err := c.client.Do(request)
	if err != nil {
		return c.transportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, readErr := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
		if readErr != nil {
			return c.transportError(readErr)
		}
		if c.kind == agentClient && response.StatusCode == http.StatusUpgradeRequired {
			return errors.New(AgentVersionMismatchMessage)
		}
		var responseError Error
		if json.Unmarshal(data, &responseError) != nil || responseError.Message == "" {
			responseError.Message = response.Status
		}
		responseError.Status = response.StatusCode
		return &responseError
	}
	if strict && response.Header.Get("Content-Type") != "application/x-ndjson" {
		return errors.New("agent emitted an invalid NDJSON content type")
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 1024), MaxResponseBytes)
	for scanner.Scan() {
		data := append(json.RawMessage(nil), scanner.Bytes()...)
		if !json.Valid(data) {
			return errors.New("agent emitted invalid JSON event")
		}
		if err := event(data); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return c.transportError(err)
	}
	return nil
}

type Error struct {
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

func NewClient(endpoint string) *Client {
	return newClient(endpoint, genericClient, strconv.Itoa(ipcversion.Agent))
}

// NewAgentClient returns a client whose local transport failures are classified
// and redacted for safe presentation by user-facing commands.
func NewAgentClient(endpoint string) *Client {
	return newClient(endpoint, agentClient, strconv.Itoa(ipcversion.Agent))
}

// NewServerAdminClient returns a client with server-administration transport
// errors that cannot be mistaken for local-agent failures.
func NewServerAdminClient(endpoint string, version int) *Client {
	return newClient(endpoint, serverAdminClient, fmt.Sprint(version))
}

func newClient(endpoint string, kind clientKind, ipcVersion string) *Client {
	client := localgateway.NewClient(endpoint, localgateway.ClientConfig{DialTimeout: localDialTimeout})
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.DisableKeepAlives = true
	}
	client.Transport = normalizingTransport{base: client.Transport}
	return &Client{client: client, kind: kind, ipcVersion: ipcVersion}
}

type normalizingTransport struct{ base http.RoundTripper }

func (t normalizingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	return response, normalizeDialError(request.Context(), err)
}

// HTTPClient exposes the bounded local transport for protocol-specific clients.
// Callers remain responsible for protocol headers and body limits.
func (c *Client) HTTPClient() *http.Client { return c.client }

// Dial opens one protected local endpoint connection for protocol conformance
// clients that must control response handling themselves.
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, localDialTimeout)
	defer cancel()
	connection, err := localgateway.Dial(dialContext, endpoint)
	return connection, normalizeDialError(ctx, err)
}

func (c *Client) JSON(ctx context.Context, method, path string, input, output any) error {
	return c.json(ctx, method, path, input, output, false)
}

// JSONStrict rejects unknown response fields in addition to malformed or
// trailing JSON. It is intended for stable security-sensitive DTOs.
func (c *Client) JSONStrict(ctx context.Context, method, path string, input, output any) error {
	return c.json(ctx, method, path, input, output, true)
}

func (c *Client) json(ctx context.Context, method, path string, input, output any, strict bool) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode agent request: %w", err)
		}
		if len(encoded) > MaxRequestBytes {
			return fmt.Errorf("agent request is %d bytes, limit is %d", len(encoded), MaxRequestBytes)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, localgateway.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("create agent request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-PX-IPC-Version", c.version())
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return c.transportError(err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, MaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return c.transportError(err)
	}
	if len(data) > MaxResponseBytes {
		return errors.New("agent response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if c.kind == agentClient && response.StatusCode == http.StatusUpgradeRequired {
			return errors.New(AgentVersionMismatchMessage)
		}
		if c.kind == serverAdminClient && response.StatusCode == http.StatusUpgradeRequired {
			return ErrServerAdminVersionMismatch
		}
		var responseError Error
		if json.Unmarshal(data, &responseError) != nil || responseError.Message == "" {
			responseError.Message = response.Status
		}
		responseError.Status = response.StatusCode
		return &responseError
	}
	if output != nil {
		if strict {
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(output); err != nil {
				return fmt.Errorf("decode agent response: %w", err)
			}
			if decoder.Decode(&struct{}{}) != io.EOF {
				return errors.New("decode agent response: trailing data")
			}
		} else if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode agent response: %w", err)
		}
	}
	return nil
}

func (c *Client) version() string {
	if c.ipcVersion == "" {
		if c.kind == agentClient || c.kind == genericClient {
			return strconv.Itoa(ipcversion.Agent)
		}
		return "1"
	}
	return c.ipcVersion
}

func (c *Client) transportError(err error) error {
	switch c.kind {
	case agentClient:
		return redactAgentTransportError(err)
	case serverAdminClient:
		return redactServerAdminTransportError(err)
	default:
		return redactLocalTransportError(err)
	}
}

func normalizeDialError(parent context.Context, err error) error {
	if err == nil {
		return nil
	}
	if parentErr := parent.Err(); parentErr != nil {
		return parentErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errLocalDialTimeout
	}
	return err
}
