package contexts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coder/websocket"
	"github.com/scotthaleen/go-app"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/benchmark"
	"github.com/scotthaleen/px/internal/contextwatch"
	"github.com/scotthaleen/px/internal/diagnostics"
	"github.com/scotthaleen/px/internal/direct"
	"github.com/scotthaleen/px/internal/getcleanup"
	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/inbox"
	"github.com/scotthaleen/px/internal/inviteapi"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/offered"
	"github.com/scotthaleen/px/internal/ping"
	"github.com/scotthaleen/px/internal/probe"
	"github.com/scotthaleen/px/internal/put"
	"github.com/scotthaleen/px/internal/putroot"
	"github.com/scotthaleen/px/internal/recent"
	"github.com/scotthaleen/px/internal/rendezvousproto"
	"github.com/scotthaleen/px/internal/signalproto"
	"github.com/scotthaleen/px/internal/transfer"
)

const (
	pollInterval             = 5 * time.Second
	maxHTTPBody              = 64 << 10
	contextProjectionReserve = 4 << 10
	contextProjectionSize    = localipc.MaxResponseBytes - contextProjectionReserve
	MaxContexts              = 64
	MaxAliasesPerContext     = 64
	EnvCAFile                = "PX_CA_FILE"
)

var (
	// DefaultSTUNURL may be replaced with -ldflags -X for deployment-specific client builds.
	DefaultSTUNURL                = "stun:stun.l.google.com:19302"
	ErrContextDisconnected        = errors.New("context is not connected")
	ErrContextActive              = errors.New("context has an active root operation")
	ErrContextAuthorityBlocked    = errors.New("context offered-root authority change is blocked by durable public-send state")
	ErrAliasNotFound              = errors.New("context alias not found")
	ErrInvalidConfiguration       = errors.New("invalid context configuration")
	ErrInvalidAlias               = errors.New("invalid context alias")
	ErrInvalidContextState        = errors.New("invalid context state")
	ErrOperationRejected          = errors.New("context operation rejected")
	ErrMemberOperationCapacity    = errors.New("context member-operation capacity reached")
	ErrApprovalOutcomeUnknown     = errors.New("approval outcome unknown; inspect devices list or devices pending before retrying")
	ErrInviteCreateOutcomeUnknown = errors.New("invite creation outcome_unknown: issuance may have committed but the one-time token cannot be recovered; list active invites, revoke the unrecoverable invite, and create a replacement")
	ErrInviteRevokeOutcomeUnknown = errors.New("invite revocation outcome_unknown: revocation may have committed; list active invites before deciding whether another action is needed")
	ErrPeerUnknown                = errors.New("peer is not enrolled in the selected context")
	ErrPeerOffline                = errors.New("peer is enrolled but offline in the selected context")
	ErrPeerSelf                   = errors.New("peer resolves to the local device in the selected context")
	ErrContextCapacity            = errors.New("context capacity reached")
	ErrAliasCapacity              = errors.New("context alias capacity reached")
	ErrContextProjection          = errors.New("context configuration exceeds the local IPC projection limit")
)

type Manager struct {
	paths          apphome.Paths
	database       func() *sql.DB
	logger         *slog.Logger
	client         *http.Client
	clientErr      error
	lifecycle      sync.Mutex
	shutdownMu     sync.Mutex
	inboxMovesMu   sync.Mutex
	inboxMoves     map[string]*inboxMoveLock
	stopping       bool
	mu             sync.Mutex
	runtime        context.Context
	cancel         context.CancelFunc
	workers        map[string]*contextWorker
	controls       map[string]*controlConnection
	active         map[string]activeOperations
	activeDone     map[string]chan struct{}
	transferOps    map[string]*runtimeTransfer
	activated      bool
	pending        []string
	transfers      *transfer.ResumeStore
	puts           *put.Store
	getCleanup     *getcleanup.Store
	recent         *recent.Store
	watchOnce      sync.Once
	watch          *contextwatch.Hub
	incoming       chan struct{}
	policy         connectionPolicy
	writeProbe     func(string) error
	recentLease    func()
	recentQuery    func()
	recentDeadline time.Duration
	mutations      sync.WaitGroup
	wg             sync.WaitGroup
}

type runtimeTransfer struct {
	item   transfer.InventoryItem
	cancel context.CancelFunc
	phase  string
}

type inboxMoveLock struct {
	token chan struct{}
	refs  int
}

type operationScope uint8

const (
	operationOffered operationScope = 1 << iota
	operationInbox
	operationPut
)

type activeOperations struct {
	total   int
	offered int
	inbox   int
	put     int
}

type contextWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type State struct {
	Name                       string                 `json:"name"`
	ServerURL                  string                 `json:"server_url"`
	ServerID                   string                 `json:"server_id"`
	DeviceID                   string                 `json:"device_id"`
	Label                      string                 `json:"label"`
	Credential                 *membership.Credential `json:"-"`
	PendingCode                string                 `json:"pending_code,omitempty"`
	ExpiresAt                  *time.Time             `json:"expires_at,omitempty"`
	State                      string                 `json:"state"`
	Enabled                    bool                   `json:"enabled"`
	OfferedRoot                string                 `json:"offered_root"`
	OfferedRootScope           string                 `json:"offered_root_scope"`
	OfferedRootRevision        int64                  `json:"offered_root_revision"`
	FilesystemRootAcknowledged bool                   `json:"filesystem_root_acknowledged"`
	OfferedRootAuthorityValid  bool                   `json:"offered_root_authority_valid"`
	InboxRoot                  string                 `json:"inbox_root"`
	PutRoot                    *string                `json:"put_root"`
	AllowPut                   bool                   `json:"allow_put"`
	PutRootRevision            int64                  `json:"put_root_revision"`
	PutRootAuthorityValid      bool                   `json:"put_root_authority_valid"`
	STUNURLs                   []string               `json:"stun_urls,omitempty"`
	Aliases                    map[string]string      `json:"aliases"`
	CreatedAt                  time.Time              `json:"created_at"`
	UpdatedAt                  time.Time              `json:"updated_at"`
	privatePath                string
	publicPath                 string
}

type Alias struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

type Configuration struct {
	Name                       string   `json:"name"`
	IsDefault                  bool     `json:"is_default"`
	ServerOrigin               string   `json:"server_origin"`
	ServerID                   string   `json:"server_id"`
	DeviceID                   string   `json:"device_id"`
	Label                      string   `json:"label"`
	Enabled                    bool     `json:"enabled"`
	State                      string   `json:"state"`
	OfferedRoot                string   `json:"offered_root"`
	OfferedRootScope           string   `json:"offered_root_scope"`
	OfferedRootRevision        int64    `json:"offered_root_revision"`
	FilesystemRootAcknowledged bool     `json:"filesystem_root_acknowledged"`
	OfferedRootAuthorityValid  bool     `json:"offered_root_authority_valid"`
	InboxRoot                  string   `json:"inbox_root"`
	PutRoot                    *string  `json:"put_root"`
	AllowPut                   bool     `json:"allow_put"`
	PutRootRevision            int64    `json:"put_root_revision"`
	PutRootAuthorityValid      bool     `json:"put_root_authority_valid"`
	STUNURLs                   []string `json:"stun_urls"`
	Aliases                    []Alias  `json:"aliases"`
	Warnings                   []string `json:"warnings,omitempty"`
}

type UpdateRequest struct {
	OfferedRoot         *string   `json:"offered_root,omitempty"`
	InboxRoot           *string   `json:"inbox_root,omitempty"`
	STUNURLs            *[]string `json:"stun_urls,omitempty"`
	AllowFilesystemRoot bool      `json:"allow_filesystem_root,omitempty"`
	PutRoot             *string   `json:"put_root,omitempty"`
	ClearPutRoot        bool      `json:"clear_put_root,omitempty"`
	AllowPut            *bool     `json:"allow_put,omitempty"`
}

type JoinRequest struct {
	Name                string   `json:"name"`
	ServerURL           string   `json:"server_url"`
	Label               string   `json:"label"`
	OfferedRoot         string   `json:"offered_root"`
	InboxRoot           string   `json:"inbox_root"`
	STUNURLs            []string `json:"stun_urls,omitempty"`
	DefaultSTUN         bool     `json:"default_stun,omitempty"`
	NoSTUN              bool     `json:"no_stun,omitempty"`
	RequireUnchanged    bool     `json:"require_unchanged,omitempty"`
	RequireExisting     bool     `json:"require_existing,omitempty"`
	Invite              string   `json:"invite,omitempty"`
	AllowFilesystemRoot bool     `json:"allow_filesystem_root,omitempty"`
	PutRoot             *string  `json:"put_root,omitempty"`
	AllowPut            bool     `json:"allow_put,omitempty"`
	AllowPutSet         bool     `json:"allow_put_set,omitempty"`
}

type controlMessage = rendezvousproto.ControlMessage

type Peer struct {
	Label    string   `json:"label"`
	DeviceID string   `json:"device_id"`
	Aliases  []string `json:"aliases"`
}

type StatusSnapshot struct {
	Context   *StatusContext
	Transfers *transfer.Counts
}

type StatusContext struct {
	Name                      string
	State                     string
	Enabled                   bool
	OnlinePeers               *int
	OfferedRootScope          string
	OfferedRootAuthorityValid bool
	AllowPut                  bool
	PutRootAuthorityValid     bool
}

type Device struct {
	Label     string    `json:"label"`
	DeviceID  string    `json:"device_id"`
	Aliases   []string  `json:"aliases"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type PendingDevice struct {
	Code      string    `json:"code"`
	Label     string    `json:"label"`
	DeviceID  string    `json:"device_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type controlConnection struct {
	manager  *Manager
	context  State
	ctx      context.Context
	conn     *websocket.Conn
	writes   contextWriteGate
	mu       sync.Mutex
	peers    map[string]membership.Member
	sessions map[string]*contextSignaler
	waiters  map[string]controlWaiter
}

type controlWaiter struct {
	operation string
	response  chan controlResponse
}

type controlResponse struct {
	message controlMessage
	data    []byte
	err     error
}

type InviteError struct {
	Code    string
	Message string
}

func (e *InviteError) Error() string { return e.Message }

type contextWriteGate struct {
	once  sync.Once
	token chan struct{}
}

func (g *contextWriteGate) run(ctx context.Context, write func() error) (bool, error) {
	g.once.Do(func() {
		g.token = make(chan struct{}, 1)
		g.token <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-g.token:
	}
	defer func() { g.token <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, write()
}

type contextSignaler struct {
	control  *controlConnection
	session  string
	peerID   string
	ctx      context.Context
	cancel   context.CancelFunc
	incoming chan []byte
	once     sync.Once
}

func NewManager(paths apphome.Paths, database func() *sql.DB, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	client, clientErr := rendezvousHTTPClient()
	transfers := transfer.NewResumeStore(database, paths.AgentTransfers)
	puts := put.NewStore(database)
	puts.SetOutcomeUnknown(func(id string) {
		logger.Error("remote put publication outcome is unknown", "event", "put.outcome_unknown", "transfer_id", id)
	})
	puts.SetResolved(func(event put.ResolutionEvent) {
		logger.Warn("accepted current put destination as local final state", "event", event.Type, "transfer_id", event.TransferID, "context", event.Context)
	})
	recentStore := recent.NewStore(database)
	transfers.SetObservationWriter(func(ctx context.Context, value transfer.TransferObservation) error {
		return recentStore.Insert(ctx, recentFromTransfer(value))
	}, func(ctx context.Context, tx *sql.Tx, value transfer.TransferObservation) error {
		return recentStore.InsertTx(ctx, tx, recentFromTransfer(value))
	})
	transfers.SetSharedSenderMaintenance(puts.ExpireSenders)
	puts.SetSharedSenderMaintenance(transfers.ExpireSenders)
	return &Manager{
		paths: paths, database: database, logger: logger,
		client: client, clientErr: clientErr, workers: make(map[string]*contextWorker),
		controls: make(map[string]*controlConnection), active: make(map[string]activeOperations), activeDone: make(map[string]chan struct{}), transferOps: make(map[string]*runtimeTransfer), transfers: transfers, puts: puts, recent: recentStore, watch: contextwatch.NewHub(), incoming: make(chan struct{}, 4), getCleanup: getcleanup.NewStore(database, getcleanup.WithNotifications(func(result getcleanup.ReapResult) {
			logger.Warn("expired get staging remains unresolved", "event", "get.cleanup_expired", "examined", result.Examined, "removed", result.Removed, "retained", result.Retained, "expired", result.Expired)
		})),
		policy: defaultConnectionPolicy(), writeProbe: probeRootWrite,
	}
}

func recentFromTransfer(value transfer.TransferObservation) recent.Observation {
	return recent.Observation{Context: value.Context, Direction: value.Direction, TransferID: value.TransferID, Kind: value.Kind, PeerDeviceID: value.PeerDeviceID, PeerLabel: value.PeerLabel, Destination: value.Destination, Visibility: string(value.Visibility), Bytes: value.Bytes, ObservedAt: value.ObservedAt}
}

func rendezvousHTTPClient() (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system TLS trust store: %w", err)
	}
	if roots == nil {
		return nil, errors.New("load system TLS trust store: no certificate pool")
	}
	if certificateFile := os.Getenv(EnvCAFile); certificateFile != "" {
		certificates, err := os.ReadFile(certificateFile)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", EnvCAFile, err)
		}
		if !roots.AppendCertsFromPEM(certificates) {
			return nil, fmt.Errorf("load %s: file contains no valid certificates", EnvCAFile)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{RootCAs: roots}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (m *Manager) Component() *app.Component {
	return app.NewComponent(
		app.WithName("agent contexts"),
		app.WithOnStart(m.Start),
		app.WithOnStop(m.Stop),
	)
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runtime != nil {
		return errors.New("context manager already started")
	}
	if m.clientErr != nil {
		return m.clientErr
	}
	if _, err := m.db(); err != nil {
		return err
	}
	if err := m.transfers.GC(ctx, time.Now()); err != nil {
		return fmt.Errorf("garbage collect transfer resumes: %w", err)
	}
	if err := m.puts.Startup(ctx); err != nil {
		return fmt.Errorf("initialize put leases: %w", err)
	}
	getCleanup, err := m.getCleanup.Startup(ctx)
	if err != nil {
		return fmt.Errorf("initialize get cleanup leases: %w", err)
	}
	if getCleanup.Rows > 0 {
		m.logger.Info("initialized get cleanup state", "event", "get.cleanup_initialized", "rows", getCleanup.Rows, "cleared_leases", getCleanup.ClearedLeases, "due", getCleanup.Due)
	}
	runtimeContext := app.MustGet[app.RuntimeContext](ctx)
	var runtimeCancel context.CancelFunc
	m.runtime, runtimeCancel = context.WithCancel(runtimeContext)
	m.shutdownMu.Lock()
	m.cancel = runtimeCancel
	m.stopping = false
	m.shutdownMu.Unlock()
	states, err := m.list(m.runtime)
	if err != nil {
		runtimeCancel()
		m.shutdownMu.Lock()
		m.cancel = nil
		m.shutdownMu.Unlock()
		m.runtime = nil
		return err
	}
	for _, state := range states {
		if state.Enabled && state.State != "revoked" && state.State != "expired" {
			m.pending = append(m.pending, state.Name)
		}
	}
	return nil
}

func (m *Manager) Activate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activated {
		return
	}
	m.activated = true
	for _, name := range m.pending {
		m.startWorkerLocked(name)
	}
	m.pending = nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.shutdownMu.Lock()
	m.stopping = true
	cancel := m.cancel
	m.shutdownMu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		m.mutations.Wait()
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		m.watchHub().Close()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Join(ctx context.Context, request JoinRequest) (State, error) {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	if err := membership.ValidateLabel(request.Name); err != nil {
		return State{}, fmt.Errorf("context name: %w", err)
	}
	if err := membership.ValidateLabel(request.Label); err != nil {
		return State{}, fmt.Errorf("device label: %w", err)
	}
	if err := ValidateOfferedRootPath(request.OfferedRoot); err != nil {
		return State{}, fmt.Errorf("offered root: %w", err)
	}
	serverURL, err := normalizeServerURL(request.ServerURL)
	if err != nil {
		return State{}, err
	}
	request.ServerURL = serverURL
	if request.Invite != "" {
		if err := validateInviteTransport(serverURL); err != nil {
			return State{}, err
		}
	}
	request.OfferedRoot, err = m.absoluteRoot(request.OfferedRoot, filepath.Join(m.paths.Root, "offered"), false)
	if err != nil {
		return State{}, fmt.Errorf("offered root: %w", err)
	}
	requestedScope, err := OfferedRootScope(request.OfferedRoot)
	if err != nil {
		return State{}, fmt.Errorf("offered root: %w", err)
	}
	if requestedScope == OfferedRootScopeFilesystemRoot && !request.AllowFilesystemRoot {
		return State{}, errors.New("offered root is a filesystem root; --allow-filesystem-root is required")
	}
	if requestedScope == OfferedRootScopeNarrow && request.AllowFilesystemRoot {
		return State{}, errors.New("--allow-filesystem-root is only valid for a filesystem root")
	}
	request.InboxRoot, err = m.absoluteRoot(request.InboxRoot, filepath.Join(m.paths.Root, "inbox"), true)
	if err != nil {
		return State{}, fmt.Errorf("inbox root: %w", err)
	}
	if request.PutRoot != nil {
		root, rootErr := putroot.Canonical(*request.PutRoot)
		if rootErr != nil {
			return State{}, fmt.Errorf("put root: %w", rootErr)
		}
		request.PutRoot = &root
	}
	if request.AllowPut && request.PutRoot == nil {
		return State{}, errors.New("--allow-put requires --put-root")
	}
	if err := direct.ValidateSTUNURLs(request.STUNURLs); err != nil {
		return State{}, err
	}
	if request.DefaultSTUN && (request.NoSTUN || request.STUNURLs != nil) || request.NoSTUN && request.STUNURLs != nil {
		return State{}, errors.New("default STUN, no STUN, and explicit STUN URLs are mutually exclusive")
	}
	if request.DefaultSTUN {
		if err := direct.ValidateSTUNURLs([]string{DefaultSTUNURL}); err != nil {
			return State{}, fmt.Errorf("default STUN URL: %w", err)
		}
	}

	m.mu.Lock()
	existing, err := m.get(ctx, request.Name)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		m.mu.Unlock()
		return State{}, err
	}
	if request.RequireExisting && existing.Name == "" {
		m.mu.Unlock()
		return State{}, errors.New("context was removed during onboarding")
	}
	if existing.Name == "" {
		db, dbErr := m.db()
		if dbErr != nil {
			m.mu.Unlock()
			return State{}, dbErr
		}
		var count int
		if countErr := db.QueryRowContext(ctx, `select count(*) from contexts`).Scan(&count); countErr != nil {
			m.mu.Unlock()
			return State{}, countErr
		}
		if count >= MaxContexts {
			m.mu.Unlock()
			return State{}, ErrContextCapacity
		}
	}
	m.mu.Unlock()
	if existing.Name != "" && !existing.OfferedRootAuthorityValid {
		return State{}, errors.New("context offered-root authority is inconsistent; repair it with context configure before resuming join or onboarding")
	}
	if existing.Name != "" && request.RequireUnchanged {
		if !existing.Enabled {
			return State{}, errors.New("context is disabled")
		}
		if existing.State == "revoked" {
			return State{}, errors.New("context membership is revoked")
		}
		requestedSTUN := request.STUNURLs
		if request.NoSTUN {
			requestedSTUN = []string{}
		}
		if existing.ServerURL != request.ServerURL || existing.Label != request.Label || existing.OfferedRoot != request.OfferedRoot || existing.InboxRoot != request.InboxRoot || request.PutRoot != nil && !sameOptionalRoot(existing.PutRoot, request.PutRoot) || request.AllowPutSet && request.AllowPut != existing.AllowPut || !request.DefaultSTUN && !slices.Equal(existing.STUNURLs, requestedSTUN) {
			return State{}, errors.New("context already exists with different settings")
		}
	}
	serverInfo, err := m.serverInfo(ctx, serverURL)
	if err != nil {
		return State{}, err
	}
	if serverInfo.ServerID != serverInfo.Authority {
		return State{}, errors.New("server identity and authority mismatch")
	}
	privatePath := filepath.Join(m.paths.AgentKeys, request.Name+".key")
	publicPath := filepath.Join(m.paths.AgentKeys, request.Name+".pub")
	if existing.Name != "" {
		if existing.ServerURL != serverURL || existing.ServerID != serverInfo.ServerID || existing.Label != request.Label {
			return State{}, errors.New("context already exists with different server identity, URL, or label")
		}
		privatePath, publicPath = existing.privatePath, existing.publicPath
	} else if err := ensureIdentity(privatePath, publicPath); err != nil {
		return State{}, err
	}
	privateKey, err := identity.LoadPrivate(privatePath)
	if err != nil {
		return State{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	storedPublicKey, err := identity.LoadPublic(publicPath)
	if err != nil {
		return State{}, err
	}
	if !publicKey.Equal(storedPublicKey) {
		return State{}, errors.New("context public key does not match private key")
	}
	if existing.Name != "" && existing.DeviceID != identity.ID(publicKey) {
		return State{}, errors.New("context database identity does not match key files")
	}
	var enrollment rendezvousproto.Enrollment
	if request.Invite == "" {
		enrollment, err = m.enroll(ctx, serverURL, publicKey, request.Label)
	} else {
		enrollment, err = m.redeemInvite(ctx, serverURL, serverInfo, request.Invite, publicKey, request.Label)
	}
	if err != nil {
		return State{}, err
	}
	now := time.Now().UTC()
	state := "pending"
	var credentialJSON any
	var pendingCode any = enrollment.Code
	var pendingExpiry any
	if !enrollment.ExpiresAt.IsZero() {
		pendingExpiry = enrollment.ExpiresAt.Unix()
	}
	if enrollment.State == "enrolled" && enrollment.Credential != nil {
		if err := verifyEnrollment(*enrollment.Credential, serverInfo.ServerID, identity.ID(publicKey), request.Label); err != nil {
			return State{}, err
		}
		encoded, err := json.Marshal(enrollment.Credential)
		if err != nil {
			return State{}, err
		}
		credentialJSON = string(encoded)
		pendingCode, pendingExpiry = nil, nil
		state = "enrolled"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	latest, latestErr := m.get(ctx, request.Name)
	if latestErr != nil && !errors.Is(latestErr, sql.ErrNoRows) {
		return State{}, latestErr
	}
	if existing.Name != "" && latest.Name == "" {
		return State{}, errors.New("context was removed during enrollment")
	}
	if latest.State == "revoked" || latest.State == "expired" {
		return State{}, fmt.Errorf("%w: context membership is %s", ErrInvalidContextState, latest.State)
	}
	stunURLs := request.STUNURLs
	if latest.Name == "" && request.DefaultSTUN {
		stunURLs = []string{DefaultSTUNURL}
	} else if request.NoSTUN {
		stunURLs = []string{}
	}
	aliases := map[string]string{}
	createdAt := now
	if latest.Name != "" {
		aliases = latest.Aliases
		createdAt = latest.CreatedAt
		if request.STUNURLs == nil && !request.NoSTUN {
			stunURLs = latest.STUNURLs
		}
	}
	candidate := State{
		Name: request.Name, ServerURL: serverURL, ServerID: serverInfo.ServerID,
		DeviceID: identity.ID(publicKey), Label: request.Label, Credential: enrollment.Credential,
		PendingCode: enrollment.Code, State: state, Enabled: true, OfferedRoot: request.OfferedRoot,
		InboxRoot: request.InboxRoot, STUNURLs: append([]string(nil), stunURLs...), Aliases: aliases,
		CreatedAt: createdAt, UpdatedAt: now, privatePath: privatePath, publicPath: publicPath,
	}
	candidate.PutRoot, candidate.AllowPut, candidate.PutRootRevision = request.PutRoot, request.AllowPut, 1
	if latest.Name != "" {
		if request.PutRoot == nil {
			candidate.PutRoot = latest.PutRoot
		}
		if !request.AllowPutSet {
			candidate.AllowPut = latest.AllowPut
		}
		candidate.PutRootRevision = latest.PutRootRevision
		if !sameOptionalRoot(candidate.PutRoot, latest.PutRoot) || candidate.AllowPut != latest.AllowPut {
			candidate.PutRootRevision++
		}
	}
	candidate.PutRootAuthorityValid = validatePutRootAuthority(candidate) == nil
	candidate.OfferedRootScope = requestedScope
	candidate.FilesystemRootAcknowledged = requestedScope == OfferedRootScopeFilesystemRoot
	candidate.OfferedRootRevision = 1
	if latest.Name != "" {
		candidate.OfferedRootRevision = latest.OfferedRootRevision
		if latest.OfferedRoot != candidate.OfferedRoot || latest.OfferedRootScope != candidate.OfferedRootScope || latest.FilesystemRootAcknowledged != candidate.FilesystemRootAcknowledged {
			candidate.OfferedRootRevision++
		}
	}
	candidate.OfferedRootAuthorityValid = validateOfferedRootAuthority(candidate) == nil
	if !enrollment.ExpiresAt.IsZero() {
		expiresAt := enrollment.ExpiresAt
		candidate.ExpiresAt = &expiresAt
	}
	if err := m.validateContextProjectionLocked(ctx, candidate); err != nil {
		return State{}, err
	}
	if err := validateContextResponse(candidate); err != nil {
		return State{}, err
	}
	mutationDone, err := m.beginMutationCommit()
	if err != nil {
		return State{}, err
	}
	defer mutationDone()
	db, err := m.db()
	if err != nil {
		return State{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return State{}, fmt.Errorf("begin context persistence: %w", err)
	}
	defer tx.Rollback()
	if latest.Name != "" {
		authorityChanged := candidate.OfferedRootRevision != latest.OfferedRootRevision
		putAuthorityChanged := candidate.PutRootRevision != latest.PutRootRevision
		inboxChanged := candidate.InboxRoot != latest.InboxRoot
		active := m.active[request.Name]
		if authorityChanged && active.offered != 0 || putAuthorityChanged && active.put != 0 || inboxChanged && active.inbox != 0 {
			return State{}, ErrContextActive
		}
		if authorityChanged {
			if err := blockDurablePublicSendAuthorityChange(ctx, tx, request.Name); err != nil {
				return State{}, err
			}
		}
		if putAuthorityChanged {
			if err := blockDurablePutAuthorityChange(ctx, tx, request.Name); err != nil {
				return State{}, err
			}
		}
	}
	result, err := tx.ExecContext(ctx, `insert into contexts (name, server_url, server_id, device_id, private_key_path, public_key_path, label, credential, pending_code, pending_expires_at, state, enabled, offered_root, offered_root_scope, offered_root_revision, filesystem_root_acknowledged, inbox_root, put_root, allow_put, put_root_revision, created_at, updated_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(name) do update set credential = excluded.credential, pending_code = excluded.pending_code, pending_expires_at = excluded.pending_expires_at, state = case when contexts.state = 'connected' and excluded.state = 'enrolled' then contexts.state else excluded.state end, enabled = 1, offered_root = excluded.offered_root, offered_root_scope = excluded.offered_root_scope, offered_root_revision = excluded.offered_root_revision, filesystem_root_acknowledged = excluded.filesystem_root_acknowledged, inbox_root = excluded.inbox_root, put_root = excluded.put_root, allow_put = excluded.allow_put, put_root_revision = excluded.put_root_revision, updated_at = excluded.updated_at
		where contexts.state not in ('revoked', 'expired')`,
		request.Name, serverURL, serverInfo.ServerID, identity.ID(publicKey), privatePath, publicPath, request.Label,
		credentialJSON, pendingCode, pendingExpiry, state, request.OfferedRoot, candidate.OfferedRootScope, candidate.OfferedRootRevision, candidate.FilesystemRootAcknowledged, request.InboxRoot, optionalString(candidate.PutRoot), candidate.AllowPut, candidate.PutRootRevision, now.Unix(), now.Unix())
	if err != nil {
		return State{}, fmt.Errorf("persist context: %w", err)
	}
	if changed, rowsErr := result.RowsAffected(); rowsErr != nil {
		return State{}, rowsErr
	} else if changed != 1 {
		return State{}, fmt.Errorf("%w: context membership became terminal during enrollment", ErrInvalidContextState)
	}
	if _, err := tx.ExecContext(ctx, `update context_settings set default_context = coalesce(default_context, ?) where singleton = 1`, request.Name); err != nil {
		return State{}, fmt.Errorf("set initial default context: %w", err)
	}
	if existing.Name == "" || request.STUNURLs != nil || request.NoSTUN {
		if _, err := tx.ExecContext(ctx, `delete from context_stun_servers where context_name = ?`, request.Name); err != nil {
			return State{}, fmt.Errorf("replace context STUN servers: %w", err)
		}
		for position, stunURL := range stunURLs {
			if _, err := tx.ExecContext(ctx, `insert into context_stun_servers (context_name, position, url) values (?, ?, ?)`, request.Name, position, stunURL); err != nil {
				return State{}, fmt.Errorf("persist context STUN server: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return State{}, fmt.Errorf("commit context persistence: %w", err)
	}
	m.startWorkerLocked(request.Name)
	return m.get(ctx, request.Name)
}

func (m *Manager) Get(ctx context.Context, name string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.get(ctx, name)
}

func (m *Manager) List(ctx context.Context) ([]State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.list(ctx)
}

func (m *Manager) Configuration(ctx context.Context, name string) (Configuration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.get(ctx, name)
	if err != nil {
		return Configuration{}, err
	}
	return m.configuration(ctx, state)
}

func (m *Manager) Update(ctx context.Context, name string, request UpdateRequest) (Configuration, error) {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	if request.OfferedRoot == nil && request.InboxRoot == nil && request.STUNURLs == nil && request.PutRoot == nil && !request.ClearPutRoot && request.AllowPut == nil {
		return Configuration{}, fmt.Errorf("%w: at least one root, put policy, or STUN update is required", ErrInvalidConfiguration)
	}
	if request.AllowFilesystemRoot && request.OfferedRoot == nil {
		return Configuration{}, fmt.Errorf("%w: --allow-filesystem-root requires an offered-root update", ErrInvalidConfiguration)
	}
	var err error
	if request.OfferedRoot != nil {
		if err := ValidateOfferedRootPath(*request.OfferedRoot); err != nil {
			return Configuration{}, fmt.Errorf("%w: offered root: %v", ErrInvalidConfiguration, err)
		}
		root, rootErr := m.configuredRoot(*request.OfferedRoot, false)
		err = rootErr
		if err != nil {
			return Configuration{}, fmt.Errorf("%w: offered root: %v", ErrInvalidConfiguration, err)
		}
		request.OfferedRoot = &root
		scope, scopeErr := OfferedRootScope(root)
		if scopeErr != nil {
			return Configuration{}, fmt.Errorf("%w: offered root: %v", ErrInvalidConfiguration, scopeErr)
		}
		if scope == OfferedRootScopeFilesystemRoot && !request.AllowFilesystemRoot {
			return Configuration{}, fmt.Errorf("%w: offered root is a filesystem root; --allow-filesystem-root is required", ErrInvalidConfiguration)
		}
		if scope == OfferedRootScopeNarrow && request.AllowFilesystemRoot {
			return Configuration{}, fmt.Errorf("%w: --allow-filesystem-root is only valid for a filesystem root", ErrInvalidConfiguration)
		}
	}
	if request.InboxRoot != nil {
		root, rootErr := m.configuredRoot(*request.InboxRoot, true)
		err = rootErr
		if err != nil {
			return Configuration{}, fmt.Errorf("%w: inbox root: %v", ErrInvalidConfiguration, err)
		}
		request.InboxRoot = &root
	}
	if request.PutRoot != nil && request.ClearPutRoot {
		return Configuration{}, fmt.Errorf("%w: --put-root and --clear-put-root cannot be combined", ErrInvalidConfiguration)
	}
	if request.PutRoot != nil {
		root, rootErr := putroot.Canonical(*request.PutRoot)
		if rootErr != nil {
			return Configuration{}, fmt.Errorf("%w: put root: %v", ErrInvalidConfiguration, rootErr)
		}
		request.PutRoot = &root
	}
	if request.STUNURLs != nil {
		if err := direct.ValidateSTUNURLs(*request.STUNURLs); err != nil {
			return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
		}
	}

	m.mu.Lock()
	state, err := m.get(ctx, name)
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	offeredChanged := request.OfferedRoot != nil && *request.OfferedRoot != state.OfferedRoot
	authorityChanged := false
	requestedScope := state.OfferedRootScope
	requestedAcknowledged := state.FilesystemRootAcknowledged
	if request.OfferedRoot != nil {
		requestedScope, err = OfferedRootScope(*request.OfferedRoot)
		if err != nil {
			m.mu.Unlock()
			return Configuration{}, fmt.Errorf("%w: offered root: %v", ErrInvalidConfiguration, err)
		}
		requestedAcknowledged = requestedScope == OfferedRootScopeFilesystemRoot
		authorityChanged = offeredChanged || requestedScope != state.OfferedRootScope || requestedAcknowledged != state.FilesystemRootAcknowledged
	}
	legacyAuthorityRepair := authorityChanged && !offeredChanged && !state.OfferedRootAuthorityValid && request.OfferedRoot != nil
	inboxChanged := request.InboxRoot != nil && *request.InboxRoot != state.InboxRoot
	stunChanged := request.STUNURLs != nil && !slices.Equal(*request.STUNURLs, state.STUNURLs)
	putRoot := state.PutRoot
	if request.PutRoot != nil {
		putRoot = request.PutRoot
	} else if request.ClearPutRoot {
		putRoot = nil
	}
	allowPut := state.AllowPut
	if request.AllowPut != nil {
		allowPut = *request.AllowPut
	}
	if allowPut && putRoot == nil {
		m.mu.Unlock()
		return Configuration{}, fmt.Errorf("%w: enabling put requires --put-root", ErrInvalidConfiguration)
	}
	putAuthorityChanged := !sameOptionalRoot(putRoot, state.PutRoot) || allowPut != state.AllowPut
	active := m.active[name]
	if authorityChanged && active.offered != 0 || inboxChanged && active.inbox != 0 || putAuthorityChanged && active.put != 0 {
		m.mu.Unlock()
		return Configuration{}, ErrContextActive
	}
	db, err := m.db()
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	offeredRoot, inboxRoot := state.OfferedRoot, state.InboxRoot
	if request.OfferedRoot != nil {
		offeredRoot = *request.OfferedRoot
	}
	if request.InboxRoot != nil {
		inboxRoot = *request.InboxRoot
	}
	newState := state.State
	if stunChanged && state.Enabled && state.State == "connected" {
		newState = "disconnected"
	}
	projectedState := state
	projectedState.OfferedRoot = offeredRoot
	projectedState.OfferedRootScope = requestedScope
	projectedState.FilesystemRootAcknowledged = requestedAcknowledged
	if authorityChanged {
		projectedState.OfferedRootRevision++
	}
	projectedState.OfferedRootAuthorityValid = validateOfferedRootAuthority(projectedState) == nil
	projectedState.InboxRoot = inboxRoot
	projectedState.PutRoot = putRoot
	projectedState.AllowPut = allowPut
	if putAuthorityChanged {
		projectedState.PutRootRevision++
	}
	projectedState.PutRootAuthorityValid = validatePutRootAuthority(projectedState) == nil
	projectedState.State = newState
	projectedState.UpdatedAt = time.Now().UTC()
	if request.STUNURLs != nil {
		projectedState.STUNURLs = append([]string(nil), (*request.STUNURLs)...)
	}
	if err := m.validateContextProjectionLocked(ctx, projectedState); err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	projectedConfiguration, err := m.configuration(ctx, projectedState)
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	if err := validateContextResponse(projectedConfiguration); err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if authorityChanged {
		if legacyAuthorityRepair {
			if err := rebindLegacyPublicReceives(ctx, tx, name, state.OfferedRootRevision, projectedState.OfferedRootRevision); err != nil {
				m.mu.Unlock()
				return Configuration{}, err
			}
		} else {
			if err := blockDurablePublicSendAuthorityChange(ctx, tx, name); err != nil {
				m.mu.Unlock()
				return Configuration{}, err
			}
		}
	}
	if putAuthorityChanged {
		if blockErr := blockDurablePutAuthorityChange(ctx, tx, name); blockErr != nil {
			m.mu.Unlock()
			return Configuration{}, blockErr
		}
	}
	result, err := tx.ExecContext(ctx, `update contexts set offered_root = ?, offered_root_scope = ?, offered_root_revision = ?, filesystem_root_acknowledged = ?, inbox_root = ?, put_root = ?, allow_put = ?, put_root_revision = ?, state = ?, updated_at = ? where name = ?`, offeredRoot, requestedScope, projectedState.OfferedRootRevision, requestedAcknowledged, inboxRoot, optionalString(putRoot), allowPut, projectedState.PutRootRevision, newState, time.Now().Unix(), name)
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, fmt.Errorf("update context configuration: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		m.mu.Unlock()
		if err != nil {
			return Configuration{}, err
		}
		return Configuration{}, sql.ErrNoRows
	}
	if request.STUNURLs != nil {
		if _, err := tx.ExecContext(ctx, `delete from context_stun_servers where context_name = ?`, name); err != nil {
			m.mu.Unlock()
			return Configuration{}, fmt.Errorf("replace context STUN servers: %w", err)
		}
		for position, stunURL := range *request.STUNURLs {
			if _, err := tx.ExecContext(ctx, `insert into context_stun_servers (context_name, position, url) values (?, ?, ?)`, name, position, stunURL); err != nil {
				m.mu.Unlock()
				return Configuration{}, fmt.Errorf("persist context STUN server: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		m.mu.Unlock()
		return Configuration{}, fmt.Errorf("commit context configuration: %w", err)
	}
	rollback = false
	worker := m.workers[name]
	if stunChanged && worker != nil {
		delete(m.workers, name)
		worker.cancel()
	}
	m.mu.Unlock()

	if stunChanged && worker != nil {
		<-worker.done
	}
	m.mu.Lock()
	if stunChanged && state.Enabled {
		m.startWorkerLocked(name)
	}
	updated, err := m.get(ctx, name)
	if err != nil {
		m.mu.Unlock()
		return Configuration{}, err
	}
	configuration, err := m.configuration(ctx, updated)
	m.mu.Unlock()
	return configuration, err
}

func (m *Manager) configuration(ctx context.Context, state State) (Configuration, error) {
	db, err := m.db()
	if err != nil {
		return Configuration{}, err
	}
	var defaultName sql.NullString
	if err := db.QueryRowContext(ctx, `select default_context from context_settings where singleton = 1`).Scan(&defaultName); err != nil {
		return Configuration{}, err
	}
	warnings, err := m.sharedRootWarnings(ctx, state)
	if err != nil {
		return Configuration{}, err
	}
	return Configuration{
		Name: state.Name, IsDefault: defaultName.Valid && state.Name == defaultName.String, ServerOrigin: state.ServerURL,
		ServerID: state.ServerID, DeviceID: state.DeviceID, Label: state.Label,
		Enabled: state.Enabled, State: state.State, OfferedRoot: state.OfferedRoot,
		OfferedRootScope: state.OfferedRootScope, OfferedRootRevision: state.OfferedRootRevision,
		FilesystemRootAcknowledged: state.FilesystemRootAcknowledged,
		OfferedRootAuthorityValid:  state.OfferedRootAuthorityValid,
		InboxRoot:                  state.InboxRoot, PutRoot: cloneString(state.PutRoot), AllowPut: state.AllowPut, PutRootRevision: state.PutRootRevision, PutRootAuthorityValid: state.PutRootAuthorityValid, STUNURLs: append([]string{}, state.STUNURLs...),
		Aliases: orderedAliases(state.Aliases), Warnings: warnings,
	}, nil
}

func (m *Manager) sharedRootWarnings(ctx context.Context, state State) ([]string, error) {
	db, err := m.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `select name, offered_root, inbox_root, put_root from contexts where name != ? order by name`, state.Name)
	if err != nil {
		return nil, err
	}
	type otherContext struct {
		name    string
		offered string
		inbox   string
		put     sql.NullString
	}
	var others []otherContext
	for rows.Next() {
		var other otherContext
		if err := rows.Scan(&other.name, &other.offered, &other.inbox, &other.put); err != nil {
			rows.Close()
			return nil, err
		}
		others = append(others, other)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	warnings := make([]string, 0, 3)
	if err := validateOfferedRootAuthority(state); err != nil {
		warnings = append(warnings, "offered-root authority is inconsistent and offered-root/public-send service is blocked; reconfigure the offered root explicitly")
	} else if state.OfferedRootScope == OfferedRootScopeFilesystemRoot {
		warnings = append(warnings, "DANGER: this context offers the filesystem root; every authenticated member can browse and retrieve every reachable regular file allowed by the agent OS identity")
	}
	if state.AllowPut && !state.PutRootAuthorityValid {
		warnings = append(warnings, "put authority is enabled but invalid; incoming put is blocked")
	} else if state.AllowPut {
		warnings = append(warnings, "WARNING: every authenticated context member may create files and request supported replacement beneath the configured put root")
	}
	for _, root := range []struct {
		kind string
		path string
	}{
		{kind: "offered", path: state.OfferedRoot},
		{kind: "inbox", path: state.InboxRoot},
	} {
		var names []string
		for _, other := range others {
			if rootsOverlap(root.path, other.offered) || rootsOverlap(root.path, other.inbox) || other.put.Valid && rootsOverlap(root.path, other.put.String) {
				names = append(names, other.name)
			}
		}
		if len(names) != 0 {
			warnings = append(warnings, fmt.Sprintf("%s root is shared with context(s) %s; members of every sharing context may affect or access the same native files", root.kind, strings.Join(names, ", ")))
		}
	}
	if state.PutRoot != nil {
		for _, local := range []struct{ kind, path string }{{"offered", state.OfferedRoot}, {"inbox", state.InboxRoot}} {
			if rootsOverlap(*state.PutRoot, local.path) {
				warnings = append(warnings, fmt.Sprintf("put root overlaps this context's %s root; remote creation or supported replacement may affect files exposed by another capability", local.kind))
			}
		}
		var names []string
		for _, other := range others {
			if rootsOverlap(*state.PutRoot, other.offered) || rootsOverlap(*state.PutRoot, other.inbox) || other.put.Valid && rootsOverlap(*state.PutRoot, other.put.String) {
				names = append(names, other.name)
			}
		}
		if len(names) > 0 {
			warnings = append(warnings, fmt.Sprintf("put root overlaps context(s) %s; remote creation or supported replacement and members of those contexts may affect or access the same native files", strings.Join(names, ", ")))
		}
	}
	return warnings, nil
}

func rootsOverlap(first, second string) bool {
	if sameRoot(first, second) {
		return true
	}
	a, b := filepath.Clean(first), filepath.Clean(second)
	rel, err := filepath.Rel(a, b)
	if err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return true
	}
	rel, err = filepath.Rel(b, a)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func sameRoot(first, second string) bool {
	if first == second {
		return true
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}

func blockDurablePublicSendAuthorityChange(ctx context.Context, tx interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string,
) error {
	var count int
	if err := tx.QueryRowContext(ctx, `select count(*) from transfer_resumes where direction = 'receive' and visibility = 'public' and context_name = ? and state != 'committed'`, name).Scan(&count); err != nil {
		return fmt.Errorf("inspect durable public-send state: %w", err)
	}
	if count != 0 {
		return ErrContextAuthorityBlocked
	}
	return nil
}

type putBlockerQuery interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func purgeSafePutBlockerRows(ctx context.Context, query putBlockerQuery, name string, now time.Time) error {
	if _, err := query.ExecContext(ctx, `update put_transfers set parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,old_metadata=null,backup_name=null,backup_identity=null,backup_size=0,stage_removed=0,backup_removed=0,parent_synced=0,updated_at=? where context_name=? and direction='receive' and state='committed' and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1 and lease_token is null`, now.Unix(), name); err != nil {
		return fmt.Errorf("finalize committed put cleanup state: %w", err)
	}
	if _, err := query.ExecContext(ctx, `delete from put_transfers where context_name=? and direction='receive' and state='cleanup_not_attempted' and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1 and lease_token is null`, name); err != nil {
		return fmt.Errorf("purge finalized put cleanup state: %w", err)
	}
	if _, err := query.ExecContext(ctx, `delete from put_transfers where context_name=? and direction='send' and expires_at<=? and lease_token is null`, name, now.Unix()); err != nil {
		return fmt.Errorf("purge expired put sender state: %w", err)
	}
	return nil
}

func blockDurablePutAuthorityChange(ctx context.Context, query putBlockerQuery, name string) error {
	if err := purgeSafePutBlockerRows(ctx, query, name, time.Now().UTC()); err != nil {
		return err
	}
	var count int
	if err := query.QueryRowContext(ctx, `select count(*) from put_transfers where context_name=? and direction='receive' and (state not in ('committed','resolved_accept_current') or stage_identity is not null or backup_identity is not null)`, name).Scan(&count); err != nil {
		return fmt.Errorf("inspect durable put state: %w", err)
	}
	if count != 0 {
		return ErrContextAuthorityBlocked
	}
	return nil
}

func blockDurablePutRemoval(ctx context.Context, query putBlockerQuery, name string) error {
	if err := purgeSafePutBlockerRows(ctx, query, name, time.Now().UTC()); err != nil {
		return err
	}
	var count int
	if err := query.QueryRowContext(ctx, `select count(*) from put_transfers where context_name=? and (state not in ('committed','resolved_accept_current') or stage_identity is not null or backup_identity is not null)`, name).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrContextAuthorityBlocked
	}
	return nil
}

func sameOptionalRoot(first, second *string) bool {
	return first == nil && second == nil || first != nil && second != nil && *first == *second
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func validatePutRootAuthority(state State) error {
	if state.PutRootRevision <= 0 || state.AllowPut && state.PutRoot == nil || !putroot.Valid(state.PutRoot) {
		return put.ErrAuthority
	}
	return nil
}

func rebindLegacyPublicReceives(ctx context.Context, tx *sql.Tx, name string, currentRevision, nextRevision int64) error {
	var incompatible int
	if err := tx.QueryRowContext(ctx, `select count(*) from transfer_resumes where direction = 'receive' and visibility = 'public' and context_name = ? and state != 'committed' and offered_root_revision is not null and offered_root_revision != ?`, name, currentRevision).Scan(&incompatible); err != nil {
		return fmt.Errorf("inspect legacy public-send revisions: %w", err)
	}
	if incompatible != 0 {
		return ErrContextAuthorityBlocked
	}
	if _, err := tx.ExecContext(ctx, `update transfer_resumes set offered_root_revision = ? where direction = 'receive' and visibility = 'public' and context_name = ? and state != 'committed' and (offered_root_revision is null or offered_root_revision = ?)`, nextRevision, name, currentRevision); err != nil {
		return fmt.Errorf("rebind legacy public-send revisions: %w", err)
	}
	return nil
}

func (m *Manager) SetDefault(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return err
	}
	var count int
	if err := db.QueryRowContext(ctx, `select count(*) from contexts where name = ?`, name).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	_, err = db.ExecContext(ctx, `update context_settings set default_context = ? where singleton = 1`, name)
	return err
}

func (m *Manager) Disable(ctx context.Context, name string) (State, error) {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	db, err := m.db()
	if err != nil {
		m.mu.Unlock()
		return State{}, err
	}
	state, err := m.get(ctx, name)
	if err != nil {
		m.mu.Unlock()
		return State{}, err
	}
	projectedState := state
	projectedState.Enabled = false
	if projectedState.State == "connected" {
		projectedState.State = "disconnected"
	}
	projectedState.UpdatedAt = time.Now().UTC()
	if err := m.validateContextProjectionLocked(ctx, projectedState); err != nil {
		m.mu.Unlock()
		return State{}, err
	}
	if err := validateContextResponse(projectedState); err != nil {
		m.mu.Unlock()
		return State{}, err
	}
	result, err := db.ExecContext(ctx, `update contexts set enabled = 0, state = case when state = 'connected' then 'disconnected' else state end, updated_at = ? where name = ?`, time.Now().Unix(), name)
	if err != nil {
		m.mu.Unlock()
		return State{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		m.mu.Unlock()
		if err != nil {
			return State{}, err
		}
		return State{}, sql.ErrNoRows
	}
	worker := m.workers[name]
	if worker != nil {
		delete(m.workers, name)
		worker.cancel()
	}
	m.mu.Unlock()
	if worker != nil {
		select {
		case <-worker.done:
		case <-ctx.Done():
			return State{}, ctx.Err()
		}
	}
	if err := m.waitForTransfers(ctx, name); err != nil {
		return State{}, err
	}
	return m.Get(ctx, name)
}

func (m *Manager) Enable(ctx context.Context, name string) (State, error) {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return State{}, err
	}
	state, err := m.get(ctx, name)
	if err != nil {
		return State{}, err
	}
	if state.State == "revoked" || state.State == "expired" {
		return State{}, fmt.Errorf("%w: context membership is %s", ErrInvalidContextState, state.State)
	}
	projectedState := state
	projectedState.Enabled = true
	projectedState.UpdatedAt = time.Now().UTC()
	if err := m.validateContextProjectionLocked(ctx, projectedState); err != nil {
		return State{}, err
	}
	if err := validateContextResponse(projectedState); err != nil {
		return State{}, err
	}
	result, err := db.ExecContext(ctx, `update contexts set enabled = 1, updated_at = ? where name = ?`, time.Now().Unix(), name)
	if err != nil {
		return State{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return State{}, err
	}
	if changed != 1 {
		return State{}, sql.ErrNoRows
	}
	state, err = m.get(ctx, name)
	if err != nil {
		return State{}, err
	}
	m.startWorkerLocked(name)
	return state, nil
}

func (m *Manager) Remove(ctx context.Context, name string) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	if m.active[name].total != 0 {
		m.mu.Unlock()
		return ErrContextActive
	}
	state, err := m.get(ctx, name)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	db, err := m.db()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	worker := m.workers[name]
	if worker != nil {
		delete(m.workers, name)
		worker.cancel()
	}
	m.mu.Unlock()
	if worker != nil {
		select {
		case <-worker.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	if m.active[name].total != 0 {
		if state.Enabled {
			m.startWorkerLocked(name)
		}
		m.mu.Unlock()
		return ErrContextActive
	}
	if err := blockDurablePublicSendAuthorityChange(ctx, db, name); err != nil {
		if state.Enabled {
			m.startWorkerLocked(name)
		}
		m.mu.Unlock()
		return err
	}
	if err := blockDurablePutRemoval(ctx, db, name); err != nil {
		if state.Enabled {
			m.startWorkerLocked(name)
		}
		m.mu.Unlock()
		return err
	}
	if _, err := db.ExecContext(ctx, `update contexts set enabled = 0, state = case when state = 'connected' then 'disconnected' else state end, updated_at = ? where name = ?`, time.Now().Unix(), name); err != nil {
		if state.Enabled {
			m.startWorkerLocked(name)
		}
		m.mu.Unlock()
		return err
	}
	staged, err := stageContextKeys(state.privatePath, state.publicPath)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	err = m.transfers.RemoveContextWith(ctx, name, func(tx *sql.Tx) error {
		if err := blockDurablePublicSendAuthorityChange(ctx, tx, name); err != nil {
			return err
		}
		if err := blockDurablePutRemoval(ctx, tx, name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `update context_settings set default_context = null where default_context = ?`, name); err != nil {
			return fmt.Errorf("clear default context: %w", err)
		}
		result, err := tx.ExecContext(ctx, `delete from contexts where name = ?`, name)
		if err != nil {
			return fmt.Errorf("delete context: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
	if err != nil && !errors.Is(err, transfer.ErrTransferCleanupPending) {
		restoreContextKeys(staged)
		return fmt.Errorf("remove context and transfer state: %w", err)
	}
	if errors.Is(err, transfer.ErrTransferCleanupPending) {
		m.logger.Warn("removed context with private transfer cleanup pending", "context", name)
	}
	for _, key := range staged {
		if err := os.Remove(key.staged); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.logger.Warn("removed context but could not delete staged key", "context", name, "path", key.staged, "reason", err)
		}
	}
	return nil
}

type stagedContextKey struct {
	original string
	staged   string
}

func stageContextKeys(paths ...string) ([]stagedContextKey, error) {
	staged := make([]stagedContextKey, 0, len(paths))
	for _, path := range paths {
		suffix, err := newContextSession(".removing-")
		if err != nil {
			restoreContextKeys(staged)
			return nil, fmt.Errorf("stage context keys: %w", err)
		}
		key := stagedContextKey{original: path, staged: path + suffix}
		if err := os.Rename(key.original, key.staged); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			restoreContextKeys(staged)
			return nil, fmt.Errorf("stage context key %q: %w", path, err)
		}
		staged = append(staged, key)
	}
	return staged, nil
}

func restoreContextKeys(keys []stagedContextKey) {
	for index := len(keys) - 1; index >= 0; index-- {
		_ = os.Rename(keys[index].staged, keys[index].original)
	}
}

func (m *Manager) beginRootOperation(ctx context.Context, name string) (State, error) {
	return m.beginContextOperation(ctx, name, 0)
}

func (m *Manager) beginLocalContextOperation(ctx context.Context, name string) (State, error) {
	return m.beginLocalContextOperationScope(ctx, name, 0)
}

func (m *Manager) beginLocalContextOperationScope(ctx context.Context, name string, scope operationScope) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.get(ctx, name)
	if err != nil {
		return State{}, err
	}
	active := m.active[name]
	if active.total == 0 {
		m.activeDone[name] = make(chan struct{})
	}
	active.total++
	if scope&operationOffered != 0 {
		active.offered++
	}
	if scope&operationInbox != 0 {
		active.inbox++
	}
	if scope&operationPut != 0 {
		active.put++
	}
	m.active[name] = active
	return state, nil
}

func (m *Manager) beginContextOperation(ctx context.Context, name string, scope operationScope) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.get(ctx, name)
	if err != nil {
		return State{}, err
	}
	if !state.Enabled {
		return State{}, fmt.Errorf("%w: context is disabled", ErrInvalidContextState)
	}
	active := m.active[name]
	if active.total == 0 {
		m.activeDone[name] = make(chan struct{})
	}
	active.total++
	if scope&operationOffered != 0 {
		active.offered++
	}
	if scope&operationInbox != 0 {
		active.inbox++
	}
	if scope&operationPut != 0 {
		active.put++
	}
	m.active[name] = active
	return state, nil
}

func (m *Manager) Inbox(ctx context.Context, name, sender string) ([]inbox.Entry, error) {
	state, err := m.beginContextOperation(ctx, name, operationInbox)
	if err != nil {
		return nil, err
	}
	defer m.endContextOperation(name, operationInbox)
	return inbox.List(state.InboxRoot, state.Name, sender)
}

func (m *Manager) InboxPath(ctx context.Context, name, portablePath string) (inbox.PathResult, error) {
	state, err := m.beginContextOperation(ctx, name, operationInbox)
	if err != nil {
		return inbox.PathResult{}, err
	}
	defer m.endContextOperation(name, operationInbox)
	source, err := inbox.Open(state.InboxRoot, state.Name, portablePath)
	if err != nil {
		return inbox.PathResult{}, err
	}
	defer source.Close()
	return source.PathResult(), nil
}

func (m *Manager) MoveInbox(ctx context.Context, name, portablePath, destination string) (inbox.MoveResult, error) {
	if _, _, err := inbox.ValidatePath(portablePath); err != nil {
		return inbox.MoveResult{}, err
	}
	destination = filepath.Clean(destination)
	if !filepath.IsAbs(destination) || filepath.Dir(destination) == destination {
		return inbox.MoveResult{}, inbox.ErrInvalidDestination
	}
	unlock, err := m.lockInboxMove(ctx, inboxMoveKey(name, portablePath))
	if err != nil {
		return inbox.MoveResult{}, err
	}
	defer unlock()
	state, err := m.beginContextOperation(ctx, name, operationInbox)
	if err != nil {
		return inbox.MoveResult{}, err
	}
	defer m.endContextOperation(name, operationInbox)
	source, err := inbox.Open(state.InboxRoot, state.Name, portablePath)
	if err != nil {
		return inbox.MoveResult{}, err
	}
	defer source.Close()
	stage, err := m.getCleanup.Create(ctx, destination, source.Size())
	if err != nil {
		return inbox.MoveResult{}, err
	}
	cleanupStage := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = stage.Cleanup(cleanupCtx)
		cancel()
	}
	if err := source.CopyTo(ctx, stage.File()); err != nil {
		cleanupStage()
		return inbox.MoveResult{}, err
	}
	if err := source.Revalidate(); err != nil {
		cleanupStage()
		return inbox.MoveResult{}, err
	}
	result := inbox.MoveResult{Version: inbox.ResultVersion, Source: portablePath, Destination: destination}
	committed, publishErr := stage.Publish(ctx, filepath.Base(destination))
	if publishErr != nil {
		cleanupStage()
		if !committed {
			return inbox.MoveResult{}, publishErr
		}
		result.State = inbox.MoveStateRetained
		result.DestinationCommitted = true
		result.DurabilityUnconfirmed = true
		result.Warning = "destination committed with durability or cleanup pending; inbox source retained"
		m.logger.Warn("inbox move destination committed with source retained", "event", "inbox.move_partial", "destination_committed", 1, "source_removed", 0)
		return result, nil
	}
	removed, removeErr := source.Remove()
	if removeErr != nil {
		result.DestinationCommitted = true
		if removed {
			result.State = inbox.MoveStateUncertain
			result.DurabilityUnconfirmed = true
			result.Warning = "destination committed; inbox source removal durability is uncertain"
		} else {
			result.State = inbox.MoveStateRetained
			result.Warning = "destination committed; inbox source retained because safe removal could not be confirmed"
		}
		m.logger.Warn("inbox move source cleanup incomplete", "event", "inbox.move_partial", "destination_committed", 1, "source_removed", 0)
		return result, nil
	}
	result.State = inbox.MoveStateMoved
	result.DestinationCommitted = true
	result.SourceRemovalConfirmed = true
	return result, nil
}

func inboxMoveKey(name, portablePath string) string {
	return strings.Map(func(value rune) rune {
		canonical := value
		for folded := unicode.SimpleFold(value); folded != value; folded = unicode.SimpleFold(folded) {
			canonical = min(canonical, folded)
		}
		return canonical
	}, name+"\x00"+portablePath)
}

func (m *Manager) lockInboxMove(ctx context.Context, key string) (func(), error) {
	m.inboxMovesMu.Lock()
	if m.inboxMoves == nil {
		m.inboxMoves = make(map[string]*inboxMoveLock)
	}
	lock := m.inboxMoves[key]
	if lock == nil {
		lock = &inboxMoveLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		m.inboxMoves[key] = lock
	}
	lock.refs++
	m.inboxMovesMu.Unlock()

	select {
	case <-ctx.Done():
		m.releaseInboxMove(key, lock, false)
		return nil, ctx.Err()
	case <-lock.token:
		return func() { m.releaseInboxMove(key, lock, true) }, nil
	}
}

func (m *Manager) releaseInboxMove(key string, lock *inboxMoveLock, held bool) {
	if held {
		lock.token <- struct{}{}
	}
	m.inboxMovesMu.Lock()
	lock.refs--
	if lock.refs == 0 {
		delete(m.inboxMoves, key)
	}
	m.inboxMovesMu.Unlock()
}

func (m *Manager) endTransfer(name string) {
	m.endContextOperation(name, 0)
}

func (m *Manager) endContextOperation(name string, scope operationScope) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := m.active[name]
	active.total--
	if scope&operationOffered != 0 {
		active.offered--
	}
	if scope&operationInbox != 0 {
		active.inbox--
	}
	if scope&operationPut != 0 {
		active.put--
	}
	if active.total == 0 {
		delete(m.active, name)
		close(m.activeDone[name])
		delete(m.activeDone, name)
	} else {
		m.active[name] = active
	}
}

func (m *Manager) waitForTransfers(ctx context.Context, name string) error {
	m.mu.Lock()
	done := m.activeDone[name]
	m.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Default(ctx context.Context) (string, error) {
	db, err := m.db()
	if err != nil {
		return "", err
	}
	var name sql.NullString
	if err := db.QueryRowContext(ctx, `select default_context from context_settings where singleton = 1`).Scan(&name); err != nil {
		return "", err
	}
	if !name.Valid {
		return "", errors.New("default context is not configured")
	}
	return name.String, nil
}

func (m *Manager) SetAlias(ctx context.Context, contextName, alias, target string) error {
	if err := membership.ValidateLabel(alias); err != nil {
		return fmt.Errorf("%w: alias: %v", ErrInvalidAlias, err)
	}
	if err := membership.ValidateLabel(target); err != nil {
		return fmt.Errorf("%w: target label: %v", ErrInvalidAlias, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return err
	}
	state, err := m.get(ctx, contextName)
	if err != nil {
		return err
	}
	currentTarget, exists := state.Aliases[alias]
	if !exists && len(state.Aliases) >= MaxAliasesPerContext {
		return ErrAliasCapacity
	}
	projectedAliases := make(map[string]string, len(state.Aliases)+1)
	for name, value := range state.Aliases {
		projectedAliases[name] = value
	}
	projectedAliases[alias] = target
	state.Aliases = projectedAliases
	if err := m.validateContextProjectionLocked(ctx, state); err != nil && (!exists || currentTarget != target) {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `insert into context_aliases (context_name, alias, target_label) values (?, ?, ?) on conflict(context_name, alias) do update set target_label = excluded.target_label`, contextName, alias, target)
	if err != nil {
		return fmt.Errorf("set context alias: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit context alias: %w", err)
	}
	return nil
}

func (m *Manager) validateContextProjectionLocked(ctx context.Context, candidate State) error {
	states, err := m.list(ctx)
	if err != nil {
		return err
	}
	currentSize, err := encodedContextProjectionSize(states)
	if err != nil {
		return err
	}
	projected := append([]State(nil), states...)
	found := false
	for index := range projected {
		if projected[index].Name == candidate.Name {
			projected[index] = candidate
			found = true
			break
		}
	}
	if !found {
		if len(projected) >= MaxContexts {
			return ErrContextCapacity
		}
		projected = append(projected, candidate)
	}
	projectedSize, err := encodedContextProjectionSize(projected)
	if err != nil {
		return err
	}
	if projectedSize > contextProjectionSize && projectedSize > currentSize {
		return ErrContextProjection
	}
	return nil
}

func encodedContextProjectionSize(states []State) (int, error) {
	encoded, err := json.Marshal(states)
	if err != nil {
		return 0, fmt.Errorf("encode context projection: %w", err)
	}
	return len(encoded) + 1, nil
}

func validateContextResponse(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode context response: %w", err)
	}
	if len(encoded)+1 > localipc.MaxResponseBytes {
		return ErrContextProjection
	}
	return nil
}

func (m *Manager) ListAliases(ctx context.Context, contextName string) ([]Alias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.get(ctx, contextName)
	if err != nil {
		return nil, err
	}
	return orderedAliases(state.Aliases), nil
}

func (m *Manager) GetAlias(ctx context.Context, contextName, alias string) (Alias, error) {
	if err := membership.ValidateLabel(alias); err != nil {
		return Alias{}, fmt.Errorf("%w: alias: %v", ErrInvalidAlias, err)
	}
	values, err := m.ListAliases(ctx, contextName)
	if err != nil {
		return Alias{}, err
	}
	for _, value := range values {
		if value.Name == alias {
			return value, nil
		}
	}
	return Alias{}, ErrAliasNotFound
}

func (m *Manager) RemoveAlias(ctx context.Context, contextName, alias string) (Alias, error) {
	if err := membership.ValidateLabel(alias); err != nil {
		return Alias{}, fmt.Errorf("%w: alias: %v", ErrInvalidAlias, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return Alias{}, err
	}
	var contextCount int
	if err := db.QueryRowContext(ctx, `select count(*) from contexts where name = ?`, contextName).Scan(&contextCount); err != nil {
		return Alias{}, err
	}
	if contextCount != 1 {
		return Alias{}, sql.ErrNoRows
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Alias{}, err
	}
	defer tx.Rollback()
	var removed Alias
	if err := tx.QueryRowContext(ctx, `select alias, target_label from context_aliases where context_name = ? and alias = ?`, contextName, alias).Scan(&removed.Name, &removed.Target); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Alias{}, ErrAliasNotFound
		}
		return Alias{}, err
	}
	if _, err := tx.ExecContext(ctx, `delete from context_aliases where context_name = ? and alias = ?`, contextName, removed.Name); err != nil {
		return Alias{}, fmt.Errorf("remove context alias: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Alias{}, fmt.Errorf("commit context alias removal: %w", err)
	}
	return removed, nil
}

func orderedAliases(values map[string]string) []Alias {
	result := make([]Alias, 0, len(values))
	for name, target := range values {
		result = append(result, Alias{Name: name, Target: target})
	}
	slices.SortFunc(result, func(a, b Alias) int {
		if value := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); value != 0 {
			return value
		}
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func (m *Manager) Peers(ctx context.Context, contextName string) ([]Peer, error) {
	state, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return nil, err
	}
	control.mu.Lock()
	members := make([]membership.Member, 0, len(control.peers))
	for _, member := range control.peers {
		members = append(members, member)
	}
	control.mu.Unlock()
	slices.SortFunc(members, compareMembers)
	result := make([]Peer, 0, len(members))
	for _, member := range members {
		result = append(result, Peer{Label: member.Label, DeviceID: member.DeviceID, Aliases: aliasesFor(state.Aliases, member.Label)})
	}
	return result, nil
}

func (m *Manager) Watch(ctx context.Context, contextName string) (*contextwatch.Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.get(ctx, contextName); err != nil {
		return nil, err
	}
	return m.watchHub().Subscribe(contextName)
}

func (m *Manager) watchHub() *contextwatch.Hub {
	m.watchOnce.Do(func() {
		if m.watch == nil {
			m.watch = contextwatch.NewHub()
		}
	})
	return m.watch
}

func (m *Manager) Members(ctx context.Context, contextName string) ([]Device, error) {
	state, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return nil, err
	}
	response, err := control.request(ctx, "members.list", "")
	if err != nil {
		return nil, err
	}
	online, coherent := control.presenceSnapshot()
	result := make([]Device, 0, len(response.Members))
	for _, member := range response.Members {
		status := memberStatus(state.DeviceID, member.DeviceID, online, coherent)
		result = append(result, Device{Label: member.Label, DeviceID: member.DeviceID, Aliases: aliasesFor(state.Aliases, member.Label), Status: status, CreatedAt: member.CreatedAt})
	}
	slices.SortFunc(result, compareDevices)
	return result, nil
}

func (m *Manager) PendingDevices(ctx context.Context, contextName string) ([]PendingDevice, error) {
	_, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return nil, err
	}
	response, err := control.request(ctx, "pending.list", "")
	if err != nil {
		return nil, err
	}
	result := make([]PendingDevice, 0, len(response.Pending))
	for _, pending := range response.Pending {
		result = append(result, PendingDevice{Code: pending.Code, Label: pending.Label, DeviceID: pending.DeviceID, CreatedAt: pending.CreatedAt, ExpiresAt: pending.ExpiresAt})
	}
	return result, nil
}

func (m *Manager) ApproveDevice(ctx context.Context, contextName, code string) (Device, error) {
	code, err := membership.NormalizeApprovalCode(code)
	if err != nil {
		return Device{}, err
	}
	state, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return Device{}, err
	}
	response, err := control.request(ctx, "pending.approve", code)
	if err != nil {
		return Device{}, err
	}
	if response.Member == nil {
		return Device{}, errors.New("rendezvous returned an invalid approval response")
	}
	member := response.Member
	online, coherent := control.presenceSnapshot()
	return Device{Label: member.Label, DeviceID: member.DeviceID, Aliases: aliasesFor(state.Aliases, member.Label), Status: memberStatus(state.DeviceID, member.DeviceID, online, coherent), CreatedAt: member.CreatedAt}, nil
}

func (m *Manager) CreateInvite(ctx context.Context, contextName, label string, lifetime time.Duration) (inviteapi.Creation, error) {
	if membership.ValidateLabel(label) != nil || lifetime < membership.MinInviteLifetime || lifetime > membership.MaxInviteLifetime || lifetime%time.Second != 0 {
		return inviteapi.Creation{}, &InviteError{Code: "invalid_request", Message: "invalid invite request"}
	}
	state, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return inviteapi.Creation{}, err
	}
	requestID, err := newContextSession("")
	if err != nil {
		return inviteapi.Creation{}, err
	}
	request := inviteapi.ControlCreateRequest{Type: "invite.create", RequestID: requestID, CreateRequest: inviteapi.CreateRequest{Version: inviteapi.Version, Label: label, LifetimeSeconds: int64(lifetime / time.Second)}}
	data, err := control.requestControl(ctx, requestID, request.Type, request, true)
	if err != nil {
		return inviteapi.Creation{}, err
	}
	if inviteErr, ok := decodeInviteError(data, requestID, "invalid_request", string(membership.CodeInviteLabelUnavailable), string(membership.CodeInviteCapacity)); ok {
		var deterministic *InviteError
		if errors.As(inviteErr, &deterministic) {
			return inviteapi.Creation{}, inviteErr
		}
		return inviteapi.Creation{}, ErrInviteCreateOutcomeUnknown
	}
	var response inviteapi.ControlCreation
	if decodeStrictControlJSON(data, &response) != nil || response.Type != "invite.created" || response.RequestID != requestID || inviteapi.ValidateCreation(response.Creation, state.ServerID, label, "member", state.DeviceID, lifetime) != nil {
		return inviteapi.Creation{}, ErrInviteCreateOutcomeUnknown
	}
	return response.Creation, nil
}

func (m *Manager) ListInvites(ctx context.Context, contextName string) (inviteapi.List, error) {
	_, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return inviteapi.List{}, err
	}
	requestID, err := newContextSession("")
	if err != nil {
		return inviteapi.List{}, err
	}
	request := inviteapi.ControlListRequest{Type: "invite.list", RequestID: requestID, Version: inviteapi.Version}
	data, err := control.requestControl(ctx, requestID, request.Type, request, false)
	if err != nil {
		return inviteapi.List{}, err
	}
	if inviteErr, ok := decodeInviteError(data, requestID, "invalid_request"); ok {
		return inviteapi.List{}, inviteErr
	}
	var response inviteapi.ControlList
	if decodeStrictControlJSON(data, &response) != nil || response.Type != "invite.listed" || response.RequestID != requestID || inviteapi.ValidateList(response.List) != nil {
		return inviteapi.List{}, errors.New("rendezvous returned an invalid invite list")
	}
	return response.List, nil
}

func (m *Manager) RevokeInvite(ctx context.Context, contextName, inviteID string) (inviteapi.Revocation, error) {
	if membership.ValidateInviteID(inviteID) != nil {
		return inviteapi.Revocation{}, &InviteError{Code: "invalid_request", Message: "invalid invite request"}
	}
	_, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return inviteapi.Revocation{}, err
	}
	requestID, err := newContextSession("")
	if err != nil {
		return inviteapi.Revocation{}, err
	}
	request := inviteapi.ControlRevokeRequest{Type: "invite.revoke", RequestID: requestID, Version: inviteapi.Version, InviteID: inviteID}
	data, err := control.requestControl(ctx, requestID, request.Type, request, true)
	if err != nil {
		return inviteapi.Revocation{}, err
	}
	if inviteErr, ok := decodeInviteError(data, requestID, "invalid_request", string(membership.CodeInviteUnavailable)); ok {
		var deterministic *InviteError
		if errors.As(inviteErr, &deterministic) {
			return inviteapi.Revocation{}, inviteErr
		}
		return inviteapi.Revocation{}, ErrInviteRevokeOutcomeUnknown
	}
	var response inviteapi.ControlRevocation
	if decodeStrictControlJSON(data, &response) != nil || response.Type != "invite.revoked" || response.RequestID != requestID || response.Version != inviteapi.Version || response.State != "revoked" || response.Invite.InviteID != inviteID || inviteapi.Validate(response.Invite) != nil {
		return inviteapi.Revocation{}, ErrInviteRevokeOutcomeUnknown
	}
	return response.Revocation, nil
}

func decodeInviteError(data []byte, requestID string, allowed ...string) (error, bool) {
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Type != "invite.error" {
		return nil, false
	}
	var response inviteapi.ControlError
	if decodeStrictControlJSON(data, &response) != nil || response.Type != "invite.error" || response.RequestID != requestID || response.Version != inviteapi.Version || len(response.Message) == 0 || len(response.Message) > 256 {
		return errors.New("rendezvous returned an invalid invite error"), true
	}
	messages := map[string]string{
		"invalid_request": "invalid invite request",
		string(membership.CodeInviteLabelUnavailable): "invite label is unavailable",
		string(membership.CodeInviteCapacity):         "invite capacity reached",
		string(membership.CodeInviteUnavailable):      "invite is unavailable",
		"internal_error":                              "invite administration failed",
	}
	if messages[response.Code] != response.Message {
		return errors.New("rendezvous returned an invalid invite error"), true
	}
	for _, code := range allowed {
		if response.Code == code {
			return &InviteError{Code: response.Code, Message: response.Message}, true
		}
	}
	if response.Code == "internal_error" {
		return errors.New("invite administration failed"), true
	}
	return errors.New("rendezvous returned an invalid invite error"), true
}

func (m *Manager) connectedControl(ctx context.Context, contextName string) (State, *controlConnection, error) {
	state, err := m.Get(ctx, contextName)
	if err != nil {
		return State{}, nil, err
	}
	m.mu.Lock()
	control := m.controls[contextName]
	m.mu.Unlock()
	if control == nil || control.ctx.Err() != nil {
		return State{}, nil, ErrContextDisconnected
	}
	return state, control, nil
}

func (c *controlConnection) presenceSnapshot() (map[string]bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	online := make(map[string]bool, len(c.peers))
	for _, peer := range c.peers {
		online[peer.DeviceID] = true
	}
	return online, c.ctx.Err() == nil
}

func memberStatus(localID, memberID string, online map[string]bool, coherent bool) string {
	if !coherent {
		return "unknown"
	}
	if memberID == localID {
		return "local"
	}
	if online[memberID] {
		return "online"
	}
	return "offline"
}

func aliasesFor(aliases map[string]string, label string) []string {
	result := make([]string, 0)
	for alias, target := range aliases {
		if strings.EqualFold(target, label) {
			result = append(result, alias)
		}
	}
	slices.SortFunc(result, func(a, b string) int {
		if value := strings.Compare(strings.ToLower(a), strings.ToLower(b)); value != 0 {
			return value
		}
		return strings.Compare(a, b)
	})
	return result
}

func compareMembers(a, b membership.Member) int {
	if value := strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)); value != 0 {
		return value
	}
	return strings.Compare(a.DeviceID, b.DeviceID)
}

func compareDevices(a, b Device) int {
	if value := strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)); value != 0 {
		return value
	}
	return strings.Compare(a.DeviceID, b.DeviceID)
}

func (m *Manager) startWorkerLocked(name string) {
	m.shutdownMu.Lock()
	defer m.shutdownMu.Unlock()
	if m.stopping {
		return
	}
	m.startWorkerWhileRunningLocked(name)
}

func (m *Manager) beginMutationCommit() (func(), error) {
	m.shutdownMu.Lock()
	defer m.shutdownMu.Unlock()
	if m.stopping {
		return nil, context.Canceled
	}
	m.mutations.Add(1)
	return m.mutations.Done, nil
}

func (m *Manager) startWorkerWhileRunningLocked(name string) {
	if m.runtime == nil {
		return
	}
	if !m.activated {
		if !slices.Contains(m.pending, name) {
			m.pending = append(m.pending, name)
		}
		return
	}
	if _, exists := m.workers[name]; exists {
		return
	}
	ctx, cancel := context.WithCancel(m.runtime)
	worker := &contextWorker{cancel: cancel, done: make(chan struct{})}
	m.workers[name] = worker
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			if m.workers[name] == worker {
				delete(m.workers, name)
			}
			m.mu.Unlock()
			close(worker.done)
		}()
		m.runContext(ctx, name)
	}()
}

func (m *Manager) runContext(ctx context.Context, name string) {
	failures := 0
	for ctx.Err() == nil {
		state, err := m.get(ctx, name)
		if err != nil || !state.Enabled || state.State == "revoked" || state.State == "expired" {
			return
		}
		switch state.State {
		case "pending":
			if state.ExpiresAt != nil && !time.Now().Before(*state.ExpiresAt) {
				_ = m.updateState(ctx, name, "expired")
				return
			}
			_ = m.refreshEnrollment(ctx, state)
			if !sleep(ctx, pollInterval) {
				return
			}
		default:
			if state.Credential == nil {
				_ = m.updateState(ctx, name, "disconnected")
				return
			}
			result := m.connectControl(ctx, state)
			if ctx.Err() != nil {
				return
			}
			if result.revoked {
				_ = m.updateState(ctx, name, "revoked")
				m.logger.Warn("context membership revoked", "context", state.Name, "peer", "@"+state.Label)
				return
			}
			if result.err != nil {
				m.logger.Warn("context protocol incompatible", "event", "protocol.unsupported", "context", state.Name, "reason", result.err)
			}
			_ = m.updateState(ctx, name, "disconnected")
			if result.healthy {
				failures = 0
			}
			failures++
			delay := m.policy.reconnectDelay(failures)
			if shouldLogReconnect(failures) {
				m.logger.Info("context reconnect scheduled", "event", "context.retry", "context", state.Name, "peer", "@"+state.Label, "attempt", failures, "delay", delay)
			}
			if !sleep(ctx, delay) {
				return
			}
		}
	}
}

func (m *Manager) refreshEnrollment(ctx context.Context, state State) error {
	publicKey, err := identity.LoadPublic(state.publicPath)
	if err != nil {
		return err
	}
	enrollment, err := m.enrollmentStatus(ctx, state.ServerURL, publicKey, state.Label)
	if err != nil {
		return err
	}
	if enrollment.State == "revoked" || enrollment.State == "expired" {
		return m.updateState(ctx, state.Name, enrollment.State)
	}
	if enrollment.State != "enrolled" || enrollment.Credential == nil {
		return nil
	}
	if err := verifyEnrollment(*enrollment.Credential, state.ServerID, state.DeviceID, state.Label); err != nil {
		return err
	}
	encoded, err := json.Marshal(enrollment.Credential)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `update contexts set credential = ?, pending_code = null, pending_expires_at = null, state = 'enrolled', updated_at = ? where name = ?`, string(encoded), time.Now().Unix(), state.Name)
	return err
}

type controlResult struct {
	revoked bool
	healthy bool
	err     error
}

func (m *Manager) connectControl(ctx context.Context, state State) (result controlResult) {
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		return controlResult{}
	}
	endpoint, err := websocketEndpoint(state.ServerURL)
	if err != nil {
		return controlResult{}
	}
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: m.client})
	if err != nil {
		return controlResult{}
	}
	defer conn.CloseNow()
	conn.SetReadLimit(rendezvousproto.MaxControlBytes)
	_, data, err := conn.Read(ctx)
	if err != nil {
		return controlResult{}
	}
	if version := controlProtocolVersion(data); version != rendezvousproto.AuthenticationVersion {
		return controlResult{err: &rendezvousproto.ProtocolMismatch{Boundary: "authentication", Expected: rendezvousproto.AuthenticationVersion, Actual: version, Remote: "server"}}
	}
	var challenge rendezvousproto.Challenge
	if decodeStrictControlJSON(data, &challenge) != nil {
		return controlResult{}
	}
	if challenge.Version != rendezvousproto.AuthenticationVersion {
		return controlResult{err: &rendezvousproto.ProtocolMismatch{Boundary: "authentication", Expected: rendezvousproto.AuthenticationVersion, Actual: challenge.Version, Remote: "server"}}
	}
	if rendezvousproto.VerifyServerChallenge(challenge, state.ServerID, time.Now()) != nil {
		return controlResult{}
	}
	signature, err := rendezvousproto.SignChallenge(privateKey, challenge)
	if err != nil {
		return controlResult{}
	}
	if writeWS(ctx, conn, rendezvousproto.Authentication{Version: rendezvousproto.AuthenticationVersion, Type: "authenticate", Credential: *state.Credential, Signature: signature}) != nil {
		return controlResult{}
	}
	_, data, err = conn.Read(ctx)
	if err != nil {
		return controlResult{}
	}
	if version := controlProtocolVersion(data); version != rendezvousproto.Version {
		return controlResult{err: &rendezvousproto.ProtocolMismatch{Boundary: "control", Expected: rendezvousproto.Version, Actual: version, Remote: "server"}}
	}
	var message controlMessage
	if decodeStrictControlJSON(data, &message) != nil {
		return controlResult{}
	}
	if message.Version != rendezvousproto.Version {
		return controlResult{err: &rendezvousproto.ProtocolMismatch{Boundary: "control", Expected: rendezvousproto.Version, Actual: message.Version, Remote: "server"}}
	}
	if message.Type != "authenticated" {
		return controlResult{}
	}
	if message.AuthenticationProof == nil || rendezvousproto.VerifyServerChallenge(challenge, state.ServerID, time.Now()) != nil || rendezvousproto.VerifyAuthenticatedProof(challenge, *message.AuthenticationProof, state.ServerID, state.DeviceID, state.Credential.Claims.DeviceKey, state.Credential.Claims.Revision, signature) != nil {
		return controlResult{}
	}
	baseline := make([]contextwatch.Peer, 0, len(message.Members))
	for _, member := range message.Members {
		if member.DeviceID == state.DeviceID {
			return controlResult{}
		}
		baseline = append(baseline, contextwatch.Peer{DeviceID: member.DeviceID, Label: member.Label})
	}
	if err := m.watchHub().Connect(state.Name, baseline); err != nil {
		return controlResult{}
	}
	controlContext, cancelControl := context.WithCancel(ctx)
	control := &controlConnection{
		manager: m, context: state, ctx: controlContext, conn: conn,
		peers: make(map[string]membership.Member), sessions: make(map[string]*contextSignaler), waiters: make(map[string]controlWaiter),
	}
	for _, member := range message.Members {
		control.peers[strings.ToLower(member.Label)] = member
	}
	m.mu.Lock()
	m.controls[state.Name] = control
	m.mu.Unlock()
	m.logger.Info("context connected", "event", "context.connected", "context", state.Name, "peer", "@"+state.Label, "peers", len(control.peers))
	keepaliveDone := make(chan keepaliveResult, 1)
	go func() {
		result := runKeepalive(controlContext, conn, &control.writes, m.policy)
		keepaliveDone <- result
		if result.err != nil {
			cancelControl()
		}
	}()
	defer func() {
		cancelControl()
		keepalive := <-keepaliveDone
		result.healthy = keepalive.healthy
		if keepalive.err != nil && ctx.Err() == nil {
			m.logger.Warn("context keepalive failed", "context", state.Name, "peer", "@"+state.Label, "reason", keepalive.err)
		}
		control.closeSessions()
		control.closeWaiters()
		m.mu.Lock()
		if m.controls[state.Name] == control {
			m.watchHub().Disconnect(state.Name)
			delete(m.controls, state.Name)
		}
		m.mu.Unlock()
		m.logger.Info("context disconnected", "event", "context.disconnected", "context", state.Name, "peer", "@"+state.Label)
	}()
	_ = m.updateState(ctx, state.Name, "connected")
	for {
		_, data, err = conn.Read(controlContext)
		if err != nil {
			return result
		}
		var envelope struct {
			Version   int    `json:"version"`
			Type      string `json:"type"`
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(data, &envelope) != nil {
			continue
		}
		if !strings.HasPrefix(envelope.Type, "invite.") && envelope.Version != rendezvousproto.Version {
			result.err = &rendezvousproto.ProtocolMismatch{Boundary: "control", Expected: rendezvousproto.Version, Actual: envelope.Version, Remote: "server"}
			return result
		}
		message = controlMessage{Version: envelope.Version, Type: envelope.Type, RequestID: envelope.RequestID}
		if !strings.HasPrefix(envelope.Type, "invite.") && decodeStrictControlJSON(data, &message) != nil {
			continue
		}
		if message.Type == "revoked" && message.DeviceID == state.DeviceID {
			result.revoked = true
			return result
		}
		if control.handleData(data, message) != nil {
			return result
		}
	}
}

func decodeStrictControlJSON(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("control message has trailing data")
	}
	return nil
}

func controlProtocolVersion(data []byte) int {
	var envelope struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(data, &envelope)
	return envelope.Version
}

func (c *controlConnection) handle(message controlMessage) {
	data, _ := json.Marshal(message)
	_ = c.handleData(data, message)
}

func (c *controlConnection) handleData(data []byte, message controlMessage) error {
	if message.RequestID != "" && (message.Type == "presence.joined" || message.Type == "presence.left") {
		return contextwatch.ErrInvalidProjection
	}
	if (message.Version == rendezvousproto.Version || strings.HasPrefix(message.Type, "invite.")) && message.RequestID != "" {
		operation := message.Type
		switch operation {
		case "pending.approved":
			operation = "pending.approve"
		case "invite.created":
			operation = "invite.create"
		case "invite.listed":
			operation = "invite.list"
		case "invite.revoked":
			operation = "invite.revoke"
		case "ping.response":
			operation = "ping.request"
		case "invite.error":
			operation = ""
		default:
			operation = strings.TrimSuffix(operation, ".error")
		}
		c.mu.Lock()
		waiter, exists := c.waiters[message.RequestID]
		if exists && (waiter.operation == operation || operation == "" && strings.HasPrefix(waiter.operation, "invite.")) {
			waiter.response <- controlResponse{message: message, data: append([]byte(nil), data...)}
			delete(c.waiters, message.RequestID)
		}
		c.mu.Unlock()
		return nil
	}
	switch message.Type {
	case "presence.joined":
		if message.Member == nil || message.Member.DeviceID == c.context.DeviceID {
			return contextwatch.ErrInvalidProjection
		}
		c.mu.Lock()
		if err := c.manager.watchHub().Join(c.context.Name, contextwatch.Peer{DeviceID: message.Member.DeviceID, Label: message.Member.Label}); err != nil {
			c.mu.Unlock()
			return err
		}
		if previous, exists := c.peers[strings.ToLower(message.Member.Label)]; exists && previous.DeviceID != message.Member.DeviceID {
			c.cancelPeerSessionsLocked(previous.DeviceID)
		}
		c.peers[strings.ToLower(message.Member.Label)] = *message.Member
		c.mu.Unlock()
		c.manager.logger.Info("peer joined", "event", "peer.joined", "context", c.context.Name, "peer", "@"+message.Member.Label)
	case "presence.left":
		c.mu.Lock()
		left := make([]string, 0, 1)
		for label, peer := range c.peers {
			if peer.DeviceID == message.DeviceID {
				delete(c.peers, label)
				left = append(left, peer.Label)
			}
		}
		c.cancelPeerSessionsLocked(message.DeviceID)
		c.manager.watchHub().Leave(c.context.Name, message.DeviceID)
		c.mu.Unlock()
		for _, label := range left {
			c.manager.logger.Info("peer left", "event", "peer.left", "context", c.context.Name, "peer", "@"+label)
		}
	case "signal":
		if len(message.Payload) == 0 || len(message.Payload) > signalproto.MaxEnvelopeBytes {
			return nil
		}
		var envelope signalproto.Envelope
		if json.Unmarshal(message.Payload, &envelope) != nil || envelope.From != message.From || envelope.To != c.context.DeviceID || !validContextSession(envelope.Session) {
			return nil
		}
		c.mu.Lock()
		signaler := c.sessions[envelope.Session]
		peer := c.peerByIDLocked(message.From)
		if signaler == nil && envelope.Kind == signalproto.KindDescription && len(c.sessions) < 16 && peer != nil {
			signaler = c.newSignalerLocked(envelope.Session, message.From)
			c.manager.wg.Add(1)
			go func() {
				defer c.manager.wg.Done()
				c.manager.serveIncoming(c.context, *peer, signaler)
			}()
		}
		c.mu.Unlock()
		if signaler != nil {
			select {
			case signaler.incoming <- append([]byte(nil), message.Payload...):
			case <-signaler.ctx.Done():
			default:
				signaler.cancel()
			}
		}
	}
	return nil
}

func (c *controlConnection) cancelPeerSessionsLocked(deviceID string) {
	for session, signaler := range c.sessions {
		if signaler.peerID == deviceID {
			delete(c.sessions, session)
			signaler.cancel()
		}
	}
}

func (c *controlConnection) currentPeer(deviceID, label string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	peer := c.peerByIDLocked(deviceID)
	return peer != nil && peer.DeviceID == deviceID && peer.Label == label
}

func (c *controlConnection) request(ctx context.Context, operation, code string) (controlMessage, error) {
	requestID, err := newContextSession("")
	if err != nil {
		return controlMessage{}, err
	}
	data, err := c.requestControl(ctx, requestID, operation, controlMessage{Version: rendezvousproto.Version, Type: operation, RequestID: requestID, Code: code}, operation == "pending.approve")
	if err != nil {
		return controlMessage{}, err
	}
	var response controlMessage
	if decodeStrictControlJSON(data, &response) != nil {
		if operation == "pending.approve" {
			return controlMessage{}, ErrApprovalOutcomeUnknown
		}
		return controlMessage{}, errors.New("rendezvous returned an invalid control response")
	}
	if response.Error != "" {
		return controlMessage{}, fmt.Errorf("%w: %s", ErrOperationRejected, response.Error)
	}
	return response, nil
}

func (c *controlConnection) requestControl(ctx context.Context, requestID, operation string, request any, mutation bool) ([]byte, error) {
	waiter := controlWaiter{operation: operation, response: make(chan controlResponse, 1)}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, errors.New("context control connection is unavailable")
	}
	if len(c.waiters) >= 4 {
		c.mu.Unlock()
		return nil, ErrMemberOperationCapacity
	}
	c.waiters[requestID] = waiter
	c.mu.Unlock()
	attempted, err := c.writes.run(ctx, func() error {
		return writeWS(ctx, c.conn, request)
	})
	if err != nil {
		c.removeWaiter(requestID)
		if mutation && attempted {
			return nil, mutationOutcomeUnknown(operation)
		}
		return nil, err
	}
	response, err := c.waitControlResponse(ctx, waiter)
	if err != nil {
		c.removeWaiter(requestID)
		if mutation {
			return nil, mutationOutcomeUnknown(operation)
		}
		return nil, err
	}
	return response.data, nil
}

func mutationOutcomeUnknown(operation string) error {
	switch operation {
	case "pending.approve":
		return ErrApprovalOutcomeUnknown
	case "invite.create":
		return ErrInviteCreateOutcomeUnknown
	default:
		return ErrInviteRevokeOutcomeUnknown
	}
}

func (c *controlConnection) waitResponse(ctx context.Context, waiter controlWaiter) (controlMessage, error) {
	response, err := c.waitControlResponse(ctx, waiter)
	return response.message, err
}

func (c *controlConnection) waitControlResponse(ctx context.Context, waiter controlWaiter) (controlResponse, error) {
	select {
	case result := <-waiter.response:
		return result, result.err
	default:
	}
	select {
	case result := <-waiter.response:
		return result, result.err
	case <-ctx.Done():
		select {
		case result := <-waiter.response:
			return result, result.err
		default:
			return controlResponse{}, ctx.Err()
		}
	case <-c.ctx.Done():
		select {
		case result := <-waiter.response:
			return result, result.err
		default:
			return controlResponse{}, ErrContextDisconnected
		}
	}
}

func (c *controlConnection) removeWaiter(requestID string) {
	c.mu.Lock()
	delete(c.waiters, requestID)
	c.mu.Unlock()
}

func (c *controlConnection) closeWaiters() {
	c.mu.Lock()
	waiters := c.waiters
	c.waiters = make(map[string]controlWaiter)
	c.mu.Unlock()
	for _, waiter := range waiters {
		waiter.response <- controlResponse{err: ErrContextDisconnected}
	}
}

func (c *controlConnection) peerByIDLocked(deviceID string) *membership.Member {
	for _, peer := range c.peers {
		if peer.DeviceID == deviceID {
			value := peer
			return &value
		}
	}
	return nil
}

func (c *controlConnection) newSignalerLocked(session, peerID string) *contextSignaler {
	ctx, cancel := context.WithCancel(c.ctx)
	value := &contextSignaler{control: c, session: session, peerID: peerID, ctx: ctx, cancel: cancel, incoming: make(chan []byte, 32)}
	c.sessions[session] = value
	return value
}

func (c *controlConnection) openSignaler(session, peerID string) (*contextSignaler, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return nil, errors.New("context control connection is unavailable")
	}
	if len(c.sessions) >= 16 {
		return nil, errors.New("context direct-session capacity reached")
	}
	if c.peerByIDLocked(peerID) == nil {
		return nil, ErrPeerOffline
	}
	if _, exists := c.sessions[session]; exists {
		return nil, errors.New("direct session already exists")
	}
	return c.newSignalerLocked(session, peerID), nil
}

func (c *controlConnection) closeSessions() {
	c.mu.Lock()
	values := make([]*contextSignaler, 0, len(c.sessions))
	for _, value := range c.sessions {
		values = append(values, value)
	}
	c.sessions = make(map[string]*contextSignaler)
	c.mu.Unlock()
	for _, value := range values {
		value.cancel()
	}
}

func (s *contextSignaler) Send(ctx context.Context, payload []byte) error {
	if len(payload) == 0 || len(payload) > signalproto.MaxEnvelopeBytes {
		return errors.New("signaling envelope exceeds bounds")
	}
	_, err := s.control.writes.run(ctx, func() error {
		// Canceling a WebSocket write closes the shared control connection. Once
		// admitted, finish this frame independently of the direct session.
		writeContext, cancel := context.WithTimeout(s.control.ctx, 10*time.Second)
		defer cancel()
		return writeWS(writeContext, s.control.conn, controlMessage{Version: rendezvousproto.Version, Type: "signal", To: s.peerID, Payload: json.RawMessage(payload)})
	})
	return err
}

func (s *contextSignaler) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case value := <-s.incoming:
		return value, nil
	}
}

func (s *contextSignaler) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.control.mu.Lock()
		if s.control.sessions[s.session] == s {
			delete(s.control.sessions, s.session)
		}
		s.control.mu.Unlock()
	})
	return nil
}

func (m *Manager) serveIncoming(state State, peer membership.Member, signaler *contextSignaler) {
	protocol, ok := classifyIncomingSession(signaler.session)
	if !ok {
		_ = signaler.Close()
		return
	}
	current, scope, err := m.incomingState(signaler.control.ctx, state.Name, signaler.session)
	if err != nil {
		_ = signaler.Close()
		return
	}
	state = current
	if scope != 0 {
		defer m.endContextOperation(state.Name, scope)
	}
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return
	}
	switch protocol.kind {
	case incomingProbe:
		_, _ = probe.Run(signaler.control.ctx, probe.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			Timeout: 20 * time.Second, AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, Logger: m.logger,
		})
		return
	case incomingPing:
		incomingContext, cancel := context.WithCancel(signaler.control.ctx)
		defer cancel()
		connectTimer := time.AfterFunc(20*time.Second, cancel)
		session, err := direct.Connect(incomingContext, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: ping.ChannelLabel, ChannelProtocol: ping.Protocol,
			MaxMessageBytes: ping.MaxMessageBytes, MessageQueue: ping.MessageQueue, MaxBufferedBytes: ping.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true,
		})
		connectTimer.Stop()
		if err != nil {
			return
		}
		defer session.Close()
		_ = ping.Serve(incomingContext, session)
		return
	case incomingBenchmark:
		select {
		case m.incoming <- struct{}{}:
			defer func() { <-m.incoming }()
		default:
			_ = signaler.Close()
			return
		}
		incomingContext, cancel := context.WithCancel(signaler.control.ctx)
		defer cancel()
		connectTimer := time.AfterFunc(20*time.Second, cancel)
		session, err := direct.Connect(incomingContext, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: benchmark.ChannelLabel, ChannelProtocol: benchmark.Protocol,
			MaxMessageBytes: benchmark.MaxMessageBytes, MessageQueue: benchmark.MessageQueue, MaxBufferedBytes: benchmark.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true,
		})
		connectTimer.Stop()
		if err != nil {
			return
		}
		defer session.Close()
		if err := benchmark.Serve(incomingContext, session); err != nil {
			m.logIncomingProtocolFailure("benchmark", state.Name, peer.Label)
		}
		return
	case incomingRecent:
		session, err := direct.Connect(signaler.ctx, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: recent.ChannelLabel, ChannelProtocol: recent.Protocol,
			MaxMessageBytes: recent.MaxMessageBytes, MessageQueue: recent.MessageQueue, MaxBufferedBytes: recent.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true,
		})
		if err != nil {
			return
		}
		defer session.Close()
		_ = m.serveRecentChannel(session.Context(), signaler, recent.NewDirectChannel(session), state, peer)
		return
	case incomingRecoverableSend:
		select {
		case m.incoming <- struct{}{}:
			defer func() { <-m.incoming }()
		default:
			_ = signaler.Close()
			return
		}
		if err := os.MkdirAll(state.InboxRoot, 0o700); err != nil {
			return
		}
		session, err := direct.Connect(signaler.control.ctx, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: "px-transfer", ChannelProtocol: transfer.ResumeProtocol,
			MaxMessageBytes: transfer.MaxMessageBytes, MessageQueue: transfer.DefaultQueueDepth, MaxBufferedBytes: transfer.DefaultBufferedBytes, Logger: m.logger,
		})
		if err != nil {
			return
		}
		defer session.Close()
		started, committed := false, false
		transferID, transferName := "", ""
		result, err := transfer.ReceiveResumable(session.Context(), transfer.NewDirectChannel(session), transfer.ResumeReceiveConfig{
			InboxRoot: state.InboxRoot, OfferedRoot: state.OfferedRoot, Context: state.Name, SenderID: peer.DeviceID, SenderLabel: peer.Label, ReceiverID: state.DeviceID,
			OfferedRootRevision: state.OfferedRootRevision, MaxFileBytes: transfer.DefaultMaxFileBytes, Store: m.transfers, Progress: func(event transfer.ResumeEvent) {
				if event.TransferID != "" {
					transferID = event.TransferID
				}
				if event.Name != "" {
					transferName = event.Name
				}
				if !started {
					started = true
					m.logTransfer("transfer.started", "incoming transfer started", "incoming", state.Name, peer.Label, transferID, transferName, 0)
				}
				if event.State == "committed" {
					committed = true
					m.logTransfer("transfer.committed", "incoming transfer committed", "incoming", state.Name, peer.Label, transferID, transferName, event.Bytes)
				}
			},
		})
		if err != nil {
			if started && !committed {
				m.logTransfer("transfer.failed", "incoming transfer failed", "incoming", state.Name, peer.Label, transferID, transferName, 0)
			}
			return
		}
		if !committed {
			m.logTransfer("transfer.committed", "incoming transfer committed", "incoming", state.Name, peer.Label, transferID, result.Name, result.Bytes)
		}
		return
	case incomingFastSend:
		select {
		case m.incoming <- struct{}{}:
			defer func() { <-m.incoming }()
		default:
			_ = signaler.Close()
			return
		}
		if err := os.MkdirAll(state.InboxRoot, 0o700); err != nil {
			return
		}
		session, err := direct.Connect(signaler.control.ctx, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: transfer.FastChannelLabel, ChannelProtocol: transfer.FastProtocol,
			MaxMessageBytes: transfer.MaxMessageBytes, MessageQueue: transfer.DefaultQueueDepth, MaxBufferedBytes: transfer.DefaultBufferedBytes, Logger: m.logger,
		})
		if err != nil {
			return
		}
		defer session.Close()
		if _, err := transfer.ReceiveFast(session.Context(), transfer.NewDirectChannel(session), transfer.FastReceiveConfig{
			InboxRoot: state.InboxRoot, OfferedRoot: state.OfferedRoot, Context: state.Name, SenderLabel: peer.Label, MaxFileBytes: transfer.DefaultMaxFileBytes,
		}); err != nil {
			m.logIncomingProtocolFailure("fast_send", state.Name, peer.Label)
		}
		return
	case incomingPut:
		select {
		case m.incoming <- struct{}{}:
			defer func() { <-m.incoming }()
		default:
			_ = signaler.Close()
			return
		}
		if state.PutRoot == nil || !state.AllowPut || validatePutRootAuthority(state) != nil {
			return
		}
		session, err := direct.Connect(signaler.control.ctx, direct.Config{
			Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
			AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: put.ChannelLabel, ChannelProtocol: put.Protocol,
			MaxMessageBytes: put.MaxMessageBytes, MessageQueue: put.QueueDepth, MaxBufferedBytes: put.MaxBufferedBytes, Logger: m.logger,
		})
		if err != nil {
			return
		}
		defer session.Close()
		_, _ = put.Receive(session.Context(), put.NewDirectChannel(session), put.ReceiveConfig{Root: *state.PutRoot, Context: state.Name, SenderID: peer.DeviceID, SenderLabel: peer.Label, ReceiverID: state.DeviceID, RootRevision: state.PutRootRevision, Store: m.puts, Committed: func(event put.CommittedEvent) {
			m.logger.Info("remote put committed", "event", event.Type, "transfer_id", event.TransferID, "context", event.Context, "peer", "@"+event.PeerLabel, "created", event.Created, "replaced", event.Replaced, "bytes", event.Bytes, "durability", event.Durability)
		}})
		return
	case incomingOffered:
		// Continue below after the specialized protocol handlers.
	}
	session, err := direct.Connect(signaler.control.ctx, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey,
		AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: "px-offered", ChannelProtocol: offered.Protocol,
		MaxMessageBytes: offered.MaxMessageBytes, MessageQueue: offered.DefaultQueueDepth, MaxBufferedBytes: offered.DefaultBufferedBytes, Logger: m.logger,
	})
	if err != nil {
		return
	}
	defer session.Close()
	_ = offered.Serve(session.Context(), offered.NewDirectChannel(session), state.OfferedRoot)
}

func (m *Manager) serveRecentChannel(ctx context.Context, signaler *contextSignaler, channel recent.Channel, state State, peer membership.Member) error {
	defer signaler.Close()
	deadline := m.recentDeadline
	if deadline <= 0 {
		deadline = recent.InboundDeadline
	}
	reporter := recent.Reporter{DeviceID: state.DeviceID, Label: state.Label}
	return recent.ServeWithDeadline(ctx, channel, reporter, peer.DeviceID, func(ctx context.Context, peerID string, limit int) ([]recent.Observation, error) {
		return m.recentForPeer(ctx, signaler.control, state.Name, peer, peerID, limit)
	}, deadline)
}

func (m *Manager) recentForPeer(ctx context.Context, control *controlConnection, contextName string, peer membership.Member, peerID string, limit int) ([]recent.Observation, error) {
	if peerID != peer.DeviceID || !control.currentPeer(peer.DeviceID, peer.Label) {
		return nil, ErrPeerOffline
	}
	values, err := m.recent.List(ctx, contextName, peerID, limit)
	if err == nil && m.recentQuery != nil {
		m.recentQuery()
	}
	return values, err
}

func (m *Manager) incomingState(ctx context.Context, name, session string) (State, operationScope, error) {
	protocol, ok := classifyIncomingSession(session)
	if !ok {
		return State{}, 0, ErrOperationRejected
	}
	if protocol.scope == 0 {
		state, err := m.Get(ctx, name)
		return state, 0, err
	}
	scope := protocol.scope
	state, err := m.beginContextOperation(ctx, name, scope)
	if err != nil {
		return State{}, 0, err
	}
	if scope&operationOffered != 0 {
		if err := validateOfferedRootAuthority(state); err != nil {
			m.endContextOperation(name, scope)
			return State{}, 0, fmt.Errorf("%w: %v", ErrInvalidContextState, err)
		}
	}
	if scope&operationPut != 0 && (!state.AllowPut || validatePutRootAuthority(state) != nil) {
		m.endContextOperation(name, scope)
		return State{}, 0, fmt.Errorf("%w: put authority is disabled or invalid", ErrInvalidContextState)
	}
	return state, scope, nil
}

func (m *Manager) ListRemote(ctx context.Context, contextName, peerName, path string) ([]offered.Entry, error) {
	if _, err := m.beginRootOperation(ctx, contextName); err != nil {
		return nil, err
	}
	defer m.endTransfer(contextName)
	session, err := m.connectPeer(ctx, contextName, peerName)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return offered.RequestList(session.Context(), offered.NewDirectChannel(session), path)
}

func (m *Manager) GetRemote(ctx context.Context, contextName, peerName, path, destination string, maxFileBytes int64) (offered.GetResult, error) {
	return m.GetRemoteProgress(ctx, contextName, peerName, path, destination, maxFileBytes, nil)
}

func (m *Manager) GetRemoteProgress(ctx context.Context, contextName, peerName, path, destination string, maxFileBytes int64, progress func(offered.GetEvent)) (offered.GetResult, error) {
	if _, err := m.beginRootOperation(ctx, contextName); err != nil {
		return offered.GetResult{}, err
	}
	defer m.endTransfer(contextName)
	operationContext, operationID, release, err := m.beginRuntimeTransfer(ctx, transfer.InventoryItem{Kind: "get", Context: contextName, Peer: strings.TrimPrefix(peerName, "@"), Name: filepath.Base(filepath.FromSlash(path)), State: "active"})
	if err != nil {
		return offered.GetResult{}, err
	}
	defer release()
	session, err := m.connectPeer(operationContext, contextName, peerName)
	if err != nil {
		return offered.GetResult{}, err
	}
	defer session.Close()
	result, err := offered.RequestGetProgressStaged(session.Context(), offered.NewDirectChannel(session), path, destination, maxFileBytes, func(ctx context.Context, destination string, declared int64) (offered.StagedFile, error) {
		return m.getCleanup.Create(ctx, destination, declared)
	}, func(event offered.GetEvent) {
		m.updateRuntimeTransfer(operationID, event.State, event.Bytes, event.Total)
		if progress != nil {
			progress(event)
		}
	})
	if getcleanup.IsCommittedCleanupPending(err) {
		m.logger.Warn("get committed with cleanup pending", "event", "get.cleanup_failed", "committed", 1, "retained", 1)
	}
	return result, err
}

func (m *Manager) ProbeRemote(ctx context.Context, contextName, peerName string, timeout time.Duration) (probe.Result, error) {
	state, peer, signaler, err := m.openPeerSignaler(ctx, contextName, peerName, "px-probe-")
	if err != nil {
		return probe.Result{}, err
	}
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return probe.Result{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return probe.Result{}, err
	}
	return probe.Run(ctx, probe.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true,
		Timeout: timeout, AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, Logger: m.logger,
	})
}

func (m *Manager) PingPeer(ctx context.Context, contextName, peerName string, count int, showAddresses bool) (ping.Result, error) {
	if err := ping.ValidateCount(count); err != nil {
		return ping.Result{}, err
	}
	operationContext, cancelOperation := context.WithTimeout(ctx, 30*time.Second)
	defer cancelOperation()
	state, peer, signaler, err := m.openPeerSignaler(operationContext, contextName, peerName, ping.SessionPrefix)
	if err != nil {
		return ping.Result{}, err
	}
	defer signaler.Close()
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		return ping.Result{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		return ping.Result{}, err
	}
	sessionContext, cancelSession := context.WithCancel(signaler.control.ctx)
	stopCancellation := context.AfterFunc(operationContext, cancelSession)
	defer func() { stopCancellation(); cancelSession() }()
	connectTimer := time.AfterFunc(20*time.Second, cancelSession)
	started := time.Now()
	session, err := direct.Connect(sessionContext, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true,
		AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: ping.ChannelLabel, ChannelProtocol: ping.Protocol,
		MaxMessageBytes: ping.MaxMessageBytes, MessageQueue: ping.MessageQueue, MaxBufferedBytes: ping.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true,
	})
	setup := time.Since(started).Nanoseconds()
	connectTimer.Stop()
	if err != nil {
		return ping.Result{}, err
	}
	defer session.Close()
	result := ping.Peer(operationContext, session, count)
	if err := operationContext.Err(); err != nil {
		return ping.Result{}, err
	}
	result.Mode = "peer"
	result.Reporter = ping.Identity{DeviceID: state.DeviceID, Label: state.Label}
	result.Target = ping.Identity{DeviceID: peer.DeviceID, Label: peer.Label}
	result.SetupDurationNS = &setup
	pair := session.CandidatePair()
	result.GatheredCandidateTypes = session.GatheredCandidateTypes()
	result.SelectedLocalCandidateType = pair.LocalType
	result.SelectedRemoteCandidateType = pair.RemoteType
	if showAddresses {
		result.SelectedLocalAddress = pair.LocalAddress
		result.SelectedRemoteAddress = pair.RemoteAddress
	}
	relay := pair.LocalType == "relay" || pair.RemoteType == "relay"
	result.RelayUsed = &relay
	return result, nil
}

func (m *Manager) BenchmarkPeer(ctx context.Context, contextName, peerName string, duration time.Duration) (benchmark.Result, error) {
	if err := benchmark.ValidateDuration(duration); err != nil {
		return benchmark.Result{}, err
	}
	operationContext, cancelOperation := context.WithTimeout(ctx, 20*time.Second+2*duration+10*time.Second)
	defer cancelOperation()
	state, peer, signaler, err := m.openPeerSignaler(operationContext, contextName, peerName, benchmark.SessionPrefix)
	if err != nil {
		return benchmark.Result{}, err
	}
	defer signaler.Close()
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		return benchmark.Result{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		return benchmark.Result{}, err
	}
	sessionContext, cancelSession := context.WithCancel(signaler.control.ctx)
	stopCancellation := context.AfterFunc(operationContext, cancelSession)
	defer func() { stopCancellation(); cancelSession() }()
	connectTimer := time.AfterFunc(20*time.Second, cancelSession)
	started := time.Now()
	session, err := direct.Connect(sessionContext, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true,
		AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: benchmark.ChannelLabel, ChannelProtocol: benchmark.Protocol,
		MaxMessageBytes: benchmark.MaxMessageBytes, MessageQueue: benchmark.MessageQueue, MaxBufferedBytes: benchmark.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true,
	})
	setup := time.Since(started).Nanoseconds()
	connectTimer.Stop()
	if err != nil {
		return benchmark.Result{}, err
	}
	defer session.Close()
	result, err := benchmark.Run(operationContext, session, duration)
	if err != nil {
		return benchmark.Result{}, err
	}
	result.Reporter = benchmark.Identity{DeviceID: state.DeviceID, Label: state.Label}
	result.Target = benchmark.Identity{DeviceID: peer.DeviceID, Label: peer.Label}
	result.SetupDurationNS = setup
	pair := session.CandidatePair()
	result.GatheredCandidateTypes = session.GatheredCandidateTypes()
	result.SelectedLocalCandidateType = pair.LocalType
	result.SelectedRemoteCandidateType = pair.RemoteType
	result.RelayUsed = pair.LocalType == "relay" || pair.RemoteType == "relay"
	return result, nil
}

func (m *Manager) PingServer(ctx context.Context, contextName string, count int) (ping.Result, error) {
	if err := ping.ValidateCount(count); err != nil {
		return ping.Result{}, err
	}
	state, err := m.Get(ctx, contextName)
	if err != nil {
		return ping.Result{}, err
	}
	m.mu.Lock()
	control := m.controls[contextName]
	m.mu.Unlock()
	if control == nil {
		return ping.Result{}, ErrContextDisconnected
	}
	operationContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := ping.Measure(operationContext, count, func(sampleContext context.Context, _ int) error {
		requestID, err := newContextSession("")
		if err != nil {
			return err
		}
		request := rendezvousproto.PingControl{Version: rendezvousproto.Version, Type: "ping.request", RequestID: requestID}
		data, err := control.requestControl(sampleContext, requestID, request.Type, request, false)
		if err != nil {
			return err
		}
		var response rendezvousproto.PingControl
		if decodeStrictControlJSON(data, &response) != nil || response.Version != rendezvousproto.Version || response.Type != "ping.response" || response.RequestID != requestID {
			return errors.New("rendezvous returned an invalid ping response")
		}
		return nil
	})
	if err := operationContext.Err(); err != nil {
		return ping.Result{}, err
	}
	result.Mode = "server"
	result.Reporter = ping.Identity{DeviceID: state.DeviceID, Label: state.Label}
	result.Target = ping.Identity{DeviceID: state.ServerID}
	return result, nil
}

func (m *Manager) SendRemote(ctx context.Context, contextName, peerName, source, name, transferID string, stdinSpool, public, recoverable bool, maxFileBytes int64, progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	var retry transfer.RetryMetadata
	var lease *transfer.SendLease
	var err error
	if transferID != "" {
		state, err := m.Get(ctx, contextName)
		if err != nil {
			return transfer.Result{}, err
		}
		requestedPeer := peerName
		if alias := state.Aliases[requestedPeer]; alias != "" {
			requestedPeer = alias
		}
		lease, err = m.transfers.ClaimSend(ctx, transferID, contextName, requestedPeer, time.Now())
		if err != nil {
			return transfer.Result{}, err
		}
		defer lease.Release()
		retry = lease.Metadata()
		peerName = retry.PeerLabel
		ctx = lease.Context()
	}
	if stdinSpool && !validStdinSpool(m.paths.AgentTransfers, source) {
		return transfer.Result{}, errors.New("stdin spool is outside agent transfer state")
	}
	if stdinSpool && !recoverable {
		defer func() { _ = os.Remove(source) }()
	}
	if _, err := m.beginRootOperation(ctx, contextName); err != nil {
		return transfer.Result{}, err
	}
	defer m.endTransfer(contextName)
	prefix := transfer.FastSessionPrefix
	if recoverable {
		prefix = "px-send-"
	}
	state, peer, signaler, err := m.openPeerSignaler(ctx, contextName, peerName, prefix)
	if err != nil {
		return transfer.Result{}, err
	}
	if transferID != "" && retryPeerError(retry, peer) != nil {
		_ = signaler.Close()
		return transfer.Result{}, transfer.ErrTransferPeerMismatch
	}
	return m.executeRemoteSend(ctx, contextName, peerName, source, name, transferID, stdinSpool, public, recoverable, maxFileBytes, lease, state, peer, signaler, progress)
}

func (m *Manager) PutRemote(ctx context.Context, contextName, peerName, source, destination string, replace bool, expectSHA256 string, progress func(put.Event)) (put.Result, error) {
	operationContext, cancelOperation := context.WithCancel(ctx)
	defer cancelOperation()
	operationID := ""
	register := func(event put.Event) {
		if event.TransferID != "" && operationID == "" {
			operationID = event.TransferID
		}
		if operationID != "" {
			m.mu.Lock()
			operation := m.transferOps[operationID]
			if operation == nil {
				now := time.Now().UTC()
				operation = &runtimeTransfer{item: transfer.InventoryItem{ID: operationID, Kind: "put-send", Context: contextName, Peer: strings.TrimPrefix(peerName, "@"), Name: destination, State: "active", Total: event.Total, CreatedAt: now, UpdatedAt: now, Active: true}, cancel: cancelOperation}
				m.transferOps[operationID] = operation
			}
			operation.item.Bytes, operation.item.Total, operation.item.UpdatedAt = event.Bytes, event.Total, time.Now().UTC()
			m.mu.Unlock()
		}
		if progress != nil {
			progress(event)
		}
	}
	defer func() {
		if operationID != "" {
			m.mu.Lock()
			delete(m.transferOps, operationID)
			m.mu.Unlock()
		}
	}()
	if _, err := m.beginRootOperation(operationContext, contextName); err != nil {
		return put.Result{}, err
	}
	defer m.endTransfer(contextName)
	state, peer, signaler, err := m.openPeerSignaler(operationContext, contextName, peerName, put.SessionPrefix)
	if err != nil {
		return put.Result{}, err
	}
	return m.executeRemotePut(operationContext, state, peer, signaler, source, destination, replace, expectSHA256, nil, register)
}

func (m *Manager) executeRemotePut(ctx context.Context, state State, peer membership.Member, signaler *contextSignaler, source, destination string, replace bool, expectSHA256 string, lease *put.SenderLease, progress func(put.Event)) (put.Result, error) {
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return put.Result{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return put.Result{}, err
	}
	sessionContext, cancelSession := context.WithCancel(signaler.control.ctx)
	stopCancellation := context.AfterFunc(ctx, cancelSession)
	session, err := direct.Connect(sessionContext, direct.Config{Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true, AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: put.ChannelLabel, ChannelProtocol: put.Protocol, MaxMessageBytes: put.MaxMessageBytes, MessageQueue: put.QueueDepth, MaxBufferedBytes: put.MaxBufferedBytes, Logger: m.logger})
	if err != nil {
		stopCancellation()
		cancelSession()
		return put.Result{}, err
	}
	defer func() { _ = session.Close(); stopCancellation(); cancelSession() }()
	return put.Send(session.Context(), put.NewDirectChannel(session), put.SendConfig{Source: source, Destination: destination, Context: state.Name, SenderID: state.DeviceID, ReceiverID: peer.DeviceID, PeerLabel: peer.Label, Replace: replace, ExpectSHA256: expectSHA256, Store: m.puts, Lease: lease, Progress: progress})
}

func (m *Manager) executeRemoteSend(ctx context.Context, contextName, peerName, source, name, transferID string, stdinSpool, public, recoverable bool, maxFileBytes int64, lease *transfer.SendLease, state State, peer membership.Member, signaler *contextSignaler, progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	m.logTransfer("transfer.started", "outgoing transfer started", "outgoing", contextName, peerName, transferID, name, 0)
	failed := true
	loggedID, loggedName := transferID, name
	defer func() {
		if failed {
			m.logTransfer("transfer.failed", "outgoing transfer failed", "outgoing", contextName, peerName, loggedID, loggedName, 0)
		}
	}()
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return transfer.Result{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return transfer.Result{}, err
	}
	sessionContext, cancelSession := context.WithCancel(signaler.control.ctx)
	stopCancellation := context.AfterFunc(ctx, cancelSession)
	channelLabel, channelProtocol := transfer.FastChannelLabel, transfer.FastProtocol
	if recoverable {
		channelLabel, channelProtocol = "px-transfer", transfer.ResumeProtocol
	}
	session, err := direct.Connect(sessionContext, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true,
		AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: channelLabel, ChannelProtocol: channelProtocol,
		MaxMessageBytes: transfer.MaxMessageBytes, MessageQueue: transfer.DefaultQueueDepth, MaxBufferedBytes: transfer.DefaultBufferedBytes, Logger: m.logger,
	})
	if err != nil {
		stopCancellation()
		cancelSession()
		return transfer.Result{}, err
	}
	defer func() {
		_ = session.Close()
		stopCancellation()
		cancelSession()
	}()
	visibility := transfer.VisibilityPrivate
	if public {
		visibility = transfer.VisibilityPublic
	}
	if !recoverable {
		result, err := transfer.SendFast(session.Context(), transfer.NewDirectChannel(session), transfer.FastSendConfig{Source: source, Name: name, Public: public, MaxFileBytes: maxFileBytes, Progress: progress})
		if err == nil {
			failed = false
			m.logTransfer("transfer.committed", "outgoing fast send completed", "outgoing", contextName, peer.Label, loggedID, result.Name, result.Bytes)
		} else if errors.Is(err, transfer.ErrFastOutcomeUnknown) {
			failed = false
			m.logTransfer("transfer.outcome_unknown", "outgoing fast send outcome is unknown", "outgoing", contextName, peer.Label, loggedID, result.Name, result.Bytes)
		}
		return result, err
	}
	result, err := transfer.SendResumable(session.Context(), transfer.NewDirectChannel(session), transfer.ResumeSendConfig{
		Source: source, Name: name, Context: state.Name, SenderID: state.DeviceID, ReceiverID: peer.DeviceID, PeerLabel: peer.Label,
		MaxFileBytes: maxFileBytes, StdinSpool: stdinSpool, Visibility: visibility, TransferID: transferID, Store: m.transfers, Lease: lease, Progress: func(event transfer.ResumeEvent) {
			if event.TransferID != "" {
				loggedID = event.TransferID
			}
			if event.Name != "" {
				loggedName = event.Name
			}
			if progress != nil {
				progress(event)
			}
		},
	})
	if err != nil {
		if result.Name != "" {
			failed = false
			m.logTransfer("transfer.committed", "outgoing transfer committed", "outgoing", contextName, peer.Label, loggedID, result.Name, result.Bytes)
		}
		return result, err
	}
	failed = false
	m.logTransfer("transfer.committed", "outgoing transfer committed", "outgoing", contextName, peer.Label, loggedID, result.Name, result.Bytes)
	return result, nil
}

func retryPeerError(retry transfer.RetryMetadata, peer membership.Member) error {
	if retry.PeerDeviceID != peer.DeviceID || !strings.EqualFold(retry.PeerLabel, peer.Label) {
		return transfer.ErrTransferPeerMismatch
	}
	return nil
}

type PreparedRetry struct {
	manager     *Manager
	contextName string
	retry       transfer.RetryMetadata
	lease       *transfer.SendLease
	state       State
	peer        membership.Member
	signaler    *contextSignaler
	once        sync.Once
}

type RetryOperation interface {
	Run(func(transfer.ResumeEvent)) (transfer.Result, error)
	Close()
}

func (m *Manager) PrepareRetry(ctx context.Context, contextName, id string) (RetryOperation, error) {
	if _, err := m.Get(ctx, contextName); err != nil {
		return nil, err
	}
	lease, err := m.transfers.ClaimSend(ctx, id, contextName, "", time.Now())
	if err != nil {
		if errors.Is(err, transfer.ErrTransferNotFound) {
			putLease, putErr := m.puts.ClaimSender(ctx, contextName, id)
			if putErr != nil {
				return nil, putErr
			}
			if putErr = put.ValidateSenderLease(ctx, putLease); putErr != nil {
				putLease.Release()
				return nil, putErr
			}
			record := putLease.Record()
			if _, putErr = m.beginRootOperation(ctx, contextName); putErr != nil {
				putLease.Release()
				return nil, putErr
			}
			state, peer, signaler, putErr := m.openPeerSignaler(ctx, contextName, record.PeerLabel, put.SessionPrefix)
			if putErr != nil {
				m.endTransfer(contextName)
				putLease.Release()
				return nil, putErr
			}
			if peer.DeviceID != record.ReceiverID || !strings.EqualFold(peer.Label, record.PeerLabel) {
				_ = signaler.Close()
				m.endTransfer(contextName)
				putLease.Release()
				return nil, transfer.ErrTransferPeerMismatch
			}
			return &PreparedPutRetry{manager: m, contextName: contextName, lease: putLease, state: state, peer: peer, signaler: signaler, ctx: ctx}, nil
		}
		return nil, err
	}
	retry := lease.Metadata()
	if _, err := m.beginRootOperation(lease.Context(), contextName); err != nil {
		lease.Release()
		return nil, err
	}
	state, peer, signaler, err := m.openPeerSignaler(lease.Context(), contextName, retry.PeerLabel, "px-send-")
	if err != nil {
		m.endTransfer(contextName)
		lease.Release()
		return nil, err
	}
	if retryPeerError(retry, peer) != nil {
		_ = signaler.Close()
		m.endTransfer(contextName)
		lease.Release()
		return nil, transfer.ErrTransferPeerMismatch
	}
	return &PreparedRetry{manager: m, contextName: contextName, retry: retry, lease: lease, state: state, peer: peer, signaler: signaler}, nil
}

type PreparedPutRetry struct {
	manager     *Manager
	contextName string
	lease       *put.SenderLease
	state       State
	peer        membership.Member
	signaler    *contextSignaler
	ctx         context.Context
	once        sync.Once
}

func (p *PreparedPutRetry) Run(progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	if p == nil || p.manager == nil || p.lease == nil || p.signaler == nil {
		return transfer.Result{}, transfer.ErrTransferNotFound
	}
	defer p.Close()
	record := p.lease.Record()
	operationContext, cancel := context.WithCancel(p.ctx)
	now := time.Now().UTC()
	p.manager.mu.Lock()
	if _, exists := p.manager.transferOps[record.ID]; exists {
		p.manager.mu.Unlock()
		cancel()
		return transfer.Result{}, transfer.ErrTransferActive
	}
	p.manager.transferOps[record.ID] = &runtimeTransfer{item: transfer.InventoryItem{ID: record.ID, Kind: "put-send", Context: record.Context, Peer: record.PeerLabel, Name: record.Destination, State: "active", Total: record.Size, CreatedAt: now, UpdatedAt: now, Active: true}, cancel: cancel}
	p.manager.mu.Unlock()
	defer func() {
		cancel()
		p.manager.mu.Lock()
		delete(p.manager.transferOps, record.ID)
		p.manager.mu.Unlock()
	}()
	result, err := p.manager.executeRemotePut(operationContext, p.state, p.peer, p.signaler, record.SourcePath, record.Destination, record.Mode == "replace", record.ExpectSHA256, p.lease, func(event put.Event) {
		p.manager.mu.Lock()
		if operation := p.manager.transferOps[record.ID]; operation != nil {
			operation.item.Bytes = event.Bytes
			operation.item.Total = event.Total
			operation.item.UpdatedAt = time.Now().UTC()
		}
		p.manager.mu.Unlock()
		if progress != nil {
			progress(transfer.ResumeEvent{Version: transfer.ResumeEventVersion, State: event.State, TransferID: event.TransferID, Bytes: event.Bytes, Total: event.Total, Name: event.Destination, Error: event.Error, Outcome: event.Outcome, Durability: event.Durability, Created: event.Created, Replaced: event.Replaced})
		}
	})
	return transfer.Result{Name: result.Destination, Bytes: result.Bytes, SHA256: result.SHA256}, err
}

func (p *PreparedPutRetry) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		if p.signaler != nil {
			_ = p.signaler.Close()
		}
		if p.manager != nil {
			p.manager.endTransfer(p.contextName)
		}
		if p.lease != nil {
			p.lease.Release()
		}
	})
}

func (p *PreparedRetry) Run(progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	if p == nil || p.manager == nil || p.lease == nil || p.signaler == nil {
		return transfer.Result{}, transfer.ErrTransferNotFound
	}
	defer p.Close()
	return p.manager.executeRemoteSend(p.lease.Context(), p.contextName, p.retry.PeerLabel, "", p.retry.Name, p.retry.ID, false, p.retry.Visibility == transfer.VisibilityPublic, true, transfer.DefaultMaxFileBytes, p.lease, p.state, p.peer, p.signaler, progress)
}

func (p *PreparedRetry) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		if p.signaler != nil {
			_ = p.signaler.Close()
		}
		if p.manager != nil {
			p.manager.endTransfer(p.contextName)
		}
		if p.lease != nil {
			p.lease.Release()
		}
	})
}

func (m *Manager) RetryTransfer(ctx context.Context, contextName, id string, progress func(transfer.ResumeEvent)) (transfer.Result, error) {
	prepared, err := m.PrepareRetry(ctx, contextName, id)
	if err != nil {
		return transfer.Result{}, err
	}
	return prepared.Run(progress)
}

func (m *Manager) ListTransfers(ctx context.Context, contextName string, limit int) (transfer.Inventory, error) {
	if err := m.requireTransferContext(ctx, contextName); err != nil {
		return transfer.Inventory{}, err
	}
	if limit <= 0 || limit > transfer.MaxInventoryLimit {
		return transfer.Inventory{}, fmt.Errorf("transfer limit must be between 1 and %d", transfer.MaxInventoryLimit)
	}
	inventory, err := m.transfers.List(ctx, contextName, transfer.MaxInventoryLimit, time.Now())
	if err != nil {
		return transfer.Inventory{}, err
	}
	putRecords, err := m.puts.Inventory(ctx, contextName, transfer.MaxInventoryLimit)
	if err != nil {
		return transfer.Inventory{}, err
	}
	for _, record := range putRecords {
		expires := record.ExpiresAt
		inventory.Transfers = append(inventory.Transfers, transfer.InventoryItem{ID: record.ID, Kind: "put-" + record.Direction, Context: record.Context, Peer: record.PeerLabel, Name: record.Destination, State: record.State, Bytes: record.Offset, Total: record.Size, Retryable: record.Direction == "send" && record.State == "transferring" && time.Now().Before(record.ExpiresAt), LocalCommitted: record.State == "committed", Created: record.State == "committed" && record.Mode == "create", Replaced: record.State == "committed" && record.Mode == "replace", Durability: record.Durability, OutcomeUnknown: record.State == "outcome_unknown", ActionRequired: record.State == "outcome_unknown" || record.State == "accept_current_intent", CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, ExpiresAt: &expires, CleanupPending: record.StageName != "" || record.BackupName != ""})
	}
	m.mu.Lock()
	positions := make(map[string]int, len(inventory.Transfers))
	for index, item := range inventory.Transfers {
		positions[item.Kind+":"+item.ID] = index
	}
	for _, operation := range m.transferOps {
		if contextName == "" || operation.item.Context == contextName {
			key := operation.item.Kind + ":" + operation.item.ID
			if index, exists := positions[key]; exists {
				inventory.Transfers[index] = operation.item
			} else {
				positions[key] = len(inventory.Transfers)
				inventory.Transfers = append(inventory.Transfers, operation.item)
			}
		}
	}
	m.mu.Unlock()
	slices.SortFunc(inventory.Transfers, func(a, b transfer.InventoryItem) int {
		if value := b.UpdatedAt.Compare(a.UpdatedAt); value != 0 {
			return value
		}
		if value := strings.Compare(a.Kind, b.Kind); value != 0 {
			return value
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(inventory.Transfers) > limit {
		inventory.Transfers = inventory.Transfers[:limit]
	}
	return inventory, nil
}

func (m *Manager) Recent(ctx context.Context, contextName string, limit int) (recent.Snapshot, error) {
	state, err := m.beginLocalContextOperation(ctx, contextName)
	if err != nil {
		return recent.Snapshot{}, err
	}
	defer m.endContextOperation(contextName, 0)
	if m.recentLease != nil {
		m.recentLease()
	}
	values, err := m.recent.List(ctx, contextName, "", limit)
	if err != nil {
		return recent.Snapshot{}, err
	}
	return recent.Snapshot{Version: recent.Version, Description: recent.Description, Reporter: recent.Reporter{DeviceID: state.DeviceID, Label: state.Label, Context: contextName}, Observations: values}, nil
}

func (m *Manager) ClearRecent(ctx context.Context, contextName string) (recent.ClearResult, error) {
	state, err := m.beginLocalContextOperation(ctx, contextName)
	if err != nil {
		return recent.ClearResult{}, err
	}
	defer m.endContextOperation(contextName, 0)
	if m.recentLease != nil {
		m.recentLease()
	}
	count, err := m.recent.Clear(ctx, contextName)
	if err != nil {
		return recent.ClearResult{}, err
	}
	return recent.ClearResult{Version: recent.Version, Description: recent.Description, Reporter: recent.Reporter{DeviceID: state.DeviceID, Label: state.Label, Context: contextName}, Cleared: count}, nil
}

func (m *Manager) RecentPeer(ctx context.Context, contextName, peerName string, limit int) (recent.Snapshot, error) {
	state, peer, signaler, err := m.openPeerSignaler(ctx, contextName, peerName, recent.SessionPrefix)
	if err != nil {
		return recent.Snapshot{}, err
	}
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return recent.Snapshot{}, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return recent.Snapshot{}, err
	}
	sessionContext, cancel := context.WithCancel(signaler.ctx)
	stop := context.AfterFunc(ctx, cancel)
	session, err := direct.Connect(sessionContext, direct.Config{Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true, AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: recent.ChannelLabel, ChannelProtocol: recent.Protocol, MaxMessageBytes: recent.MaxMessageBytes, MessageQueue: recent.MessageQueue, MaxBufferedBytes: recent.MaxBufferedBytes, Logger: m.logger, RetainSignaler: true})
	if err != nil {
		stop()
		cancel()
		return recent.Snapshot{}, err
	}
	defer func() { _ = session.Close(); stop(); cancel() }()
	expectedReporter := recent.Reporter{DeviceID: peer.DeviceID, Label: peer.Label}
	return recent.Request(session.Context(), recent.NewDirectChannel(session), limit, expectedReporter, state.DeviceID)
}

func (m *Manager) StatusSnapshot(ctx context.Context, requestedContext string) (StatusSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	contextName := requestedContext
	if contextName == "" {
		db, err := m.db()
		if err != nil {
			return StatusSnapshot{}, err
		}
		var selected sql.NullString
		if err := db.QueryRowContext(ctx, `select default_context from context_settings where singleton=1`).Scan(&selected); err != nil {
			return StatusSnapshot{}, err
		}
		if !selected.Valid {
			return StatusSnapshot{}, nil
		}
		contextName = selected.String
	}
	state, err := m.get(ctx, contextName)
	if err != nil {
		return StatusSnapshot{}, err
	}
	control := m.controls[contextName]
	runtimeTransfers := 0
	for _, operation := range m.transferOps {
		if operation.item.Context == contextName {
			runtimeTransfers++
		}
	}
	if control != nil {
		control.mu.Lock()
		defer control.mu.Unlock()
	}
	var snapshot StatusSnapshot
	err = m.transfers.ObserveCounts(ctx, contextName, time.Now().UTC(), func(counts transfer.Counts) {
		statusContext := &StatusContext{Name: state.Name, State: state.State, Enabled: state.Enabled, OfferedRootScope: state.OfferedRootScope, OfferedRootAuthorityValid: validateOfferedRootAuthority(state) == nil, AllowPut: state.AllowPut, PutRootAuthorityValid: validatePutRootAuthority(state) == nil}
		if control != nil && control.ctx.Err() == nil {
			online := len(control.peers)
			statusContext.OnlinePeers = &online
		}
		counts.Active += runtimeTransfers
		snapshot = StatusSnapshot{Context: statusContext, Transfers: &counts}
	})
	if err != nil {
		return StatusSnapshot{}, err
	}
	putActive, putRetryable, err := m.puts.Counts(ctx, contextName)
	if err != nil {
		return StatusSnapshot{}, err
	}
	snapshot.Transfers.Active += putActive
	snapshot.Transfers.Retryable += putRetryable
	return snapshot, nil
}

func (m *Manager) CompletionContexts(ctx context.Context, prefix string, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return nil, err
	}
	lower, upper := completionRange(prefix)
	return completionNames(ctx, db, `select name from contexts where name>=? and name<? order by name limit ?`, lower, upper, limit)
}

func (m *Manager) CompletionAliases(ctx context.Context, contextName, prefix string, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return nil, err
	}
	var count int
	if err := db.QueryRowContext(ctx, `select count(*) from contexts where name=?`, contextName).Scan(&count); err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, sql.ErrNoRows
	}
	lower, upper := completionRange(prefix)
	return completionNames(ctx, db, `select alias from context_aliases where context_name=? and alias>=? and alias<? order by alias limit ?`, contextName, lower, upper, limit)
}

func (m *Manager) CompletionPeers(ctx context.Context, contextName, prefix string, includeAliases bool, limit int) ([]string, error) {
	m.mu.Lock()
	control := m.controls[contextName]
	m.mu.Unlock()
	if control == nil || control.ctx.Err() != nil {
		return nil, ErrContextDisconnected
	}
	control.mu.Lock()
	online := make(map[string]bool, len(control.peers))
	values := make([]string, 0, min(len(control.peers), limit))
	for _, peer := range control.peers {
		online[strings.ToLower(peer.Label)] = true
		if strings.HasPrefix(peer.Label, prefix) {
			values = append(values, peer.Label)
		}
	}
	coherent := control.ctx.Err() == nil
	control.mu.Unlock()
	if !coherent {
		return nil, ErrContextDisconnected
	}
	if includeAliases && len(online) > 0 {
		m.mu.Lock()
		db, err := m.db()
		if err == nil {
			labels := make([]string, 0, len(online))
			for label := range online {
				labels = append(labels, label)
			}
			slices.Sort(labels)
			lower, upper := completionRange(prefix)
			for _, label := range labels {
				remaining := limit - len(values)
				if remaining <= 0 {
					break
				}
				aliases, queryErr := completionNames(ctx, db, `select alias from context_aliases where context_name=? and lower(target_label)=? and alias>=? and alias<? order by alias limit ?`, contextName, label, lower, upper, remaining)
				if queryErr != nil {
					err = queryErr
					break
				}
				values = append(values, aliases...)
			}
		}
		m.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(values, func(a, b string) int {
		if order := strings.Compare(strings.ToLower(a), strings.ToLower(b)); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	values = slices.Compact(values)
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func (m *Manager) CompletionInviteIDs(ctx context.Context, contextName, prefix string, limit int) ([]string, error) {
	result, err := m.ListInvites(ctx, contextName)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, min(len(result.Invites), limit))
	for _, invite := range result.Invites {
		if strings.HasPrefix(invite.InviteID, prefix) {
			values = append(values, invite.InviteID)
		}
	}
	slices.Sort(values)
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func (m *Manager) CompletionTransferIDs(ctx context.Context, contextName, action, peer, prefix string, limit int) ([]string, error) {
	if err := m.requireTransferContext(ctx, contextName); err != nil {
		return nil, err
	}
	var values []string
	if action != "resolve" {
		var err error
		values, err = m.transfers.CompletionIDs(ctx, contextName, action, peer, prefix, limit, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	}
	if action == "retry" || action == "show" || action == "resolve" {
		putIDs, putErr := m.puts.CompletionIDs(ctx, contextName, action, peer, prefix, limit)
		if putErr != nil {
			return nil, putErr
		}
		values = append(values, putIDs...)
	}
	if action == "show" || action == "cancel" {
		m.mu.Lock()
		for _, operation := range m.transferOps {
			if operation.item.Context == contextName && strings.HasPrefix(operation.item.ID, prefix) {
				values = append(values, operation.item.ID)
			}
		}
		m.mu.Unlock()
	}
	slices.Sort(values)
	values = slices.Compact(values)
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func (m *Manager) CompletionPeerTarget(ctx context.Context, contextName, value string) (string, error) {
	m.mu.Lock()
	target := value
	db, err := m.db()
	if err == nil {
		aliasErr := db.QueryRowContext(ctx, `select target_label from context_aliases where context_name=? and alias=?`, contextName, value).Scan(&target)
		if aliasErr != nil && !errors.Is(aliasErr, sql.ErrNoRows) {
			err = aliasErr
		}
	}
	control := m.controls[contextName]
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	if control == nil || control.ctx.Err() != nil {
		return "", ErrContextDisconnected
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.ctx.Err() != nil {
		return "", ErrContextDisconnected
	}
	for _, peer := range control.peers {
		if strings.EqualFold(peer.Label, target) {
			return peer.Label, nil
		}
	}
	return "", ErrPeerOffline
}

func completionNames(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func completionRange(prefix string) (string, string) {
	return prefix, prefix + "\x7f"
}

func (m *Manager) ShowTransfer(ctx context.Context, contextName, id string) (transfer.InventoryItem, error) {
	if err := m.requireTransferContext(ctx, contextName); err != nil {
		return transfer.InventoryItem{}, err
	}
	stored, storedErr := m.transfers.Show(ctx, contextName, id, time.Now())
	putRecord, putErr := m.puts.Show(ctx, contextName, id)
	if putErr == nil {
		if storedErr == nil {
			return transfer.InventoryItem{}, transfer.ErrTransferAmbiguous
		}
		expires := putRecord.ExpiresAt
		stored = transfer.InventoryItem{ID: putRecord.ID, Kind: "put-" + putRecord.Direction, Context: putRecord.Context, Peer: putRecord.PeerLabel, Name: putRecord.Destination, State: putRecord.State, Bytes: putRecord.Offset, Total: putRecord.Size, Retryable: putRecord.Direction == "send" && putRecord.State == "transferring" && time.Now().Before(putRecord.ExpiresAt), LocalCommitted: putRecord.State == "committed", Created: putRecord.State == "committed" && putRecord.Mode == "create", Replaced: putRecord.State == "committed" && putRecord.Mode == "replace", Durability: putRecord.Durability, OutcomeUnknown: putRecord.State == "outcome_unknown", ActionRequired: putRecord.State == "outcome_unknown" || putRecord.State == "accept_current_intent", CreatedAt: putRecord.CreatedAt, UpdatedAt: putRecord.UpdatedAt, ExpiresAt: &expires, CleanupPending: putRecord.StageName != "" || putRecord.BackupName != ""}
		storedErr = nil
	} else if errors.Is(putErr, put.ErrAmbiguous) {
		return transfer.InventoryItem{}, transfer.ErrTransferAmbiguous
	} else if !errors.Is(putErr, put.ErrNotFound) {
		return transfer.InventoryItem{}, putErr
	}
	m.mu.Lock()
	operation := m.transferOps[id]
	if operation != nil && contextName != "" && operation.item.Context != contextName {
		operation = nil
	}
	m.mu.Unlock()
	if operation != nil {
		if storedErr == nil && stored.Kind != operation.item.Kind {
			return transfer.InventoryItem{}, transfer.ErrTransferAmbiguous
		}
		if storedErr != nil && !errors.Is(storedErr, transfer.ErrTransferNotFound) {
			return transfer.InventoryItem{}, storedErr
		}
		return operation.item, nil
	}
	return stored, storedErr
}

func (m *Manager) CancelTransfer(ctx context.Context, contextName, id string) error {
	if err := m.requireTransferContext(ctx, contextName); err != nil {
		return err
	}
	err := m.transfers.Cancel(contextName, id)
	if err == nil || !errors.Is(err, transfer.ErrTransferNotActive) {
		return err
	}
	m.mu.Lock()
	operation := m.transferOps[id]
	if operation != nil && contextName != "" && operation.item.Context != contextName {
		operation = nil
	}
	m.mu.Unlock()
	if operation == nil {
		if item, showErr := m.ShowTransfer(ctx, contextName, id); showErr == nil && strings.HasPrefix(item.Kind, "put-") {
			_, abandonErr := m.puts.Abandon(ctx, contextName, id)
			switch {
			case abandonErr == nil:
				return nil
			case errors.Is(abandonErr, put.ErrActive):
				return transfer.ErrTransferActive
			case errors.Is(abandonErr, put.ErrNotAbandonable):
				return transfer.ErrTransferNotActive
			default:
				return abandonErr
			}
		} else if showErr == nil {
			return transfer.ErrTransferNotActive
		} else if errors.Is(showErr, transfer.ErrTransferNotFound) {
			return transfer.ErrTransferNotFound
		} else {
			return showErr
		}
	}
	operation.cancel()
	return nil
}

func (m *Manager) DeleteTransfer(ctx context.Context, contextName, id string) (transfer.InventoryItem, error) {
	if err := m.requireTransferContext(ctx, contextName); err != nil {
		return transfer.InventoryItem{}, err
	}
	m.mu.Lock()
	operation := m.transferOps[id]
	active := operation != nil && (contextName == "" || operation.item.Context == contextName)
	m.mu.Unlock()
	if active {
		return transfer.InventoryItem{}, transfer.ErrTransferActive
	}
	if item, showErr := m.ShowTransfer(ctx, contextName, id); showErr == nil && strings.HasPrefix(item.Kind, "put-") {
		record, abandonErr := m.puts.Abandon(ctx, contextName, id)
		switch {
		case abandonErr == nil:
			item.State = record.State
			return item, nil
		case errors.Is(abandonErr, put.ErrActive):
			return transfer.InventoryItem{}, transfer.ErrTransferActive
		case errors.Is(abandonErr, put.ErrNotAbandonable):
			return transfer.InventoryItem{}, transfer.ErrTransferNotDeletable
		default:
			return transfer.InventoryItem{}, abandonErr
		}
	} else if showErr != nil && !errors.Is(showErr, transfer.ErrTransferNotFound) {
		return transfer.InventoryItem{}, showErr
	}
	return m.transfers.Delete(ctx, contextName, id, time.Now())
}

func (m *Manager) ResolveTransferAcceptCurrent(ctx context.Context, contextName, id string) (put.ResolutionResult, error) {
	state, err := m.beginLocalContextOperationScope(ctx, contextName, operationPut)
	if err != nil {
		return put.ResolutionResult{}, err
	}
	defer m.endContextOperation(contextName, operationPut)
	if state.PutRoot == nil || validatePutRootAuthority(state) != nil {
		return put.ResolutionResult{}, put.ErrAuthority
	}
	result, err := m.puts.ResolveAcceptCurrent(ctx, contextName, id, *state.PutRoot, state.PutRootRevision)
	if err != nil {
		return put.ResolutionResult{}, err
	}
	return result, nil
}

func (m *Manager) requireTransferContext(ctx context.Context, contextName string) error {
	if contextName == "" {
		return transfer.ErrTransferContextRequired
	}
	_, err := m.Get(ctx, contextName)
	return err
}

func (m *Manager) beginRuntimeTransfer(parent context.Context, item transfer.InventoryItem) (context.Context, string, func(), error) {
	id, err := newContextSession("get-")
	if err != nil {
		return nil, "", nil, err
	}
	now := time.Now().UTC()
	item.ID = id
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	item.Active = true
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	if _, exists := m.transferOps[id]; exists {
		m.mu.Unlock()
		cancel()
		return nil, "", nil, transfer.ErrTransferActive
	}
	m.transferOps[id] = &runtimeTransfer{item: item, cancel: cancel}
	m.mu.Unlock()
	return ctx, id, func() {
		cancel()
		m.mu.Lock()
		delete(m.transferOps, id)
		m.mu.Unlock()
	}, nil
}

func (m *Manager) updateRuntimeTransfer(id, phase string, bytes, total int64) {
	m.mu.Lock()
	if operation := m.transferOps[id]; operation != nil {
		changed := operation.phase != phase || operation.item.Bytes != bytes || operation.item.Total != total
		operation.phase = phase
		operation.item.State = "active"
		operation.item.Bytes = bytes
		operation.item.Total = total
		if changed {
			operation.item.UpdatedAt = time.Now().UTC()
		}
	}
	m.mu.Unlock()
}

func shouldLogReconnect(failures int) bool {
	return failures == 1 || failures%10 == 0
}

func (m *Manager) logTransfer(event, message, direction, contextName, peer, transferID, name string, bytes int64) {
	attrs := []any{"event", event, "direction", direction, "context", contextName, "peer", "@" + strings.TrimPrefix(peer, "@")}
	if transferID != "" {
		attrs = append(attrs, "transfer_id", transferID)
	}
	if name != "" {
		attrs = append(attrs, "name", name)
	}
	if bytes != 0 {
		attrs = append(attrs, "bytes", bytes)
	}
	m.logger.Info(message, attrs...)
}

func (m *Manager) logIncomingProtocolFailure(protocol, contextName, peer string) {
	m.logger.Warn("incoming direct protocol failed", "event", "direct.incoming_failed", "protocol", protocol, "context", contextName, "peer", "@"+strings.TrimPrefix(peer, "@"))
}

func validStdinSpool(root, path string) bool {
	if filepath.Dir(path) != root || !strings.HasPrefix(filepath.Base(path), ".stdin-") || !strings.HasSuffix(path, ".spool") {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func (m *Manager) DiagnoseContexts(ctx context.Context, selected string) []diagnostics.Check {
	states, err := m.List(ctx)
	if err != nil {
		return []diagnostics.Check{{ID: "context.state", Layer: "context", Context: selected, Status: diagnostics.Fail, Summary: "context state is unavailable"}}
	}
	if selected != "" {
		filtered := states[:0]
		for _, state := range states {
			if state.Name == selected {
				filtered = append(filtered, state)
			}
		}
		states = filtered
		if len(states) == 0 {
			return []diagnostics.Check{{ID: "context.selection", Layer: "context", Context: selected, Status: diagnostics.Fail, Summary: "selected context is not configured"}}
		}
	}
	checks := make([]diagnostics.Check, 0, len(states)*6)
	for _, state := range states {
		authorityCheck := diagnostics.Check{ID: "context.offered_root_authority", Layer: "context", Context: state.Name, Status: diagnostics.Pass, Summary: "offered-root authority is narrow and consistent"}
		if err := validateOfferedRootAuthority(state); err != nil {
			authorityCheck.Status, authorityCheck.Summary = diagnostics.Fail, "offered-root authority is inconsistent; offered-root and incoming-send service is blocked until explicit repair"
		} else if state.OfferedRootScope == OfferedRootScopeFilesystemRoot {
			authorityCheck.Status, authorityCheck.Summary = diagnostics.Warn, "DANGER: every authenticated member can browse and retrieve every reachable regular file beneath the filesystem root"
		}
		checks = append(checks, authorityCheck)
		putCheck := diagnostics.Check{ID: "context.put_root_authority", Layer: "context", Context: state.Name, Status: diagnostics.Pass, Summary: "remote put is disabled"}
		if state.AllowPut {
			if validatePutRootAuthority(state) != nil {
				putCheck.Status, putCheck.Summary = diagnostics.Fail, "put authority is enabled but invalid; incoming put is blocked"
			} else {
				putCheck.Status, putCheck.Summary = diagnostics.Warn, "every authenticated context member may create files and request supported replacement beneath the configured put root"
			}
		} else if state.PutRoot != nil {
			putCheck.Summary = "put root is configured and remote put is disabled"
		}
		checks = append(checks, putCheck)
		enrollmentStatus := diagnostics.Pass
		enrollmentSummary := "membership credential is enrolled"
		if state.State == "pending" || state.State == "expired" || state.State == "revoked" || state.Credential == nil {
			enrollmentStatus = diagnostics.Fail
			enrollmentSummary = "context membership is " + state.State
		}
		checks = append(checks, diagnostics.Check{ID: "context.enrollment", Layer: "context", Context: state.Name, Status: enrollmentStatus, Summary: enrollmentSummary})

		identityStatus, identitySummary := diagnostics.Pass, "device key is accessible and matches context identity"
		privateKey, privateErr := identity.LoadPrivate(state.privatePath)
		publicKey, publicErr := identity.LoadPublic(state.publicPath)
		if privateErr != nil || publicErr != nil || !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) || identity.ID(publicKey) != state.DeviceID {
			identityStatus, identitySummary = diagnostics.Fail, "device key is unavailable or mismatched"
		}
		checks = append(checks, diagnostics.Check{ID: "context.identity", Layer: "context", Context: state.Name, Status: identityStatus, Summary: identitySummary})

		credentialStatus, credentialSummary := diagnostics.Skipped, "membership credential is unavailable"
		if state.Credential != nil {
			if err := verifyEnrollment(*state.Credential, state.ServerID, state.DeviceID, state.Label); err != nil {
				credentialStatus, credentialSummary = diagnostics.Fail, "membership credential or server identity is invalid"
			} else {
				credentialStatus, credentialSummary = diagnostics.Pass, "membership credential matches the pinned server identity"
			}
		}
		checks = append(checks, diagnostics.Check{ID: "context.credential", Layer: "context", Context: state.Name, Status: credentialStatus, Summary: credentialSummary})

		m.mu.Lock()
		control := m.controls[state.Name]
		m.mu.Unlock()
		controlStatus, controlSummary := diagnostics.Fail, "authenticated control connection is unavailable"
		if control != nil && control.ctx.Err() == nil {
			controlStatus, controlSummary = diagnostics.Pass, "authenticated control connection is active"
		}
		checks = append(checks, diagnostics.Check{ID: "context.control", Layer: "context", Context: state.Name, Status: controlStatus, Summary: controlSummary})
		if control == nil || control.ctx.Err() != nil {
			checks = append(checks,
				diagnostics.Check{ID: "context.heartbeat", Layer: "context", Context: state.Name, Status: diagnostics.Skipped, Summary: "control connection prerequisite failed"},
				diagnostics.Check{ID: "context.presence", Layer: "context", Context: state.Name, Status: diagnostics.Skipped, Summary: "control connection prerequisite failed"},
			)
		} else {
			pingContext, cancelPing := context.WithTimeout(ctx, 2*time.Second)
			started := time.Now()
			_, pingErr := control.writes.run(pingContext, func() error { return control.conn.Ping(pingContext) })
			cancelPing()
			heartbeat := diagnostics.Check{ID: "context.heartbeat", Layer: "context", Context: state.Name, Status: diagnostics.Pass, Summary: "rendezvous heartbeat succeeded", HeartbeatRTT: time.Since(started)}
			if pingErr != nil {
				heartbeat.Status, heartbeat.Summary, heartbeat.HeartbeatRTT = diagnostics.Fail, "rendezvous heartbeat failed", 0
			}
			control.mu.Lock()
			peerCount := len(control.peers)
			control.mu.Unlock()
			checks = append(checks, heartbeat, diagnostics.Check{ID: "context.presence", Layer: "context", Context: state.Name, Status: diagnostics.Pass, Summary: fmt.Sprintf("presence is active with %d other device(s)", peerCount)})
		}
		stunCheck := diagnostics.Check{ID: "context.stun", Layer: "context", Context: state.Name, Status: diagnostics.Skipped, Summary: "no STUN server is configured"}
		if len(state.STUNURLs) > 0 && enrollmentStatus == diagnostics.Pass {
			gatherContext, cancelGather := context.WithTimeout(ctx, 3*time.Second)
			types, gatherErr := direct.GatherCandidateTypes(gatherContext, state.STUNURLs, allowLoopbackServer(state.ServerURL))
			cancelGather()
			stunCheck.GatheredTypes = types
			if gatherErr != nil || !contains(types, "srflx") {
				stunCheck.Status, stunCheck.Summary = diagnostics.Fail, "server-reflexive candidate gathering failed"
			} else {
				stunCheck.Status, stunCheck.Summary = diagnostics.Pass, "server-reflexive candidate gathering succeeded"
			}
		}
		checks = append(checks, stunCheck)
	}
	return checks
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (m *Manager) connectPeer(ctx context.Context, contextName, peerName string) (*direct.Session, error) {
	state, peer, signaler, err := m.openPeerSignaler(ctx, contextName, peerName, "px-offered-")
	if err != nil {
		return nil, err
	}
	privateKey, err := identity.LoadPrivate(state.privatePath)
	if err != nil {
		_ = signaler.Close()
		return nil, err
	}
	peerKey, err := identity.ParseID(peer.DeviceID)
	if err != nil {
		_ = signaler.Close()
		return nil, err
	}
	sessionContext, cancelSession := context.WithCancel(signaler.control.ctx)
	stopCancellation := context.AfterFunc(ctx, cancelSession)
	session, err := direct.Connect(sessionContext, direct.Config{
		Signaler: signaler, Session: signaler.session, PrivateKey: privateKey, PeerKey: peerKey, Offer: true,
		AllowLoopback: allowLoopbackServer(state.ServerURL), STUNURLs: state.STUNURLs, ChannelLabel: "px-offered", ChannelProtocol: offered.Protocol,
		MaxMessageBytes: offered.MaxMessageBytes, MessageQueue: offered.DefaultQueueDepth, MaxBufferedBytes: offered.DefaultBufferedBytes, Logger: m.logger,
	})
	if err != nil {
		stopCancellation()
		cancelSession()
		return nil, err
	}
	go func() {
		<-session.Context().Done()
		stopCancellation()
		cancelSession()
	}()
	return session, nil
}

func (m *Manager) openPeerSignaler(ctx context.Context, contextName, peerName, prefix string) (State, membership.Member, *contextSignaler, error) {
	if err := membership.ValidateLabel(peerName); err != nil {
		return State{}, membership.Member{}, nil, fmt.Errorf("peer: %w", err)
	}
	state, control, err := m.connectedControl(ctx, contextName)
	if err != nil {
		return State{}, membership.Member{}, nil, err
	}
	target := peerName
	if alias := state.Aliases[peerName]; alias != "" {
		target = alias
	}
	peer, exists := control.onlinePeer(target)
	if !exists {
		response, err := control.request(ctx, "members.list", "")
		if err != nil {
			return State{}, membership.Member{}, nil, err
		}
		if peer, exists = control.onlinePeer(target); !exists {
			member, enrolled := activeMemberByLabel(response.Members, target)
			switch {
			case !enrolled:
				return State{}, membership.Member{}, nil, ErrPeerUnknown
			case member.DeviceID == state.DeviceID:
				return State{}, membership.Member{}, nil, ErrPeerSelf
			default:
				return State{}, membership.Member{}, nil, ErrPeerOffline
			}
		}
	}
	if peer.DeviceID == state.DeviceID {
		return State{}, membership.Member{}, nil, ErrPeerSelf
	}
	sessionID, err := newContextSession(prefix)
	if err != nil {
		return State{}, membership.Member{}, nil, err
	}
	signaler, err := control.openSignaler(sessionID, peer.DeviceID)
	if err != nil {
		return State{}, membership.Member{}, nil, err
	}
	return state, peer, signaler, nil
}

func (c *controlConnection) onlinePeer(label string) (membership.Member, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	peer, exists := c.peers[strings.ToLower(label)]
	return peer, exists
}

func activeMemberByLabel(members []membership.Member, label string) (membership.Member, bool) {
	for _, member := range members {
		if strings.EqualFold(member.Label, label) {
			return member, true
		}
	}
	return membership.Member{}, false
}

func newContextSession(prefix string) (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate direct session: %w", err)
	}
	return prefix + hex.EncodeToString(data), nil
}

type incomingProtocolKind uint8

const (
	incomingOffered incomingProtocolKind = iota + 1
	incomingProbe
	incomingRecoverableSend
	incomingFastSend
	incomingBenchmark
	incomingPut
	incomingRecent
	incomingPing
)

type incomingProtocol struct {
	kind   incomingProtocolKind
	prefix string
	scope  operationScope
}

var incomingProtocols = []incomingProtocol{
	{kind: incomingOffered, prefix: "px-offered-", scope: operationOffered},
	{kind: incomingProbe, prefix: "px-probe-"},
	{kind: incomingRecoverableSend, prefix: "px-send-", scope: operationOffered | operationInbox},
	{kind: incomingFastSend, prefix: transfer.FastSessionPrefix, scope: operationOffered | operationInbox},
	{kind: incomingBenchmark, prefix: benchmark.SessionPrefix},
	{kind: incomingPut, prefix: put.SessionPrefix, scope: operationPut},
	{kind: incomingRecent, prefix: recent.SessionPrefix},
	{kind: incomingPing, prefix: ping.SessionPrefix},
}

func classifyIncomingSession(session string) (incomingProtocol, bool) {
	for _, protocol := range incomingProtocols {
		if strings.HasPrefix(session, protocol.prefix) {
			return protocol, true
		}
	}
	return incomingProtocol{}, false
}

func validContextSession(value string) bool {
	protocol, ok := classifyIncomingSession(value)
	if !ok {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, protocol.prefix))
	return err == nil && len(decoded) == 16
}

func allowLoopbackServer(serverURL string) bool {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}

func (m *Manager) serverInfo(ctx context.Context, serverURL string) (rendezvousproto.ServerInfo, error) {
	var result rendezvousproto.ServerInfo
	if err := m.getJSON(ctx, serverURL+"/v1/server", &result); err != nil {
		return result, err
	}
	controlVersion := result.ControlVersion
	if controlVersion == 0 {
		controlVersion = result.Version
	}
	if result.ControlVersion != 0 && result.Version != result.ControlVersion {
		return result, fmt.Errorf("rendezvous server discovery reports inconsistent control protocol versions %d and %d", result.Version, result.ControlVersion)
	}
	if controlVersion != rendezvousproto.Version {
		return result, &rendezvousproto.ProtocolMismatch{Boundary: "control", Expected: rendezvousproto.Version, Actual: controlVersion, Remote: "server"}
	}
	if result.AuthenticationVersion != 0 && result.AuthenticationVersion != rendezvousproto.AuthenticationVersion {
		return result, &rendezvousproto.ProtocolMismatch{Boundary: "authentication", Expected: rendezvousproto.AuthenticationVersion, Actual: result.AuthenticationVersion, Remote: "server"}
	}
	if result.ServerID == "" {
		return result, errors.New("unsupported rendezvous server identity")
	}
	return result, nil
}

func (m *Manager) enroll(ctx context.Context, serverURL string, publicKey ed25519.PublicKey, label string) (rendezvousproto.Enrollment, error) {
	var result rendezvousproto.Enrollment
	err := m.postJSON(ctx, serverURL+"/v1/enrollments", rendezvousproto.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: label}, &result)
	return result, err
}

func (m *Manager) enrollmentStatus(ctx context.Context, serverURL string, publicKey ed25519.PublicKey, label string) (rendezvousproto.Enrollment, error) {
	var result rendezvousproto.Enrollment
	err := m.postJSON(ctx, serverURL+"/v1/enrollments/status", rendezvousproto.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: label}, &result)
	return result, err
}

func (m *Manager) redeemInvite(ctx context.Context, serverURL string, serverInfo rendezvousproto.ServerInfo, tokenText string, publicKey ed25519.PublicKey, label string) (rendezvousproto.Enrollment, error) {
	if err := validateInviteTransport(serverURL); err != nil {
		return rendezvousproto.Enrollment{}, err
	}
	if serverInfo.InviteVersion != 1 {
		return rendezvousproto.Enrollment{}, errors.New("rendezvous server does not support enrollment invites; upgrade px-server")
	}
	token, err := membership.ParseInviteToken(tokenText)
	if err != nil {
		return rendezvousproto.Enrollment{}, errors.New("invalid enrollment invite token")
	}
	if token.ServerTag != membership.InviteServerTag(serverInfo.ServerID) {
		return rendezvousproto.Enrollment{}, errors.New("enrollment invite is for a different rendezvous server")
	}
	request := rendezvousproto.InviteRedemptionRequest{Version: 1, Token: tokenText, DeviceKey: identity.ID(publicKey), Label: label}
	redemption, err := m.redeemInviteRequest(ctx, serverURL, request)
	if err == nil {
		if enrolled, validationErr := validatedInviteEnrollment(redemption, serverInfo.ServerID, identity.ID(publicKey), label); validationErr == nil {
			return enrolled, nil
		}
	}
	var responseErr *rendezvousHTTPError
	if errors.As(err, &responseErr) {
		if responseErr.status == http.StatusNotFound {
			enrolled, ok, reliable := m.reconciledEnrollmentStatus(ctx, serverURL, publicKey, label, serverInfo.ServerID)
			if ok {
				return enrolled, nil
			}
			if !reliable {
				return rendezvousproto.Enrollment{}, errors.New("invite redemption outcome is unknown; retry onboarding with the same invite, context, label, and device key")
			}
		}
		return rendezvousproto.Enrollment{}, responseErr
	}
	if enrolled, ok, _ := m.reconciledEnrollmentStatus(ctx, serverURL, publicKey, label, serverInfo.ServerID); ok {
		return enrolled, nil
	}
	redemption, retryErr := m.redeemInviteRequest(ctx, serverURL, request)
	if retryErr == nil {
		if enrolled, validationErr := validatedInviteEnrollment(redemption, serverInfo.ServerID, identity.ID(publicKey), label); validationErr == nil {
			return enrolled, nil
		}
	}
	if enrolled, ok, _ := m.reconciledEnrollmentStatus(ctx, serverURL, publicKey, label, serverInfo.ServerID); ok {
		return enrolled, nil
	}
	return rendezvousproto.Enrollment{}, errors.New("invite redemption outcome is unknown; retry onboarding with the same invite, context, label, and device key")
}

func (m *Manager) redeemInviteRequest(ctx context.Context, serverURL string, request rendezvousproto.InviteRedemptionRequest) (rendezvousproto.InviteRedemption, error) {
	var result rendezvousproto.InviteRedemption
	data, err := json.Marshal(request)
	if err != nil {
		return result, errors.New("encode invite redemption request")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/invites/redeem", bytes.NewReader(data))
	if err != nil {
		return result, errors.New("create invite redemption request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(httpRequest)
	if err != nil {
		return result, errors.New("invite redemption transport failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		return result, errors.New("read invite redemption response")
	}
	if len(body) > maxHTTPBody {
		return result, errors.New("invite redemption response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		return result, inviteRedemptionHTTPError(response.StatusCode, body)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return rendezvousproto.InviteRedemption{}, errors.New("decode invite redemption response")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return rendezvousproto.InviteRedemption{}, errors.New("invite redemption response has trailing data")
	}
	return result, nil
}

func inviteRedemptionHTTPError(status int, body []byte) error {
	var value struct {
		Code string `json:"code"`
	}
	if len(body) <= maxHTTPBody {
		_ = json.Unmarshal(body, &value)
	}
	code := value.Code
	if len(code) > 64 {
		code = ""
	}
	switch status {
	case http.StatusBadRequest:
		return &rendezvousHTTPError{status: status, code: code, message: "invalid invite redemption request"}
	case http.StatusNotFound:
		return &rendezvousHTTPError{status: status, code: code, message: "invite is invalid, unavailable, expired, revoked, used, or does not match this enrollment"}
	case http.StatusConflict:
		return &rendezvousHTTPError{status: status, code: code, message: "enrollment is unavailable"}
	case http.StatusTooManyRequests:
		return &rendezvousHTTPError{status: status, code: code, message: "invite redemption rate limit exceeded"}
	default:
		return errors.New("invite redemption outcome may be unknown")
	}
}

func validateInviteTransport(serverURL string) error {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return errors.New("invalid rendezvous server origin for invite redemption")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowLoopbackServer(serverURL)) {
		return errors.New("enrollment invite redemption requires HTTPS except for explicit loopback development servers")
	}
	return nil
}

func (m *Manager) reconciledEnrollmentStatus(ctx context.Context, serverURL string, publicKey ed25519.PublicKey, label, serverID string) (rendezvousproto.Enrollment, bool, bool) {
	result, err := m.inviteEnrollmentStatus(ctx, serverURL, publicKey, label)
	if err != nil {
		return rendezvousproto.Enrollment{}, false, false
	}
	if result.State != "enrolled" {
		return rendezvousproto.Enrollment{}, false, true
	}
	if result.Credential == nil || verifyEnrollment(*result.Credential, serverID, identity.ID(publicKey), label) != nil {
		return rendezvousproto.Enrollment{}, false, false
	}
	return result, true, true
}

func (m *Manager) inviteEnrollmentStatus(ctx context.Context, serverURL string, publicKey ed25519.PublicKey, label string) (rendezvousproto.Enrollment, error) {
	data, err := json.Marshal(rendezvousproto.EnrollmentRequest{DeviceKey: identity.ID(publicKey), Label: label})
	if err != nil {
		return rendezvousproto.Enrollment{}, errors.New("encode invite enrollment status request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/v1/enrollments/status", bytes.NewReader(data))
	if err != nil {
		return rendezvousproto.Enrollment{}, errors.New("create invite enrollment status request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return rendezvousproto.Enrollment{}, errors.New("invite enrollment status transport failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		return rendezvousproto.Enrollment{}, errors.New("read invite enrollment status response")
	}
	if len(body) > maxHTTPBody {
		return rendezvousproto.Enrollment{}, errors.New("invite enrollment status response exceeds size limit")
	}
	if response.StatusCode != http.StatusOK {
		return rendezvousproto.Enrollment{}, errors.New("invite enrollment status unavailable")
	}
	var result rendezvousproto.Enrollment
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return rendezvousproto.Enrollment{}, errors.New("decode invite enrollment status response")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return rendezvousproto.Enrollment{}, errors.New("invite enrollment status response has trailing data")
	}
	switch result.State {
	case "enrolled":
		if result.Credential == nil || result.Code != "" || !result.ExpiresAt.IsZero() {
			return rendezvousproto.Enrollment{}, errors.New("invalid enrolled invite status response")
		}
	case "pending":
		code, codeErr := membership.NormalizeApprovalCode(result.Code)
		if codeErr != nil || code != result.Code || result.ExpiresAt.IsZero() || result.Credential != nil {
			return rendezvousproto.Enrollment{}, errors.New("invalid pending invite status response")
		}
	case "expired":
		if result.Code != "" || !result.ExpiresAt.IsZero() || result.Credential != nil {
			return rendezvousproto.Enrollment{}, errors.New("invalid expired invite status response")
		}
	default:
		return rendezvousproto.Enrollment{}, errors.New("invalid invite enrollment status state")
	}
	return result, nil
}

func validatedInviteEnrollment(result rendezvousproto.InviteRedemption, serverID, deviceID, label string) (rendezvousproto.Enrollment, error) {
	if result.Version != 1 || result.State != "enrolled" {
		return rendezvousproto.Enrollment{}, errors.New("rendezvous returned an invalid invite redemption response")
	}
	if err := verifyEnrollment(result.Credential, serverID, deviceID, label); err != nil {
		return rendezvousproto.Enrollment{}, errors.New("rendezvous returned an invalid invite enrollment credential")
	}
	return rendezvousproto.Enrollment{State: "enrolled", Credential: &result.Credential}, nil
}

func (m *Manager) get(ctx context.Context, name string) (State, error) {
	db, err := m.db()
	if err != nil {
		return State{}, err
	}
	var state State
	var credential sql.NullString
	var pendingCode sql.NullString
	var pendingExpiry sql.NullInt64
	var enabled int
	var createdAt, updatedAt int64
	var acknowledged int
	var putRoot sql.NullString
	var allowPut int
	err = db.QueryRowContext(ctx, `select name, server_url, server_id, device_id, private_key_path, public_key_path, label, credential, pending_code, pending_expires_at, state, enabled, offered_root, offered_root_scope, offered_root_revision, filesystem_root_acknowledged, inbox_root, put_root, allow_put, put_root_revision, created_at, updated_at from contexts where name = ?`, name).
		Scan(&state.Name, &state.ServerURL, &state.ServerID, &state.DeviceID, &state.privatePath, &state.publicPath, &state.Label, &credential, &pendingCode, &pendingExpiry, &state.State, &enabled, &state.OfferedRoot, &state.OfferedRootScope, &state.OfferedRootRevision, &acknowledged, &state.InboxRoot, &putRoot, &allowPut, &state.PutRootRevision, &createdAt, &updatedAt)
	if err != nil {
		return State{}, err
	}
	state.Enabled = enabled == 1
	state.FilesystemRootAcknowledged = acknowledged == 1
	state.OfferedRootAuthorityValid = validateOfferedRootAuthority(state) == nil
	if putRoot.Valid {
		state.PutRoot = &putRoot.String
	}
	state.AllowPut = allowPut == 1
	state.PutRootAuthorityValid = validatePutRootAuthority(state) == nil
	state.CreatedAt = time.Unix(createdAt, 0).UTC()
	state.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	state.PendingCode = pendingCode.String
	if pendingExpiry.Valid {
		value := time.Unix(pendingExpiry.Int64, 0).UTC()
		state.ExpiresAt = &value
	}
	if credential.Valid {
		var value membership.Credential
		if err := json.Unmarshal([]byte(credential.String), &value); err != nil {
			return State{}, err
		}
		state.Credential = &value
	}
	state.Aliases, err = aliases(ctx, db, name)
	if err == nil {
		state.STUNURLs, err = stunURLs(ctx, db, name)
	}
	return state, err
}

func (m *Manager) list(ctx context.Context) ([]State, error) {
	db, err := m.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `select name from contexts order by name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	states := make([]State, 0, len(names))
	for _, name := range names {
		state, err := m.get(ctx, name)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, nil
}

func aliases(ctx context.Context, db *sql.DB, name string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `select alias, target_label from context_aliases where context_name = ? order by alias`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var alias, target string
		if err := rows.Scan(&alias, &target); err != nil {
			return nil, err
		}
		result[alias] = target
	}
	return result, rows.Err()
}

func stunURLs(ctx context.Context, db *sql.DB, name string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `select url from context_stun_servers where context_name = ? order by position`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (m *Manager) updateState(ctx context.Context, name, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.db()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `update contexts set state = ?, updated_at = ? where name = ?`, state, time.Now().Unix(), name)
	return err
}

func (m *Manager) db() (*sql.DB, error) {
	if m.database == nil || m.database() == nil {
		return nil, errors.New("agent context database is not ready")
	}
	return m.database(), nil
}

func ensureIdentity(privatePath, publicPath string) error {
	privateInfo, privateErr := os.Stat(privatePath)
	publicInfo, publicErr := os.Stat(publicPath)
	if privateErr == nil && publicErr == nil && !privateInfo.IsDir() && !publicInfo.IsDir() {
		_, err := identity.LoadPrivate(privatePath)
		if err != nil {
			return err
		}
		_, err = identity.LoadPublic(publicPath)
		return err
	}
	if !errors.Is(privateErr, os.ErrNotExist) || !errors.Is(publicErr, os.ErrNotExist) {
		return errors.New("context identity files are incomplete")
	}
	return identity.WriteFiles(privatePath, publicPath)
}

func verifyEnrollment(credential membership.Credential, serverID, deviceID, label string) error {
	authorityKey, err := identity.ParseID(serverID)
	if err != nil {
		return err
	}
	claims, err := membership.VerifyCredential(credential, authorityKey, serverID)
	if err != nil {
		return err
	}
	if claims.DeviceKey != deviceID || claims.Label != label || claims.Revision != 1 {
		return errors.New("membership credential does not match context")
	}
	return nil
}

type rendezvousHTTPError struct {
	status  int
	code    string
	message string
}

func (e *rendezvousHTTPError) Error() string { return e.message }

func normalizeServerURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("server URL must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func websocketEndpoint(serverURL string) (string, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "https" {
		parsed.Scheme = "wss"
	} else {
		parsed.Scheme = "ws"
	}
	parsed.Path = "/v1/connect"
	return parsed.String(), nil
}

func (m *Manager) absoluteRoot(value, fallback string, requireWrite bool) (string, error) {
	if value == "" {
		value = fallback
	}
	root, err := normalizedRoot(value)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create root: %w", err)
	}
	return m.validatedRoot(root, requireWrite)
}

func (m *Manager) configuredRoot(value string, requireWrite bool) (string, error) {
	root, err := normalizedRoot(value)
	if err != nil {
		return "", err
	}
	return m.validatedRoot(root, requireWrite)
}

func normalizedRoot(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errors.New("path must not be empty")
	}
	root, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(root), nil
}

func (m *Manager) validatedRoot(root string, requireWrite bool) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("root must not be a symbolic link")
	}
	if !info.IsDir() {
		return "", errors.New("root must be a directory")
	}
	directory, err := os.Open(root)
	if err != nil {
		return "", fmt.Errorf("open root: %w", err)
	}
	_, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("read root: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close root: %w", closeErr)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize root: %w", err)
	}
	canonical = filepath.Clean(canonical)
	if err := validateRootSearch(canonical); err != nil {
		return "", fmt.Errorf("verify root search/traversal capability: %w", err)
	}
	if requireWrite {
		probe := m.writeProbe
		if probe == nil {
			probe = probeRootWrite
		}
		if err := probe(canonical); err != nil {
			return "", fmt.Errorf("verify root create/write/delete capability: %w", err)
		}
	}
	return canonical, nil
}

func probeRootWrite(root string) (err error) {
	file, err := os.CreateTemp(root, ".px-root-check-")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	path := file.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary file: %w", removeErr))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict temporary file: %w", err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close temporary file: %w", err)
	}
	closed = true
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete temporary file: %w", err)
	}
	return nil
}

func (m *Manager) getJSON(ctx context.Context, endpoint string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return m.doJSON(request, output)
}

func (m *Manager) postJSON(ctx context.Context, endpoint string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return m.doJSON(request, output)
}

func (m *Manager) doJSON(request *http.Request, output any) error {
	response, err := m.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxHTTPBody {
		return errors.New("rendezvous response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var value struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &value)
		if value.Error == "" {
			value.Error = response.Status
		}
		return &rendezvousHTTPError{status: response.StatusCode, message: value.Error}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return err
	}
	return nil
}

func writeWS(ctx context.Context, conn *websocket.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
