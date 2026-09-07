package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	ResumeProtocol        = "px-transfer-v4"
	ResumeChunkSize       = MaxMessageBytes
	ResumeAckWindow       = 8
	ResumeLifetime        = 24 * time.Hour
	MaxResumeBytes        = int64(4 << 30)
	MaxResumeStates       = 64
	MaxSendSpoolBytes     = int64(4 << 30)
	MaxSendResumeStates   = 64
	DefaultInventoryLimit = 32
	MaxInventoryLimit     = 64
	InventoryVersion      = 3
	resumeVersion         = 3
	ResumeEventVersion    = 3
	ReservedNamePrefix    = ".px-"
	maxCommitScanEntries  = 4096
	cleanupTimeout        = 5 * time.Second
)

var publicCommitMu sync.Mutex

var (
	ErrTransferNotFound        = errors.New("transfer not found")
	ErrTransferNotActive       = errors.New("transfer is not active")
	ErrTransferActive          = errors.New("transfer is active")
	ErrTransferAmbiguous       = errors.New("transfer ID is ambiguous")
	ErrTransferNotDeletable    = errors.New("transfer state is not abandoned and retryable")
	ErrTransferContextRequired = errors.New("transfer context is required")
	ErrTransferContextMismatch = errors.New("transfer context does not match persisted state")
	ErrTransferPeerMismatch    = errors.New("transfer peer does not match persisted state")
	ErrCorruptTransferState    = errors.New("transfer state is corrupt")
	ErrTransferCleanup         = errors.New("transfer state cleanup failed")
	ErrTransferCleanupPending  = errors.New("transfer state was removed with cleanup pending")
	ErrSendResumeCapacity      = errors.New("sender resume state capacity reached")
	ErrSendSpoolOwnership      = errors.New("sender resume state already owns a different stdin spool; retry or delete the existing transfer")
)

type Visibility string

const (
	VisibilityPrivate Visibility = "private"
	VisibilityPublic  Visibility = "public"
)

type ResumeEvent struct {
	Version    int    `json:"version"`
	State      string `json:"state"`
	TransferID string `json:"transfer_id,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	Total      int64  `json:"total,omitempty"`
	Resumed    bool   `json:"resumed,omitempty"`
	Name       string `json:"name,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Path       string `json:"path,omitempty"`
	Error      string `json:"error,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Durability string `json:"durability,omitempty"`
	Created    bool   `json:"created,omitempty"`
	Replaced   bool   `json:"replaced,omitempty"`
}

type ResumeStore struct {
	database                func() *sql.DB
	root                    string
	quota                   int64
	sendQuota               int64
	maintenanceMu           sync.Mutex
	activeMu                sync.Mutex
	active                  map[string]*activeResume
	sharedSenderMaintenance func(context.Context, time.Time) error
	insertObservation       func(context.Context, TransferObservation) error
	insertObservationTx     func(context.Context, *sql.Tx, TransferObservation) error
}

type TransferObservation struct {
	Context      string
	Direction    string
	TransferID   string
	Kind         string
	PeerDeviceID string
	PeerLabel    string
	Destination  string
	Visibility   Visibility
	Bytes        int64
	ObservedAt   time.Time
}

type activeResume struct {
	record    resumeRecord
	direction string
	cancel    context.CancelFunc
	item      InventoryItem
	phase     string
}

type SendLease struct {
	store  *ResumeStore
	key    string
	ctx    context.Context
	record resumeRecord
	once   sync.Once
}

func (l *SendLease) Metadata() RetryMetadata {
	return retryMetadata(l.record)
}

func (l *SendLease) Context() context.Context {
	if l == nil {
		return nil
	}
	return l.ctx
}

func (l *SendLease) Release() {
	if l == nil || l.store == nil {
		return
	}
	l.once.Do(func() {
		l.store.activeMu.Lock()
		if active := l.store.active[l.key]; active != nil {
			active.cancel()
			delete(l.store.active, l.key)
		}
		l.store.activeMu.Unlock()
	})
}

type InventoryItem struct {
	ID               string     `json:"id"`
	Kind             string     `json:"kind"`
	Context          string     `json:"context"`
	Peer             string     `json:"peer"`
	Name             string     `json:"name"`
	Visibility       Visibility `json:"visibility,omitempty"`
	State            string     `json:"state"`
	Bytes            int64      `json:"bytes"`
	Total            int64      `json:"total"`
	Retryable        bool       `json:"retryable"`
	LocalCommitted   bool       `json:"local_committed"`
	PeerConfirmation string     `json:"peer_confirmation,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CleanupPending   bool       `json:"cleanup_pending,omitempty"`
	Created          bool       `json:"created,omitempty"`
	Replaced         bool       `json:"replaced,omitempty"`
	Durability       string     `json:"durability,omitempty"`
	OutcomeUnknown   bool       `json:"outcome_unknown,omitempty"`
	ActionRequired   bool       `json:"action_required,omitempty"`
	Active           bool       `json:"-"`
}

type Inventory struct {
	Version   int             `json:"version"`
	Transfers []InventoryItem `json:"transfers"`
}

type Counts struct {
	Active    int `json:"active"`
	Retryable int `json:"retryable"`
}

type completionItem struct {
	direction string
	peer      string
	state     string
	active    bool
	corrupt   bool
}

type RetryMetadata struct {
	ID           string
	Context      string
	PeerDeviceID string
	PeerLabel    string
	Name         string
	Visibility   Visibility
	Bytes        int64
	Total        int64
	UpdatedAt    time.Time
	ExpiresAt    time.Time
}

type ResumeSendConfig struct {
	Source       string
	Name         string
	Context      string
	SenderID     string
	ReceiverID   string
	PeerLabel    string
	MaxFileBytes int64
	StdinSpool   bool
	Visibility   Visibility
	TransferID   string
	Store        *ResumeStore
	Lease        *SendLease
	Progress     func(ResumeEvent)
}

type ResumeReceiveConfig struct {
	InboxRoot           string
	OfferedRoot         string
	Context             string
	SenderID            string
	SenderLabel         string
	ReceiverID          string
	OfferedRootRevision int64
	MaxFileBytes        int64
	Store               *ResumeStore
	AvailableSpace      func(string) (uint64, error)
	Progress            func(ResumeEvent)
}

type resumeManifest struct {
	Version    int        `json:"version"`
	ID         string     `json:"id"`
	Context    string     `json:"context"`
	SenderID   string     `json:"sender_id"`
	ReceiverID string     `json:"receiver_id"`
	Name       string     `json:"name"`
	Visibility Visibility `json:"visibility,omitempty"`
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256"`
	ChunkSize  int        `json:"chunk_size"`
	AckWindow  int        `json:"ack_window"`
}

type resumeControl struct {
	Version  int             `json:"version"`
	Type     string          `json:"type"`
	Manifest *resumeManifest `json:"manifest,omitempty"`
	Token    string          `json:"token,omitempty"`
	Offset   int64           `json:"offset,omitempty"`
	Bytes    int64           `json:"bytes,omitempty"`
	Error    string          `json:"error,omitempty"`
}

type resumeRecord struct {
	resumeManifest
	Token               string
	Offset              int64
	PeerLabel           string
	SourcePath          string
	StdinSpool          bool
	State               string
	ExpiresAt           time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	OfferedRootRevision int64
}

func NewResumeStore(database func() *sql.DB, root string) *ResumeStore {
	return &ResumeStore{database: database, root: root, quota: MaxResumeBytes, sendQuota: MaxSendSpoolBytes, active: make(map[string]*activeResume)}
}

func (s *ResumeStore) SetSharedSenderMaintenance(maintenance func(context.Context, time.Time) error) {
	s.sharedSenderMaintenance = maintenance
}

func (s *ResumeStore) SetObservationWriter(insert func(context.Context, TransferObservation) error, insertTx func(context.Context, *sql.Tx, TransferObservation) error) {
	s.insertObservation = insert
	s.insertObservationTx = insertTx
}

func (s *ResumeStore) ExpireSenders(ctx context.Context, now time.Time) error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.database().QueryContext(ctx, `select transfer_id,coalesce(source_path,''),stdin_spool from transfer_resumes where direction='send' and expires_at<=? and state!='corrupt'`, now.Unix())
	if err != nil {
		return err
	}
	type expired struct {
		id, source string
		spool      bool
	}
	var values []expired
	for rows.Next() {
		var value expired
		var spool int
		if err := rows.Scan(&value.id, &value.source, &spool); err != nil {
			rows.Close()
			return err
		}
		value.spool = spool == 1
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	active := s.activeSnapshot()
	for _, value := range values {
		if _, owned := active["send:"+value.id]; owned {
			continue
		}
		row := storedArtifact{item: InventoryItem{ID: value.id}, direction: "send", source: value.source, spool: value.spool}
		if _, err := s.deleteStoredRow(ctx, row, `direction='send' and transfer_id=? and expires_at<=?`, value.id, now.Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (s *ResumeStore) activeSnapshot() map[string]activeResume {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	result := make(map[string]activeResume, len(s.active))
	for key, active := range s.active {
		result[key] = *active
	}
	return result
}

func (s *ResumeStore) GC(ctx context.Context, now time.Time) error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if err := s.drainCleanup(ctx); err != nil {
		return err
	}
	db := s.database()
	if _, err := db.ExecContext(ctx, `update transfer_resumes set acknowledged_bytes=0 where state='transferring' and acknowledged_bytes!=0`); err != nil {
		return err
	}
	ids, err := db.QueryContext(ctx, `select direction, transfer_id from transfer_resumes where state != 'corrupt'`)
	if err != nil {
		return err
	}
	type identity struct{ direction, id string }
	var identities []identity
	for ids.Next() {
		var value identity
		if err := ids.Scan(&value.direction, &value.id); err != nil {
			ids.Close()
			return err
		}
		identities = append(identities, value)
	}
	if err := ids.Close(); err != nil {
		return err
	}
	for _, value := range identities {
		if !validTransferID(value.id) {
			if err := s.quarantine(ctx, value.direction, value.id); err != nil {
				return err
			}
		}
	}
	rows, err := db.QueryContext(ctx, `select direction, transfer_id, coalesce(source_path, ''), stdin_spool from transfer_resumes where expires_at <= ? and state != 'corrupt' and not (direction = 'receive' and visibility = 'public' and state in ('committing', 'committed_pending_confirmation'))`, now.Unix())
	if err != nil {
		return err
	}
	type expired struct {
		direction, id, source string
		spool                 bool
	}
	var values []expired
	for rows.Next() {
		var value expired
		var spool int
		if err := rows.Scan(&value.direction, &value.id, &value.source, &spool); err != nil {
			rows.Close()
			return err
		}
		value.spool = spool == 1
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	active := s.activeSnapshot()
	for _, value := range values {
		if !validTransferID(value.id) {
			if err := s.quarantine(ctx, value.direction, value.id); err != nil {
				return err
			}
			continue
		}
		if _, owned := active[value.direction+":"+value.id]; owned {
			continue
		}
		row := storedArtifact{item: InventoryItem{ID: value.id}, direction: value.direction, source: value.source, spool: value.spool}
		if _, err := s.deleteStoredRow(ctx, row, `direction = ? and transfer_id = ? and expires_at <= ?`, value.direction, value.id, now.Unix()); errors.Is(err, ErrCorruptTransferState) {
			if err := s.quarantine(ctx, value.direction, value.id); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (s *ResumeStore) acquire(ctx context.Context, direction string, record resumeRecord) (context.Context, func(), error) {
	if !validTransferID(record.ID) {
		return nil, nil, ErrCorruptTransferState
	}
	id := record.ID
	key := direction + ":" + id
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if _, exists := s.active[key]; exists {
		return nil, nil, errors.New("duplicate transfer is already active")
	}
	operationContext, cancel := context.WithCancel(ctx)
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	s.active[key] = &activeResume{record: record, direction: direction, cancel: cancel, item: inventoryFromRecord(direction, record)}
	return operationContext, func() {
		cancel()
		s.activeMu.Lock()
		delete(s.active, key)
		s.activeMu.Unlock()
	}, nil
}

func (s *ResumeStore) acquireSendRetry(ctx context.Context, id string) (context.Context, func(), error) {
	if !validTransferID(id) {
		return nil, nil, ErrTransferNotFound
	}
	key := "send:" + id
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	s.activeMu.Lock()
	if _, exists := s.active[key]; exists {
		s.activeMu.Unlock()
		return nil, nil, errors.New("duplicate transfer is already active")
	}
	s.activeMu.Unlock()
	record, exists, err := s.load(ctx, "send", id)
	if err != nil || !exists {
		return nil, nil, errors.New("retryable transfer state not found")
	}
	operationContext, cancel := context.WithCancel(ctx)
	s.activeMu.Lock()
	s.active[key] = &activeResume{record: record, direction: "send", cancel: cancel, item: inventoryFromRecord("send", record)}
	s.activeMu.Unlock()
	return operationContext, func() {
		cancel()
		s.activeMu.Lock()
		delete(s.active, key)
		s.activeMu.Unlock()
	}, nil
}

func (s *ResumeStore) ClaimSend(ctx context.Context, id, contextName, peerLabel string, now time.Time) (*SendLease, error) {
	if contextName == "" {
		return nil, ErrTransferContextRequired
	}
	if !validTransferID(id) {
		return nil, ErrTransferNotFound
	}
	if err := s.GC(ctx, now); err != nil {
		return nil, err
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	s.activeMu.Lock()
	key := "send:" + id
	if _, exists := s.active[key]; exists {
		s.activeMu.Unlock()
		return nil, ErrTransferActive
	}
	s.activeMu.Unlock()
	record, exists, err := s.load(ctx, "send", id)
	if err != nil {
		return nil, err
	}
	if !exists || record.State != "transferring" || !now.Before(record.ExpiresAt) {
		return nil, ErrTransferNotFound
	}
	if record.Context != contextName {
		return nil, ErrTransferContextMismatch
	}
	if peerLabel != "" && !strings.EqualFold(strings.TrimPrefix(peerLabel, "@"), record.PeerLabel) {
		return nil, ErrTransferPeerMismatch
	}
	operationContext, cancel := context.WithCancel(ctx)
	s.activeMu.Lock()
	s.active[key] = &activeResume{record: record, direction: "send", cancel: cancel, item: inventoryFromRecord("send", record)}
	s.activeMu.Unlock()
	return &SendLease{store: s, key: key, ctx: operationContext, record: record}, nil
}

func SendResumable(ctx context.Context, channel Channel, cfg ResumeSendConfig) (Result, error) {
	if cfg.Store == nil {
		return Result{}, errors.New("resume store is required")
	}
	if cfg.Lease != nil {
		if cfg.Lease.store != cfg.Store || cfg.TransferID == "" || cfg.Lease.record.ID != cfg.TransferID {
			return Result{}, errors.New("invalid transfer retry lease")
		}
		ctx = cfg.Lease.ctx
	} else if err := cfg.Store.GC(ctx, time.Now()); err != nil {
		return Result{}, err
	}
	var (
		release func()
		err     error
	)
	if cfg.TransferID != "" && cfg.Lease == nil {
		ctx, release, err = cfg.Store.acquireSendRetry(ctx, cfg.TransferID)
		if err != nil {
			return Result{}, err
		}
		defer release()
	}
	record, file, err := prepareSend(ctx, cfg)
	if err != nil {
		return Result{}, err
	}
	defer file.Close()
	retrying := cfg.TransferID != "" || record.Token != ""
	if release == nil && cfg.Lease == nil {
		ctx, release, err = cfg.Store.acquire(ctx, "send", record)
		if err != nil {
			return Result{}, err
		}
		defer release()
	}
	if err := cfg.Store.saveSend(ctx, record, record.SourcePath, record.StdinSpool); err != nil {
		return Result{}, err
	}
	cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "submitted", TransferID: record.ID, Total: record.Size, Name: record.Name})
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "offer", Manifest: &record.resumeManifest, Token: record.Token}); err != nil {
		return Result{}, err
	}
	response, err := receiveResumeControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "rejected" {
		_ = file.Close()
		if sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ack"}) == nil {
			cleanupCtx, cancelCleanup := durableCleanupContext(ctx)
			_ = cfg.Store.finishSend(cleanupCtx, record.ID)
			cancelCleanup()
		}
		cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "rejected", TransferID: record.ID, Error: response.Error})
		return Result{}, fmt.Errorf("receiver rejected transfer: %s", response.Error)
	}
	if response.Type == "committed" {
		result := Result{Name: record.Name, Bytes: record.Size, SHA256: record.SHA256}
		if err := file.Close(); err != nil {
			return result, err
		}
		if err := cfg.Store.observeSend(ctx, record); err != nil {
			return result, err
		}
		cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "committed", TransferID: record.ID, Bytes: record.Size, Total: record.Size, Resumed: true, Name: record.Name, SHA256: record.SHA256})
		if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ack"}); err != nil {
			return result, err
		}
		cleanupCtx, cancelCleanup := durableCleanupContext(ctx)
		err := cfg.Store.finishSend(cleanupCtx, record.ID)
		cancelCleanup()
		if err != nil {
			return result, err
		}
		return result, nil
	}
	if response.Type != "ready" || response.Token == "" || (response.Offset != 0 && response.Offset != record.Size) {
		return Result{}, errors.New("receiver sent invalid resume state")
	}
	record.Token, record.Offset = response.Token, response.Offset
	if err := cfg.Store.saveSend(ctx, record, record.SourcePath, record.StdinSpool); err != nil {
		return Result{}, err
	}
	if _, err := file.Seek(record.Offset, io.SeekStart); err != nil {
		return Result{}, sourceError(SourceUnreadableCode, "local source cannot be read", err)
	}
	state := "transferring"
	if retrying {
		state = "resumed"
	}
	cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: state, TransferID: record.ID, Bytes: record.Offset, Total: record.Size, Resumed: retrying})
	buffer := make([]byte, record.ChunkSize)
	offset := record.Offset
	lastEvent := offset
	streamHash := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Result{}, sourceError(SourceUnreadableCode, "local source cannot be read", err)
	}
	if _, err := io.CopyN(streamHash, file, record.Offset); err != nil {
		return Result{}, sourceError(SourceInvalidCode, "local source changed before resume", err)
	}
	for offset < record.Size {
		remaining := record.Size - offset
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		count, readErr := io.ReadFull(file, chunk)
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return Result{}, sourceError(SourceInvalidCode, "local source changed during transfer", readErr)
		}
		if count == 0 {
			return Result{}, sourceError(SourceInvalidCode, "local source changed during transfer", readErr)
		}
		_, _ = streamHash.Write(chunk[:count])
		if err := channel.Send(ctx, Message{Data: chunk[:count]}); err != nil {
			return Result{}, err
		}
		offset += int64(count)
		if offset == record.Size {
			ack, err := receiveResumeControl(ctx, channel)
			if err != nil || ack.Type != "ack" || ack.Offset != offset {
				return Result{}, errors.New("receiver sent invalid chunk acknowledgement")
			}
		}
		if offset-lastEvent >= 8<<20 || offset == record.Size {
			cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "transferring", TransferID: record.ID, Bytes: offset, Total: record.Size, Resumed: retrying})
			lastEvent = offset
		}
	}
	if hex.EncodeToString(streamHash.Sum(nil)) != record.SHA256 {
		_ = sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "failed", Error: "source changed during transfer"})
		return Result{}, sourceError(SourceInvalidCode, "local source changed during transfer", nil)
	}
	// Windows cannot remove the stdin spool during terminal cleanup while this handle is open.
	if err := file.Close(); err != nil {
		return Result{}, err
	}
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "complete"}); err != nil {
		return Result{}, err
	}
	committed, err := receiveResumeControl(ctx, channel)
	if err == nil && committed.Type == "rejected" {
		_ = sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ack"})
		cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "rejected", TransferID: record.ID, Error: committed.Error})
		return Result{}, fmt.Errorf("receiver rejected transfer: %s", committed.Error)
	}
	if err != nil || committed.Type != "committed" || committed.Bytes != record.Size {
		return Result{}, errors.New("receiver sent invalid commit confirmation")
	}
	result := Result{Name: record.Name, Bytes: record.Size, SHA256: record.SHA256}
	if err := cfg.Store.observeSend(ctx, record); err != nil {
		return result, err
	}
	cfg.Store.emitActive("send", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "committed", TransferID: record.ID, Bytes: record.Size, Total: record.Size, Resumed: retrying, Name: record.Name, SHA256: record.SHA256})
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ack"}); err != nil {
		return result, err
	}
	cleanupCtx, cancelCleanup := durableCleanupContext(ctx)
	err = cfg.Store.finishSend(cleanupCtx, record.ID)
	cancelCleanup()
	if err != nil {
		return result, err
	}
	return result, nil
}

func ReceiveResumable(ctx context.Context, channel Channel, cfg ResumeReceiveConfig) (Result, error) {
	if cfg.Store == nil {
		return Result{}, errors.New("resume store is required")
	}
	if err := cfg.Store.GC(ctx, time.Now()); err != nil {
		return Result{}, err
	}
	offer, err := receiveResumeControl(ctx, channel)
	if err != nil || offer.Type != "offer" || offer.Manifest == nil {
		return Result{}, errors.New("invalid resumable transfer offer")
	}
	manifest := *offer.Manifest
	if err := validateManifest(manifest, cfg); err != nil {
		_ = rejectResume(ctx, channel, err.Error())
		return Result{}, err
	}
	activeRecord := resumeRecord{resumeManifest: manifest, PeerLabel: cfg.SenderLabel, State: "transferring", ExpiresAt: time.Now().Add(ResumeLifetime), OfferedRootRevision: cfg.OfferedRootRevision}
	ctx, release, err := cfg.Store.acquire(ctx, "receive", activeRecord)
	if err != nil {
		_ = rejectResume(ctx, channel, err.Error())
		return Result{}, err
	}
	defer release()
	cfg.Store.emitActive("receive", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "submitted", TransferID: manifest.ID, Total: manifest.Size, Name: manifest.Name})
	record, exists, err := cfg.Store.load(ctx, "receive", manifest.ID)
	if err != nil {
		return Result{}, err
	}
	if exists {
		cfg.Store.setActiveRecord("receive", record)
	}
	if exists && effectiveVisibility(manifest) == VisibilityPublic && record.OfferedRootRevision != cfg.OfferedRootRevision {
		_ = rejectResume(ctx, channel, "stored resume state belongs to another offered-root revision")
		return Result{}, errors.New("stored resume state belongs to another offered-root revision")
	}
	if exists && (record.Token == "" || record.Offset < 0 || record.Offset > manifest.Size || (record.Offset != manifest.Size && record.Offset%int64(manifest.ChunkSize) != 0)) {
		_ = cfg.Store.discardReceive(ctx, manifest.ID)
		_ = rejectResume(ctx, channel, "stored resume state is incompatible")
		return Result{}, errors.New("stored resume state is incompatible")
	}
	if exists && (record.State == "committed_pending_confirmation" || record.State == "committed") {
		if offer.Token != record.Token {
			_ = rejectResume(ctx, channel, "stale or mismatched resume token")
			return Result{}, errors.New("stale or mismatched resume token")
		}
		result := Result{Name: manifest.Name, Bytes: manifest.Size, SHA256: manifest.SHA256}
		if err := cfg.Store.markCommittedRecord(ctx, record); err != nil {
			return result, err
		}
		cfg.Store.emitActive("receive", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "committed", TransferID: manifest.ID, Bytes: manifest.Size, Total: manifest.Size, Resumed: true, Name: manifest.Name, SHA256: manifest.SHA256})
		if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "committed", Bytes: manifest.Size}); err != nil {
			return result, err
		}
		ack, err := receiveResumeControl(ctx, channel)
		if err != nil || ack.Type != "ack" {
			return result, errors.New("sender did not acknowledge prior commit")
		}
		cleanupCtx, cancelCleanup := durableCleanupContext(ctx)
		err = cfg.Store.finishReceive(cleanupCtx, manifest.ID)
		cancelCleanup()
		if err != nil {
			return result, err
		}
		return result, nil
	}
	if exists && offer.Token != "" && offer.Token != record.Token {
		_ = rejectResume(ctx, channel, "stale or mismatched resume token")
		return Result{}, errors.New("stale or mismatched resume token")
	}
	created := false
	if !exists {
		if offer.Token != "" {
			_ = rejectResume(ctx, channel, "stale resume token")
			return Result{}, errors.New("stale resume token")
		}
		now := time.Now().UTC()
		record = resumeRecord{resumeManifest: manifest, Token: randomToken(), PeerLabel: cfg.SenderLabel, ExpiresAt: now.Add(ResumeLifetime), CreatedAt: now, UpdatedAt: now, State: "transferring", OfferedRootRevision: cfg.OfferedRootRevision}
		if record.Token == "" {
			return Result{}, errors.New("generate resume token")
		}
		if err := cfg.Store.reserveReceive(ctx, record); err != nil {
			_ = rejectResume(ctx, channel, err.Error())
			return Result{}, err
		}
		cfg.Store.setActiveRecord("receive", record)
		created = true
	}
	if record.State == "transferring" {
		record.Offset = 0
		if err := cfg.Store.updateOffset(ctx, manifest.ID, 0); err != nil {
			return Result{}, err
		}
	}
	transferRoot, err := os.OpenRoot(cfg.Store.root)
	if err != nil {
		return Result{}, errors.New("open transfer state root failed")
	}
	defer transferRoot.Close()
	partialName := manifest.ID + ".part"
	partial, err := transferRoot.OpenFile(partialName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return Result{}, errors.New("open transfer partial failed")
	}
	defer partial.Close()
	if err := partial.Truncate(record.Offset); err != nil {
		return Result{}, err
	}
	if _, err := partial.Seek(record.Offset, io.SeekStart); err != nil {
		return Result{}, err
	}
	space := cfg.AvailableSpace
	if space == nil {
		space = availableSpace
	}
	available, err := space(cfg.Store.root)
	if err != nil || uint64(manifest.Size-record.Offset) > available {
		if created {
			_ = cfg.Store.discardReceive(ctx, manifest.ID)
		}
		_ = rejectResume(ctx, channel, "insufficient transfer spool space")
		return Result{}, errors.New("insufficient transfer spool space")
	}
	if record.State != "committing" {
		if err := requireDestinationSpace(cfg, manifest); err != nil {
			if created {
				_ = cfg.Store.discardReceive(ctx, manifest.ID)
			}
			_ = rejectResume(ctx, channel, err.Error())
			return Result{}, err
		}
	}
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ready", Token: record.Token, Offset: record.Offset}); err != nil {
		return Result{}, err
	}
	offset := record.Offset
	for offset < manifest.Size {
		message, err := channel.Receive(ctx)
		if err != nil {
			return Result{}, err
		}
		if message.Text || len(message.Data) == 0 || len(message.Data) > manifest.ChunkSize || offset+int64(len(message.Data)) > manifest.Size {
			return Result{}, errors.New("invalid resumable file chunk")
		}
		if _, err := partial.Write(message.Data); err != nil {
			return Result{}, errors.New("write transfer partial failed")
		}
		offset += int64(len(message.Data))
		if offset == manifest.Size {
			if err := partial.Sync(); err != nil {
				return Result{}, errors.New("sync transfer partial failed")
			}
			if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "ack", Offset: offset}); err != nil {
				return Result{}, err
			}
		}
	}
	complete, err := receiveResumeControl(ctx, channel)
	if err != nil || complete.Type != "complete" {
		return Result{}, errors.New("sender did not complete transfer")
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return Result{}, err
	}
	hash, err := hashFile(ctx, partial, manifest.Size)
	if err != nil && ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil || hash != manifest.SHA256 {
		_ = cfg.Store.discardReceive(ctx, manifest.ID)
		_ = rejectResume(ctx, channel, "complete-file checksum mismatch")
		return Result{}, errors.New("complete-file checksum mismatch")
	}
	path, err := commitResume(ctx, cfg, record, partial)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		_ = cfg.Store.discardReceive(ctx, manifest.ID)
		_ = rejectResume(ctx, channel, err.Error())
		return Result{}, err
	}
	result := Result{Name: manifest.Name, Bytes: manifest.Size, SHA256: manifest.SHA256, Path: path}
	if err := cfg.Store.markCommittedRecord(ctx, record); err != nil {
		return result, err
	}
	cfg.Store.emitActive("receive", cfg.Progress, ResumeEvent{Version: ResumeEventVersion, State: "committed", TransferID: manifest.ID, Bytes: manifest.Size, Total: manifest.Size, Name: manifest.Name, SHA256: manifest.SHA256})
	_ = partial.Close()
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "committed", Bytes: manifest.Size}); err != nil {
		return result, err
	}
	ack, err := receiveResumeControl(ctx, channel)
	if err != nil || ack.Type != "ack" {
		return result, errors.New("sender did not acknowledge commit")
	}
	cleanupCtx, cancelCleanup := durableCleanupContext(ctx)
	err = cfg.Store.finishReceive(cleanupCtx, manifest.ID)
	cancelCleanup()
	if err != nil {
		return result, err
	}
	return result, nil
}

func durableCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func prepareSend(ctx context.Context, cfg ResumeSendConfig) (resumeRecord, *os.File, error) {
	if cfg.TransferID != "" && cfg.Source == "" {
		record, exists, err := cfg.Store.load(ctx, "send", cfg.TransferID)
		if err != nil || !exists || record.State != "transferring" || record.SourcePath == "" {
			return resumeRecord{}, nil, errors.New("retryable transfer state not found")
		}
		file, info, err := openSource(record.SourcePath)
		if err != nil {
			return resumeRecord{}, nil, err
		}
		if info.Size() != record.Size {
			file.Close()
			return resumeRecord{}, nil, sourceError(SourceInvalidCode, "retry source is unavailable or changed", nil)
		}
		hash, hashErr := hashFile(ctx, file, info.Size())
		if hashErr != nil {
			file.Close()
			return resumeRecord{}, nil, hashErr
		}
		if hash != record.SHA256 {
			file.Close()
			return resumeRecord{}, nil, sourceError(SourceInvalidCode, "retry source is unavailable or changed", nil)
		}
		_, _ = file.Seek(0, io.SeekStart)
		record.SenderID = cfg.SenderID
		return record, file, nil
	}
	file, info, err := openSource(cfg.Source)
	if err != nil {
		return resumeRecord{}, nil, err
	}
	name := cfg.Name
	if name == "" {
		name = filepath.Base(cfg.Source)
	}
	if err := ValidatePortableName(name); err != nil {
		file.Close()
		return resumeRecord{}, nil, err
	}
	if info.Size() > fileLimit(cfg.MaxFileBytes) {
		file.Close()
		return resumeRecord{}, nil, sourceError(SourceTooLargeCode, "local source exceeds the transfer limit", nil)
	}
	hash, err := hashFile(ctx, file, info.Size())
	if err != nil {
		file.Close()
		return resumeRecord{}, nil, err
	}
	visibility := cfg.Visibility
	if visibility == "" {
		visibility = VisibilityPrivate
	}
	if visibility != VisibilityPrivate && visibility != VisibilityPublic {
		file.Close()
		return resumeRecord{}, nil, errors.New("invalid transfer visibility")
	}
	if visibility == VisibilityPublic && IsReservedName(name) {
		file.Close()
		return resumeRecord{}, nil, errors.New("public destination uses a reserved name")
	}
	manifest := resumeManifest{Version: resumeVersion, Context: cfg.Context, SenderID: cfg.SenderID, ReceiverID: cfg.ReceiverID, Name: name, Visibility: visibility, Size: info.Size(), SHA256: hash, ChunkSize: ResumeChunkSize, AckWindow: ResumeAckWindow}
	manifest.ID = manifestID(manifest)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return resumeRecord{}, nil, err
	}
	record, exists, err := cfg.Store.load(ctx, "send", manifest.ID)
	if err != nil {
		file.Close()
		return resumeRecord{}, nil, err
	}
	if exists {
		if record.StdinSpool && (!cfg.StdinSpool || record.SourcePath != cfg.Source) {
			file.Close()
			return resumeRecord{}, nil, ErrSendSpoolOwnership
		}
		record.SourcePath = cfg.Source
		record.StdinSpool = cfg.StdinSpool
		record.SenderID = cfg.SenderID
		record.PeerLabel = cfg.PeerLabel
		return record, file, nil
	}
	return resumeRecord{resumeManifest: manifest, PeerLabel: cfg.PeerLabel, SourcePath: cfg.Source, StdinSpool: cfg.StdinSpool, State: "transferring", ExpiresAt: time.Now().Add(ResumeLifetime)}, file, nil
}

func validateManifest(manifest resumeManifest, cfg ResumeReceiveConfig) error {
	if !validTransferID(manifest.ID) || (manifest.Version != 2 && manifest.Version != resumeVersion) || manifest.Context != cfg.Context || manifest.SenderID != cfg.SenderID || manifest.ReceiverID != cfg.ReceiverID || manifest.ID != manifestID(manifest) {
		return errors.New("transfer manifest identity mismatch")
	}
	visibility := effectiveVisibility(manifest)
	if (manifest.Version == 2 && manifest.Visibility != "") || (visibility != VisibilityPrivate && visibility != VisibilityPublic) || (visibility == VisibilityPublic && IsReservedName(manifest.Name)) || ValidatePortableName(manifest.Name) != nil || manifest.Size < 0 || manifest.Size > fileLimit(cfg.MaxFileBytes) || !validHash(manifest.SHA256) || manifest.ChunkSize != ResumeChunkSize || manifest.AckWindow != ResumeAckWindow {
		return errors.New("incompatible transfer manifest")
	}
	return nil
}

func manifestID(manifest resumeManifest) string {
	manifest.ID = ""
	data, _ := json.Marshal(manifest)
	prefix := fmt.Sprintf("px-transfer-manifest-v%d\x00", manifest.Version)
	sum := sha256.Sum256(append([]byte(prefix), data...))
	return hex.EncodeToString(sum[:])
}

func commitResume(ctx context.Context, cfg ResumeReceiveConfig, record resumeRecord, source *os.File) (string, error) {
	manifest := record.resumeManifest
	public := effectiveVisibility(manifest) == VisibilityPublic
	rootPath := cfg.InboxRoot
	directory := filepath.Join(cfg.Context, cfg.SenderLabel)
	rootKind := "inbox"
	if public {
		rootPath, directory, rootKind = cfg.OfferedRoot, "", "offered root"
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", fmt.Errorf("open %s failed", rootKind)
	}
	defer root.Close()
	if directory != "" {
		if err := root.MkdirAll(directory, 0o700); err != nil {
			return "", errors.New("create inbox namespace failed")
		}
	}
	destination := filepath.Join(directory, manifest.Name)
	if record.State == "committing" {
		if public {
			publicCommitMu.Lock()
			defer publicCommitMu.Unlock()
		}
		committed, err := reconcileResumeDestination(ctx, root, destination, manifest)
		if err != nil {
			return "", err
		}
		if committed {
			if err := syncRootDirectory(root, directory); err != nil {
				return "", fmt.Errorf("sync reconciled %s destination failed", rootKind)
			}
			return filepath.ToSlash(destination), nil
		}
		if public {
			if err := rejectPortableCollision(root, manifest.Name); err != nil {
				return "", err
			}
		}
		if err := requireDestinationSpace(cfg, manifest); err != nil {
			return "", err
		}
	} else {
		if _, err := root.Lstat(destination); err == nil {
			return "", errors.New("destination already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("inspect destination failed")
		}
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("rewind verified partial failed")
	}
	temporary, err := temporaryResumeName(directory)
	if err != nil {
		return "", err
	}
	target, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s temporary failed", rootKind)
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		_ = root.Remove(temporary)
		return "", errors.New("copy verified partial failed")
	}
	if err := target.Sync(); err != nil {
		target.Close()
		_ = root.Remove(temporary)
		return "", fmt.Errorf("sync %s temporary failed", rootKind)
	}
	if err := target.Close(); err != nil {
		_ = root.Remove(temporary)
		return "", fmt.Errorf("close %s temporary failed", rootKind)
	}
	if public && record.State != "committing" {
		publicCommitMu.Lock()
		defer publicCommitMu.Unlock()
		if err := rejectPortableCollision(root, manifest.Name); err != nil {
			_ = root.Remove(temporary)
			return "", err
		}
	}
	if record.State != "committing" {
		if err := cfg.Store.markCommitting(ctx, manifest.ID); err != nil {
			_ = root.Remove(temporary)
			return "", errors.New("persist transfer commit intent failed")
		}
	}
	if err := root.Link(temporary, destination); err != nil {
		_ = root.Remove(temporary)
		return "", fmt.Errorf("commit %s destination failed", rootKind)
	}
	if err := syncRootDirectory(root, directory); err != nil {
		_ = root.Remove(destination)
		_ = root.Remove(temporary)
		_ = syncRootDirectory(root, directory)
		return "", fmt.Errorf("sync %s destination failed", rootKind)
	}
	// Once the destination directory is durable, cleanup failures leave only a
	// reserved, unreadable internal name and must not contradict publication.
	if root.Remove(temporary) == nil {
		_ = syncRootDirectory(root, directory)
	}
	return filepath.ToSlash(destination), nil
}

func reconcileResumeDestination(ctx context.Context, root *os.Root, destination string, manifest resumeManifest) (bool, error) {
	file, err := root.Open(destination)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("inspect committing destination failed")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != manifest.Size {
		return false, errors.New("destination already exists")
	}
	hash, err := hashFile(ctx, file, manifest.Size)
	if err != nil || hash != manifest.SHA256 {
		return false, errors.New("destination already exists")
	}
	return true, nil
}

func requireDestinationSpace(cfg ResumeReceiveConfig, manifest resumeManifest) error {
	root, kind := cfg.InboxRoot, "inbox"
	if effectiveVisibility(manifest) == VisibilityPublic {
		root, kind = cfg.OfferedRoot, "offered root"
	}
	space := cfg.AvailableSpace
	if space == nil {
		space = availableSpace
	}
	available, err := space(root)
	if err != nil || uint64(manifest.Size) > available {
		return errors.New("insufficient " + kind + " space")
	}
	return nil
}

func rejectPortableCollision(root *os.Root, destination string) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("inspect offered root failed")
	}
	defer directory.Close()
	scanned := 0
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return errors.New("inspect offered root failed")
		}
		scanned += len(entries)
		if scanned > maxCommitScanEntries {
			return errors.New("offered root contains too many entries to inspect safely")
		}
		for _, entry := range entries {
			if strings.EqualFold(entry.Name(), destination) {
				return errors.New("destination already exists")
			}
		}
		if errors.Is(err, io.EOF) || len(entries) == 0 {
			return nil
		}
	}
}

func temporaryResumeName(directory string) (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", errors.New("generate transfer temporary name failed")
	}
	return filepath.Join(directory, ReservedNamePrefix+hex.EncodeToString(data)+".part"), nil
}

func IsReservedName(name string) bool {
	return len(name) >= len(ReservedNamePrefix) && strings.EqualFold(name[:len(ReservedNamePrefix)], ReservedNamePrefix)
}

func effectiveVisibility(manifest resumeManifest) Visibility {
	if manifest.Version == 2 && manifest.Visibility == "" {
		return VisibilityPrivate
	}
	return manifest.Visibility
}

func (s *ResumeStore) reserveReceive(ctx context.Context, record resumeRecord) error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	db := s.database()
	var count int
	var reserved int64
	if err := db.QueryRowContext(ctx, `select count(*), coalesce(sum(source_size), 0) from transfer_resumes where direction = 'receive' and state in ('transferring', 'committing', 'committed_pending_confirmation')`).Scan(&count, &reserved); err != nil {
		return err
	}
	if count >= MaxResumeStates || reserved+record.Size > s.quota {
		return errors.New("resume state quota exceeded")
	}
	now := time.Now().Unix()
	var rootRevision any
	if effectiveVisibility(record.resumeManifest) == VisibilityPublic {
		rootRevision = record.OfferedRootRevision
	}
	_, err := db.ExecContext(ctx, `insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, state, created_at, updated_at, expires_at, manifest_version, visibility, offered_root_revision) values ('receive', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'transferring', ?, ?, ?, ?, ?, ?)`, record.ID, record.Context, record.SenderID, record.PeerLabel, record.Name, record.Size, record.SHA256, record.ChunkSize, record.AckWindow, record.Token, now, now, record.ExpiresAt.Unix(), record.Version, effectiveVisibility(record.resumeManifest), rootRevision)
	return err
}

func (s *ResumeStore) saveSend(ctx context.Context, record resumeRecord, source string, spool bool) error {
	now := time.Now().UTC()
	if err := s.ExpireSenders(ctx, now); err != nil {
		return err
	}
	if s.sharedSenderMaintenance != nil {
		if err := s.sharedSenderMaintenance(ctx, now); err != nil {
			return err
		}
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	db := s.database()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingSize int64
	var existingSpool int
	var existingSource string
	exists := true
	if err := tx.QueryRowContext(ctx, `select source_size, stdin_spool, coalesce(source_path, '') from transfer_resumes where direction = 'send' and transfer_id = ?`, record.ID).Scan(&existingSize, &existingSpool, &existingSource); errors.Is(err, sql.ErrNoRows) {
		exists = false
	} else if err != nil {
		return err
	}
	var count int
	var spoolBytes int64
	if err := tx.QueryRowContext(ctx, `select count(*), coalesce(sum(case when stdin_spool = 1 then source_size else 0 end), 0) from transfer_resumes where direction = 'send'`).Scan(&count, &spoolBytes); err != nil {
		return err
	}
	if count < 0 || spoolBytes < 0 || existingSize < 0 || (existingSpool != 0 && existingSpool != 1) {
		return ErrCorruptTransferState
	}
	if exists && existingSpool == 1 && (!spool || existingSource != source) {
		return ErrSendSpoolOwnership
	}
	projectedCount := count
	if !exists {
		projectedCount++
	}
	projectedSpoolBytes := spoolBytes
	if exists && existingSpool == 1 {
		projectedSpoolBytes -= existingSize
	}
	if spool {
		projectedSpoolBytes += record.Size
	}
	if (projectedCount > MaxSendResumeStates && projectedCount > count) || (projectedSpoolBytes > s.sendQuota && projectedSpoolBytes > spoolBytes) {
		return ErrSendResumeCapacity
	}
	spoolValue := 0
	if spool {
		spoolValue = 1
	}
	_, err = tx.ExecContext(ctx, `insert into transfer_resumes (direction, transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, source_path, stdin_spool, state, created_at, updated_at, expires_at, manifest_version, visibility) values ('send', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'transferring', ?, ?, ?, ?, ?) on conflict(direction, transfer_id) do update set resume_token = excluded.resume_token, acknowledged_bytes = excluded.acknowledged_bytes, source_path = excluded.source_path, stdin_spool = excluded.stdin_spool, updated_at = excluded.updated_at, expires_at = excluded.expires_at`, record.ID, record.Context, record.ReceiverID, record.PeerLabel, record.Name, record.Size, record.SHA256, record.ChunkSize, record.AckWindow, record.Token, record.Offset, source, spoolValue, now.Unix(), now.Unix(), now.Add(ResumeLifetime).Unix(), record.Version, effectiveVisibility(record.resumeManifest))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ResumeStore) load(ctx context.Context, direction, id string) (resumeRecord, bool, error) {
	if !validTransferID(id) {
		return resumeRecord{}, false, ErrCorruptTransferState
	}
	var record resumeRecord
	var spool int
	var created, updated, expires int64
	var visibility string
	var rootRevision sql.NullInt64
	err := s.database().QueryRowContext(ctx, `select transfer_id, context_name, peer_device_id, peer_label, destination_name, source_size, source_sha256, chunk_size, ack_window, resume_token, acknowledged_bytes, coalesce(source_path, ''), stdin_spool, state, created_at, updated_at, expires_at, manifest_version, visibility, offered_root_revision from transfer_resumes where direction = ? and transfer_id = ?`, direction, id).Scan(&record.ID, &record.Context, &record.ReceiverID, &record.PeerLabel, &record.Name, &record.Size, &record.SHA256, &record.ChunkSize, &record.AckWindow, &record.Token, &record.Offset, &record.SourcePath, &spool, &record.State, &created, &updated, &expires, &record.Version, &visibility, &rootRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return resumeRecord{}, false, nil
	}
	if err != nil {
		return resumeRecord{}, false, err
	}
	if !validTransferID(record.ID) {
		return resumeRecord{}, false, ErrCorruptTransferState
	}
	if direction == "receive" {
		record.SenderID = record.ReceiverID
		record.ReceiverID = ""
	}
	if record.Version >= resumeVersion {
		record.Visibility = Visibility(visibility)
	}
	record.StdinSpool, record.CreatedAt, record.UpdatedAt, record.ExpiresAt = spool == 1, time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC(), time.Unix(expires, 0).UTC()
	record.OfferedRootRevision = rootRevision.Int64
	return record, true, nil
}

func (s *ResumeStore) updateOffset(ctx context.Context, id string, offset int64) error {
	_, err := s.database().ExecContext(ctx, `update transfer_resumes set acknowledged_bytes = ?, updated_at = ?, expires_at = ? where direction = 'receive' and transfer_id = ?`, offset, time.Now().Unix(), time.Now().Add(ResumeLifetime).Unix(), id)
	return err
}

func (s *ResumeStore) markCommitted(ctx context.Context, id string) error {
	record, exists, err := s.load(ctx, "receive", id)
	if err != nil {
		return err
	}
	if !exists {
		return ErrTransferNotFound
	}
	return s.markCommittedRecord(ctx, record)
}

func (s *ResumeStore) markCommittedRecord(ctx context.Context, record resumeRecord) error {
	now := time.Now().UTC()
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `update transfer_resumes set state = 'committed_pending_confirmation', updated_at = ?, expires_at = ? where direction = 'receive' and transfer_id = ? and state in ('committing','committed_pending_confirmation','committed')`, now.Unix(), now.Add(ResumeLifetime).Unix(), record.ID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrCorruptTransferState
	}
	if s.insertObservationTx == nil {
		return errors.New("recent observation journal is unavailable")
	}
	if err := s.insertObservationTx(ctx, tx, observationFromRecord(record, "receive", now)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.updateActiveReceiverState(record.ID, "committed_pending_confirmation", now)
	return nil
}

func (s *ResumeStore) observeSend(ctx context.Context, record resumeRecord) error {
	if s.insertObservation == nil {
		return errors.New("recent observation journal is unavailable")
	}
	return s.insertObservation(ctx, observationFromRecord(record, "send", time.Now().UTC()))
}

func observationFromRecord(record resumeRecord, direction string, observedAt time.Time) TransferObservation {
	peerID := record.ReceiverID
	kind := "sender_observed_commit"
	if direction == "receive" {
		peerID = record.SenderID
		kind = "receiver_published"
	}
	return TransferObservation{Context: record.Context, Direction: direction, TransferID: record.ID, Kind: kind, PeerDeviceID: peerID, PeerLabel: record.PeerLabel, Destination: record.Name, Visibility: effectiveVisibility(record.resumeManifest), Bytes: record.Size, ObservedAt: observedAt}
}

func (s *ResumeStore) markCommitting(ctx context.Context, id string) error {
	now := time.Now().UTC()
	result, err := s.database().ExecContext(ctx, `update transfer_resumes set state = 'committing', acknowledged_bytes = source_size, updated_at = ?, expires_at = ? where direction = 'receive' and transfer_id = ? and state = 'transferring'`, now.Unix(), now.Add(ResumeLifetime).Unix(), id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("receiver resume state cannot begin commit")
	}
	s.updateActiveReceiverState(id, "committing", now)
	return nil
}

func (s *ResumeStore) updateActiveReceiverState(id, state string, now time.Time) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	active := s.active["receive:"+id]
	if active == nil {
		return
	}
	active.record.State = state
	active.record.Offset = active.record.Size
	active.record.UpdatedAt = now
	active.item.Bytes = active.item.Total
	active.item.UpdatedAt = now
	applyInventoryState(&active.item, state)
}

func (s *ResumeStore) discardReceive(ctx context.Context, id string) error {
	if !validTransferID(id) {
		return ErrCorruptTransferState
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.storedArtifacts(ctx, "", id)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.direction == "receive" {
			_, err := s.deleteStoredRow(ctx, row, `direction = 'receive' and transfer_id = ?`, id)
			return err
		}
	}
	return nil
}

func (s *ResumeStore) finishReceive(ctx context.Context, id string) error {
	if !validTransferID(id) {
		return ErrCorruptTransferState
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.storedArtifacts(ctx, "", id)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.direction == "receive" && row.state == "committed_pending_confirmation" {
			_, err := s.deleteStoredRow(ctx, row, `direction = 'receive' and transfer_id = ? and state = 'committed_pending_confirmation'`, id)
			return err
		}
	}
	return nil
}

func (s *ResumeStore) finishSend(ctx context.Context, id string) error {
	if !validTransferID(id) {
		return ErrCorruptTransferState
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.storedArtifacts(ctx, "", id)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.direction == "send" {
			_, err := s.deleteStoredRow(ctx, row, `direction = 'send' and transfer_id = ?`, id)
			return err
		}
	}
	return nil
}

func (s *ResumeStore) partialPath(id string) string {
	if !validTransferID(id) {
		return ""
	}
	return filepath.Join(s.root, id+".part")
}

func (s *ResumeStore) validStdinSpoolPath(path string) bool {
	return path == filepath.Join(s.root, filepath.Base(path)) && strings.HasPrefix(filepath.Base(path), ".stdin-") && strings.HasSuffix(filepath.Base(path), ".spool")
}

func (s *ResumeStore) List(ctx context.Context, contextName string, limit int, now time.Time) (Inventory, error) {
	if limit <= 0 || limit > MaxInventoryLimit {
		return Inventory{}, fmt.Errorf("transfer limit must be between 1 and %d", MaxInventoryLimit)
	}
	if err := s.GC(ctx, now); err != nil {
		return Inventory{}, err
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	query := `select direction, transfer_id, context_name, peer_label, destination_name, source_size, acknowledged_bytes, state, created_at, updated_at, expires_at, visibility from transfer_resumes where expires_at > ? and state != 'corrupt'`
	args := []any{now.Unix()}
	if contextName != "" {
		query += ` and context_name = ?`
		args = append(args, contextName)
	}
	query += ` order by updated_at desc, direction, transfer_id limit ?`
	args = append(args, MaxInventoryLimit)
	rows, err := s.database().QueryContext(ctx, query, args...)
	if err != nil {
		return Inventory{}, err
	}
	defer rows.Close()
	items := make([]InventoryItem, 0, limit)
	byKey := make(map[string]int)
	for rows.Next() {
		var direction, state, visibility string
		var createdAt, updatedAt, expiresAt int64
		var item InventoryItem
		if err := rows.Scan(&direction, &item.ID, &item.Context, &item.Peer, &item.Name, &item.Total, &item.Bytes, &state, &createdAt, &updatedAt, &expiresAt, &visibility); err != nil {
			return Inventory{}, err
		}
		if !validTransferID(item.ID) {
			return Inventory{}, ErrCorruptTransferState
		}
		item.Kind = direction
		item.Visibility = Visibility(visibility)
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		expires := time.Unix(expiresAt, 0).UTC()
		item.ExpiresAt = &expires
		applyInventoryState(&item, state)
		byKey[direction+":"+item.ID] = len(items)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Inventory{}, err
	}
	for key, active := range s.activeSnapshot() {
		if contextName != "" && active.record.Context != contextName {
			continue
		}
		if index, exists := byKey[key]; exists {
			items[index] = active.item
			continue
		}
		items = append(items, active.item)
	}
	sortInventory(items)
	if len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		items = []InventoryItem{}
	}
	return Inventory{Version: InventoryVersion, Transfers: items}, nil
}

func (s *ResumeStore) Counts(ctx context.Context, contextName string, now time.Time) (Counts, error) {
	var result Counts
	err := s.ObserveCounts(ctx, contextName, now, func(counts Counts) { result = counts })
	return result, err
}

func (s *ResumeStore) ObserveCounts(ctx context.Context, contextName string, now time.Time, observe func(Counts)) error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.database().QueryContext(ctx, `select direction,transfer_id from transfer_resumes where context_name=? and expires_at>? and state='transferring'`, contextName, now.Unix())
	if err != nil {
		return err
	}
	retryable := make(map[string]struct{})
	for rows.Next() {
		var direction, id string
		if err := rows.Scan(&direction, &id); err != nil {
			rows.Close()
			return err
		}
		if !validTransferID(id) {
			rows.Close()
			return ErrCorruptTransferState
		}
		retryable[direction+":"+id] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	counts := Counts{}
	for key, active := range s.activeSnapshot() {
		if active.record.Context != contextName {
			continue
		}
		counts.Active++
		delete(retryable, key)
	}
	counts.Retryable = len(retryable)
	observe(counts)
	return nil
}

func (s *ResumeStore) CompletionIDs(ctx context.Context, contextName, action, peer, prefix string, limit int, now time.Time) ([]string, error) {
	if limit <= 0 || limit > MaxInventoryLimit {
		return nil, errors.New("transfer completion limit is invalid")
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	lower, upper := prefix, prefix+"\x7f"
	ids := make([]string, 0, limit+1)
	activeSendIDs := make([]string, 0)
	activeAnyIDs := make([]string, 0)
	activeTransfers := s.activeSnapshot()
	for _, active := range activeTransfers {
		if active.record.Context != contextName || !strings.HasPrefix(active.record.ID, prefix) {
			continue
		}
		activeAnyIDs = append(activeAnyIDs, active.record.ID)
		if active.direction == "send" {
			activeSendIDs = append(activeSendIDs, active.record.ID)
		}
		if action == "show" || action == "cancel" {
			ids = append(ids, active.record.ID)
		}
	}
	query := ""
	args := []any{contextName, lower, upper, now.Unix()}
	switch action {
	case "show":
		query = `select transfer_id from transfer_resumes where context_name=? and transfer_id>=? and transfer_id<? and (expires_at>? or state='corrupt') group by transfer_id having count(*)=1 and max(state)!='corrupt'`
	case "retry":
		query = `select distinct transfer_id from transfer_resumes where context_name=? and transfer_id>=? and transfer_id<? and expires_at>? and direction='send' and state='transferring'`
		if peer != "" {
			query += ` and lower(peer_label)=lower(?)`
			args = append(args, peer)
		}
		query, args = excludeCompletionIDs(query, args, activeSendIDs)
	case "delete":
		query = `select transfer_id from transfer_resumes where context_name=? and transfer_id>=? and transfer_id<? and (expires_at>? or state='corrupt')`
		query, args = excludeCompletionIDs(query, args, activeAnyIDs)
		query += ` group by transfer_id having count(*)=1 and max(state)='transferring'`
	case "cancel":
	default:
		return nil, errors.New("transfer completion action is invalid")
	}
	if query != "" {
		query += ` order by transfer_id limit ?`
		args = append(args, limit+1)
		rows, err := s.database().QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	items := make(map[string]map[string]completionItem, len(ids))
	if len(ids) > 0 {
		placeholders := make([]string, len(ids))
		args := make([]any, 0, len(ids)+1)
		args = append(args, contextName)
		for index, id := range ids {
			placeholders[index] = "?"
			args = append(args, id)
		}
		query := `select direction,transfer_id,peer_label,state,expires_at from transfer_resumes where context_name=? and transfer_id in (` + strings.Join(placeholders, ",") + `)`
		rows, err := s.database().QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var direction, id, peerLabel, state string
			var expires int64
			if err := rows.Scan(&direction, &id, &peerLabel, &state, &expires); err != nil {
				rows.Close()
				return nil, err
			}
			if state != "corrupt" && expires <= now.Unix() {
				continue
			}
			if items[id] == nil {
				items[id] = make(map[string]completionItem)
			}
			items[id][direction] = completionItem{direction: direction, peer: peerLabel, state: state, corrupt: state == "corrupt"}
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	for _, active := range activeTransfers {
		if active.record.Context != contextName || !slices.Contains(ids, active.record.ID) {
			continue
		}
		if items[active.record.ID] == nil {
			items[active.record.ID] = make(map[string]completionItem)
		}
		items[active.record.ID][active.direction] = completionItem{direction: active.direction, peer: active.record.PeerLabel, state: active.record.State, active: true}
	}
	result := make([]string, 0, limit)
	for _, id := range ids {
		entries := items[id]
		eligible := false
		switch action {
		case "show":
			if len(entries) == 1 {
				for _, item := range entries {
					eligible = !item.corrupt
				}
			}
		case "cancel":
			active := 0
			for _, item := range entries {
				if item.active {
					active++
				}
			}
			eligible = active == 1
		case "retry":
			item, exists := entries["send"]
			eligible = exists && !item.active && !item.corrupt && item.state == "transferring" && (peer == "" || strings.EqualFold(peer, item.peer))
		case "delete":
			if len(entries) == 1 {
				for _, item := range entries {
					eligible = !item.active && !item.corrupt && item.state == "transferring"
				}
			}
		}
		if eligible {
			result = append(result, id)
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func excludeCompletionIDs(query string, args []any, ids []string) (string, []any) {
	if len(ids) == 0 {
		return query, args
	}
	ids = append([]string(nil), ids...)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	placeholders := make([]string, len(ids))
	for index, id := range ids {
		placeholders[index] = "?"
		args = append(args, id)
	}
	return query + ` and transfer_id not in (` + strings.Join(placeholders, ",") + `)`, args
}

func (s *ResumeStore) Show(ctx context.Context, contextName, id string, now time.Time) (InventoryItem, error) {
	if !validTransferID(id) {
		return InventoryItem{}, ErrTransferNotFound
	}
	if err := s.GC(ctx, now); err != nil {
		return InventoryItem{}, err
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	rows, err := s.storedArtifacts(ctx, contextName, id)
	if err != nil {
		return InventoryItem{}, err
	}
	matches := make(map[string]InventoryItem, len(rows))
	for _, row := range rows {
		matches[row.direction+":"+row.item.ID] = row.item
	}
	for key, active := range s.activeSnapshot() {
		if active.record.ID == id && (contextName == "" || active.record.Context == contextName) {
			matches[key] = active.item
		}
	}
	if len(matches) == 0 {
		return InventoryItem{}, ErrTransferNotFound
	}
	if len(matches) > 1 {
		return InventoryItem{}, ErrTransferAmbiguous
	}
	for _, item := range matches {
		return item, nil
	}
	panic("unreachable")
}

func (s *ResumeStore) Cancel(contextName, id string) error {
	if !validTransferID(id) && !strings.HasPrefix(id, "get-") {
		return ErrTransferNotActive
	}
	s.activeMu.Lock()
	matches := make([]context.CancelFunc, 0, 1)
	for _, active := range s.active {
		if active.record.ID == id && (contextName == "" || active.record.Context == contextName) {
			matches = append(matches, active.cancel)
		}
	}
	s.activeMu.Unlock()
	if len(matches) == 0 {
		return ErrTransferNotActive
	}
	if len(matches) > 1 {
		return ErrTransferAmbiguous
	}
	matches[0]()
	return nil
}

func (s *ResumeStore) Delete(ctx context.Context, contextName, id string, now time.Time) (InventoryItem, error) {
	if !validTransferID(id) {
		return InventoryItem{}, ErrTransferNotFound
	}
	if err := s.GC(ctx, now); err != nil {
		return InventoryItem{}, err
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	for _, active := range s.activeSnapshot() {
		if active.record.ID == id && (contextName == "" || active.record.Context == contextName) {
			return InventoryItem{}, ErrTransferActive
		}
	}
	rows, err := s.storedArtifacts(ctx, contextName, id)
	if err != nil {
		return InventoryItem{}, err
	}
	if len(rows) == 0 {
		return InventoryItem{}, ErrTransferNotFound
	}
	if len(rows) > 1 {
		return InventoryItem{}, ErrTransferAmbiguous
	}
	row := rows[0]
	if row.state != "transferring" {
		return InventoryItem{}, ErrTransferNotDeletable
	}
	pending, err := s.deleteStoredRow(ctx, row, `direction = ? and transfer_id = ?`, row.direction, row.item.ID)
	if err != nil {
		return InventoryItem{}, err
	}
	row.item.CleanupPending = pending
	return row.item, nil
}

func (s *ResumeStore) RemoveContext(ctx context.Context, contextName string) error {
	return s.RemoveContextWith(ctx, contextName, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `delete from transfer_resumes where context_name = ?`, contextName)
		return err
	})
}

func (s *ResumeStore) RemoveContextWith(ctx context.Context, contextName string, remove func(*sql.Tx) error) error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if err := s.drainCleanup(ctx); err != nil {
		return err
	}
	for _, active := range s.activeSnapshot() {
		if active.record.Context == contextName {
			return ErrTransferActive
		}
	}
	rows, err := s.storedArtifacts(ctx, contextName, "")
	if err != nil {
		return err
	}
	healthy := make([]storedArtifact, 0, len(rows))
	for _, row := range rows {
		if !row.corrupt {
			healthy = append(healthy, row)
		}
	}
	intents, err := s.createCleanupIntents(ctx, healthy)
	if err != nil {
		return err
	}
	if err := s.executeCleanupIntents(ctx, intents); err != nil {
		return err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		_ = s.recoverCleanup(ctx)
		return ErrTransferCleanup
	}
	if err := remove(tx); err != nil {
		tx.Rollback()
		_ = s.recoverCleanup(ctx)
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = s.recoverCleanup(ctx)
		return ErrTransferCleanup
	}
	if err := s.recoverCleanup(ctx); err != nil {
		return ErrTransferCleanupPending
	}
	return nil
}

type storedArtifact struct {
	item      InventoryItem
	direction string
	source    string
	spool     bool
	state     string
	corrupt   bool
}

func (s *ResumeStore) storedArtifacts(ctx context.Context, contextName, id string) ([]storedArtifact, error) {
	query := `select direction, transfer_id, context_name, peer_label, destination_name, source_size, acknowledged_bytes, state, created_at, updated_at, expires_at, visibility, coalesce(source_path, ''), stdin_spool from transfer_resumes where 1 = 1`
	args := []any{}
	if contextName != "" {
		query += ` and context_name = ?`
		args = append(args, contextName)
	}
	if id != "" {
		query += ` and transfer_id = ?`
		args = append(args, id)
	}
	query += ` order by direction, transfer_id`
	rows, err := s.database().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []storedArtifact
	for rows.Next() {
		var row storedArtifact
		var state, visibility string
		var createdAt, updatedAt, expiresAt int64
		var spool int
		if err := rows.Scan(&row.direction, &row.item.ID, &row.item.Context, &row.item.Peer, &row.item.Name, &row.item.Total, &row.item.Bytes, &state, &createdAt, &updatedAt, &expiresAt, &visibility, &row.source, &spool); err != nil {
			return nil, err
		}
		row.item.Kind, row.item.Visibility = row.direction, Visibility(visibility)
		row.item.CreatedAt, row.item.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
		expires := time.Unix(expiresAt, 0).UTC()
		row.item.ExpiresAt = &expires
		row.spool = spool == 1
		row.state = state
		row.corrupt = state == "corrupt" || !validTransferID(row.item.ID) || (row.direction == "send" && row.spool && !s.validStdinSpoolPath(row.source))
		if !row.corrupt {
			applyInventoryState(&row.item, state)
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

type cleanupIntent struct {
	direction string
	id        string
	original  string
	staged    string
	phase     string
}

func (s *ResumeStore) deleteStoredRow(ctx context.Context, row storedArtifact, where string, args ...any) (bool, error) {
	return s.deleteStoredRows(ctx, []storedArtifact{row}, where, args...)
}

func (s *ResumeStore) deleteStoredRows(ctx context.Context, rows []storedArtifact, where string, args ...any) (bool, error) {
	intents, err := s.createCleanupIntents(ctx, rows)
	if err != nil {
		return false, err
	}
	if err := s.executeCleanupIntents(ctx, intents); err != nil {
		return false, err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		_ = s.recoverCleanup(ctx)
		return false, ErrTransferCleanup
	}
	result, err := tx.ExecContext(ctx, `delete from transfer_resumes where `+where, args...)
	if err != nil {
		tx.Rollback()
		_ = s.recoverCleanup(ctx)
		return false, ErrTransferCleanup
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != int64(len(rows)) {
		tx.Rollback()
		_ = s.recoverCleanup(ctx)
		return false, ErrTransferCleanup
	}
	if err := tx.Commit(); err != nil {
		_ = s.recoverCleanup(ctx)
		return false, ErrTransferCleanup
	}
	if err := s.recoverCleanup(ctx); err != nil {
		return true, nil
	}
	return false, nil
}

func (s *ResumeStore) createCleanupIntents(ctx context.Context, rows []storedArtifact) ([]cleanupIntent, error) {
	intents := make([]cleanupIntent, 0, len(rows))
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, ErrTransferCleanup
	}
	defer root.Close()
	for _, row := range rows {
		if row.corrupt {
			return nil, ErrCorruptTransferState
		}
		original, err := s.artifactName(ctx, row)
		if err != nil {
			return nil, err
		}
		if original == "" {
			continue
		}
		if _, err := rootFileExists(root, original); err != nil {
			return nil, err
		}
		data := make([]byte, 16)
		if _, err := rand.Read(data); err != nil {
			return nil, ErrTransferCleanup
		}
		intents = append(intents, cleanupIntent{direction: row.direction, id: row.item.ID, original: original, staged: ".cleanup-" + hex.EncodeToString(data), phase: "intent"})
	}
	if len(intents) == 0 {
		return intents, nil
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrTransferCleanup
	}
	for _, intent := range intents {
		if _, err := tx.ExecContext(ctx, `insert into transfer_cleanup (direction, transfer_id, original_name, staged_name, phase, created_at) values (?, ?, ?, ?, 'intent', ?)`, intent.direction, intent.id, intent.original, intent.staged, time.Now().Unix()); err != nil {
			tx.Rollback()
			return nil, ErrTransferCleanup
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, ErrTransferCleanup
	}
	return intents, nil
}

func (s *ResumeStore) artifactName(ctx context.Context, row storedArtifact) (string, error) {
	if !validTransferID(row.item.ID) {
		return "", ErrCorruptTransferState
	}
	if row.direction == "receive" {
		return row.item.ID + ".part", nil
	}
	if !row.spool {
		return "", nil
	}
	if !s.validStdinSpoolPath(row.source) {
		return "", ErrCorruptTransferState
	}
	var owners int
	if err := s.database().QueryRowContext(ctx, `select count(*) from transfer_resumes where direction = 'send' and stdin_spool = 1 and source_path = ?`, row.source).Scan(&owners); err != nil {
		return "", ErrTransferCleanup
	}
	if owners != 1 {
		return "", ErrCorruptTransferState
	}
	for key, active := range s.activeSnapshot() {
		if key != row.direction+":"+row.item.ID && active.record.StdinSpool && active.record.SourcePath == row.source {
			return "", ErrTransferActive
		}
	}
	return filepath.Base(row.source), nil
}

func (s *ResumeStore) executeCleanupIntents(ctx context.Context, intents []cleanupIntent) error {
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return ErrTransferCleanup
	}
	defer root.Close()
	for _, intent := range intents {
		originalExists, err := rootFileExists(root, intent.original)
		if err != nil {
			return err
		}
		stagedExists, err := rootFileExists(root, intent.staged)
		if err != nil {
			return err
		}
		switch {
		case originalExists && !stagedExists:
			if err := root.Rename(intent.original, intent.staged); err != nil {
				return ErrTransferCleanup
			}
			if err := syncRootDirectory(root, ""); err != nil {
				return ErrTransferCleanup
			}
		case !originalExists && stagedExists:
			// Recovery will reconcile the already executed rename.
		case !originalExists && !stagedExists:
			// Missing optional artifacts still retain an owner-bound intent.
		default:
			return ErrCorruptTransferState
		}
		if _, err := s.database().ExecContext(ctx, `update transfer_cleanup set phase = 'renamed' where direction = ? and transfer_id = ?`, intent.direction, intent.id); err != nil {
			return ErrTransferCleanup
		}
	}
	return nil
}

func (s *ResumeStore) recoverCleanup(ctx context.Context) error {
	rows, err := s.database().QueryContext(ctx, `select direction, transfer_id, original_name, staged_name, phase from transfer_cleanup order by created_at, direction, transfer_id`)
	if err != nil {
		return err
	}
	var intents []cleanupIntent
	for rows.Next() {
		var intent cleanupIntent
		if err := rows.Scan(&intent.direction, &intent.id, &intent.original, &intent.staged, &intent.phase); err != nil {
			rows.Close()
			return err
		}
		intents = append(intents, intent)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return ErrTransferCleanup
	}
	defer root.Close()
	for _, intent := range intents {
		if !validCleanupIntent(intent) {
			if err := s.deleteCleanupIntent(ctx, intent); err != nil {
				return err
			}
			continue
		}
		owned, valid, err := s.cleanupIntentOwnership(ctx, intent)
		if err != nil {
			return ErrTransferCleanup
		}
		if !valid {
			if err := s.deleteCleanupIntent(ctx, intent); err != nil {
				return err
			}
			continue
		}
		originalExists, err := rootFileExists(root, intent.original)
		if err != nil {
			if err := s.deleteCleanupIntent(ctx, intent); err != nil {
				return err
			}
			continue
		}
		stagedExists, err := rootFileExists(root, intent.staged)
		if err != nil {
			if err := s.deleteCleanupIntent(ctx, intent); err != nil {
				return err
			}
			continue
		}
		if owned {
			switch {
			case originalExists && !stagedExists:
				// Intent committed before rename; the owner still has its artifact.
			case !originalExists && stagedExists:
				if err := root.Rename(intent.staged, intent.original); err != nil {
					return ErrTransferCleanup
				}
			case originalExists && stagedExists:
				if err := root.Remove(intent.staged); err != nil {
					return ErrTransferCleanup
				}
			default:
				return ErrTransferCleanup
			}
		} else {
			for name, exists := range map[string]bool{intent.original: originalExists, intent.staged: stagedExists} {
				if exists {
					if err := root.Remove(name); err != nil {
						return ErrTransferCleanup
					}
				}
			}
		}
		if err := syncRootDirectory(root, ""); err != nil {
			return ErrTransferCleanup
		}
		if err := s.deleteCleanupIntent(ctx, intent); err != nil {
			return err
		}
	}
	return nil
}

func validCleanupIntent(intent cleanupIntent) bool {
	return (intent.direction == "send" || intent.direction == "receive") && validTransferID(intent.id) && validCleanupName(intent.staged) && validArtifactName(intent.original) && (intent.phase == "intent" || intent.phase == "renamed")
}

func (s *ResumeStore) deleteCleanupIntent(ctx context.Context, intent cleanupIntent) error {
	if _, err := s.database().ExecContext(ctx, `delete from transfer_cleanup where direction = ? and transfer_id = ?`, intent.direction, intent.id); err != nil {
		return ErrTransferCleanup
	}
	return nil
}

func (s *ResumeStore) cleanupIntentOwnership(ctx context.Context, intent cleanupIntent) (bool, bool, error) {
	var source string
	var spool int
	err := s.database().QueryRowContext(ctx, `select coalesce(source_path, ''), stdin_spool from transfer_resumes where direction = ? and transfer_id = ?`, intent.direction, intent.id).Scan(&source, &spool)
	persisted := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, false, err
	}
	if intent.direction == "receive" {
		return persisted, intent.original == intent.id+".part", nil
	}
	if persisted {
		if spool != 1 || !s.validStdinSpoolPath(source) || filepath.Base(source) != intent.original {
			return false, false, nil
		}
	}
	artifact := filepath.Join(s.root, intent.original)
	rows, err := s.database().QueryContext(ctx, `select source_path from transfer_resumes where direction = 'send' and stdin_spool = 1`)
	if err != nil {
		return false, false, err
	}
	persistedOwners := 0
	for rows.Next() {
		var candidate string
		if err := rows.Scan(&candidate); err != nil {
			rows.Close()
			return false, false, err
		}
		if filepath.Clean(candidate) == artifact {
			persistedOwners++
		}
	}
	if err := rows.Close(); err != nil {
		return false, false, err
	}
	activeOwners := 0
	for key, candidate := range s.activeSnapshot() {
		if key == intent.direction+":"+intent.id {
			continue
		}
		if candidate.direction == "send" && candidate.record.StdinSpool && filepath.Clean(candidate.record.SourcePath) == artifact {
			activeOwners++
		}
	}
	owners := persistedOwners + activeOwners
	if persisted {
		return true, owners == 1, nil
	}
	return false, owners == 0, nil
}

func (s *ResumeStore) drainCleanup(ctx context.Context) error { return s.recoverCleanup(ctx) }

func (s *ResumeStore) quarantine(ctx context.Context, direction, id string) error {
	var state, visibility string
	if err := s.database().QueryRowContext(ctx, `select state, visibility from transfer_resumes where direction = ? and transfer_id = ?`, direction, id).Scan(&state, &visibility); err != nil {
		return ErrTransferCleanup
	}
	if direction == "receive" && visibility == string(VisibilityPublic) && state == "transferring" {
		result, err := s.database().ExecContext(ctx, `delete from transfer_resumes where direction = 'receive' and transfer_id = ? and visibility = 'public' and state = 'transferring'`, id)
		if err != nil {
			return ErrTransferCleanup
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrTransferCleanup
		}
		return nil
	}
	result, err := s.database().ExecContext(ctx, `update transfer_resumes set state = 'corrupt', updated_at = ? where direction = ? and transfer_id = ?`, time.Now().Unix(), direction, id)
	if err != nil {
		return ErrTransferCleanup
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrTransferCleanup
	}
	return nil
}

func rootFileExists(root *os.Root, name string) (bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, ErrCorruptTransferState
	}
	return true, nil
}

func validArtifactName(name string) bool {
	if filepath.Base(name) != name {
		return false
	}
	if strings.HasPrefix(name, ".stdin-") && strings.HasSuffix(name, ".spool") {
		return true
	}
	return strings.HasSuffix(name, ".part") && validTransferID(strings.TrimSuffix(name, ".part"))
}

func validCleanupName(name string) bool {
	if !strings.HasPrefix(name, ".cleanup-") || len(name) != len(".cleanup-")+32 || filepath.Base(name) != name {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, ".cleanup-"))
	return err == nil
}

func inventoryFromRecord(direction string, record resumeRecord) InventoryItem {
	expires := record.ExpiresAt.UTC()
	item := InventoryItem{ID: record.ID, Kind: direction, Context: record.Context, Peer: record.PeerLabel, Name: record.Name, Visibility: effectiveVisibility(record.resumeManifest), State: "active", Bytes: record.Offset, Total: record.Size, CreatedAt: record.CreatedAt.UTC(), UpdatedAt: record.UpdatedAt.UTC(), Active: true}
	if !record.ExpiresAt.IsZero() {
		item.ExpiresAt = &expires
	}
	return item
}

func retryMetadata(record resumeRecord) RetryMetadata {
	return RetryMetadata{ID: record.ID, Context: record.Context, PeerDeviceID: record.ReceiverID, PeerLabel: record.PeerLabel, Name: record.Name, Visibility: effectiveVisibility(record.resumeManifest), Bytes: record.Offset, Total: record.Size, UpdatedAt: record.UpdatedAt, ExpiresAt: record.ExpiresAt}
}

func validTransferID(id string) bool {
	if len(id) != sha256.Size*2 || strings.ToLower(id) != id {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == sha256.Size
}

func applyInventoryState(item *InventoryItem, state string) {
	switch state {
	case "committing":
		item.State = "committing"
		item.Retryable = true
	case "committed_pending_confirmation":
		item.State = "pending_peer_confirmation"
		item.LocalCommitted = true
		item.PeerConfirmation = "pending"
	case "committed":
		item.State = "confirmed"
		item.LocalCommitted = true
		item.PeerConfirmation = "confirmed"
	default:
		item.State = "retryable"
		item.Retryable = true
	}
}

func sortInventory(items []InventoryItem) {
	slices.SortFunc(items, func(a, b InventoryItem) int {
		if value := b.UpdatedAt.Compare(a.UpdatedAt); value != 0 {
			return value
		}
		if value := strings.Compare(a.Kind, b.Kind); value != 0 {
			return value
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func sendResumeControl(ctx context.Context, channel Channel, value resumeControl) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxControlBytes {
		return errors.New("resumable transfer control exceeds bounds")
	}
	return channel.Send(ctx, Message{Text: true, Data: data})
}

func receiveResumeControl(ctx context.Context, channel Channel) (resumeControl, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return resumeControl{}, err
	}
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxControlBytes {
		return resumeControl{}, errors.New("invalid resumable transfer control")
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Data))
	decoder.DisallowUnknownFields()
	var value resumeControl
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != resumeVersion {
		return resumeControl{}, errors.New("invalid resumable transfer control")
	}
	return value, nil
}

func rejectResume(ctx context.Context, channel Channel, message string) error {
	if err := sendResumeControl(ctx, channel, resumeControl{Version: resumeVersion, Type: "rejected", Error: message}); err != nil {
		return err
	}
	ack, err := receiveResumeControl(ctx, channel)
	if err != nil || ack.Type != "ack" {
		return errors.New("sender did not acknowledge rejection")
	}
	return nil
}

func randomToken() string {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func (s *ResumeStore) emitActive(direction string, progress func(ResumeEvent), event ResumeEvent) {
	s.activeMu.Lock()
	if active := s.active[direction+":"+event.TransferID]; active != nil {
		changed := active.phase != event.State || event.Bytes != 0 && active.item.Bytes != event.Bytes || event.Total != 0 && active.item.Total != event.Total || event.Name != "" && active.item.Name != event.Name
		active.phase = event.State
		if event.Bytes != 0 || event.State == "transferring" || event.State == "resumed" || event.State == "committed" {
			active.item.Bytes = event.Bytes
		}
		if event.Total != 0 {
			active.item.Total = event.Total
		}
		if event.Name != "" {
			active.item.Name = event.Name
		}
		if changed {
			active.item.UpdatedAt = time.Now().UTC()
		}
	}
	s.activeMu.Unlock()
	emit(progress, event)
}

func (s *ResumeStore) setActiveRecord(direction string, record resumeRecord) {
	s.activeMu.Lock()
	if active := s.active[direction+":"+record.ID]; active != nil {
		active.record = record
		item := inventoryFromRecord(direction, record)
		if record.State == "transferring" {
			item.State = active.item.State
		} else {
			applyInventoryState(&item, record.State)
		}
		active.item = item
	}
	s.activeMu.Unlock()
}

func emit(progress func(ResumeEvent), event ResumeEvent) {
	if progress != nil {
		progress(event)
	}
}
