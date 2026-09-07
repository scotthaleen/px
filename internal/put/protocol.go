package put

import (
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
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/scotthaleen/go-toolbelt/strictjson"
	"github.com/scotthaleen/px/internal/transfer"
)

const (
	Protocol                     = "px-put-v3"
	SessionPrefix                = "px-put-"
	ChannelLabel                 = "px-put"
	MaxMessageBytes              = 32 << 10
	MaxControlBytes              = 8 << 10
	MaxFileBytes           int64 = 1 << 30
	ChunkSize                    = 32 << 10
	AckWindow                    = 8
	QueueDepth                   = 8
	MaxBufferedBytes             = 4 << 20
	Lifetime                     = 24 * time.Hour
	EventVersion                 = 2
	ResolutionVersion            = 1
	ResolutionEventVersion       = 1
	protocolVersion              = 2
	settlementTimeout            = 10 * time.Second
	resultDeliveryTimeout        = settlementTimeout + 5*time.Second
)

var (
	ErrDisabled            = errors.New("remote put is disabled for this context")
	ErrAuthority           = errors.New("put-root authority is invalid")
	ErrCapacity            = errors.New("shared send/put capacity reached")
	ErrNotFound            = errors.New("put transfer not found")
	ErrAmbiguous           = errors.New("put transfer ID is ambiguous")
	ErrActive              = errors.New("put transfer is active")
	ErrNotAbandonable      = errors.New("put transfer cannot be abandoned")
	ErrNotResolvable       = errors.New("put transfer cannot be resolved by accepting the current destination")
	ErrResolutionUnsafe    = errors.New("put accept-current resolution is unsafe")
	ErrUnsafeState         = errors.New("put durable filesystem ownership evidence is unsafe")
	ErrOutcomeUnknown      = errors.New("put publication outcome is unknown; automatic republication is refused")
	ErrCASMismatch         = errors.New("replacement destination does not match --expect-sha256")
	ErrNativeUnsupported   = errors.New("put is unavailable: native filesystem operations cannot satisfy the safety contract on this platform")
	errNativeRetryable     = errors.New("temporary native filesystem interference; retry is required")
	errPublishNotAttempted = errors.New("put publication canceled before native publish")
)

type Message struct {
	Text bool
	Data []byte
}

type Channel interface {
	Send(context.Context, Message) error
	Receive(context.Context) (Message, error)
}

type peerCloseWaiter interface {
	WaitPeerClose(context.Context) error
}

type Manifest struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	Context      string `json:"context"`
	SenderID     string `json:"sender_id"`
	ReceiverID   string `json:"receiver_id"`
	Destination  string `json:"destination"`
	Mode         string `json:"mode"`
	ExpectSHA256 string `json:"expect_sha256,omitempty"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	ChunkSize    int    `json:"chunk_size"`
	AckWindow    int    `json:"ack_window"`
	RootRevision int64  `json:"put_root_revision"`
}

type control struct {
	Version      int       `json:"version"`
	Type         string    `json:"type"`
	Manifest     *Manifest `json:"manifest,omitempty"`
	ID           string    `json:"id,omitempty"`
	Offset       int64     `json:"offset,omitempty"`
	Bytes        int64     `json:"bytes,omitempty"`
	Created      bool      `json:"created,omitempty"`
	Replaced     bool      `json:"replaced,omitempty"`
	Durability   string    `json:"durability,omitempty"`
	RootRevision int64     `json:"put_root_revision,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type Result struct {
	TransferID            string `json:"transfer_id"`
	Destination           string `json:"destination"`
	Bytes                 int64  `json:"bytes"`
	SHA256                string `json:"sha256"`
	Created               bool   `json:"created"`
	Replaced              bool   `json:"replaced"`
	DurabilityConfirmed   bool   `json:"durability_confirmed"`
	DurabilityUnconfirmed bool   `json:"durability_unconfirmed"`
	RootRevision          int64  `json:"-"`
}

type ResolutionResult struct {
	Version     int    `json:"version"`
	TransferID  string `json:"transfer_id"`
	Context     string `json:"context"`
	Destination string `json:"destination"`
	State       string `json:"state"`
}

type ResolutionEvent struct {
	Version    int       `json:"version"`
	Type       string    `json:"type"`
	TransferID string    `json:"transfer_id"`
	At         time.Time `json:"at"`
	Context    string    `json:"context"`
}

type Event struct {
	Version               int    `json:"version"`
	State                 string `json:"state"`
	TransferID            string `json:"transfer_id,omitempty"`
	Bytes                 int64  `json:"bytes,omitempty"`
	Total                 int64  `json:"total,omitempty"`
	Destination           string `json:"destination,omitempty"`
	Created               bool   `json:"created,omitempty"`
	Replaced              bool   `json:"replaced,omitempty"`
	DurabilityConfirmed   bool   `json:"durability_confirmed,omitempty"`
	DurabilityUnconfirmed bool   `json:"durability_unconfirmed,omitempty"`
	Outcome               string `json:"outcome,omitempty"`
	Durability            string `json:"durability,omitempty"`
	Error                 string `json:"error,omitempty"`
}

type CommittedEvent struct {
	SchemaVersion int       `json:"schema_version"`
	Type          string    `json:"type"`
	TransferID    string    `json:"transfer_id"`
	At            time.Time `json:"at"`
	Context       string    `json:"context"`
	PeerDeviceID  string    `json:"peer_device_id"`
	PeerLabel     string    `json:"peer_label"`
	Created       bool      `json:"created"`
	Replaced      bool      `json:"replaced"`
	Bytes         int64     `json:"bytes"`
	Durability    string    `json:"durability"`
}

type SendConfig struct {
	Source, Destination, Context, SenderID, ReceiverID, PeerLabel string
	Replace                                                       bool
	ExpectSHA256                                                  string
	Store                                                         *Store
	Lease                                                         *SenderLease
	Progress                                                      func(Event)
}

type ReceiveConfig struct {
	Root, Context, SenderID, SenderLabel, ReceiverID string
	RootRevision                                     int64
	Store                                            *Store
	Progress                                         func(Event)
	Committed                                        func(CommittedEvent)
}

func Send(ctx context.Context, channel Channel, cfg SendConfig) (Result, error) {
	if cfg.Store == nil {
		return Result{}, errors.New("put store is required")
	}
	var file *os.File
	var manifest Manifest
	lease := cfg.Lease
	if lease != nil {
		manifest = lease.record.Manifest
		if manifest.Context != cfg.Context || manifest.ReceiverID != cfg.ReceiverID {
			return Result{}, errors.New("put retry lease does not match peer context")
		}
		if lease.record.State == "transferring" {
			var err error
			file, err = openAndValidateRecordSource(ctx, lease.record)
			if err != nil {
				return Result{}, err
			}
			defer file.Close()
		}
	} else {
		if err := ValidateDestination(cfg.Destination); err != nil {
			return Result{}, err
		}
		opened, info, err := openSource(cfg.Source)
		if err != nil {
			return Result{}, err
		}
		file = opened
		defer file.Close()
		hash, err := hashSource(ctx, file, info.Size())
		if err != nil {
			return Result{}, err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return Result{}, err
		}
		id, err := randomID(16)
		if err != nil {
			return Result{}, err
		}
		mode := "create"
		if cfg.Replace {
			mode = "replace"
		}
		manifest = Manifest{Version: protocolVersion, ID: id, Context: cfg.Context, SenderID: cfg.SenderID, ReceiverID: cfg.ReceiverID, Destination: cfg.Destination, Mode: mode, ExpectSHA256: cfg.ExpectSHA256, Size: info.Size(), SHA256: hash, ChunkSize: ChunkSize, AckWindow: AckWindow}
	}
	if err := validateManifest(manifest); err != nil {
		return Result{}, err
	}
	emit(cfg.Progress, Event{Version: EventVersion, State: "submitted", TransferID: manifest.ID, Total: manifest.Size, Destination: manifest.Destination})
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "offer", Manifest: &manifest}); err != nil {
		return Result{}, err
	}
	response, err := receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "error" || response.Type == "retryable_error" {
		return Result{}, senderTerminalError(channel, cfg, manifest.ID, response, lease, "peer refused put")
	}
	if response.Type == "committed" {
		return senderCommitted(ctx, channel, cfg, manifest, response, lease)
	}
	if response.Type != "prepared" || response.ID != manifest.ID || response.RootRevision <= 0 || manifest.RootRevision != 0 && manifest.RootRevision != response.RootRevision {
		return Result{}, errors.New("peer sent invalid put preparation")
	}
	manifest.RootRevision = response.RootRevision
	if lease == nil {
		lease, err = cfg.Store.ReserveSender(ctx, manifest, cfg.PeerLabel, cfg.Source)
		if err != nil {
			return Result{}, err
		}
		defer lease.Release()
	} else if lease.record.RootRevision != manifest.RootRevision {
		return Result{}, errors.New("put retry belongs to another put-root revision")
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "start", ID: manifest.ID}); err != nil {
		return Result{}, err
	}
	response, err = receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "error" || response.Type == "retryable_error" {
		return Result{}, senderTerminalError(channel, cfg, manifest.ID, response, lease, "peer refused put")
	}
	if response.Type != "ready" || response.ID != manifest.ID {
		return Result{}, errors.New("peer sent invalid put readiness")
	}
	if file == nil {
		return Result{}, errors.New("put source is unavailable for transfer")
	}
	buffer := make([]byte, ChunkSize)
	hasher := sha256.New()
	var sent int64
	lastEvent := int64(0)
	for sent < manifest.Size {
		count, readErr := file.Read(buffer)
		if count > 0 {
			if sent+int64(count) > manifest.Size {
				return Result{}, errors.New("put source changed during transfer")
			}
			_, _ = hasher.Write(buffer[:count])
			if err := channel.Send(ctx, Message{Data: append([]byte(nil), buffer[:count]...)}); err != nil {
				return Result{}, err
			}
			sent += int64(count)
			if sent-lastEvent >= 8<<20 || sent == manifest.Size {
				emit(cfg.Progress, Event{Version: EventVersion, State: "transferring", TransferID: manifest.ID, Bytes: sent, Total: manifest.Size, Destination: manifest.Destination})
				lastEvent = sent
			}
			if sent == manifest.Size {
				ack, err := receiveControl(ctx, channel)
				if err != nil {
					return Result{}, errors.New("peer sent invalid put acknowledgement")
				}
				if ack.Type == "error" || ack.Type == "retryable_error" {
					return Result{}, senderTerminalError(channel, cfg, manifest.ID, ack, lease, "peer refused put")
				}
				if ack.Type != "ack" || ack.ID != manifest.ID || ack.Offset != sent {
					return Result{}, errors.New("peer sent invalid put acknowledgement")
				}
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return Result{}, errors.New("put source read failed")
		}
		if count == 0 && errors.Is(readErr, io.EOF) && sent != manifest.Size {
			return Result{}, errors.New("put source changed during transfer")
		}
	}
	if manifest.Size == 0 {
		emit(cfg.Progress, Event{Version: EventVersion, State: "transferring", TransferID: manifest.ID, Total: manifest.Size, Destination: manifest.Destination})
	}
	if hex.EncodeToString(hasher.Sum(nil)) != manifest.SHA256 {
		return Result{}, errors.New("put source changed during transfer")
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "complete", ID: manifest.ID}); err != nil {
		return Result{}, err
	}
	response, err = receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if response.Type == "error" || response.Type == "retryable_error" {
		return Result{}, senderTerminalError(channel, cfg, manifest.ID, response, lease, "peer failed put")
	}
	return senderCommitted(ctx, channel, cfg, manifest, response, lease)
}

func senderCommitted(ctx context.Context, channel Channel, cfg SendConfig, manifest Manifest, response control, lease *SenderLease) (Result, error) {
	wantCreated := manifest.Mode == "create"
	wantReplaced := manifest.Mode == "replace"
	if response.Type != "committed" || response.ID != manifest.ID || response.Bytes != manifest.Size || response.RootRevision != manifest.RootRevision || response.Created != wantCreated || response.Replaced != wantReplaced || (response.Durability != "durability_confirmed" && response.Durability != "durability_unconfirmed") {
		return Result{}, errors.New("peer sent invalid put result")
	}
	result := resultFrom(manifest, response.Durability)
	if err := runSettlement(func(settleCtx context.Context) error {
		return cfg.Store.MarkSenderCommitted(settleCtx, lease, response.Durability)
	}); err != nil {
		return result, err
	}
	emit(cfg.Progress, committedProgress(manifest, result))
	acknowledgeTerminal(channel, manifest.ID)
	return result, nil
}

func senderTerminalError(channel Channel, cfg SendConfig, id string, response control, lease *SenderLease, prefix string) error {
	if response.ID != id {
		return errors.New("peer sent put error for another transfer")
	}
	resultErr := fmt.Errorf("%s: %s", prefix, response.Error)
	if response.Type == "retryable_error" {
		resultErr = fmt.Errorf("peer requires put retry: %s", response.Error)
	} else if lease != nil {
		if err := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.DeleteSenderWithLease(settleCtx, lease)
		}); err != nil {
			return errors.Join(resultErr, err)
		}
	}
	acknowledgeTerminal(channel, id)
	return resultErr
}

func acknowledgeTerminal(channel Channel, id string) {
	ctx, cancel := newDetachedContext(resultDeliveryTimeout)
	defer cancel()
	if sendControl(ctx, channel, control{Version: protocolVersion, Type: "result_ack", ID: id}) != nil {
		return
	}
	if waiter, ok := channel.(peerCloseWaiter); ok {
		_ = waiter.WaitPeerClose(ctx)
	}
}

func Receive(ctx context.Context, channel Channel, cfg ReceiveConfig) (Result, error) {
	if cfg.Store == nil {
		return Result{}, errors.New("put store is required")
	}
	offer, err := receiveControl(ctx, channel)
	if err != nil || offer.Type != "offer" || offer.Manifest == nil {
		return Result{}, errors.New("invalid put offer")
	}
	manifest := *offer.Manifest
	if err := validateManifestFor(manifest, cfg); err != nil {
		_ = reject(ctx, channel, manifest.ID, publicError(err))
		return Result{}, err
	}
	nativeSupport := nativeReceiveSupported
	if manifest.Mode == "replace" {
		nativeSupport = nativeReplacementSupported
	}
	if err := nativeSupport(); err != nil {
		_ = reject(ctx, channel, manifest.ID, publicError(err))
		return Result{}, err
	}
	manifest.RootRevision = cfg.RootRevision
	parent, err := openDestinationParent(cfg.Root, manifest.Destination, false)
	if err != nil {
		if errors.Is(err, errNativeRetryable) {
			_ = retryable(ctx, channel, manifest.ID, errNativeRetryable.Error())
		} else {
			_ = reject(ctx, channel, manifest.ID, publicError(err))
		}
		return Result{}, err
	}
	defer parent.Close()
	destination := filepath.Base(filepath.FromSlash(manifest.Destination))
	releaseDestination, err := lockPutDestination(ctx, parent.identities[len(parent.identities)-1])
	if err != nil {
		return Result{}, err
	}
	defer releaseDestination()
	record, exists, err := cfg.Store.Load(ctx, "receive", manifest.ID)
	if err != nil {
		return Result{}, err
	}
	if exists && !record.matches(manifest) {
		_ = reject(ctx, channel, manifest.ID, "put transfer identity does not match durable state")
		return Result{}, errors.New("put transfer identity does not match durable state")
	}
	if exists && (record.State == "accept_current_intent" || record.State == "resolved_accept_current") {
		_ = retryable(ctx, channel, manifest.ID, ErrOutcomeUnknown.Error())
		return Result{}, ErrOutcomeUnknown
	}
	if exists && record.State == "committed" {
		if record.StageIdentity != "" || record.BackupIdentity != "" {
			receiverLease, claimErr := cfg.Store.ClaimReceiver(ctx, manifest.ID)
			if claimErr == nil {
				defer cfg.Store.ReleaseReceiver(manifest.ID, receiverLease)
				_ = runSettlement(func(settleCtx context.Context) error {
					return cfg.Store.CleanupCommitted(settleCtx, record, receiverLease)
				})
			}
		}
		result := record.result()
		return result, deliverResult(channel, result)
	}
	if exists && record.State == "outcome_unknown" {
		unknownLease, claimErr := cfg.Store.ClaimReceiver(ctx, manifest.ID)
		if claimErr != nil {
			_ = retryable(ctx, channel, manifest.ID, ErrOutcomeUnknown.Error())
			return Result{}, claimErr
		}
		result, settled, reconcileErr := reconcilePublication(record)
		if reconcileErr == nil && settled {
			commitErr := runSettlement(func(settleCtx context.Context) error {
				if err := cfg.Store.CommitReceiver(settleCtx, manifest.ID, unknownLease, result.Durability()); err != nil {
					return err
				}
				record.State = "committed"
				return cfg.Store.CleanupCommitted(settleCtx, record, unknownLease)
			})
			cfg.Store.ReleaseReceiver(manifest.ID, unknownLease)
			if commitErr != nil {
				return result, commitErr
			}
			return result, deliverResult(channel, result)
		}
		if errors.Is(reconcileErr, errPublishNotAttempted) {
			cleanupErr := runSettlement(func(settleCtx context.Context) error {
				if err := cfg.Store.BeginCleanupNotAttempted(settleCtx, manifest.ID, unknownLease); err != nil {
					return err
				}
				record.State = "cleanup_not_attempted"
				return cfg.Store.CleanupNotAttempted(settleCtx, record, unknownLease)
			})
			cfg.Store.ReleaseReceiver(manifest.ID, unknownLease)
			if cleanupErr != nil {
				_ = rejectCleanup(ctx, channel, manifest.ID, ErrOutcomeUnknown.Error(), cleanupErr)
				return Result{}, errors.Join(ErrOutcomeUnknown, cleanupErr)
			}
			exists, record = false, Record{}
		} else {
			cfg.Store.ReleaseReceiver(manifest.ID, unknownLease)
			_ = retryable(ctx, channel, manifest.ID, ErrOutcomeUnknown.Error())
			return Result{}, ErrOutcomeUnknown
		}
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "prepared", ID: manifest.ID, RootRevision: cfg.RootRevision}); err != nil {
		return Result{}, err
	}
	start, err := receiveControl(ctx, channel)
	if err != nil || start.Type != "start" || start.ID != manifest.ID {
		return Result{}, errors.New("sender did not authorize prepared put")
	}
	var receiverLease string
	if exists {
		receiverLease, err = cfg.Store.ClaimReceiver(ctx, manifest.ID)
		if err != nil {
			_ = retryable(ctx, channel, manifest.ID, "put receiver state is active; retry is required")
			return Result{}, err
		}
		defer cfg.Store.ReleaseReceiver(manifest.ID, receiverLease)
	}
	if exists && record.State == "cleanup_not_attempted" {
		cleanupErr := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.CleanupNotAttempted(settleCtx, record, receiverLease)
		})
		if cleanupErr != nil {
			_ = rejectCleanup(ctx, channel, manifest.ID, "put cleanup remains pending; retry is required", cleanupErr)
			return Result{}, errors.Join(ErrNotFound, cleanupErr)
		}
		exists, record = false, Record{}
	}
	if exists && record.State == "publication_intent" {
		return resumePublication(ctx, channel, cfg, record, receiverLease)
	}
	if manifest.Mode == "create" {
		err = validateCreateDestination(parent, destination)
	}
	if err != nil {
		var cleanupErr error
		if exists {
			cleanupErr = runSettlement(func(settleCtx context.Context) error {
				return cfg.Store.AbortPrepublication(settleCtx, record, receiverLease)
			})
		}
		_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), cleanupErr)
		return Result{}, errors.Join(err, cleanupErr)
	}
	if !exists {
		stageID, randomErr := randomID(16)
		if randomErr != nil {
			parent.Close()
			return Result{}, randomErr
		}
		stageName := ".px-" + stageID + ".put"
		record = Record{Manifest: manifest, Direction: "receive", PeerLabel: cfg.SenderLabel, ParentPath: parent.path, ParentIdentity: parentDurableIdentity(parent), StageName: stageName, State: "stage_intent"}
		if manifest.Mode == "replace" {
			evidence, inspectErr := inspectReplacementDestination(parent, destination)
			if inspectErr != nil {
				parent.Close()
				if errors.Is(inspectErr, errNativeRetryable) {
					_ = retryable(ctx, channel, manifest.ID, errNativeRetryable.Error())
				} else {
					_ = reject(ctx, channel, manifest.ID, publicError(inspectErr))
				}
				return Result{}, inspectErr
			}
			record.OldIdentity, record.OldMetadata, record.OldUID, record.OldGID, record.OldMode = evidence.Identity, evidence.Metadata, evidence.UID, evidence.GID, evidence.Mode
			backupID, randomErr := randomID(16)
			if randomErr != nil {
				parent.Close()
				return Result{}, randomErr
			}
			record.BackupName, record.BackupSize, inspectErr = replacementBackupEvidence(parent, backupID, evidence)
			if inspectErr != nil {
				parent.Close()
				_ = reject(ctx, channel, manifest.ID, publicError(inspectErr))
				return Result{}, inspectErr
			}
			if record.BackupName != "" {
				record.BackupIdentity = evidence.Identity
			}
		}
		receiverLease, err = cfg.Store.ReserveReceiver(ctx, record, record.ParentPath, record.ParentIdentity, record.StageName)
		if err != nil {
			parent.Close()
			_ = reject(ctx, channel, manifest.ID, publicError(err))
			return Result{}, err
		}
		defer cfg.Store.ReleaseReceiver(manifest.ID, receiverLease)
		if err := cfg.Store.runFault("after_stage_intent"); err != nil {
			parent.Close()
			return Result{}, err
		}
	}
	stage, attachIdentity, err := createOrOpenStage(parent, manifest, record)
	if err != nil {
		parent.Close()
		cleanupErr := runSettlement(func(settleCtx context.Context) error {
			if err := cfg.Store.BeginCleanupNotAttempted(settleCtx, record.ID, receiverLease); err != nil {
				return err
			}
			updated, ok, err := cfg.Store.Load(settleCtx, "receive", record.ID)
			if err != nil {
				return err
			}
			if !ok {
				return ErrNotFound
			}
			return cfg.Store.CleanupNotAttempted(settleCtx, updated, receiverLease)
		})
		if errors.Is(err, errNativeRetryable) && cleanupErr == nil {
			_ = retryable(ctx, channel, manifest.ID, errNativeRetryable.Error())
		} else {
			_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), cleanupErr)
		}
		return Result{}, errors.Join(err, cleanupErr)
	}
	defer stage.Close()
	if attachIdentity {
		if err := cfg.Store.runFault("after_stage_create"); err != nil {
			return Result{}, err
		}
		if err := cfg.Store.AttachStage(ctx, manifest.ID, receiverLease, stage.Identity); err != nil {
			cleanupErr := runSettlement(func(settleCtx context.Context) error {
				if err := cfg.Store.BeginCleanupNotAttempted(settleCtx, record.ID, receiverLease); err != nil {
					return err
				}
				updated, ok, err := cfg.Store.Load(settleCtx, "receive", record.ID)
				if err != nil || !ok {
					return err
				}
				return cfg.Store.CleanupNotAttempted(settleCtx, updated, receiverLease)
			})
			if cleanupErr != nil {
				_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), cleanupErr)
				return Result{}, errors.Join(err, cleanupErr)
			}
			_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), nil)
			return Result{}, err
		}
		record.StageIdentity, record.State = stage.Identity, "transferring"
		if err := cfg.Store.runFault("after_stage_attach"); err != nil {
			return Result{}, err
		}
	}
	if err := cfg.Store.ReapParent(ctx, stage.ParentPath, stage.ParentIdentity, manifest.ID); err != nil {
		return Result{}, err
	}
	if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ready", ID: manifest.ID}); err != nil {
		return Result{}, err
	}
	result, receiveErr := receiveData(ctx, channel, cfg, manifest, record, stage, receiverLease)
	if receiveErr != nil && isDeterministicProtocolError(receiveErr) {
		cleanupErr := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.AbortPrepublication(settleCtx, record, receiverLease)
		})
		_ = rejectCleanup(ctx, channel, manifest.ID, publicError(receiveErr), cleanupErr)
		receiveErr = errors.Join(receiveErr, cleanupErr)
	}
	return result, receiveErr
}

func receiveData(ctx context.Context, channel Channel, cfg ReceiveConfig, manifest Manifest, record Record, stage *Stage, lease string) (Result, error) {
	hasher := sha256.New()
	var received int64
	for received < manifest.Size {
		message, err := channel.Receive(ctx)
		if err != nil {
			return Result{}, err
		}
		if message.Text || len(message.Data) == 0 || len(message.Data) > ChunkSize || received+int64(len(message.Data)) > manifest.Size {
			return Result{}, &protocolError{message: "invalid put data chunk"}
		}
		if _, err := stage.File.Write(message.Data); err != nil {
			return Result{}, errors.New("write put stage failed")
		}
		_, _ = hasher.Write(message.Data)
		received += int64(len(message.Data))
		if received == manifest.Size {
			if err := stage.File.Sync(); err != nil {
				return Result{}, errors.New("sync put stage failed")
			}
			if err := sendControl(ctx, channel, control{Version: protocolVersion, Type: "ack", ID: manifest.ID, Offset: received}); err != nil {
				return Result{}, err
			}
			emit(cfg.Progress, Event{Version: EventVersion, State: "transferring", TransferID: manifest.ID, Bytes: received, Total: manifest.Size, Destination: manifest.Destination})
		}
	}
	complete, err := receiveControl(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	if complete.Type != "complete" || complete.ID != manifest.ID || received != manifest.Size || hex.EncodeToString(hasher.Sum(nil)) != manifest.SHA256 {
		return Result{}, &protocolError{message: "invalid or corrupt complete put"}
	}
	if err := stage.File.Sync(); err != nil {
		return Result{}, errors.New("sync complete put stage failed")
	}
	if err := cfg.Store.runFault("before_stage_verify"); err != nil {
		return Result{}, err
	}
	if err := stage.VerifyContent(ctx, manifest); err != nil {
		if errors.Is(err, errNativeRetryable) {
			_ = retryable(ctx, channel, manifest.ID, errNativeRetryable.Error())
			return Result{}, err
		}
		return Result{}, &protocolError{message: err.Error()}
	}
	if err := cfg.Store.PublicationIntent(ctx, manifest.ID, lease); err != nil {
		return Result{}, err
	}
	if err := cfg.Store.runFault("before_native_publish"); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		record.State = "publication_intent"
		if cleanupErr := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.AbortPublicationNotAttempted(settleCtx, record, lease)
		}); cleanupErr != nil {
			return Result{}, errors.Join(err, cleanupErr)
		}
		return Result{}, err
	}
	created, durability, err := stage.Publish(ctx, filepath.Base(filepath.FromSlash(manifest.Destination)), manifest)
	if err != nil {
		if errors.Is(err, errPublishNotAttempted) {
			record.State = "publication_intent"
			cleanupErr := runSettlement(func(settleCtx context.Context) error {
				return cfg.Store.AbortPublicationNotAttempted(settleCtx, record, lease)
			})
			if errors.Is(err, errNativeRetryable) && cleanupErr == nil {
				_ = retryable(ctx, channel, manifest.ID, errNativeRetryable.Error())
			} else {
				_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), cleanupErr)
			}
			return Result{}, errors.Join(err, cleanupErr)
		}
		if errors.Is(err, ErrOutcomeUnknown) {
			if markErr := runSettlement(func(settleCtx context.Context) error {
				return cfg.Store.MarkUnknown(settleCtx, manifest.ID, lease)
			}); markErr != nil {
				return Result{}, errors.Join(ErrOutcomeUnknown, markErr)
			}
			_ = retryable(ctx, channel, manifest.ID, ErrOutcomeUnknown.Error())
			return Result{}, ErrOutcomeUnknown
		}
		cleanupErr := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.AbortPublicationNotAttempted(settleCtx, record, lease)
		})
		_ = rejectCleanup(ctx, channel, manifest.ID, publicError(err), cleanupErr)
		return Result{}, errors.Join(err, cleanupErr)
	}
	if !created {
		cleanupErr := runSettlement(func(settleCtx context.Context) error {
			return cfg.Store.AbortPublicationNotAttempted(settleCtx, record, lease)
		})
		_ = rejectCleanup(ctx, channel, manifest.ID, "put publication did not create destination", cleanupErr)
		return Result{}, errors.Join(errors.New("put publication did not create destination"), cleanupErr)
	}
	if err := runSettlement(func(settleCtx context.Context) error {
		return cfg.Store.CommitReceiver(settleCtx, manifest.ID, lease, durability)
	}); err != nil {
		return Result{}, err
	}
	result := resultFrom(manifest, durability)
	record.State = "committed"
	_ = runSettlement(func(settleCtx context.Context) error { return cfg.Store.CleanupCommitted(settleCtx, record, lease) })
	return finishReceive(ctx, channel, cfg, manifest, result)
}

func resumePublication(ctx context.Context, channel Channel, cfg ReceiveConfig, record Record, lease string) (Result, error) {
	result, settled, reconcileErr := reconcilePublication(record)
	if reconcileErr != nil {
		if errors.Is(reconcileErr, errNativeRetryable) {
			_ = retryable(ctx, channel, record.ID, errNativeRetryable.Error())
			return Result{}, reconcileErr
		}
		if errors.Is(reconcileErr, errPublishNotAttempted) {
			cleanupErr := runSettlement(func(settleCtx context.Context) error {
				return cfg.Store.AbortPublicationNotAttempted(settleCtx, record, lease)
			})
			_ = rejectCleanup(ctx, channel, record.ID, publicError(reconcileErr), cleanupErr)
			return Result{}, errors.Join(reconcileErr, cleanupErr)
		}
		if errors.Is(reconcileErr, ErrOutcomeUnknown) || errors.Is(reconcileErr, ErrUnsafeState) {
			_ = runSettlement(func(settleCtx context.Context) error { return cfg.Store.MarkUnknown(settleCtx, record.ID, lease) })
			_ = retryable(ctx, channel, record.ID, ErrOutcomeUnknown.Error())
			return Result{}, ErrOutcomeUnknown
		}
		return Result{}, reconcileErr
	}
	if !settled {
		if err := runSettlement(func(settleCtx context.Context) error { return cfg.Store.MarkUnknown(settleCtx, record.ID, lease) }); err != nil {
			return Result{}, err
		}
		_ = retryable(ctx, channel, record.ID, ErrOutcomeUnknown.Error())
		return Result{}, ErrOutcomeUnknown
	}
	if err := runSettlement(func(settleCtx context.Context) error {
		return cfg.Store.CommitReceiver(settleCtx, record.ID, lease, result.Durability())
	}); err != nil {
		return result, err
	}
	record.State = "committed"
	_ = runSettlement(func(settleCtx context.Context) error { return cfg.Store.CleanupCommitted(settleCtx, record, lease) })
	return finishReceive(ctx, channel, cfg, record.Manifest, result)
}

func finishReceive(ctx context.Context, channel Channel, cfg ReceiveConfig, manifest Manifest, result Result) (Result, error) {
	emit(cfg.Progress, committedProgress(manifest, result))
	if cfg.Committed != nil {
		cfg.Committed(CommittedEvent{SchemaVersion: 1, Type: "put.committed", TransferID: manifest.ID, At: time.Now().UTC(), Context: cfg.Context, PeerDeviceID: cfg.SenderID, PeerLabel: cfg.SenderLabel, Created: result.Created, Replaced: result.Replaced, Bytes: manifest.Size, Durability: result.Durability()})
	}
	return result, deliverResult(channel, result)
}

type protocolError struct{ message string }

func (e *protocolError) Error() string { return e.message }
func isDeterministicProtocolError(err error) bool {
	var target *protocolError
	return errors.As(err, &target)
}

func deliverResult(channel Channel, result Result) error {
	return deliverTerminal(channel, control{Version: protocolVersion, Type: "committed", ID: result.TransferID, Bytes: result.Bytes, Created: result.Created, Replaced: result.Replaced, Durability: result.Durability(), RootRevision: resultRootRevision(result)})
}

func resultFrom(manifest Manifest, durability string) Result {
	return Result{TransferID: manifest.ID, Destination: manifest.Destination, Bytes: manifest.Size, SHA256: manifest.SHA256, Created: manifest.Mode == "create", Replaced: manifest.Mode == "replace", DurabilityConfirmed: durability == "durability_confirmed", DurabilityUnconfirmed: durability == "durability_unconfirmed", RootRevision: manifest.RootRevision}
}

func committedProgress(manifest Manifest, result Result) Event {
	outcome := "created"
	if result.Replaced {
		outcome = "replaced"
	}
	return Event{Version: EventVersion, State: "committed", TransferID: manifest.ID, Bytes: manifest.Size, Total: manifest.Size, Destination: manifest.Destination, Created: result.Created, Replaced: result.Replaced, DurabilityConfirmed: result.DurabilityConfirmed, DurabilityUnconfirmed: result.DurabilityUnconfirmed, Outcome: outcome, Durability: result.Durability()}
}

func resultRootRevision(result Result) int64 { return result.RootRevision }

func (r Result) Durability() string {
	if r.DurabilityConfirmed {
		return "durability_confirmed"
	}
	return "durability_unconfirmed"
}

func ValidateDestination(path string) error {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") || strings.Contains(path, "\\") {
		return errors.New("put destination must be a portable relative path")
	}
	parts := strings.Split(path, "/")
	if len(parts) > 128 {
		return errors.New("put destination has too many components")
	}
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), ".px-") {
			return errors.New("put destination uses a reserved internal name")
		}
		if err := transfer.ValidatePortableName(part); err != nil {
			return fmt.Errorf("put destination component: %w", err)
		}
	}
	return nil
}

func ValidateExpectedSHA256(value string) error {
	if value != "" && !validLowerHex(value, sha256.Size) {
		return errors.New("--expect-sha256 must be exactly 64 lowercase hexadecimal characters")
	}
	return nil
}

func validateManifest(value Manifest) error {
	if value.Version != protocolVersion || !validLowerHex(value.ID, 16) || value.Context == "" || value.SenderID == "" || value.ReceiverID == "" || value.Mode != "create" && value.Mode != "replace" || value.ExpectSHA256 != "" && (value.Mode != "replace" || !validLowerHex(value.ExpectSHA256, sha256.Size)) || value.Size < 0 || value.Size > MaxFileBytes || !validLowerHex(value.SHA256, sha256.Size) || value.ChunkSize != ChunkSize || value.AckWindow != AckWindow || value.RootRevision < 0 {
		return errors.New("invalid put manifest")
	}
	return ValidateDestination(value.Destination)
}

func validateManifestFor(value Manifest, cfg ReceiveConfig) error {
	if err := validateManifest(value); err != nil {
		return err
	}
	if value.Context != cfg.Context || value.SenderID != cfg.SenderID || value.ReceiverID != cfg.ReceiverID || value.RootRevision != 0 && value.RootRevision != cfg.RootRevision {
		return errors.New("put manifest authority binding does not match receiver")
	}
	return nil
}

func CanonicalManifest(value Manifest) ([]byte, error) {
	if err := validateManifest(value); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte("px-put-manifest-v2\x00"), data...), nil
}

func marshalControl(value control) ([]byte, error) {
	fields := map[string]any{"version": value.Version, "type": value.Type}
	switch value.Type {
	case "offer":
		fields["manifest"] = value.Manifest
	case "prepared":
		fields["id"], fields["put_root_revision"] = value.ID, value.RootRevision
	case "start", "ready", "complete", "result_ack":
		fields["id"] = value.ID
	case "ack":
		fields["id"], fields["offset"] = value.ID, value.Offset
	case "committed":
		fields["id"], fields["bytes"], fields["created"], fields["replaced"] = value.ID, value.Bytes, value.Created, value.Replaced
		fields["durability"], fields["put_root_revision"] = value.Durability, value.RootRevision
	case "error", "retryable_error":
		fields["id"], fields["error"] = value.ID, value.Error
	}
	return json.Marshal(fields)
}

func openSource(path string) (*os.File, os.FileInfo, error) {
	if err := transfer.ValidateSource(path, MaxFileBytes); err != nil {
		return nil, nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("put source is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("put source is unreadable")
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, errors.New("put source changed while opening")
	}
	return file, after, nil
}

func openAndValidateRecordSource(ctx context.Context, record Record) (*os.File, error) {
	file, info, err := openSource(record.SourcePath)
	if err != nil {
		return nil, err
	}
	hash, err := hashSource(ctx, file, info.Size())
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() != record.Size || hash != record.SHA256 {
		file.Close()
		return nil, errors.New("put retry source changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func hashSource(ctx context.Context, file *os.File, size int64) (string, error) {
	hasher := sha256.New()
	if _, err := io.CopyN(&contextWriter{ctx: ctx, writer: hasher}, file, size); err != nil {
		return "", errors.New("hash put source failed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w *contextWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(data)
}

func sendControl(ctx context.Context, channel Channel, value control) error {
	if err := validateControl(value); err != nil {
		return err
	}
	data, err := marshalControl(value)
	if err != nil || len(data) > MaxControlBytes {
		return errors.New("invalid put control message")
	}
	return channel.Send(ctx, Message{Text: true, Data: data})
}

func receiveControl(ctx context.Context, channel Channel) (control, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return control{}, err
	}
	if !message.Text || len(message.Data) == 0 || len(message.Data) > MaxControlBytes {
		return control{}, errors.New("invalid put control message")
	}
	var value control
	if strictjson.Decode(message.Data, &value, strictjson.DisallowUnknownFields()) != nil || value.Version != protocolVersion {
		return control{}, errors.New("invalid put control message")
	}
	if err := validateControlFields(message.Data, value.Type); err != nil {
		return control{}, errors.New("invalid put control message")
	}
	if err := validateControl(value); err != nil {
		return control{}, errors.New("invalid put control message")
	}
	return value, nil
}

func validateControlFields(data []byte, kind string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	allowed := map[string]map[string]bool{
		"offer":           {"version": true, "type": true, "manifest": true},
		"prepared":        {"version": true, "type": true, "id": true, "put_root_revision": true},
		"start":           {"version": true, "type": true, "id": true},
		"ready":           {"version": true, "type": true, "id": true},
		"complete":        {"version": true, "type": true, "id": true},
		"result_ack":      {"version": true, "type": true, "id": true},
		"ack":             {"version": true, "type": true, "id": true, "offset": true},
		"committed":       {"version": true, "type": true, "id": true, "bytes": true, "created": true, "replaced": true, "durability": true, "put_root_revision": true},
		"error":           {"version": true, "type": true, "id": true, "error": true},
		"retryable_error": {"version": true, "type": true, "id": true, "error": true},
	}[kind]
	if allowed == nil || len(fields) != len(allowed) {
		return errors.New("invalid put control fields")
	}
	for name := range fields {
		if !allowed[name] {
			return errors.New("invalid put control fields")
		}
	}
	return nil
}

func validateControl(value control) error {
	validID := validLowerHex(value.ID, 16)
	noResult := value.Offset == 0 && value.Bytes == 0 && !value.Created && !value.Replaced && value.Durability == "" && value.RootRevision == 0 && value.Error == ""
	switch value.Type {
	case "offer":
		if value.Manifest == nil || value.ID != "" || !noResult {
			return errors.New("invalid put offer fields")
		}
	case "prepared":
		if value.Manifest != nil || !validID || value.RootRevision <= 0 || value.Offset != 0 || value.Bytes != 0 || value.Created || value.Replaced || value.Durability != "" || value.Error != "" {
			return errors.New("invalid put prepared fields")
		}
	case "start", "ready", "complete", "result_ack":
		if value.Manifest != nil || !validID || !noResult {
			return errors.New("invalid put control fields")
		}
	case "ack":
		if value.Manifest != nil || !validID || value.Offset <= 0 || value.Bytes != 0 || value.Created || value.Replaced || value.Durability != "" || value.RootRevision != 0 || value.Error != "" {
			return errors.New("invalid put acknowledgement fields")
		}
	case "committed":
		if value.Manifest != nil || !validID || value.Offset != 0 || value.Bytes < 0 || value.Created == value.Replaced || (value.Durability != "durability_confirmed" && value.Durability != "durability_unconfirmed") || value.RootRevision <= 0 || value.Error != "" {
			return errors.New("invalid put result fields")
		}
	case "error", "retryable_error":
		if value.Manifest != nil || !validID || value.Error == "" || value.Offset != 0 || value.Bytes != 0 || value.Created || value.Replaced || value.Durability != "" || value.RootRevision != 0 {
			return errors.New("invalid put error fields")
		}
	default:
		return errors.New("invalid put control type")
	}
	return nil
}

func reject(_ context.Context, channel Channel, id, message string) error {
	if len(message) > 256 {
		message = message[:256]
	}
	return deliverTerminal(channel, control{Version: protocolVersion, Type: "error", ID: id, Error: message})
}

func rejectCleanup(_ context.Context, channel Channel, id, message string, cleanupErr error) error {
	kind := "error"
	if cleanupErr != nil {
		kind = "retryable_error"
		message = "put cleanup remains pending; retry is required"
	}
	if len(message) > 256 {
		message = message[:256]
	}
	return deliverTerminal(channel, control{Version: protocolVersion, Type: kind, ID: id, Error: message})
}

func retryable(_ context.Context, channel Channel, id, message string) error {
	if len(message) > 256 {
		message = message[:256]
	}
	return deliverTerminal(channel, control{Version: protocolVersion, Type: "retryable_error", ID: id, Error: message})
}

func deliverTerminal(channel Channel, terminal control) error {
	ctx, cancel := newDetachedContext(resultDeliveryTimeout)
	defer cancel()
	if err := sendControl(ctx, channel, terminal); err != nil {
		return err
	}
	ack, err := receiveControl(ctx, channel)
	if err != nil {
		return err
	}
	if ack.Type != "result_ack" || ack.ID != terminal.ID {
		return errors.New("sender did not acknowledge put result")
	}
	return nil
}

func publicError(err error) string {
	switch {
	case errors.Is(err, ErrCASMismatch):
		return ErrCASMismatch.Error()
	case errors.Is(err, ErrCapacity), errors.Is(err, ErrOutcomeUnknown), errors.Is(err, ErrNativeUnsupported):
		return err.Error()
	default:
		return "put destination is unavailable or unsafe"
	}
}

func validHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func validLowerHex(value string, bytes int) bool {
	return value == strings.ToLower(value) && validHex(value, bytes)
}

func newDetachedContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func runSettlement(attempt func(context.Context) error) error {
	ctx, cancel := newDetachedContext(settlementTimeout)
	defer cancel()
	return attempt(ctx)
}

func optionalDigest(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalStringValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalUint32(identity string, value uint32) any {
	if identity == "" {
		return nil
	}
	return int64(value)
}

func randomID(bytes int) (string, error) {
	data := make([]byte, bytes)
	_, err := rand.Read(data)
	return hex.EncodeToString(data), err
}

func emit(fn func(Event), event Event) {
	if fn != nil {
		fn(event)
	}
}

type Store struct {
	database                func() *sql.DB
	sharedSenderMaintenance func(context.Context, time.Time) error
	outcomeUnknown          func(string)
	resolved                func(ResolutionEvent)
	fault                   func(string) error
}

func NewStore(database func() *sql.DB) *Store { return &Store{database: database} }

func (s *Store) SetSharedSenderMaintenance(maintenance func(context.Context, time.Time) error) {
	s.sharedSenderMaintenance = maintenance
}

func (s *Store) SetOutcomeUnknown(callback func(string)) {
	s.outcomeUnknown = callback
}

func (s *Store) SetResolved(callback func(ResolutionEvent)) {
	s.resolved = callback
}

func (s *Store) runFault(point string) error {
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}

type Record struct {
	Manifest
	Direction, PeerLabel, SourcePath, ParentPath, ParentIdentity, StageName, StageIdentity, BackupName, BackupIdentity, State, Durability string
	OldIdentity, OldMetadata, ResolutionDestinationIdentity                                                                               string
	Offset, BackupSize                                                                                                                    int64
	OldUID, OldGID                                                                                                                        uint32
	OldMode                                                                                                                               uint32
	StageRemoved, BackupRemoved, ParentSynced                                                                                             bool
	CreatedAt, UpdatedAt, ExpiresAt, ResolvedAt                                                                                           time.Time
}

type SenderLease struct {
	store  *Store
	record Record
	token  string
	once   sync.Once
}

func (l *SenderLease) Record() Record { return l.record }
func (l *SenderLease) Release() {
	if l == nil || l.store == nil {
		return
	}
	l.once.Do(func() { l.store.releaseLease("send", l.record.ID, l.token) })
}

func (r Record) matches(m Manifest) bool { return r.Manifest == m }
func (r Record) result() Result          { return resultFrom(r.Manifest, r.Durability) }

func (s *Store) Startup(ctx context.Context) error {
	if _, err := s.database().ExecContext(ctx, `update put_transfers set acknowledged_bytes=case when state='transferring' then 0 else acknowledged_bytes end,lease_token=null,lease_expires_at=null where lease_token is not null or (state='transferring' and acknowledged_bytes!=0)`); err != nil {
		return err
	}
	return s.ExpireSettled(ctx, time.Now().UTC())
}

func (s *Store) ExpireSettled(ctx context.Context, now time.Time) error {
	_, err := s.database().ExecContext(ctx, `delete from put_transfers where expires_at<=? and lease_token is null and (direction='send' or (direction='receive' and ((state='committed' and stage_name is null and backup_name is null) or state='resolved_accept_current' or (state='cleanup_not_attempted' and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1))))`, now.Unix())
	return err
}

func (s *Store) ExpireSenders(ctx context.Context, now time.Time) error {
	_, err := s.database().ExecContext(ctx, `delete from put_transfers where direction='send' and expires_at<=? and lease_token is null`, now.Unix())
	return err
}

func (s *Store) ReserveSender(ctx context.Context, m Manifest, peerLabel, source string) (*SenderLease, error) {
	now := time.Now().UTC()
	if err := s.ExpireSettled(ctx, now); err != nil {
		return nil, err
	}
	if s.sharedSenderMaintenance != nil {
		if err := s.sharedSenderMaintenance(ctx, now); err != nil {
			return nil, err
		}
	}
	token, err := randomID(32)
	if err != nil {
		return nil, err
	}
	result, err := s.database().ExecContext(ctx, `insert into put_transfers(direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,state,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at)
		values('send',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'transferring',?,?,?,?,?,?)`, m.ID, m.Version, m.Context, m.ReceiverID, m.SenderID, peerLabel, m.Destination, m.Mode, optionalDigest(m.ExpectSHA256), m.Size, m.SHA256, m.ChunkSize, m.AckWindow, m.RootRevision, source, now.Unix(), now.Unix(), now.Add(Lifetime).Unix(), now.Unix(), token, now.Add(Lifetime).Unix())
	if err != nil {
		return nil, classifyCapacity(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows != 1 {
		return nil, errors.New("put transfer identity does not match durable sender state")
	}
	return &SenderLease{store: s, record: Record{Manifest: m, Direction: "send", PeerLabel: peerLabel, SourcePath: source, State: "transferring", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(Lifetime)}, token: token}, nil
}

func (s *Store) ClaimSender(ctx context.Context, contextName, id string) (*SenderLease, error) {
	token, err := randomID(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	result, err := s.database().ExecContext(ctx, `update put_transfers set lease_token=?,lease_expires_at=? where direction='send' and transfer_id=? and context_name=? and state='transferring' and expires_at>? and lease_token is null`, token, now.Add(Lifetime).Unix(), id, contextName, now.Unix())
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		record, exists, loadErr := s.Load(ctx, "send", id)
		if loadErr != nil {
			return nil, loadErr
		}
		if !exists || record.Context != contextName || record.State != "transferring" || !now.Before(record.ExpiresAt) {
			return nil, ErrNotFound
		}
		return nil, ErrActive
	}
	record, exists, err := s.Load(ctx, "send", id)
	if err != nil || !exists {
		s.releaseLease("send", id, token)
		return nil, errors.Join(err, ErrNotFound)
	}
	return &SenderLease{store: s, record: record, token: token}, nil
}

func ValidateSenderLease(ctx context.Context, lease *SenderLease) error {
	if lease == nil {
		return ErrNotFound
	}
	if lease.record.State != "transferring" || !time.Now().UTC().Before(lease.record.ExpiresAt) {
		return ErrNotFound
	}
	file, err := openAndValidateRecordSource(ctx, lease.record)
	if file != nil {
		_ = file.Close()
	}
	return err
}

func (s *Store) ReserveReceiver(ctx context.Context, r Record, parentPath, parentIdentity, stageName string) (string, error) {
	now := time.Now().UTC()
	if err := s.ExpireSettled(ctx, now); err != nil {
		return "", err
	}
	token, err := randomID(32)
	if err != nil {
		return "", err
	}
	_, err = s.database().ExecContext(ctx, `insert into put_transfers(direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,parent_path,parent_identity,stage_name,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at) values('receive',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'stage_intent',?,?,?,?,?,?)`, r.ID, r.Version, r.Context, r.SenderID, r.ReceiverID, r.PeerLabel, r.Destination, r.Mode, optionalDigest(r.ExpectSHA256), r.Size, r.SHA256, r.ChunkSize, r.AckWindow, r.RootRevision, parentPath, parentIdentity, stageName, optionalStringValue(r.OldIdentity), optionalUint32(r.OldIdentity, r.OldUID), optionalUint32(r.OldIdentity, r.OldGID), optionalUint32(r.OldIdentity, r.OldMode), optionalStringValue(r.OldMetadata), optionalStringValue(r.BackupName), optionalStringValue(r.BackupIdentity), r.BackupSize, now.Unix(), now.Unix(), now.Add(Lifetime).Unix(), now.Unix(), token, now.Add(Lifetime).Unix())
	return token, classifyCapacity(err)
}

func (s *Store) ClaimReceiver(ctx context.Context, id string) (string, error) {
	lease, err := randomID(32)
	if err != nil {
		return "", err
	}
	result, err := s.database().ExecContext(ctx, `update put_transfers set acknowledged_bytes=case when state='transferring' then 0 else acknowledged_bytes end,lease_token=?,lease_expires_at=? where direction='receive' and transfer_id=? and lease_token is null and (state in ('stage_intent','transferring','publication_intent','cleanup_not_attempted','outcome_unknown','accept_current_intent') or (state='committed' and (stage_name is not null or backup_name is not null)))`, lease, time.Now().Add(Lifetime).Unix(), id)
	if err != nil {
		return "", err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return "", ErrActive
	}
	return lease, nil
}

func (s *Store) ReleaseReceiver(id, lease string) {
	s.releaseLease("receive", id, lease)
}

func (s *Store) releaseLease(direction, id, lease string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = s.database().ExecContext(ctx, `update put_transfers set lease_token=null,lease_expires_at=null where direction=? and transfer_id=? and lease_token=?`, direction, id, lease)
}

func classifyCapacity(err error) error {
	if err != nil && strings.Contains(err.Error(), "capacity reached") {
		return ErrCapacity
	}
	return err
}

func (s *Store) Load(ctx context.Context, direction, id string) (Record, bool, error) {
	var r Record
	var parentPath, parentID, stageName, stageID, backupName, backupID, source, durability, expected, oldIdentity, oldMetadata, resolutionIdentity sql.NullString
	var oldUID, oldGID, oldMode sql.NullInt64
	var resolved sql.NullInt64
	var created, updated, expires int64
	var stageRemoved, backupRemoved, parentSynced int
	var peerID, localID string
	err := s.database().QueryRowContext(ctx, `select transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,coalesce(source_path,''),parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,durability,stage_removed,backup_removed,parent_synced,resolution_destination_identity,resolved_at,created_at,updated_at,expires_at from put_transfers where direction=? and transfer_id=?`, direction, id).Scan(&r.ID, &r.Version, &r.Context, &peerID, &localID, &r.PeerLabel, &r.Destination, &r.Mode, &expected, &r.Size, &r.SHA256, &r.ChunkSize, &r.AckWindow, &r.RootRevision, &source, &parentPath, &parentID, &stageName, &stageID, &oldIdentity, &oldUID, &oldGID, &oldMode, &oldMetadata, &backupName, &backupID, &r.BackupSize, &r.State, &r.Offset, &durability, &stageRemoved, &backupRemoved, &parentSynced, &resolutionIdentity, &resolved, &created, &updated, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	if direction == "receive" {
		r.SenderID, r.ReceiverID = peerID, localID
	} else {
		r.SenderID, r.ReceiverID = localID, peerID
	}
	r.Direction, r.SourcePath, r.ParentPath, r.ParentIdentity, r.StageName, r.StageIdentity, r.BackupName, r.BackupIdentity, r.Durability = direction, source.String, parentPath.String, parentID.String, stageName.String, stageID.String, backupName.String, backupID.String, durability.String
	r.ExpectSHA256, r.OldIdentity, r.OldMetadata, r.ResolutionDestinationIdentity = expected.String, oldIdentity.String, oldMetadata.String, resolutionIdentity.String
	r.OldUID, r.OldGID, r.OldMode = uint32(oldUID.Int64), uint32(oldGID.Int64), uint32(oldMode.Int64)
	r.CreatedAt, r.UpdatedAt, r.ExpiresAt = time.Unix(created, 0), time.Unix(updated, 0), time.Unix(expires, 0)
	r.StageRemoved = stageRemoved == 1
	r.BackupRemoved = backupRemoved == 1
	r.ParentSynced = parentSynced == 1
	if resolved.Valid {
		r.ResolvedAt = time.Unix(resolved.Int64, 0)
	}
	return r, true, nil
}

func (s *Store) AttachStage(ctx context.Context, id, lease, stageID string) error {
	if err := s.runFault("stage_registration"); err != nil {
		return err
	}
	result, err := s.database().ExecContext(ctx, `update put_transfers set stage_identity=?,state='transferring',acknowledged_bytes=0,updated_at=? where direction='receive' and transfer_id=? and state='stage_intent' and stage_identity is null and lease_token=?`, stageID, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) UpdateOffset(ctx context.Context, id, lease string, offset int64) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set acknowledged_bytes=?,updated_at=? where direction='receive' and transfer_id=? and state='transferring' and lease_token=?`, offset, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) PublicationIntent(ctx context.Context, id, lease string) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set state='publication_intent',acknowledged_bytes=source_size,updated_at=? where direction='receive' and transfer_id=? and state='transferring' and stage_identity is not null and lease_token=?`, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) CommitReceiver(ctx context.Context, id, lease, durability string) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set state='committed',created=case when mode='create' then 1 else 0 end,replaced=case when mode='replace' then 1 else 0 end,durability=?,updated_at=? where direction='receive' and transfer_id=? and state in ('publication_intent','outcome_unknown','committed') and lease_token=?`, durability, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) MarkUnknown(ctx context.Context, id, lease string) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set state='outcome_unknown',created=0,replaced=0,durability=null,updated_at=? where direction='receive' and transfer_id=? and state='publication_intent' and lease_token=?`, time.Now().Unix(), id, lease)
	if err := one(result, err); err != nil {
		return err
	}
	if s.outcomeUnknown != nil {
		s.outcomeUnknown(id)
	}
	return nil
}

func (s *Store) MarkSenderCommitted(ctx context.Context, lease *SenderLease, durability string) error {
	if lease == nil {
		return ErrNotFound
	}
	result, err := s.database().ExecContext(ctx, `update put_transfers set state='committed',created=case when mode='create' then 1 else 0 end,replaced=case when mode='replace' then 1 else 0 end,durability=?,acknowledged_bytes=source_size,updated_at=? where direction='send' and transfer_id=? and lease_token=?`, durability, time.Now().Unix(), lease.record.ID, lease.token)
	return one(result, err)
}

func (s *Store) DeleteSenderWithLease(ctx context.Context, lease *SenderLease) error {
	if lease == nil {
		return ErrNotFound
	}
	result, err := s.database().ExecContext(ctx, `delete from put_transfers where direction='send' and transfer_id=? and lease_token=? and state='transferring'`, lease.record.ID, lease.token)
	return one(result, err)
}

func (s *Store) ClearStage(ctx context.Context, id, lease string) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,old_metadata=null,backup_name=null,backup_identity=null,backup_size=0,stage_removed=0,backup_removed=0,parent_synced=0,updated_at=? where direction='receive' and transfer_id=? and state='committed' and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1 and lease_token=?`, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) BeginCleanupNotAttempted(ctx context.Context, id, lease string) error {
	result, err := s.database().ExecContext(ctx, `update put_transfers set state='cleanup_not_attempted',updated_at=? where direction='receive' and transfer_id=? and state in ('stage_intent','transferring','publication_intent','outcome_unknown') and lease_token=?`, time.Now().Unix(), id, lease)
	return one(result, err)
}

func (s *Store) AbortPrepublication(ctx context.Context, record Record, lease string) error {
	if record.State != "cleanup_not_attempted" {
		if err := s.BeginCleanupNotAttempted(ctx, record.ID, lease); err != nil {
			return err
		}
		var exists bool
		var err error
		record, exists, err = s.Load(ctx, "receive", record.ID)
		if err != nil || !exists {
			return errors.Join(err, ErrNotFound)
		}
	}
	return s.CleanupNotAttempted(ctx, record, lease)
}

func (s *Store) AbortPublicationNotAttempted(ctx context.Context, record Record, lease string) error {
	return s.AbortPrepublication(ctx, record, lease)
}

func (s *Store) CleanupNotAttempted(ctx context.Context, record Record, lease string) error {
	if record.State != "cleanup_not_attempted" {
		return ErrUnsafeState
	}
	return s.cleanupStage(ctx, record, lease, true, false)
}

func (s *Store) CleanupCommitted(ctx context.Context, record Record, lease string) error {
	if record.StageName == "" && record.BackupName == "" {
		return nil
	}
	// A committed replacement already proved rename publication, which consumed
	// the stage name; a later replacement may legitimately change destination identity.
	if record.State != "committed" || record.Mode != "replace" {
		_, settled, err := reconcilePublication(record)
		if err != nil {
			return err
		}
		if !settled {
			return ErrUnsafeState
		}
	}
	return s.cleanupStage(ctx, record, lease, false, false)
}

func (s *Store) ResolveAcceptCurrent(ctx context.Context, contextName, id, root string, rootRevision int64) (ResolutionResult, error) {
	if contextName == "" || id == "" || rootRevision <= 0 {
		return ResolutionResult{}, ErrNotResolvable
	}
	rows, err := s.database().QueryContext(ctx, `select kind,direction from (
		select 'put' as kind,direction from put_transfers where context_name=? and transfer_id=?
		union all
		select 'send' as kind,direction from transfer_resumes where context_name=? and transfer_id=?
	) order by kind,direction`, contextName, id, contextName, id)
	if err != nil {
		return ResolutionResult{}, err
	}
	type candidate struct{ kind, direction string }
	var candidates []candidate
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.kind, &value.direction); err != nil {
			rows.Close()
			return ResolutionResult{}, err
		}
		candidates = append(candidates, value)
	}
	if err := rows.Close(); err != nil {
		return ResolutionResult{}, err
	}
	if len(candidates) == 0 {
		return ResolutionResult{}, ErrNotFound
	}
	if len(candidates) != 1 {
		return ResolutionResult{}, ErrAmbiguous
	}
	if candidates[0].kind != "put" || candidates[0].direction != "receive" {
		return ResolutionResult{}, ErrNotResolvable
	}

	lease, err := randomID(32)
	if err != nil {
		return ResolutionResult{}, err
	}
	now := time.Now().UTC()
	claim, err := s.database().ExecContext(ctx, `update put_transfers set lease_token=?,lease_expires_at=? where direction='receive' and transfer_id=? and context_name=? and put_root_revision=? and state in ('outcome_unknown','accept_current_intent') and lease_token is null`, lease, now.Add(Lifetime).Unix(), id, contextName, rootRevision)
	if err != nil {
		return ResolutionResult{}, err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return ResolutionResult{}, err
	}
	if claimed != 1 {
		record, exists, loadErr := s.Load(ctx, "receive", id)
		if loadErr != nil {
			return ResolutionResult{}, loadErr
		}
		if !exists || record.Context != contextName {
			return ResolutionResult{}, ErrNotFound
		}
		if record.RootRevision != rootRevision || record.State != "outcome_unknown" && record.State != "accept_current_intent" {
			return ResolutionResult{}, ErrNotResolvable
		}
		return ResolutionResult{}, ErrActive
	}
	defer s.ReleaseReceiver(id, lease)

	record, exists, err := s.Load(ctx, "receive", id)
	if err != nil || !exists {
		return ResolutionResult{}, errors.Join(err, ErrNotFound)
	}
	identity, err := preflightAcceptCurrent(root, record)
	if err != nil || len(identity) < 8 || len(identity) > 160 {
		return ResolutionResult{}, errors.Join(ErrResolutionUnsafe, err)
	}
	if record.State == "outcome_unknown" {
		result, updateErr := s.database().ExecContext(ctx, `update put_transfers set state='accept_current_intent',resolution_destination_identity=?,updated_at=? where direction='receive' and transfer_id=? and context_name=? and put_root_revision=? and state='outcome_unknown' and lease_token=?`, identity, time.Now().UTC().Unix(), id, contextName, rootRevision, lease)
		if err := one(result, updateErr); err != nil {
			return ResolutionResult{}, err
		}
		if err := s.runFault("after_accept_current_intent"); err != nil {
			return ResolutionResult{}, err
		}
		record, exists, err = s.Load(ctx, "receive", id)
		if err != nil || !exists {
			return ResolutionResult{}, errors.Join(err, ErrNotFound)
		}
	} else if identity != record.ResolutionDestinationIdentity {
		return ResolutionResult{}, ErrResolutionUnsafe
	}
	if err := s.cleanupStage(ctx, record, lease, false, true); err != nil {
		return ResolutionResult{}, err
	}
	if s.resolved != nil {
		s.resolved(ResolutionEvent{Version: ResolutionEventVersion, Type: "put.resolved_accept_current", TransferID: record.ID, At: time.Now().UTC(), Context: record.Context})
	}
	return ResolutionResult{Version: ResolutionVersion, TransferID: record.ID, Context: record.Context, Destination: record.Destination, State: "resolved_accept_current"}, nil
}

func (s *Store) cleanupStage(ctx context.Context, record Record, lease string, deleteRow, resolve bool) error {
	stage, backup, err := openCleanupArtifacts(record)
	if err != nil {
		return err
	}
	if stage != nil {
		defer stage.Close()
	}
	if backup != nil {
		defer backup.Close()
	}
	if record.StageRemoved && stage != nil && stage.File != nil {
		return ErrUnsafeState
	}
	if record.BackupRemoved && backup != nil && backup.File != nil {
		return ErrUnsafeState
	}
	if record.StageIdentity == "" && stage != nil && stage.File != nil {
		result, attachErr := s.database().ExecContext(ctx, `update put_transfers set stage_identity=?,updated_at=? where direction='receive' and transfer_id=? and state='cleanup_not_attempted' and stage_identity is null and lease_token=?`, stage.Identity, time.Now().Unix(), record.ID, lease)
		if attachErr := one(result, attachErr); attachErr != nil {
			return attachErr
		}
		record.StageIdentity = stage.Identity
	}
	if !record.StageRemoved {
		if stage != nil {
			absent, removeErr := stage.RemoveEntry()
			if removeErr != nil || !absent {
				return removeErr
			}
		}
		if err := s.runFault("after_stage_unlink"); err != nil {
			return err
		}
		result, markErr := s.database().ExecContext(ctx, `update put_transfers set stage_removed=1,updated_at=? where direction='receive' and transfer_id=? and state=? and stage_name=? and lease_token=?`, time.Now().Unix(), record.ID, record.State, record.StageName, lease)
		if markErr := one(result, markErr); markErr != nil {
			return markErr
		}
		record.StageRemoved = true
	}
	if err := s.runFault("after_stage_removed_record"); err != nil {
		return err
	}
	if record.BackupName != "" && !record.BackupRemoved {
		if backup != nil {
			absent, removeErr := backup.RemoveEntry()
			if removeErr != nil || !absent {
				return removeErr
			}
		}
		if err := s.runFault("after_backup_unlink"); err != nil {
			return err
		}
		result, markErr := s.database().ExecContext(ctx, `update put_transfers set backup_removed=1,updated_at=? where direction='receive' and transfer_id=? and state=? and backup_name=? and lease_token=?`, time.Now().Unix(), record.ID, record.State, record.BackupName, lease)
		if markErr := one(result, markErr); markErr != nil {
			return markErr
		}
		record.BackupRemoved = true
	}
	if record.BackupName != "" {
		if err := s.runFault("after_backup_removed_record"); err != nil {
			return err
		}
	}
	if !record.ParentSynced {
		if err := s.runFault("before_parent_sync"); err != nil {
			return err
		}
		syncArtifact := stage
		if syncArtifact == nil {
			syncArtifact = backup
		}
		if syncArtifact == nil {
			return ErrUnsafeState
		}
		if err := syncArtifact.SyncParent(); err != nil {
			return err
		}
		if err := s.runFault("after_parent_fsync"); err != nil {
			return err
		}
		result, syncErr := s.database().ExecContext(ctx, `update put_transfers set parent_synced=1,updated_at=? where direction='receive' and transfer_id=? and state=? and stage_removed=1 and (backup_name is null or backup_removed=1) and lease_token=?`, time.Now().Unix(), record.ID, record.State, lease)
		if syncErr := one(result, syncErr); syncErr != nil {
			return syncErr
		}
	}
	if err := s.runFault("after_parent_sync"); err != nil {
		return err
	}
	if deleteRow {
		result, deleteErr := s.database().ExecContext(ctx, `delete from put_transfers where direction='receive' and transfer_id=? and state='cleanup_not_attempted' and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1 and lease_token=?`, record.ID, lease)
		return one(result, deleteErr)
	}
	if resolve {
		current, exists, err := s.Load(ctx, "receive", record.ID)
		if err != nil || !exists {
			return errors.Join(err, ErrNotFound)
		}
		if err := validateAcceptCurrent(current); err != nil {
			return errors.Join(ErrResolutionUnsafe, err)
		}
		tx, err := s.database().BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `update put_transfers set state='resolved_accept_current',parent_path=null,parent_identity=null,stage_name=null,stage_identity=null,old_metadata=null,backup_name=null,backup_identity=null,backup_size=0,stage_removed=0,backup_removed=0,parent_synced=0,resolved_at=?,updated_at=? where direction='receive' and transfer_id=? and state='accept_current_intent' and resolution_destination_identity=? and stage_removed=1 and (backup_name is null or backup_removed=1) and parent_synced=1 and lease_token=?`, time.Now().UTC().Unix(), time.Now().UTC().Unix(), current.ID, current.ResolutionDestinationIdentity, lease)
		if err := one(result, err); err != nil {
			_ = tx.Rollback()
			return err
		}
		return tx.Commit()
	}
	return s.ClearStage(ctx, record.ID, lease)
}

func one(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) HasBlocking(ctx context.Context, contextName string) (bool, error) {
	if err := s.ExpireSettled(ctx, time.Now().UTC()); err != nil {
		return false, err
	}
	var count int
	err := s.database().QueryRowContext(ctx, `select count(*) from put_transfers where context_name=? and ((direction='receive' and state!='resolved_accept_current') or (direction='send' and state!='committed'))`, contextName).Scan(&count)
	return count != 0, err
}

func (s *Store) Abandon(ctx context.Context, contextName, id string) (Record, error) {
	rows, err := s.database().QueryContext(ctx, `select direction from put_transfers where context_name=? and transfer_id=? order by direction`, contextName, id)
	if err != nil {
		return Record{}, err
	}
	var directions []string
	for rows.Next() {
		var direction string
		if err := rows.Scan(&direction); err != nil {
			rows.Close()
			return Record{}, err
		}
		directions = append(directions, direction)
	}
	if err := rows.Close(); err != nil {
		return Record{}, err
	}
	if len(directions) == 0 {
		return Record{}, ErrNotFound
	}
	if len(directions) != 1 {
		return Record{}, ErrAmbiguous
	}
	if directions[0] == "send" {
		record, exists, loadErr := s.Load(ctx, "send", id)
		if loadErr != nil {
			return Record{}, loadErr
		}
		if !exists || record.Context != contextName {
			return Record{}, ErrNotFound
		}
		if record.State != "transferring" {
			return Record{}, ErrNotAbandonable
		}
		lease, err := s.ClaimSender(ctx, contextName, id)
		if err != nil {
			return Record{}, err
		}
		defer lease.Release()
		record = lease.Record()
		if err := runSettlement(func(settleCtx context.Context) error { return s.DeleteSenderWithLease(settleCtx, lease) }); err != nil {
			return Record{}, err
		}
		return record, nil
	}
	record, exists, err := s.Load(ctx, "receive", id)
	if err != nil {
		return Record{}, err
	}
	if !exists || record.Context != contextName {
		return Record{}, ErrNotFound
	}
	if record.State != "stage_intent" && record.State != "transferring" && record.State != "cleanup_not_attempted" {
		return Record{}, ErrNotAbandonable
	}
	lease, err := s.ClaimReceiver(ctx, id)
	if err != nil {
		return Record{}, err
	}
	defer s.ReleaseReceiver(id, lease)
	record, exists, err = s.Load(ctx, "receive", id)
	if err != nil {
		return Record{}, err
	}
	if !exists || record.Context != contextName {
		return Record{}, ErrNotFound
	}
	var cleanupErr error
	if record.State == "cleanup_not_attempted" {
		cleanupErr = runSettlement(func(settleCtx context.Context) error { return s.CleanupNotAttempted(settleCtx, record, lease) })
	} else {
		cleanupErr = runSettlement(func(settleCtx context.Context) error { return s.AbortPrepublication(settleCtx, record, lease) })
	}
	if cleanupErr != nil {
		return Record{}, cleanupErr
	}
	return record, nil
}

func (s *Store) Inventory(ctx context.Context, contextName string, limit int) ([]Record, error) {
	if err := s.ExpireSettled(ctx, time.Now().UTC()); err != nil {
		return nil, err
	}
	rows, err := s.database().QueryContext(ctx, `select direction,transfer_id from put_transfers where context_name=? order by updated_at desc,direction,transfer_id limit ?`, contextName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct{ direction, id string }
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.direction, &k.id); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]Record, 0, len(keys))
	for _, k := range keys {
		r, ok, err := s.Load(ctx, k.direction, k.id)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *Store) CompletionIDs(ctx context.Context, contextName, action, peer, prefix string, limit int) ([]string, error) {
	if action != "show" && action != "retry" && action != "resolve" {
		return nil, nil
	}
	now := time.Now().UTC()
	if err := s.ExpireSettled(ctx, now); err != nil {
		return nil, err
	}
	lower, upper := prefix, prefix+"\x7f"
	query := `select transfer_id from put_transfers where context_name=? and transfer_id>=? and transfer_id<?`
	args := []any{contextName, lower, upper}
	if action == "retry" {
		query += ` and direction='send' and state='transferring' and expires_at>? and lease_token is null`
		args = append(args, now.Unix())
	} else if action == "resolve" {
		query += ` and direction='receive' and state in ('outcome_unknown','accept_current_intent') and lease_token is null`
	}
	if peer != "" {
		query += ` and lower(peer_label)=lower(?)`
		args = append(args, strings.TrimPrefix(peer, "@"))
	}
	query += ` order by transfer_id limit ?`
	args = append(args, limit)
	rows, err := s.database().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) Counts(ctx context.Context, contextName string) (active, retryable int, err error) {
	now := time.Now().UTC()
	if err := s.ExpireSettled(ctx, now); err != nil {
		return 0, 0, err
	}
	err = s.database().QueryRowContext(ctx, `select
		coalesce(sum(case when direction='receive' and lease_token is not null then 1 else 0 end),0),
		coalesce(sum(case when direction='send' and state='transferring' and expires_at>? and lease_token is null then 1 else 0 end),0)
		from put_transfers where context_name=?`, now.Unix(), contextName).Scan(&active, &retryable)
	return active, retryable, err
}

func (s *Store) Show(ctx context.Context, contextName, id string) (Record, error) {
	if err := s.ExpireSettled(ctx, time.Now().UTC()); err != nil {
		return Record{}, err
	}
	var found []Record
	for _, direction := range []string{"send", "receive"} {
		record, exists, err := s.Load(ctx, direction, id)
		if err != nil {
			return Record{}, err
		}
		if exists && record.Context == contextName {
			found = append(found, record)
		}
	}
	if len(found) == 0 {
		return Record{}, ErrNotFound
	}
	if len(found) > 1 {
		return Record{}, ErrAmbiguous
	}
	return found[0], nil
}

func (s *Store) reapPublicationIntent(ctx context.Context, record Record, lease string) (bool, error) {
	result, settled, reconcileErr := reconcilePublication(record)
	if errors.Is(reconcileErr, errPublishNotAttempted) {
		return s.AbortPublicationNotAttempted(ctx, record, lease) == nil, nil
	}
	if reconcileErr != nil || !settled {
		if err := s.MarkUnknown(ctx, record.ID, lease); err != nil {
			return false, errors.Join(reconcileErr, err)
		}
		return false, nil
	}
	if err := s.CommitReceiver(ctx, record.ID, lease, result.Durability()); err != nil {
		return false, err
	}
	record.State = "committed"
	record.Durability = result.Durability()
	if err := s.CleanupCommitted(ctx, record, lease); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ReapParent(ctx context.Context, parentPath, parentID, currentID string) error {
	now := time.Now().UTC()
	rows, err := s.database().QueryContext(ctx, `select transfer_id from put_transfers where direction='receive' and parent_path=? and parent_identity=? and transfer_id!=? and next_retry_at<=? and lease_token is null and (state in ('cleanup_not_attempted','publication_intent','outcome_unknown') or (expires_at<=? and state in ('stage_intent','transferring')) or (state='committed' and (stage_name is not null or backup_name is not null))) order by next_retry_at,created_at,transfer_id limit 8`, parentPath, parentID, currentID, now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		lease, err := randomID(32)
		if err != nil {
			return err
		}
		claim, err := s.database().ExecContext(ctx, `update put_transfers set lease_token=?,lease_expires_at=? where direction='receive' and transfer_id=? and lease_token is null`, lease, now.Add(Lifetime).Unix(), id)
		if err != nil {
			return err
		}
		claimed, _ := claim.RowsAffected()
		if claimed != 1 {
			continue
		}
		record, exists, err := s.Load(ctx, "receive", id)
		if err != nil {
			s.ReleaseReceiver(id, lease)
			return err
		}
		if !exists {
			s.ReleaseReceiver(id, lease)
			continue
		}
		removed := false
		if record.State == "committed" && (record.StageName != "" || record.BackupName != "") {
			removed = runSettlement(func(settleCtx context.Context) error { return s.CleanupCommitted(settleCtx, record, lease) }) == nil
		} else if record.State == "publication_intent" {
			_ = runSettlement(func(settleCtx context.Context) error {
				settled, settleErr := s.reapPublicationIntent(settleCtx, record, lease)
				removed = settled && settleErr == nil
				return settleErr
			})
		} else if record.State == "outcome_unknown" {
			_ = runSettlement(func(settleCtx context.Context) error {
				result, settled, reconcileErr := reconcilePublication(record)
				if reconcileErr == nil && settled {
					if err := s.CommitReceiver(settleCtx, record.ID, lease, result.Durability()); err != nil {
						return err
					}
					record.State = "committed"
					if err := s.CleanupCommitted(settleCtx, record, lease); err != nil {
						return err
					}
					removed = true
					return nil
				}
				if errors.Is(reconcileErr, errPublishNotAttempted) {
					if err := s.BeginCleanupNotAttempted(settleCtx, record.ID, lease); err != nil {
						return err
					}
					record.State = "cleanup_not_attempted"
					if err := s.CleanupNotAttempted(settleCtx, record, lease); err != nil {
						return err
					}
					removed = true
				}
				return nil
			})
		} else if record.State == "cleanup_not_attempted" {
			removed = runSettlement(func(settleCtx context.Context) error { return s.CleanupNotAttempted(settleCtx, record, lease) }) == nil
		} else if record.State == "stage_intent" || record.State == "transferring" {
			removed = runSettlement(func(settleCtx context.Context) error { return s.AbortPrepublication(settleCtx, record, lease) }) == nil
		}
		if removed {
			_ = runSettlement(func(settleCtx context.Context) error {
				_, releaseErr := s.database().ExecContext(settleCtx, `update put_transfers set lease_token=null,lease_expires_at=null where direction='receive' and transfer_id=? and lease_token=?`, id, lease)
				return releaseErr
			})
		} else {
			interval := 24 * time.Hour
			if now.Before(record.ExpiresAt) {
				interval = time.Hour
			}
			err = runSettlement(func(settleCtx context.Context) error {
				_, retryErr := s.database().ExecContext(settleCtx, `update put_transfers set next_retry_at=?,updated_at=?,lease_token=null,lease_expires_at=null where direction='receive' and transfer_id=? and lease_token=?`, now.Add(interval).Unix(), now.Unix(), id, lease)
				return retryErr
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
