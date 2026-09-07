package recent

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/transfer"
)

const (
	Version          = 1
	DefaultLimit     = 32
	MaxLimit         = 64
	MaxPerContext    = 64
	MaxPerAgent      = 4096
	AgeEligibility   = 30 * 24 * time.Hour
	Protocol         = "px-recent-v1"
	SessionPrefix    = "px-recent-"
	ChannelLabel     = "px-recent"
	MaxMessageBytes  = 64 << 10
	MessageQueue     = 1
	MaxBufferedBytes = 64 << 10
	Description      = "endpoint observations; not receipts or global settlement"
	InboundDeadline  = 20 * time.Second
)

var (
	ErrCorrupt         = errors.New("recent observation journal is corrupt")
	ErrProtocolTimeout = errors.New("recent request timed out")
)

type Observation struct {
	Sequence     int64     `json:"sequence,omitempty"`
	Context      string    `json:"context,omitempty"`
	Direction    string    `json:"direction"`
	TransferID   string    `json:"transfer_id"`
	Kind         string    `json:"kind"`
	PeerDeviceID string    `json:"peer_device_id"`
	PeerLabel    string    `json:"peer_label"`
	Destination  string    `json:"destination"`
	Visibility   string    `json:"visibility"`
	Bytes        int64     `json:"bytes"`
	ObservedAt   time.Time `json:"observed_at"`
}

type Reporter struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
	Context  string `json:"context,omitempty"`
}

type Snapshot struct {
	Version      int           `json:"version"`
	Description  string        `json:"description"`
	Reporter     Reporter      `json:"reporter"`
	Observations []Observation `json:"observations"`
}

type ClearResult struct {
	Version     int      `json:"version"`
	Description string   `json:"description"`
	Reporter    Reporter `json:"reporter"`
	Cleared     int64    `json:"cleared"`
}

type Store struct{ database func() *sql.DB }

func NewStore(database func() *sql.DB) *Store { return &Store{database: database} }

func (s *Store) Insert(ctx context.Context, observation Observation) error {
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.InsertTx(ctx, tx, observation); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) InsertTx(ctx context.Context, tx *sql.Tx, observation Observation) error {
	if err := ValidateObservation(observation, true); err != nil {
		return err
	}
	var existing Observation
	var observed int64
	err := tx.QueryRowContext(ctx, `select sequence,context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at from recent_observations where context_name=? and direction=? and transfer_id=?`, observation.Context, observation.Direction, observation.TransferID).Scan(&existing.Sequence, &existing.Context, &existing.Direction, &existing.TransferID, &existing.Kind, &existing.PeerDeviceID, &existing.PeerLabel, &existing.Destination, &existing.Visibility, &existing.Bytes, &observed)
	if err == nil {
		existing.ObservedAt = time.Unix(observed, 0).UTC()
		if !sameMetadata(existing, observation) || ValidateObservation(existing, true) != nil {
			return ErrCorrupt
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	cutoff := observation.ObservedAt.Add(-AgeEligibility).Unix()
	if _, err := tx.ExecContext(ctx, `delete from recent_observations where observed_at<=?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `insert into recent_observations(context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at) values(?,?,?,?,?,?,?,?,?,?)`, observation.Context, observation.Direction, observation.TransferID, observation.Kind, observation.PeerDeviceID, observation.PeerLabel, observation.Destination, observation.Visibility, observation.Bytes, observation.ObservedAt.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `delete from recent_observations where sequence in (select sequence from recent_observations where context_name=? order by observed_at desc,sequence desc limit -1 offset ?)`, observation.Context, MaxPerContext); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `delete from recent_observations where sequence in (select sequence from recent_observations order by observed_at desc,sequence desc limit -1 offset ?)`, MaxPerAgent)
	return err
}

func (s *Store) List(ctx context.Context, contextName, peerDeviceID string, limit int) ([]Observation, error) {
	if contextName == "" || limit <= 0 || limit > MaxLimit {
		return nil, errors.New("invalid recent observation query")
	}
	query := `select sequence,context_name,direction,transfer_id,kind,peer_device_id,peer_label,destination_name,visibility,bytes,observed_at from recent_observations where context_name=?`
	args := []any{contextName}
	if peerDeviceID != "" {
		query += ` and peer_device_id=?`
		args = append(args, peerDeviceID)
	}
	query += ` order by observed_at desc,sequence desc limit ?`
	args = append(args, limit)
	rows, err := s.database().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]Observation, 0, limit)
	for rows.Next() {
		var value Observation
		var observed int64
		if err := rows.Scan(&value.Sequence, &value.Context, &value.Direction, &value.TransferID, &value.Kind, &value.PeerDeviceID, &value.PeerLabel, &value.Destination, &value.Visibility, &value.Bytes, &observed); err != nil {
			return nil, err
		}
		value.ObservedAt = time.Unix(observed, 0).UTC()
		if err := ValidateObservation(value, true); err != nil {
			return nil, ErrCorrupt
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) Clear(ctx context.Context, contextName string) (int64, error) {
	if contextName == "" {
		return 0, errors.New("recent observation context is required")
	}
	result, err := s.database().ExecContext(ctx, `delete from recent_observations where context_name=?`, contextName)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func ValidateObservation(value Observation, requireContext bool) error {
	if requireContext && membership.ValidateLabel(value.Context) != nil || value.Sequence < 0 || !validTransferID(value.TransferID) || identityIDInvalid(value.PeerDeviceID) || membership.ValidateLabel(value.PeerLabel) != nil || transfer.ValidatePortableName(value.Destination) != nil || value.Bytes < 0 || value.Bytes > 1<<30 || value.ObservedAt.IsZero() || value.ObservedAt.Location() != time.UTC {
		return ErrCorrupt
	}
	if value.Direction == "send" && value.Kind != "sender_observed_commit" || value.Direction == "receive" && value.Kind != "receiver_published" || value.Direction != "send" && value.Direction != "receive" || value.Visibility != "private" && value.Visibility != "public" {
		return ErrCorrupt
	}
	return nil
}

func ValidateSnapshot(value Snapshot, remote bool) error {
	if value.Version != Version || value.Description != Description || identityIDInvalid(value.Reporter.DeviceID) || membership.ValidateLabel(value.Reporter.Label) != nil || remote && value.Reporter.Context != "" || !remote && membership.ValidateLabel(value.Reporter.Context) != nil || len(value.Observations) > MaxLimit {
		return ErrCorrupt
	}
	for _, observation := range value.Observations {
		if remote && (observation.Context != "" || observation.Sequence != 0) || ValidateObservation(observation, !remote) != nil {
			return ErrCorrupt
		}
	}
	return nil
}

func identityIDInvalid(value string) bool {
	_, err := identity.ParseID(value)
	return err != nil
}

func sameMetadata(a, b Observation) bool {
	return a.Context == b.Context && a.Direction == b.Direction && a.TransferID == b.TransferID && a.Kind == b.Kind && a.PeerDeviceID == b.PeerDeviceID && a.PeerLabel == b.PeerLabel && a.Destination == b.Destination && a.Visibility == b.Visibility && a.Bytes == b.Bytes
}

func validTransferID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func LimitError(limit int) error {
	return fmt.Errorf("recent limit %d is outside 1 through %d", limit, MaxLimit)
}
