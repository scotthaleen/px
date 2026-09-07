package rendezvousproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/scotthaleen/px/internal/membership"
)

const (
	Version               = 2
	AuthenticationVersion = 2
	MaxRequestBytes       = 8 << 10
	MaxControlBytes       = 64 << 10
	MaxSignalBytes        = 60 << 10
	AuthenticationLimit   = 10 * time.Second
)

type EnrollmentRequest struct {
	DeviceKey string `json:"device_key"`
	Label     string `json:"label"`
}

type InviteRedemptionRequest struct {
	Version   int    `json:"version"`
	Token     string `json:"token"`
	DeviceKey string `json:"device_key"`
	Label     string `json:"label"`
}

type InviteRedemption struct {
	Version    int                   `json:"version"`
	State      string                `json:"state"`
	Credential membership.Credential `json:"credential"`
}

type Enrollment struct {
	State      string                 `json:"state"`
	Code       string                 `json:"code,omitempty"`
	ExpiresAt  time.Time              `json:"expires_at,omitempty"`
	Credential *membership.Credential `json:"credential,omitempty"`
}

type ServerInfo struct {
	Version               int    `json:"version"`
	AuthenticationVersion int    `json:"authentication_version,omitempty"`
	ControlVersion        int    `json:"control_version,omitempty"`
	InviteVersion         int    `json:"invite_version,omitempty"`
	ServerID              string `json:"server_id"`
	Authority             string `json:"authority"`
}

type ProtocolMismatch struct {
	Boundary string
	Expected int
	Actual   int
	Remote   string
}

func (e *ProtocolMismatch) Error() string {
	target := "px-server"
	if e.Actual > e.Expected {
		target = "the PX agent/CLI"
	}
	return fmt.Sprintf("rendezvous %s protocol mismatch: expected %d, %s reported %d; upgrade %s", e.Boundary, e.Expected, e.Remote, e.Actual, target)
}

type ControlMessage struct {
	Version             int                  `json:"version,omitempty"`
	Type                string               `json:"type"`
	RequestID           string               `json:"request_id,omitempty"`
	To                  string               `json:"to,omitempty"`
	From                string               `json:"from,omitempty"`
	DeviceID            string               `json:"device_id,omitempty"`
	Code                string               `json:"code,omitempty"`
	Payload             json.RawMessage      `json:"payload,omitempty"`
	Member              *membership.Member   `json:"member,omitempty"`
	Members             []membership.Member  `json:"members,omitempty"`
	Pending             []membership.Pending `json:"pending,omitempty"`
	AuthenticationProof *AuthenticatedProof  `json:"authentication_proof,omitempty"`
	Error               string               `json:"error,omitempty"`
}

type PingControl struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

var requestIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidateRequestID(value string) error {
	if !requestIDPattern.MatchString(value) {
		return errors.New("invalid request ID")
	}
	return nil
}
