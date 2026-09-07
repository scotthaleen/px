package inviteapi

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/scotthaleen/px/internal/identity"
	"github.com/scotthaleen/px/internal/membership"
)

const Version = 1

type CreateRequest struct {
	Version         int    `json:"version"`
	Label           string `json:"label"`
	LifetimeSeconds int64  `json:"lifetime_seconds"`
}

type Invite struct {
	InviteID       string `json:"invite_id"`
	Label          string `json:"label"`
	IssuerType     string `json:"issuer_type"`
	IssuerDeviceID string `json:"issuer_device_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
}

type Creation struct {
	Version int `json:"version"`
	Invite
	Token string `json:"token"`
}

type List struct {
	Version int      `json:"version"`
	Invites []Invite `json:"invites"`
}

type Revocation struct {
	Version int    `json:"version"`
	State   string `json:"state"`
	Invite  Invite `json:"invite"`
}

type ControlCreateRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	CreateRequest
}

type ControlListRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Version   int    `json:"version"`
}

type ControlRevokeRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Version   int    `json:"version"`
	InviteID  string `json:"invite_id"`
}

type ControlCreation struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Creation
}

type ControlList struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	List
}

type ControlRevocation struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Revocation
}

type ControlError struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Version   int    `json:"version"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

func FromMembership(invite membership.Invite) Invite {
	return Invite{
		InviteID: invite.InviteID, Label: invite.Label, IssuerType: invite.IssuerType, IssuerDeviceID: invite.IssuerDeviceID,
		CreatedAt: invite.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		ExpiresAt: invite.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
}

func CreationFromMembership(created membership.InviteCreation) Creation {
	return Creation{Version: Version, Invite: FromMembership(created.Invite), Token: created.Token}
}

func Validate(invite Invite) error {
	if err := membership.ValidateInviteID(invite.InviteID); err != nil {
		return err
	}
	if err := membership.ValidateLabel(invite.Label); err != nil {
		return err
	}
	if invite.IssuerType == "local" {
		if invite.IssuerDeviceID != "" {
			return errors.New("invalid local invite issuer")
		}
	} else if invite.IssuerType == "member" {
		issuerKey, err := identity.ParseID(invite.IssuerDeviceID)
		if err != nil || identity.ID(issuerKey) != invite.IssuerDeviceID {
			return errors.New("invalid member invite issuer")
		}
	} else {
		return errors.New("invalid invite issuer")
	}
	created, err := time.Parse(time.RFC3339, invite.CreatedAt)
	if err != nil || created.Format(time.RFC3339) != invite.CreatedAt || created.Location() != time.UTC {
		return errors.New("invalid invite creation time")
	}
	expires, err := time.Parse(time.RFC3339, invite.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339) != invite.ExpiresAt || expires.Location() != time.UTC || expires.Sub(created) < membership.MinInviteLifetime || expires.Sub(created) > membership.MaxInviteLifetime {
		return errors.New("invalid invite expiry time")
	}
	return nil
}

func ValidateCreation(result Creation, serverID, label, issuerType, issuerDeviceID string, lifetime time.Duration) error {
	if result.Version != Version || result.Label != label || result.IssuerType != issuerType || result.IssuerDeviceID != issuerDeviceID || Validate(result.Invite) != nil {
		return errors.New("invalid invite creation response")
	}
	token, err := membership.ParseInviteToken(result.Token)
	if err != nil || hex.EncodeToString(token.InviteID[:]) != result.InviteID || token.ServerTag != membership.InviteServerTag(serverID) {
		return errors.New("invalid invite creation response")
	}
	created, _ := time.Parse(time.RFC3339, result.CreatedAt)
	expires, _ := time.Parse(time.RFC3339, result.ExpiresAt)
	if expires.Sub(created) != lifetime {
		return errors.New("invalid invite creation response")
	}
	return nil
}

func ValidateList(result List) error {
	if result.Version != Version || result.Invites == nil || len(result.Invites) > membership.MaxActiveInvites {
		return errors.New("invalid invite list")
	}
	for index, invite := range result.Invites {
		if Validate(invite) != nil {
			return errors.New("invalid invite list")
		}
		if index > 0 && (result.Invites[index-1].CreatedAt < invite.CreatedAt || result.Invites[index-1].CreatedAt == invite.CreatedAt && result.Invites[index-1].InviteID <= invite.InviteID) {
			return errors.New("invalid invite list")
		}
	}
	return nil
}
