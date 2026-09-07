package securefile

import "errors"

var (
	ErrProtectionOwner    = errors.New("protected path has an untrusted owner")
	ErrProtectionACL      = errors.New("protected path has an unsafe or unsupported ACL")
	ErrProtectionReparse  = errors.New("protected path contains a reparse or symbolic link")
	ErrProtectionIdentity = errors.New("protected path identity is unavailable or changed")
)
