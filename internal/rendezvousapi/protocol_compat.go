package rendezvousapi

import (
	"crypto/ed25519"
	"time"

	"github.com/scotthaleen/px/internal/rendezvousproto"
)

const (
	Version               = rendezvousproto.Version
	AuthenticationVersion = rendezvousproto.AuthenticationVersion
	MaxRequestBytes       = rendezvousproto.MaxRequestBytes
	MaxControlBytes       = rendezvousproto.MaxControlBytes
	MaxSignalBytes        = rendezvousproto.MaxSignalBytes
	authenticationLimit   = rendezvousproto.AuthenticationLimit
)

type (
	EnrollmentRequest       = rendezvousproto.EnrollmentRequest
	InviteRedemptionRequest = rendezvousproto.InviteRedemptionRequest
	InviteRedemption        = rendezvousproto.InviteRedemption
	ServerInfo              = rendezvousproto.ServerInfo
	Challenge               = rendezvousproto.Challenge
	Authentication          = rendezvousproto.Authentication
	AuthenticatedProof      = rendezvousproto.AuthenticatedProof
	wireMessage             = rendezvousproto.ControlMessage
)

func ValidateRequestID(value string) error {
	return rendezvousproto.ValidateRequestID(value)
}

func SignChallenge(privateKey ed25519.PrivateKey, challenge Challenge) (string, error) {
	return rendezvousproto.SignChallenge(privateKey, challenge)
}

func VerifyServerChallenge(challenge Challenge, expectedServerID string, now time.Time) error {
	return rendezvousproto.VerifyServerChallenge(challenge, expectedServerID, now)
}

func VerifyAuthenticatedProof(challenge Challenge, proof AuthenticatedProof, expectedServerID, expectedDeviceID, expectedDeviceKey string, expectedRevision int64, deviceSignature string) error {
	return rendezvousproto.VerifyAuthenticatedProof(challenge, proof, expectedServerID, expectedDeviceID, expectedDeviceKey, expectedRevision, deviceSignature)
}
