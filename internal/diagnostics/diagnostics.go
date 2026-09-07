package diagnostics

import (
	"slices"
	"time"
)

const Version = 4

const (
	Pass    = "pass"
	Warn    = "warn"
	Fail    = "fail"
	Skipped = "skipped"
)

type Check struct {
	ID                  string        `json:"id"`
	Layer               string        `json:"layer"`
	Context             string        `json:"context,omitempty"`
	Peer                string        `json:"peer,omitempty"`
	Status              string        `json:"status"`
	Summary             string        `json:"summary"`
	SetupDuration       time.Duration `json:"setup_duration_ns,omitempty"`
	HeartbeatRTT        time.Duration `json:"heartbeat_rtt_ns,omitempty"`
	LocalCandidateType  string        `json:"local_candidate_type,omitempty"`
	RemoteCandidateType string        `json:"remote_candidate_type,omitempty"`
	LocalAddress        string        `json:"local_address,omitempty"`
	RemoteAddress       string        `json:"remote_address,omitempty"`
	GatheredTypes       []string      `json:"gathered_candidate_types,omitempty"`
	RelayUsed           *bool         `json:"relay_used,omitempty"`
}

type Report struct {
	Version int     `json:"version"`
	Status  string  `json:"status"`
	Checks  []Check `json:"checks"`
}

func New(checks []Check) Report {
	result := Report{Version: Version, Status: Pass, Checks: checks}
	for _, check := range checks {
		switch check.Status {
		case Fail:
			result.Status = Fail
			return result
		case Warn:
			result.Status = Warn
		}
	}
	return result
}

func Sort(checks []Check) {
	slices.SortFunc(checks, func(a, b Check) int {
		if a.Layer != b.Layer {
			return layerRank(a.Layer) - layerRank(b.Layer)
		}
		if a.Context != b.Context {
			return compare(a.Context, b.Context)
		}
		if a.Peer != b.Peer {
			return compare(a.Peer, b.Peer)
		}
		return compare(a.ID, b.ID)
	})
}

func layerRank(layer string) int {
	switch layer {
	case "local":
		return 0
	case "context":
		return 1
	case "peer":
		return 2
	default:
		return 3
	}
}

func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
