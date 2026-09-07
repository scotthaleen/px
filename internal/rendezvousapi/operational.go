package rendezvousapi

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scotthaleen/px/internal/membership"
)

const (
	readinessCacheTTL     = 2 * time.Second
	readinessProbeTimeout = 250 * time.Millisecond
)

// OperationalState records only lifecycle gates shared by readiness and local
// administration. Dependency health is queried at inspection time.
type OperationalState struct {
	httpReady      atomic.Bool
	lifecycleReady atomic.Bool
}

func NewOperationalState() *OperationalState {
	return &OperationalState{}
}

func (s *OperationalState) SetHTTPReady(ready bool) {
	s.httpReady.Store(ready)
}

func (s *OperationalState) SetLifecycleReady(ready bool) {
	s.lifecycleReady.Store(ready)
}

func (s *OperationalState) HTTPReady() bool {
	return s != nil && s.httpReady.Load()
}

func (s *OperationalState) LifecycleReady() bool {
	return s != nil && s.lifecycleReady.Load()
}

type readinessProbe struct {
	mu         sync.Mutex
	check      func(context.Context, time.Time) error
	now        func() time.Time
	ttl        time.Duration
	timeout    time.Duration
	checking   bool
	validUntil time.Time
	healthy    bool
}

func newReadinessProbe(store *membership.Store) *readinessProbe {
	return &readinessProbe{
		check: func(ctx context.Context, now time.Time) error {
			_, err := store.PendingCount(ctx, now)
			return err
		},
		now: time.Now, ttl: readinessCacheTTL, timeout: readinessProbeTimeout,
	}
}

func (p *readinessProbe) ready(_ context.Context) bool {
	now := p.now()
	p.mu.Lock()
	if now.Before(p.validUntil) {
		healthy := p.healthy
		p.mu.Unlock()
		return healthy
	}
	if p.checking {
		p.mu.Unlock()
		return false
	}
	p.checking = true
	p.mu.Unlock()

	probeContext, cancel := context.WithTimeout(context.Background(), p.timeout)
	err := p.check(probeContext, now)
	cancel()

	p.mu.Lock()
	p.checking = false
	p.healthy = err == nil
	p.validUntil = p.now().Add(p.ttl)
	healthy := p.healthy
	p.mu.Unlock()
	return healthy
}
