package contexts

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/coder/websocket"
)

const (
	defaultKeepaliveInterval = 30 * time.Second
	defaultKeepaliveJitter   = 3 * time.Second
	defaultPongTimeout       = 10 * time.Second
	defaultBackoffMinimum    = time.Second
	defaultBackoffMaximum    = 30 * time.Second
	defaultBackoffJitter     = 500 * time.Millisecond
)

type connectionPolicy struct {
	keepaliveInterval time.Duration
	keepaliveJitter   time.Duration
	pongTimeout       time.Duration
	backoffMinimum    time.Duration
	backoffMaximum    time.Duration
	backoffJitter     time.Duration
	random            func() uint64
}

func defaultConnectionPolicy() connectionPolicy {
	return connectionPolicy{
		keepaliveInterval: defaultKeepaliveInterval,
		keepaliveJitter:   defaultKeepaliveJitter,
		pongTimeout:       defaultPongTimeout,
		backoffMinimum:    defaultBackoffMinimum,
		backoffMaximum:    defaultBackoffMaximum,
		backoffJitter:     defaultBackoffJitter,
		random:            rand.Uint64,
	}
}

func (p connectionPolicy) nextKeepalive() time.Duration {
	return jitter(p.keepaliveInterval, p.keepaliveJitter, p.sample())
}

func (p connectionPolicy) reconnectDelay(failures int) time.Duration {
	delay := p.backoffMinimum
	for count := 1; count < failures && delay < p.backoffMaximum; count++ {
		if delay > p.backoffMaximum/2 {
			delay = p.backoffMaximum
			break
		}
		delay *= 2
	}
	if delay > p.backoffMaximum {
		delay = p.backoffMaximum
	}
	delay = jitter(delay, min(p.backoffJitter, delay/2), p.sample())
	if delay > p.backoffMaximum {
		return p.backoffMaximum
	}
	return delay
}

func (p connectionPolicy) sample() uint64 {
	if p.random == nil {
		return 0
	}
	return p.random()
}

func jitter(base, spread time.Duration, sample uint64) time.Duration {
	if base <= 0 || spread <= 0 {
		return base
	}
	width := uint64(spread)*2 + 1
	offset := time.Duration(sample%width) - spread
	return base + offset
}

type keepaliveResult struct {
	healthy bool
	err     error
}

func runKeepalive(ctx context.Context, conn *websocket.Conn, writes *contextWriteGate, policy connectionPolicy) keepaliveResult {
	timer := time.NewTimer(policy.nextKeepalive())
	defer timer.Stop()
	result := keepaliveResult{}
	for {
		select {
		case <-ctx.Done():
			return result
		case <-timer.C:
			pingContext, cancelPing := context.WithTimeout(ctx, policy.pongTimeout)
			_, err := writes.run(pingContext, func() error { return conn.Ping(pingContext) })
			cancelPing()
			if err != nil {
				if ctx.Err() != nil {
					return result
				}
				result.err = err
				return result
			}
			result.healthy = true
			timer.Reset(policy.nextKeepalive())
		}
	}
}
