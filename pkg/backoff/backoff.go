// Package backoff is the one retry policy in NKNGuard.
//
// It exists as a package rather than a helper in each caller so that every
// retry in the program is jittered. A mesh whose nodes all lost the network at
// the same moment will try to come back at the same moment, and without jitter
// that is a self-inflicted denial of service against whatever they are
// reconnecting to.
package backoff

import (
	"context"
	"math/rand/v2"
	"time"
)

// Defaults for a control-plane reconnect.
const (
	DefaultInitial = 1 * time.Second
	DefaultMax     = 30 * time.Second
	DefaultFactor  = 2.0
	// DefaultJitter is the fraction of the delay that is randomised, so a
	// delay of d is drawn from [d*(1-j), d*(1+j)].
	DefaultJitter = 0.25
)

// Policy describes a retry schedule.
type Policy struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
	Jitter  float64
	// MaxAttempts bounds the sequence. Zero means unbounded, which is correct
	// for a supervisor loop that should keep trying forever, and wrong for
	// anything with a caller waiting on it.
	MaxAttempts int
}

// Default returns the standard control-plane policy.
func Default() Policy {
	return Policy{Initial: DefaultInitial, Max: DefaultMax, Factor: DefaultFactor, Jitter: DefaultJitter}
}

func (p Policy) normalised() Policy {
	if p.Initial <= 0 {
		p.Initial = DefaultInitial
	}
	if p.Max <= 0 {
		p.Max = DefaultMax
	}
	if p.Factor < 1 {
		p.Factor = DefaultFactor
	}
	if p.Jitter < 0 || p.Jitter > 1 {
		p.Jitter = DefaultJitter
	}
	return p
}

// Delay returns the wait before attempt n, counting from zero. The result is
// jittered, so two calls with the same n differ.
func (p Policy) Delay(attempt int) time.Duration {
	p = p.normalised()
	delay := float64(p.Initial)
	for i := 0; i < attempt; i++ {
		delay *= p.Factor
		if delay >= float64(p.Max) {
			delay = float64(p.Max)
			break
		}
	}
	if p.Jitter > 0 {
		spread := delay * p.Jitter
		delay = delay - spread + 2*spread*rand.Float64()
	}
	if delay < 0 {
		delay = 0
	}
	return time.Duration(delay)
}

// Retry runs work until it succeeds, the policy is exhausted, or ctx is done.
// It never sleeps past ctx: a cancelled context returns immediately, which is
// what makes `nknguard down` prompt instead of waiting out a thirty-second
// backoff.
func Retry(ctx context.Context, policy Policy, work func(ctx context.Context) error) error {
	policy = policy.normalised()
	var lastErr error
	for attempt := 0; policy.MaxAttempts == 0 || attempt < policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}
		if err := work(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(policy.Delay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastErr
		case <-timer.C:
		}
	}
	return lastErr
}
