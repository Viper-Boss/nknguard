package mesh

import "time"

// PathType is which data plane is carrying a peer.
type PathType string

const (
	PathNone     PathType = "none"
	PathDirectWG PathType = "direct-wg"
	PathNKNRelay PathType = "nkn-relay"
)

// Selector decides between a direct tunnel and a relay, and — more
// importantly — decides when NOT to change its mind.
//
// The failure this exists to prevent is flapping. A marginal direct path that
// works for ten seconds and dies for ten will, without hysteresis, produce a
// peer that alternates between paths forever, tearing down sessions on every
// switch. So: leaving direct requires the path to have been bad for
// DirectLossGrace, and returning to direct requires it to have been good for
// DirectRecoveryHold. Both are held state, not instantaneous checks.
type Selector struct {
	// DirectLossGrace is how long a direct path may be observed unhealthy
	// before we give up on it. The observation itself already tolerates a
	// lost keepalive (Timing.ReceiveTimeout), so this only has to absorb a
	// reconcile tick or two of jitter.
	DirectLossGrace time.Duration
	// DirectRecoveryHold is how long a recovered direct path must stay healthy
	// before traffic moves back onto it.
	DirectRecoveryHold time.Duration
	// DirectRetryInterval is the first wait between direct attempts for a
	// peer that is not on a direct path. It doubles after every failed
	// attempt up to DirectRetryMax, because with kernel WireGuard an attempt
	// briefly moves the peer's endpoint off the relay, and doing that every
	// thirty seconds forever would make the relay itself unreliable.
	DirectRetryInterval time.Duration
	DirectRetryMax      time.Duration

	current       PathType
	directGoodAt  time.Time
	directBadAt   time.Time
	lastDirectTry time.Time
	failures      int
}

// DefaultSelector returns the tuned defaults.
func DefaultSelector() *Selector {
	return &Selector{
		DirectLossGrace:     10 * time.Second,
		DirectRecoveryHold:  5 * time.Second,
		DirectRetryInterval: 30 * time.Second,
		DirectRetryMax:      10 * time.Minute,
		current:             PathNone,
	}
}

// Observation is what the controller knows right now.
type Observation struct {
	Now time.Time
	// DirectHealthy means a WireGuard handshake over a direct endpoint is
	// inside its freshness window. It is an observation of the data plane, not
	// a belief derived from the control plane.
	DirectHealthy bool
	// RelayOpen means a relayed session exists and is usable.
	RelayOpen bool
}

// Current is the path in use.
func (s *Selector) Current() PathType { return s.current }

// Select folds one observation into the decision and returns the path traffic
// should be on.
func (s *Selector) Select(observation Observation) PathType {
	now := observation.Now
	if observation.DirectHealthy {
		if s.directGoodAt.IsZero() {
			s.directGoodAt = now
		}
		s.directBadAt = time.Time{}
	} else {
		if s.directBadAt.IsZero() {
			s.directBadAt = now
		}
		s.directGoodAt = time.Time{}
	}

	switch s.current {
	case PathDirectWG:
		// Stay until the path has been bad for the whole grace period.
		if !observation.DirectHealthy && now.Sub(s.directBadAt) >= s.DirectLossGrace {
			if observation.RelayOpen {
				s.current = PathNKNRelay
			} else {
				s.current = PathNone
			}
		}
	case PathNKNRelay:
		// Return only after the direct path has held up for the hold period.
		if observation.DirectHealthy && now.Sub(s.directGoodAt) >= s.DirectRecoveryHold {
			s.current = PathDirectWG
		} else if !observation.RelayOpen {
			s.current = PathNone
		}
	default:
		switch {
		case observation.DirectHealthy:
			s.current = PathDirectWG
		case observation.RelayOpen:
			s.current = PathNKNRelay
		}
	}
	return s.current
}

// ShouldRetryDirect reports whether a relayed peer is due for another direct
// attempt, and records that the attempt is being made.
//
// It is a method with a side effect rather than a predicate because the
// interval must be enforced in one place: a caller that checks and then
// forgets to record would punch on every tick.
func (s *Selector) ShouldRetryDirect(now time.Time) bool {
	if s.current == PathDirectWG {
		return false
	}
	if !s.lastDirectTry.IsZero() && now.Sub(s.lastDirectTry) < s.retryInterval() {
		return false
	}
	s.lastDirectTry = now
	return true
}

func (s *Selector) retryInterval() time.Duration {
	interval := s.DirectRetryInterval
	for i := 0; i < s.failures; i++ {
		interval *= 2
		if s.DirectRetryMax > 0 && interval >= s.DirectRetryMax {
			return s.DirectRetryMax
		}
	}
	return interval
}

// RecordDirectFailure lengthens the wait before the next attempt.
func (s *Selector) RecordDirectFailure() { s.failures++ }

// RecordDirectSuccess resets the backoff. A network change after a period of
// success should be retried promptly, not at the end of a ten-minute wait
// earned by some earlier failure.
func (s *Selector) RecordDirectSuccess() { s.failures = 0 }

// Reset clears the held state, for a peer that went away entirely.
func (s *Selector) Reset() {
	s.current = PathNone
	s.directGoodAt = time.Time{}
	s.directBadAt = time.Time{}
	s.lastDirectTry = time.Time{}
	s.failures = 0
}
