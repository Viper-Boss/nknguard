package signaling

import (
	"sync"
	"time"
)

// RateLimiter is a token bucket. It guards the message types a stranger can
// send, so a flood costs the sender bandwidth and costs us a map lookup, not
// a signature verification per packet.
type RateLimiter struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	last     time.Time
	now      func() time.Time
	rejected uint64
}

// NewRateLimiter allows perSecond events on average with bursts up to burst.
func NewRateLimiter(perSecond float64, burst int) *RateLimiter {
	return &RateLimiter{rate: perSecond, burst: float64(burst), tokens: float64(burst), now: time.Now}
}

// Allow consumes a token if one is available.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if !r.last.IsZero() {
		r.tokens += now.Sub(r.last).Seconds() * r.rate
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
	}
	r.last = now
	if r.tokens < 1 {
		r.rejected++
		return false
	}
	r.tokens--
	return true
}

// Rejected is how many events were refused, for the metrics.
func (r *RateLimiter) Rejected() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rejected
}
