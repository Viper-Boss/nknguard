package controlhub

import (
	"context"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
)

// Policy applies to discovery/control traffic only. The relay data path never
// uses the secondary transport. A recovery grace prevents route flapping.
type Policy struct {
	FailoverAfter time.Duration
	RecoverAfter  time.Duration
}

func (h *Hub) notePrimaryResult(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		h.sendFailureSince = time.Time{}
	} else if h.sendFailureSince.IsZero() {
		h.sendFailureSince = h.now()
	}
}

// DiscoveryFallbackActive is also consulted before DHT lookup/publication.
// Inbound signed control is always accepted: the remote peer may need fallback
// even while our own NKN transport is healthy. The dispatcher still checks ACLs.
func (h *Hub) DiscoveryFallbackActive() bool {
	h.mu.RLock()
	p := h.primary
	h.mu.RUnlock()
	healthy := p != nil
	var lastSuccess time.Time
	if query, ok := p.(interface {
		ConnectionStatus() nknclient.ConnectionStatus
	}); ok {
		status := query.ConnectionStatus()
		healthy = status.State == "connected"
		lastSuccess = status.LastSuccess
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if !h.sendFailureSince.IsZero() && lastSuccess.After(h.sendFailureSince) {
		h.sendFailureSince = time.Time{}
	}
	healthy = healthy && h.sendFailureSince.IsZero()
	if !healthy {
		h.recoveredSince = time.Time{}
		if h.unavailableSince.IsZero() {
			h.unavailableSince = now
		}
		if now.Sub(h.unavailableSince) >= h.policy.FailoverAfter {
			h.fallback = true
		}
	} else if h.fallback {
		if h.recoveredSince.IsZero() {
			h.recoveredSince = now
		}
		if now.Sub(h.recoveredSince) >= h.policy.RecoverAfter {
			h.fallback = false
			h.unavailableSince = time.Time{}
		}
	} else {
		h.unavailableSince = time.Time{}
		h.recoveredSince = time.Time{}
	}
	return h.secondary != nil && h.fallback && h.ctx.Err() == nil
}
