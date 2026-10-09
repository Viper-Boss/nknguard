//go:build nknsdk

package nknsignal

import (
	"bytes"
	"crypto/rand"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	nkn "github.com/nknorg/nkn-sdk-go"
)

const healthTimeout = 12 * time.Second
const healthInterval = 30 * time.Second

var healthPrefix = []byte("NKNGuard-health-v1:")

type healthState struct {
	mu      sync.RWMutex
	self    string
	nonce   []byte
	started time.Time
	replies chan struct{}
	status  nknclient.ConnectionStatus
}

func (h *healthState) init(self string) {
	h.self = self
	h.replies = make(chan struct{}, 1)
	h.status.State = "checking"
}

func (h *healthState) begin(nonce []byte, now time.Time) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nonce = bytes.Clone(nonce)
	h.started = now
	return append(bytes.Clone(healthPrefix), nonce...)
}

// accept runs only after transport encryption was verified. Source, fresh
// nonce and deadline stop unrelated or delayed messages from granting health.
func (h *healthState) accept(source string, data []byte, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if source != h.self || len(h.nonce) != 32 || !bytes.Equal(data, append(bytes.Clone(healthPrefix), h.nonce...)) || now.Before(h.started) || now.Sub(h.started) > healthTimeout {
		return false
	}
	h.nonce = nil
	h.status = nknclient.ConnectionStatus{State: "connected", CheckedAt: now, LastSuccess: now, LatencyMS: now.Sub(h.started).Milliseconds()}
	select {
	case h.replies <- struct{}{}:
	default:
	}
	return true
}

func (h *healthState) failed(state string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nonce = nil
	h.status.State = state
	h.status.CheckedAt = now
	h.status.LatencyMS = 0
}

// ConnectionStatus never performs network I/O from a dashboard request.
func (t *Transport) ConnectionStatus() nknclient.ConnectionStatus {
	t.health.mu.RLock()
	defer t.health.mu.RUnlock()
	status := t.health.status
	select {
	case <-t.done:
		status.State = "closed"
		return status
	default:
	}
	if status.State == "connected" && time.Since(status.LastSuccess) > healthInterval+healthTimeout {
		status.State = "reconnecting"
	}
	return status
}

// StartHealthMonitor runs on the NAS using its existing MultiClient. One tiny
// encrypted self-message per interval does not change WireGuard or persist data.
// Start it before publishing the transport; Close joins both workers.
func (t *Transport) StartHealthMonitor() {
	t.healthOnce.Do(func() {
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			for {
				select {
				case <-t.done:
					return
				default:
				}
				nonce := make([]byte, 32)
				if _, err := rand.Read(nonce); err != nil {
					t.health.failed("reconnecting", time.Now())
					return
				}
				select {
				case <-t.health.replies:
				default:
				}
				started := time.Now()
				payload := t.health.begin(nonce, started)
				_, err := t.client.Send(nkn.NewStringArray(t.health.self), payload, &nkn.MessageConfig{NoReply: true, MaxHoldingSeconds: 0})
				if err != nil {
					t.health.failed("reconnecting", time.Now())
				} else {
					timer := time.NewTimer(time.Until(started.Add(healthTimeout)))
					select {
					case <-t.done:
						timer.Stop()
						return
					case <-t.health.replies:
						timer.Stop()
					case <-timer.C:
						t.health.failed("reconnecting", time.Now())
					}
				}
				timer := time.NewTimer(time.Until(started.Add(healthInterval)))
				select {
				case <-t.done:
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	})
}
