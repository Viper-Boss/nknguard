package mesh

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/nat"
)

// maxTransitionHistory is how many state changes are kept per peer. Enough to
// explain the last minute of a peer's life in `nknguard status`, small enough
// that a flapping peer cannot grow memory.
const maxTransitionHistory = 32

// Peer is the controller's view of one counterpart. Every field is guarded by
// its mutex; the controller reads it from the status path and writes it from
// the peer's own goroutine.
type Peer struct {
	mu sync.RWMutex
	// Serializes probe endpoint changes with delayed relay attachments.
	endpointMu     sync.Mutex
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	revoked        bool

	deviceID string
	name     string

	state      PeerState
	record     discovery.PeerRecord
	candidates []nat.EndpointCandidate
	endpoint   netip.AddrPort
	virtualIP  netip.Addr

	path     PathType
	selector *Selector

	lastHandshake time.Time
	// rxBytes is the peer's received-byte counter at the last observation
	// and rxAt is when it last moved; see NoteReceive.
	rxBytes      int64
	rxAt         time.Time
	lastProbe    time.Time
	observedAt   string
	installedKey string
	attempting   bool
	relayOpening bool
	lastRelayTry time.Time
	lastError    string
	punchRounds  int
	pathSwitches int
	history      []Transition
}

// NewPeer returns a peer in StateUnknown with the default path selector.
func NewPeer(deviceID string) *Peer { return NewPeerWithSelector(deviceID, DefaultSelector()) }

// NewPeerWithSelector returns a peer using the given selector, which it owns.
func NewPeerWithSelector(deviceID string, selector *Selector) *Peer {
	lifetime, cancel := context.WithCancel(context.Background())
	return &Peer{deviceID: deviceID, state: StateUnknown, path: PathNone, selector: selector, lifetime: lifetime, cancelLifetime: cancel}
}

func (p *Peer) Revoke() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.revoked {
		p.revoked = true
		p.cancelLifetime()
	}
}

func (p *Peer) Revoked() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.revoked
}

// BeginAttempt claims the right to run a direct attempt. It returns false if
// one is already running, which is what keeps a slow attempt and the next
// reconcile tick from racing each other on the same WireGuard peer.
func (p *Peer) BeginAttempt() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attempting || p.revoked {
		return false
	}
	p.attempting = true
	p.punchRounds++
	return true
}

func (p *Peer) Attempting() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.attempting
}

// EndAttempt records the outcome and releases the claim.
func (p *Peer) EndAttempt(succeeded bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempting = false
	if succeeded {
		p.selector.RecordDirectSuccess()
	} else {
		p.selector.RecordDirectFailure()
	}
}

// NeedsInstall reports whether the WireGuard peer must be (re)installed.
// A failed install must be retried on the next reconcile tick.
func (p *Peer) NeedsInstall() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return !p.revoked && p.record.WireGuardPublicKey != "" && p.record.WireGuardPublicKey != p.installedKey
}

func (p *Peer) markInstalled(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.installedKey = key
}

// beginRelay bounds fallback dials to one in flight and one every five seconds.
func (p *Peer) beginRelay(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked || p.relayOpening || (!p.lastRelayTry.IsZero() && now.Sub(p.lastRelayTry) < 5*time.Second) {
		return false
	}
	p.relayOpening = true
	p.lastRelayTry = now
	return true
}

func (p *Peer) endRelay() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.relayOpening = false
}

// NoteObservedEndpoint stores the endpoint WireGuard reports, which is the
// address packets actually come from rather than one anybody claimed.
func (p *Peer) NoteObservedEndpoint(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observedAt = endpoint
}

// DeviceID is the peer's stable identifier.
func (p *Peer) DeviceID() string { return p.deviceID }

// State returns the current state.
func (p *Peer) State() PeerState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// Path returns the data plane in use.
func (p *Peer) Path() PathType {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.path
}

// Apply moves the peer through an event and records the transition. An
// illegal event leaves the state untouched and returns the error, so a caller
// that gets ahead of itself is told rather than silently ignored.
func (p *Peer) Apply(event Event, now time.Time) (PeerState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next, err := Next(p.state, event)
	if err != nil {
		return p.state, err
	}
	if next != p.state {
		p.history = append(p.history, Transition{At: now, From: p.state, To: next, Event: event})
		if len(p.history) > maxTransitionHistory {
			p.history = p.history[len(p.history)-maxTransitionHistory:]
		}
		p.state = next
	}
	return next, nil
}

// SetRecord stores the latest verified record and returns whether it changed
// anything worth acting on.
func (p *Peer) SetRecord(record discovery.PeerRecord) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !record.Supersedes(p.record) {
		return false
	}
	p.record = record
	p.name = record.Name
	if len(record.Candidates) > 0 {
		p.candidates = record.Candidates
	}
	if len(record.VirtualIPs) > 0 {
		if addr, err := netip.ParsePrefix(record.VirtualIPs[0]); err == nil {
			p.virtualIP = addr.Addr()
		} else if addr, err := netip.ParseAddr(record.VirtualIPs[0]); err == nil {
			p.virtualIP = addr
		}
	}
	return true
}

// Record returns the stored record.
func (p *Peer) Record() discovery.PeerRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.record
}

// MergeCandidates replaces the peer's candidate set with a sanitised version.
func (p *Peer) MergeCandidates(candidates []nat.EndpointCandidate, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.candidates = nat.SanitiseCandidates(candidates, now)
}

// Candidates returns the current candidate set.
func (p *Peer) Candidates() []nat.EndpointCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]nat.EndpointCandidate(nil), p.candidates...)
}

// SetEndpoint records the address a packet was actually received from.
func (p *Peer) SetEndpoint(endpoint netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpoint = endpoint
}

// Endpoint is the confirmed direct address, if any.
func (p *Peer) Endpoint() netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endpoint
}

// NoteReceive records the peer's WireGuard received-byte counter and returns
// how long it has not moved. With persistent keepalive on both sides a live
// path delivers a packet at least every keepalive interval, so a counter that
// stands still for much longer means the path is dead, long before the last
// handshake ages out of its three-minute freshness window.
func (p *Peer) NoteReceive(bytes int64, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rxAt.IsZero() || bytes != p.rxBytes {
		p.rxBytes = bytes
		p.rxAt = now
	}
	return now.Sub(p.rxAt)
}

// dueProbe reports whether a quiet peer should be sent a packet now, at most
// once per interval.
func (p *Peer) dueProbe(now time.Time, interval time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.lastProbe.IsZero() && now.Sub(p.lastProbe) < interval {
		return false
	}
	p.lastProbe = now
	return true
}

// resetReceive restarts the silence clock, after the host was suspended or a
// path was just (re)established.
func (p *Peer) resetReceive(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rxAt = now
}

// NoteHandshake records a WireGuard handshake time observed on the interface.
func (p *Peer) NoteHandshake(at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if at.After(p.lastHandshake) {
		p.lastHandshake = at
	}
}

// LastHandshake is the newest handshake seen.
func (p *Peer) LastHandshake() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastHandshake
}

// NoteError stores the most recent failure for the status output.
func (p *Peer) NoteError(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastError = message
}

// SelectPath folds an observation into the selector and records a switch.
func (p *Peer) SelectPath(observation Observation) PathType {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attempting {
		return p.path
	}
	chosen := p.selector.Select(observation)
	if chosen != p.path {
		p.pathSwitches++
		p.path = chosen
	}
	return chosen
}

// ShouldRetryDirect asks the selector whether a relayed peer is due for
// another direct attempt.
func (p *Peer) ShouldRetryDirect(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.selector.ShouldRetryDirect(now)
}

// Snapshot is the peer rendered for the status API. It carries no key material
// beyond public keys, which is what lets the diagnostics bundle include it
// verbatim.
type Snapshot struct {
	DeviceID           string       `json:"device_id"`
	Name               string       `json:"name,omitempty"`
	State              PeerState    `json:"state"`
	Path               PathType     `json:"path"`
	VirtualIP          string       `json:"virtual_ip,omitempty"`
	Endpoint           string       `json:"endpoint,omitempty"`
	WireGuardPublicKey string       `json:"wireguard_public_key,omitempty"`
	NKNAddress         string       `json:"nkn_address,omitempty"`
	LastHandshake      time.Time    `json:"last_handshake,omitempty"`
	PathSwitches       int          `json:"path_switches"`
	PunchRounds        int          `json:"punch_rounds"`
	LastError          string       `json:"last_error,omitempty"`
	History            []Transition `json:"history,omitempty"`
	DirectAttempting   bool         `json:"direct_attempting"`
	NextDirectRetry    time.Time    `json:"next_direct_retry,omitempty"`
}

// Snapshot renders the peer.
func (p *Peer) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	snapshot := Snapshot{
		DeviceID:           p.deviceID,
		Name:               p.name,
		State:              p.state,
		Path:               p.path,
		WireGuardPublicKey: p.record.WireGuardPublicKey,
		NKNAddress:         p.record.NKNAddress,
		LastHandshake:      p.lastHandshake,
		PathSwitches:       p.pathSwitches,
		PunchRounds:        p.punchRounds,
		LastError:          p.lastError,
		History:            append([]Transition(nil), p.history...),
		DirectAttempting:   p.attempting,
	}
	if p.path != PathDirectWG && !p.selector.lastDirectTry.IsZero() {
		snapshot.NextDirectRetry = p.selector.lastDirectTry.Add(p.selector.retryInterval())
	}
	if p.virtualIP.IsValid() {
		snapshot.VirtualIP = p.virtualIP.String()
	}
	switch {
	case p.observedAt != "":
		snapshot.Endpoint = p.observedAt
	case p.endpoint.IsValid():
		snapshot.Endpoint = p.endpoint.String()
	}
	return snapshot
}

// stuckFor is how long the peer has been without any working path, measured
// from its last handshake or, if it never had one, from when its record was
// first seen.
func (p *Peer) stuckFor(now time.Time) time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.path != PathNone {
		return 0
	}
	since := p.lastHandshake
	if since.IsZero() && len(p.history) > 0 {
		since = p.history[0].At
	}
	if since.IsZero() {
		return 0
	}
	return now.Sub(since)
}
