package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// reconcileLoop is the controller's heartbeat. Every tick it reads what the
// data plane is actually doing and moves each peer one step towards a working
// path.
//
// Reconciling from observed state rather than reacting to events is what makes
// the daemon recoverable: a crash, a restart or a lost message leaves a state
// the next tick can repair, instead of one waiting on an event that has
// already gone past. It is also what makes Principle 4 hold — nothing here
// reads the control plane to decide whether a tunnel is healthy, so an NKN or
// DHT outage cannot make us tear one down.
func (c *Controller) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(orDefault(c.Config.Timing.ReconcileInterval, 2*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reconcileOnce(ctx)
		}
	}
}

// observation is one peer's data-plane state as WireGuard reports it.
type observation struct {
	handshake time.Time
	endpoint  string
	rxBytes   int64
}

func (c *Controller) observe(ctx context.Context) map[string]observation {
	out := make(map[string]observation)
	if c.WireGuard == nil {
		return out
	}
	stats, err := c.WireGuard.Stats(ctx)
	if err != nil {
		return out
	}
	for _, stat := range stats {
		entry := observation{endpoint: stat.Endpoint, rxBytes: stat.TransferRxBytes}
		if stat.LastHandshake > 0 {
			entry.handshake = time.Unix(stat.LastHandshake, 0)
		}
		out[stat.PublicKey] = entry
	}
	return out
}

func isLoopbackEndpoint(endpoint string) bool {
	addr, err := netip.ParseAddrPort(endpoint)
	return err == nil && addr.Addr().IsLoopback()
}

func (c *Controller) reconcileOnce(ctx context.Context) {
	now := time.Now()
	observed := c.observe(ctx)

	c.mu.Lock()
	peers := make([]*Peer, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	// A tick that arrives far later than scheduled means the host was
	// suspended (a laptop lid, a phone in deep sleep). Nothing was received
	// meanwhile on any path, dead or alive, so the silence says nothing:
	// restart the clocks and ask every peer for a packet instead.
	resumed := !c.lastReconcile.IsZero() && now.Sub(c.lastReconcile) > resumeGap(c.Config.Timing.ReconcileInterval)
	c.lastReconcile = now
	c.mu.Unlock()
	if resumed {
		c.logger().Info("resumed after a pause; re-checking paths", "component", "mesh")
		for _, peer := range peers {
			peer.resetReceive(now)
			if !peer.Revoked() {
				c.Reconnect(peer.DeviceID())
				c.nudgePeer(ctx, peer)
			}
		}
	}
	receiveTimeout := c.receiveTimeout()

	direct, relayed, switches := 0, 0, 0
	for _, peer := range peers {
		if peer.Revoked() {
			continue
		}
		record := peer.Record()
		if record.WireGuardPublicKey == "" {
			continue
		}
		if peer.NeedsInstall() {
			c.ensureWireGuardPeer(ctx, peer)
		}

		seen := observed[record.WireGuardPublicKey]
		// An attempt may finish after the shared snapshot above. Read again
		// while owning the endpoint so its temporary candidate and the old
		// relay handshake cannot be interpreted after the worker releases it.
		endpointOwned := peer.endpointMu.TryLock()
		if endpointOwned {
			seen = c.observe(ctx)[record.WireGuardPublicKey]
		}
		peer.NoteHandshake(seen.handshake)
		peer.NoteObservedEndpoint(seen.endpoint)
		fresh := !seen.handshake.IsZero() && now.Sub(seen.handshake) < wireguard.HandshakeFreshness
		viaICE := c.isICEDirect(peer.DeviceID(), seen.endpoint)
		bridge := c.bridgeFor(peer.DeviceID())
		viaBridge := bridge != nil && bridge.Stats().Open && bridge.LocalAddr().String() == seen.endpoint
		if isLoopbackEndpoint(seen.endpoint) && !viaICE && !viaBridge {
			fresh = false
		}
		// Prepare the fallback concurrently, including while direct is up.
		if bridge == nil && c.Relay != nil && c.Signaling != nil && c.initiator(peer) {
			c.spawn(func() { c.openRelay(ctx, peer, "prepare standby") })
		}
		// An attempt temporarily assigns unproven endpoints. The last
		// handshake may belong to the relay; never promote it to direct or
		// tear down the working bridge while the worker owns the endpoint.
		if !endpointOwned || (peer.Attempting() && !c.usesICE(peer)) {
			silent := peer.NoteReceive(seen.rxBytes, now)
			// Incoming authenticated relay packets can prove the fallback
			// while probes are ongoing. Only direct promotion is forbidden.
			if bridge != nil && viaBridge && fresh && silent < receiveTimeout {
				if peer.SelectPath(Observation{Now: now, RelayOpen: true, RelayActive: true}) == PathNKNRelay {
					_, _ = peer.Apply(EventRelayOpen, now)
				}
			}
			switch peer.Path() {
			case PathDirectWG:
				direct++
			case PathNKNRelay:
				relayed++
			}
			if endpointOwned {
				peer.endpointMu.Unlock()
			}
			continue
		}
		// A fresh handshake only says the path worked within the last three
		// minutes. Keepalives arrive every few seconds on a live path, so
		// their absence shows a dead one much sooner.
		silent := peer.NoteReceive(seen.rxBytes, now)
		if fresh && receiveTimeout > 0 && silent >= receiveTimeout/2 && silent < receiveTimeout && peer.dueProbe(now, probeInterval) {
			// Quiet for a while: ask for a packet before concluding anything.
			// WireGuard answers received data with a keepalive within ten
			// seconds when it has nothing else to send, so a live path
			// replies even if the other side has persistent keepalive off.
			c.spawn(func() { c.nudgePeer(ctx, peer) })
		}
		if receiveTimeout > 0 && silent >= receiveTimeout {
			fresh = false
			if viaICE {
				c.closeICEPath(peer.DeviceID())
			}
			if viaBridge && bridge != nil && !bridge.Standby() {
				// The relayed stream stopped delivering. Drop it so the
				// initiator opens a new one.
				c.dropBridge(peer.DeviceID(), "no packets received")
				bridge = nil
			}
		}

		before := peer.Path()
		path := peer.SelectPath(Observation{
			Now:           now,
			DirectHealthy: fresh && (!isLoopbackEndpoint(seen.endpoint) || viaICE),
			RelayOpen:     bridge != nil && fresh && viaBridge,
			RelayActive:   bridge != nil && fresh && viaBridge,
		})
		peer.endpointMu.Unlock()
		if path != before {
			switches++
			c.logger().Info("path changed", "component", "mesh", "peer", peer.DeviceID(), "from", before, "to", path)
		}
		if path == PathNone && viaICE && bridge != nil {
			c.activateBridge(ctx, peer, bridge)
		}

		switch path {
		case PathDirectWG:
			direct++
			_, _ = peer.Apply(EventHandshakeOK, now)
			// Keep the session ready, but stop forwarding relay stragglers.
			if bridge != nil && fresh && !viaBridge {
				bridge.SetStandby(true)
			}
			continue
		case PathNKNRelay:
			relayed++
			_, _ = peer.Apply(EventRelayOpen, now)
		default:
			if peer.State() == StateDirect {
				_, _ = peer.Apply(EventHandshakeStale, now)
			}
		}
		if bridge != nil && bridge.Standby() && !fresh {
			c.activateBridge(ctx, peer, bridge)
		}

		c.progress(ctx, peer, now, bridge)
	}

	c.mu.Lock()
	c.metrics.PeersDirect = direct
	c.metrics.PeersRelay = relayed
	c.metrics.PathSwitches += switches
	c.mu.Unlock()
}

// initiator reports whether this node drives attempts towards a peer. Exactly
// one side initiates, chosen by device id, so the two nodes never run
// competing attempts that move the same WireGuard endpoint in opposite
// directions at once.
func (c *Controller) initiator(peer *Peer) bool {
	if c.Config.OwnerDevice {
		return false
	}
	if c.Config.ClientDevice {
		return true
	}
	return c.Device.DeviceID() < peer.DeviceID()
}

// progress takes one step for a peer that is not on a direct path.
func (c *Controller) progress(ctx context.Context, peer *Peer, now time.Time, bridge *relay.Bridge) {
	if c.Signaling == nil || !c.initiator(peer) || c.Direct == nil {
		return
	}
	// The relay comes first when a peer has had no path for RelayAfter: being
	// connected slowly beats not being connected while a punch is retried.
	if bridge == nil && c.Relay != nil && peer.stuckFor(now) >= orDefault(c.Config.Timing.RelayAfter, 20*time.Second) {
		c.spawn(func() { c.openRelay(ctx, peer, "no path") })
	}
	if !c.usesICE(peer) && len(peer.Candidates()) == 0 {
		return
	}
	if !peer.ShouldRetryDirect(now) || !peer.BeginAttempt() {
		return
	}
	if c.usesICE(peer) {
		c.spawn(func() { c.runICEOffer(ctx, peer) })
		return
	}
	token, err := nat.NewSessionToken()
	if err != nil {
		peer.EndAttempt(false)
		return
	}
	startAt := now.Add(orDefault(c.Config.Timing.PunchLead, 1500*time.Millisecond))
	encoded, _ := json.Marshal(c.ownCandidates())
	request := protocol.PunchRequest{Round: 1, Candidates: encoded, StartAtUnixMilli: startAt.UnixMilli(), Token: token[:]}
	if err := c.send(ctx, peer.DeviceID(), protocol.TypePunchRequest, request); err != nil {
		// No signalling, no rendezvous. A one-sided attempt against a NAT is
		// pointless, so this counts as a failure and the relay takes over.
		peer.NoteError("punch request: " + err.Error())
		peer.EndAttempt(false)
		if bridge == nil && c.Relay != nil {
			c.spawn(func() { c.openRelay(ctx, peer, "signalling unavailable") })
		}
		return
	}
	_, _ = peer.Apply(EventPunchStarted, now)
	c.spawn(func() { c.runAttempt(ctx, peer, startAt, token, true) })
}

// runAttempt drives one direct attempt on either side of the rendezvous.
func (c *Controller) runAttempt(ctx context.Context, peer *Peer, startAt time.Time, token nat.SessionToken, initiator bool) {
	peer.endpointMu.Lock()
	defer peer.endpointMu.Unlock()
	attemptCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(peer.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if peer.Revoked() {
		peer.EndAttempt(false)
		return
	}
	record := peer.Record()
	attempt := DirectAttempt{
		DeviceID:           peer.DeviceID(),
		WireGuardPublicKey: record.WireGuardPublicKey,
		Candidates:         peer.Candidates(),
		LocalCandidates:    c.ownCandidates(),
		StartAt:            startAt,
		Token:              token,
	}
	if len(record.VirtualIPs) > 0 {
		if addr, err := netip.ParseAddr(record.VirtualIPs[0]); err == nil {
			attempt.VirtualIP = addr
		}
	}
	endpoint, err := c.Direct.Attempt(attemptCtx, attempt)
	if peer.Revoked() {
		peer.EndAttempt(false)
		if c.WireGuard != nil {
			_ = c.RemoveRevokedKey(ctx, record.WireGuardPublicKey)
		}
		return
	}
	if err != nil {
		defer peer.EndAttempt(false)
		c.mu.Lock()
		c.metrics.PunchFailure++
		c.mu.Unlock()
		_, _ = peer.Apply(EventPunchFailed, time.Now())
		if ctx.Err() == nil {
			c.logger().Info("direct attempt failed", "component", "nat", "peer", peer.DeviceID(), "error", err)
		}
		// The attempt moved WireGuard's endpoint off the relay. Put it back,
		// so a failed direct attempt costs seconds of relay traffic and not
		// the relay itself.
		if bridge := c.bridgeFor(peer.DeviceID()); bridge != nil && record.WireGuardPublicKey != "" {
			bridge.SetStandby(false)
			_ = c.WireGuard.UpdateEndpoint(ctx, record.WireGuardPublicKey, bridge.LocalAddr().String())
			peer.resetReceive(time.Now())
			c.nudgePeer(ctx, peer)
		} else if initiator && c.Relay != nil && ctx.Err() == nil {
			c.spawn(func() { c.openRelay(ctx, peer, "direct attempt failed") })
		}
		return
	}
	peer.SetEndpoint(endpoint)
	if bridge := c.bridgeFor(peer.DeviceID()); bridge != nil {
		bridge.SetStandby(true)
	}
	peer.resetReceive(time.Now())
	peer.EndAttempt(true)
	c.mu.Lock()
	c.metrics.PunchSuccess++
	c.mu.Unlock()
	_, _ = peer.Apply(EventPunchSucceeded, time.Now())
	c.logger().Info("direct path established", "component", "nat", "peer", peer.DeviceID(), "endpoint", endpoint.String())
	ready := protocol.WGReady{Endpoint: endpoint.String(), VirtualIP: c.VirtualIP().String()}
	if key, err := c.WireGuard.PublicKey(ctx); err == nil {
		ready.WireGuardPublicKey = key
	}
	_ = c.send(ctx, peer.DeviceID(), protocol.TypeWGReady, ready)
}

// ensureWireGuardPeer installs the peer's key and overlay address. It never
// sets the endpoint — that is the job of the direct strategy and the relay —
// so it can be called at any time without disturbing an attempt in flight.
func (c *Controller) ensureWireGuardPeer(ctx context.Context, peer *Peer) {
	if c.WireGuard == nil || peer.Revoked() {
		return
	}
	record := peer.Record()
	if record.WireGuardPublicKey == "" {
		return
	}
	allowed := make([]string, 0, len(record.VirtualIPs))
	for _, address := range record.VirtualIPs {
		if addr, err := netip.ParseAddr(address); err == nil {
			if !c.Config.OverlayCIDR.Contains(addr) {
				// A peer may only claim addresses inside the overlay. Without
				// this check a member could advertise 0.0.0.0/0 or a LAN
				// range and have this node route real traffic to it.
				continue
			}
			allowed = append(allowed, netip.PrefixFrom(addr, addr.BitLen()).String())
		}
	}
	if len(allowed) == 0 {
		peer.NoteError("record carries no overlay address inside " + c.Config.OverlayCIDR.String())
		return
	}
	config := wireguard.PeerConfig{
		DeviceID:            peer.DeviceID(),
		Name:                record.Name,
		PublicKey:           record.WireGuardPublicKey,
		AllowedIPs:          allowed,
		PersistentKeepalive: c.Config.Keepalive,
	}
	if err := c.WireGuard.AddPeer(ctx, config); err != nil {
		peer.NoteError("install peer: " + err.Error())
		return
	}
	peer.markInstalled(record.WireGuardPublicKey)
	if peer.Revoked() {
		_ = c.RemoveRevokedKey(ctx, record.WireGuardPublicKey)
	}
}

// ---- relay -----------------------------------------------------------------

func (c *Controller) bridgeFor(deviceID string) *relay.Bridge {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bridges[deviceID]
}

func (c *Controller) wireGuardLoopback(ctx context.Context) (netip.AddrPort, error) {
	status := c.WireGuard.Status(ctx)
	if status.ListenPort <= 0 {
		return netip.AddrPort{}, errors.New("mesh: wireguard listen port unknown")
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(status.ListenPort)), nil
}

// openRelay is the initiator's fallback: open a relayed stream and point the
// peer's WireGuard endpoint at a local bridge into it.
func (c *Controller) openRelay(ctx context.Context, peer *Peer, reason string) {
	relayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(peer.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if !peer.beginRelay(time.Now()) {
		return
	}
	defer peer.endRelay()
	if c.bridgeFor(peer.DeviceID()) != nil {
		return
	}
	if peer.Path() != PathDirectWG {
		_, _ = peer.Apply(EventRelayOpening, time.Now())
	}
	record := peer.Record()
	stream, err := c.Relay.Open(relayCtx, relay.Peer{DeviceID: peer.DeviceID(), Address: record.NKNAddress})
	if err != nil {
		if ctx.Err() == nil {
			peer.NoteError("relay: " + err.Error())
			c.logger().Warn("relay fallback failed", "component", "relay", "peer", peer.DeviceID(), "error", err)
		}
		_, _ = peer.Apply(EventRelayFailed, time.Now())
		return
	}
	if peer.Revoked() {
		_ = stream.Close()
		return
	}
	if c.attachBridge(ctx, peer, stream) {
		c.mu.Lock()
		c.metrics.RelayFallbacks++
		c.mu.Unlock()
		c.logger().Info("relay fallback started", "component", "relay", "peer", peer.DeviceID(), "reason", reason)
	}
}

// relayAcceptLoop is the responder's side: a peer opened a relayed stream to
// us, and if it is a member with a known key we bridge it to WireGuard.
func (c *Controller) relayAcceptLoop(ctx context.Context, acceptor relay.Acceptor) {
	for {
		session, err := acceptor.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		peer, known := c.lookupPeer(session.DeviceID)
		if !known || !c.Authorized(session.DeviceID) || peer.Record().WireGuardPublicKey == "" {
			_ = session.Conn.Close()
			continue
		}
		c.ensureWireGuardPeer(ctx, peer)
		if peer.Path() != PathDirectWG {
			_, _ = peer.Apply(EventRelayOpening, time.Now())
		}
		c.attachBridge(ctx, peer, session.Conn)
	}
}

func (c *Controller) attachBridge(ctx context.Context, peer *Peer, stream net.Conn) bool {
	peer.endpointMu.Lock()
	defer peer.endpointMu.Unlock()
	if peer.Revoked() {
		_ = stream.Close()
		return false
	}
	// Opening NKN can take longer than the direct probe. A stream arriving
	// afterwards must not replace a direct endpoint that is receiving packets.
	seen := c.observe(ctx)[peer.Record().WireGuardPublicKey]
	now := time.Now()
	confirmed := peer.Path() == PathDirectWG || peer.Endpoint().String() == seen.endpoint || c.isICEDirect(peer.DeviceID(), seen.endpoint)
	standby := confirmed && (!isLoopbackEndpoint(seen.endpoint) || c.isICEDirect(peer.DeviceID(), seen.endpoint)) && !seen.handshake.IsZero() &&
		now.Sub(seen.handshake) < wireguard.HandshakeFreshness && (c.receiveTimeout() == 0 || peer.NoteReceive(seen.rxBytes, now) < c.receiveTimeout())
	local, err := c.wireGuardLoopback(ctx)
	if err != nil {
		peer.NoteError(err.Error())
		_ = stream.Close()
		return false
	}
	bridge, err := relay.NewBridge(stream, local)
	if err != nil {
		peer.NoteError(err.Error())
		_ = stream.Close()
		return false
	}
	bridge.SetStandby(standby)
	c.mu.Lock()
	if existing := c.bridges[peer.DeviceID()]; existing != nil {
		c.mu.Unlock()
		bridge.Close()
		return false
	}
	c.bridges[peer.DeviceID()] = bridge
	c.mu.Unlock()
	// Start draining before endpoint updates or nudges. A blocked setup step
	// must not leave a bound UDP socket with no reader.
	c.spawn(func() {
		err := bridge.Run(ctx)
		if ctx.Err() == nil && err != nil {
			c.logger().Warn("relay stream stopped", "peer", peer.DeviceID(), "error", err)
		}
		c.mu.Lock()
		if c.bridges[peer.DeviceID()] == bridge {
			delete(c.bridges, peer.DeviceID())
		}
		c.mu.Unlock()
	})
	if standby {
		c.logger().Info("relay standby ready", "peer", peer.DeviceID())
		return true
	}
	// The previous path's silence is not evidence about this new stream.
	// Allow its first round trip before applying the receive timeout.
	peer.resetReceive(time.Now())

	record := peer.Record()
	if err := c.WireGuard.UpdateEndpoint(ctx, record.WireGuardPublicKey, bridge.LocalAddr().String()); err != nil {
		peer.NoteError("relay endpoint: " + err.Error())
		c.mu.Lock()
		if c.bridges[peer.DeviceID()] == bridge {
			delete(c.bridges, peer.DeviceID())
		}
		c.mu.Unlock()
		bridge.Close()
		return false
	}
	if peer.Revoked() {
		c.closeBridge(peer.DeviceID())
		_ = c.RemoveRevokedKey(ctx, record.WireGuardPublicKey)
		return false
	}
	if c.Nudge != nil && len(record.VirtualIPs) > 0 {
		if addr, err := netip.ParseAddr(record.VirtualIPs[0]); err == nil {
			c.Nudge(ctx, addr)
		}
	}
	return true
}

// activateBridge reuses the prepared session after direct stops receiving.
func (c *Controller) activateBridge(ctx context.Context, peer *Peer, bridge *relay.Bridge) {
	if !peer.endpointMu.TryLock() {
		return
	}
	defer peer.endpointMu.Unlock()
	if peer.Revoked() || c.bridgeFor(peer.DeviceID()) != bridge || !bridge.Standby() {
		return
	}
	bridge.SetStandby(false)
	if err := c.WireGuard.UpdateEndpoint(ctx, peer.Record().WireGuardPublicKey, bridge.LocalAddr().String()); err != nil {
		peer.NoteError("activate relay: " + err.Error())
		c.dropBridge(peer.DeviceID(), "endpoint update failed")
		return
	}
	peer.resetReceive(time.Now())
	c.nudgePeer(ctx, peer)
	c.logger().Info("activated prepared relay", "peer", peer.DeviceID())
}

func (c *Controller) closeBridge(deviceID string) {
	c.mu.Lock()
	bridge := c.bridges[deviceID]
	delete(c.bridges, deviceID)
	c.mu.Unlock()
	if bridge != nil {
		bridge.Close()
		c.logger().Info("relay closed, peer is direct", "component", "relay", "peer", deviceID)
	}
}

// dropBridge closes a relay bridge that stopped working.
func (c *Controller) dropBridge(deviceID, reason string) {
	c.mu.Lock()
	bridge := c.bridges[deviceID]
	delete(c.bridges, deviceID)
	c.mu.Unlock()
	if bridge != nil {
		bridge.Close()
		c.logger().Info("relay dropped", "component", "relay", "peer", deviceID, "reason", reason)
	}
}

// probeInterval spaces the packets sent to a quiet peer.
const probeInterval = 10 * time.Second

// resumeGap is the tick delay that is taken as the host having been
// suspended: several missed ticks, and never less than ten seconds.
func resumeGap(interval time.Duration) time.Duration {
	gap := 5 * orDefault(interval, 2*time.Second)
	if gap < 10*time.Second {
		gap = 10 * time.Second
	}
	return gap
}

func (c *Controller) closeBridges() {
	c.mu.Lock()
	bridges := c.bridges
	c.bridges = make(map[string]*relay.Bridge)
	icePaths := c.icePaths
	c.icePaths = make(map[string]*icePath)
	c.mu.Unlock()
	for _, bridge := range bridges {
		bridge.Close()
	}
	for _, path := range icePaths {
		path.bridge.Close()
	}
}
