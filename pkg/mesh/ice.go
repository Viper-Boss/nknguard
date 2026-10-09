package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/directice"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type icePending struct {
	id     string
	answer chan directice.Description
}

type iceOperation struct{ cancel context.CancelFunc }

type icePath struct {
	bridge *relay.Bridge
	remote netip.AddrPort
}

func (c *Controller) capabilities() []string {
	caps := protocol.DefaultCapabilities()
	if c.ICE != nil {
		caps = append(caps, protocol.CapICEUDPV1)
	}
	return caps
}

func (c *Controller) usesICE(peer *Peer) bool {
	return c.ICE != nil && protocol.HasCapability(peer.Record().Capabilities, protocol.CapICEUDPV1)
}

func (c *Controller) icePathFor(id string) *icePath {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.icePaths[id]
}

func (c *Controller) isICEDirect(id, endpoint string) bool {
	p := c.icePathFor(id)
	return p != nil && p.bridge.Stats().Open && p.bridge.LocalAddr().String() == endpoint
}

func (c *Controller) closeICEPath(id string) {
	c.mu.Lock()
	p := c.icePaths[id]
	delete(c.icePaths, id)
	c.mu.Unlock()
	if p != nil {
		p.bridge.Close()
	}
}

func (c *Controller) iceContext(ctx context.Context, peer *Peer) (context.Context, func()) {
	attempt, cancel := context.WithTimeout(ctx, 40*time.Second)
	stop := context.AfterFunc(peer.lifetime, cancel)
	operation := &iceOperation{cancel: cancel}
	c.mu.Lock()
	c.iceOperations[peer.DeviceID()] = operation
	c.mu.Unlock()
	return attempt, func() {
		stop()
		cancel()
		c.mu.Lock()
		if c.iceOperations[peer.DeviceID()] == operation {
			delete(c.iceOperations, peer.DeviceID())
		}
		c.mu.Unlock()
	}
}

// ICE checks use their own sockets; a running relay remains assigned to
// WireGuard throughout gathering, signalling and connectivity checks.
func (c *Controller) runICEOffer(ctx context.Context, peer *Peer) {
	succeeded := false
	defer func() { peer.EndAttempt(succeeded) }()
	attempt, cancel := c.iceContext(ctx, peer)
	defer cancel()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return
	}
	id := hex.EncodeToString(random[:])
	session, desc, err := c.ICE.Prepare(attempt, id)
	if err != nil {
		c.iceFailed(ctx, peer, err)
		return
	}
	retained := false
	defer func() {
		if !retained {
			session.Close()
		}
	}()
	pending := &icePending{id: id, answer: make(chan directice.Description, 1)}
	c.mu.Lock()
	c.icePending[peer.DeviceID()] = pending
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.icePending[peer.DeviceID()] == pending {
			delete(c.icePending, peer.DeviceID())
		}
		c.mu.Unlock()
	}()
	if err = c.send(attempt, peer.DeviceID(), protocol.TypeICEOffer, desc); err != nil {
		c.iceFailed(ctx, peer, err)
		return
	}
	var answer directice.Description
	select {
	case <-attempt.Done():
		c.iceFailed(ctx, peer, attempt.Err())
		return
	case answer = <-pending.answer:
	}
	conn, err := session.Connect(attempt, answer, true)
	if err != nil {
		c.iceFailed(ctx, peer, err)
		return
	}
	retained = c.installICEPath(ctx, attempt, peer, conn)
	succeeded = retained
}

func (c *Controller) onICEOffer(ctx context.Context, envelope protocol.Envelope) error {
	if c.ICE == nil {
		return nil
	}
	peer, ok := c.lookupPeer(envelope.FromDeviceID)
	if !ok || peer.Revoked() || c.initiator(peer) {
		return nil
	}
	var offer directice.Description
	if err := envelope.DecodePayload(&offer); err != nil {
		return err
	}
	if err := directice.Validate(offer); err != nil {
		return err
	}
	if !peer.BeginAttempt() {
		return nil
	}
	c.spawn(func() {
		succeeded := false
		defer func() { peer.EndAttempt(succeeded) }()
		attempt, cancel := c.iceContext(ctx, peer)
		defer cancel()
		session, answer, err := c.ICE.Prepare(attempt, offer.ID)
		if err != nil {
			c.iceFailed(ctx, peer, err)
			return
		}
		retained := false
		defer func() {
			if !retained {
				session.Close()
			}
		}()
		if err = c.send(attempt, peer.DeviceID(), protocol.TypeICEAnswer, answer); err != nil {
			c.iceFailed(ctx, peer, err)
			return
		}
		conn, err := session.Connect(attempt, offer, false)
		if err != nil {
			c.iceFailed(ctx, peer, err)
			return
		}
		retained = c.installICEPath(ctx, attempt, peer, conn)
		succeeded = retained
	})
	return nil
}

func (c *Controller) onICEAnswer(_ context.Context, envelope protocol.Envelope) error {
	var answer directice.Description
	if err := envelope.DecodePayload(&answer); err != nil {
		return err
	}
	if err := directice.Validate(answer); err != nil {
		return err
	}
	c.mu.RLock()
	pending := c.icePending[envelope.FromDeviceID]
	c.mu.RUnlock()
	if pending == nil || pending.id != answer.ID {
		return nil
	}
	select {
	case pending.answer <- answer:
	default:
	}
	return nil
}

func (c *Controller) iceFailed(ctx context.Context, peer *Peer, err error) {
	if ctx.Err() != nil || peer.Revoked() {
		return
	}
	c.mu.Lock()
	c.metrics.PunchFailure++
	c.mu.Unlock()
	// Do not log descriptions: they contain ephemeral ICE credentials.
	c.logger().Info("ICE direct check failed; existing path retained", "component", "nat", "peer", peer.DeviceID(), "error", err)
}

// A nominated ICE pair proves UDP reachability. A NEW authenticated WireGuard
// receive or handshake through this bridge additionally proves the NAS key.
func (c *Controller) installICEPath(ctx, attempt context.Context, peer *Peer, conn net.Conn) bool {
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return false
	}
	local, err := c.wireGuardLoopback(ctx)
	if err != nil {
		_ = conn.Close()
		return false
	}
	bridge, err := relay.NewDatagramBridge(conn, local)
	if err != nil {
		_ = conn.Close()
		return false
	}
	peer.endpointMu.Lock()
	defer peer.endpointMu.Unlock()
	if peer.Revoked() || attempt.Err() != nil {
		bridge.Close()
		return false
	}
	record := peer.Record()
	baseline := c.observe(ctx)[record.WireGuardPublicKey]
	previous := baseline.endpoint
	relayBridge := c.bridgeFor(peer.DeviceID())
	if relayBridge != nil {
		relayBridge.SetStandby(true)
	}
	c.ensureWireGuardPeer(ctx, peer)
	c.spawn(func() { _ = bridge.Run(ctx) })
	rollback := func() {
		bridge.Close()
		if peer.Revoked() {
			_ = c.RemoveRevokedKey(ctx, record.WireGuardPublicKey)
			return
		}
		if previous != "" {
			_ = c.WireGuard.UpdateEndpoint(ctx, record.WireGuardPublicKey, previous)
		}
		if relayBridge != nil {
			relayBridge.SetStandby(false)
		}
		peer.resetReceive(time.Now())
		c.nudgePeer(ctx, peer)
	}
	if err := c.WireGuard.UpdateEndpoint(ctx, record.WireGuardPublicKey, bridge.LocalAddr().String()); err != nil {
		rollback()
		return false
	}
	c.nudgePeer(ctx, peer)
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-attempt.Done():
			rollback()
			return false
		case <-deadline.C:
			rollback()
			c.iceFailed(ctx, peer, errors.New("ice: WireGuard authentication timed out"))
			return false
		case <-bridge.Done():
			rollback()
			return false
		case <-ticker.C:
			seen := c.observe(ctx)[record.WireGuardPublicKey]
			fresh := !seen.handshake.IsZero() && time.Since(seen.handshake) < wireguard.HandshakeFreshness
			if !fresh || seen.endpoint != bridge.LocalAddr().String() || bridge.Stats().BytesRecv == 0 ||
				(!seen.handshake.After(baseline.handshake) && seen.rxBytes <= baseline.rxBytes) {
				continue
			}
			if peer.Revoked() {
				rollback()
				return false
			}
			path := &icePath{bridge: bridge, remote: remote}
			c.mu.Lock()
			old := c.icePaths[peer.DeviceID()]
			c.icePaths[peer.DeviceID()] = path
			c.metrics.PunchSuccess++
			c.mu.Unlock()
			if old != nil {
				old.bridge.Close()
			}
			peer.SetEndpoint(remote)
			peer.resetReceive(time.Now())
			_, _ = peer.Apply(EventPunchSucceeded, time.Now())
			c.logger().Info("ICE direct path authenticated", "component", "nat", "peer", peer.DeviceID(), "endpoint", remote.String())
			return true
		}
	}
}
