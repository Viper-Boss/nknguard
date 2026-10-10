package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

// A failed connection has a finite lease. Repeated packets cannot renew it.
const connectionRecoveryWindow = 90 * time.Second

type connectionWindow struct {
	id         string
	until      time.Time
	started    int64
	closed     bool
	online     bool
	recovering bool
	previousID string
}

func (c *Controller) ownerConnectionActive(id string, now time.Time) bool {
	c.mu.RLock()
	w, ok := c.connections[id]
	c.mu.RUnlock()
	return ok && !w.closed && (w.online || now.Before(w.until))
}

func (c *Controller) acceptConnectionRequest(id string, info protocol.PeerInfo, timestamp int64) bool {
	now := time.Now()
	until := now.Add(connectionRecoveryWindow)
	if info.ConnectUntil != 0 {
		until = time.Unix(info.ConnectUntil, 0)
		if !until.After(now) || until.After(now.Add(connectionRecoveryWindow+5*time.Second)) || info.ConnectionID == "" || len(info.ConnectionID) > 64 {
			return false
		}
	}
	c.mu.Lock()
	old, ok := c.connections[id]
	if ok && old.id == info.ConnectionID {
		active := !old.closed && (old.online || now.Before(old.until))
		c.mu.Unlock()
		return active
	}
	if ok && (timestamp < old.started || (info.ConnectionID != "" && info.ConnectionID == old.previousID)) {
		c.mu.Unlock()
		return false
	}
	passive := ok && old.online && old.id == "" && old.started == 0
	c.connections[id] = connectionWindow{id: info.ConnectionID, until: until, started: timestamp, previousID: old.id, online: passive}
	c.mu.Unlock()
	if ok && !old.closed && !passive {
		c.closeConnectionPaths(id, "正在建立新会话")
	}
	return true
}

func (c *Controller) stopOwnerConnection(id, sessionID, reason string) {
	c.mu.Lock()
	w, ok := c.connections[id]
	if !ok || sessionID != w.id {
		c.mu.Unlock()
		return
	}
	w.closed = true
	w.online = false
	c.connections[id] = w
	c.mu.Unlock()
	c.closeConnectionPaths(id, reason)
}

func (c *Controller) closeConnectionPaths(id, reason string) {
	c.mu.RLock()
	op := c.iceOperations[id]
	c.mu.RUnlock()
	if op != nil {
		op.cancel()
	}
	c.closeICEPath(id)
	c.dropBridge(id, reason)
	if p, ok := c.lookupPeer(id); ok {
		p.endpointMu.Lock()
		if c.WireGuard != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = c.WireGuard.RemovePeer(ctx, p.Record().WireGuardPublicKey)
			cancel()
		}
		p.mu.Lock()
		p.installedKey = ""
		p.path = PathNone
		p.state = StateOffline
		p.lastError = reason
		p.mu.Unlock()
		p.endpointMu.Unlock()
	}
}

// ConnectionStatus is computed locally; ticking the UI sends no messages.
func (c *Controller) ConnectionStatus(id string) (string, int64) {
	c.mu.RLock()
	w, ok := c.connections[id]
	until := c.clientConnectUntil
	c.mu.RUnlock()
	if !ok && c.Config.ClientDevice && !until.IsZero() {
		w = connectionWindow{until: until}
		ok = true
		if time.Now().After(until) {
			w.closed = true
		}
	}
	if !ok {
		return "idle", 0
	}
	if w.closed {
		return "disconnected", 0
	}
	if w.online {
		return "connected", 0
	}
	remaining := int64(time.Until(w.until).Seconds()) + 1
	if remaining < 0 {
		remaining = 0
	}
	if w.recovering {
		return "reconnecting", remaining
	}
	return "connecting", remaining
}

// updateConnection observes the authenticated data path, not NKN presence.
func (c *Controller) updateConnection(id string, healthy bool, now time.Time) bool {
	if !c.Config.OwnerDevice && !c.Config.ClientDevice {
		return true
	}
	c.mu.Lock()
	w, ok := c.connections[id]
	if !ok && c.Config.ClientDevice {
		w = connectionWindow{id: c.clientConnectionID, until: c.clientConnectUntil}
		ok = !w.until.IsZero()
	}
	if !ok {
		// A cached verified WireGuard key can receive an authenticated handshake
		// before signaling opens. No unsolicited traffic is sent to wake it.
		if healthy {
			w = connectionWindow{online: true}
			ok = true
		}
	}
	if !ok || w.closed {
		c.mu.Unlock()
		return false
	}
	if healthy {
		w.online = true
		w.recovering = false
	} else if w.online {
		w.online = false
		w.recovering = true
		w.until = now.Add(connectionRecoveryWindow)
	}
	expired := !w.online && !now.Before(w.until)
	if expired {
		w.closed = true
	}
	c.connections[id] = w
	c.mu.Unlock()
	if expired {
		c.closeConnectionPaths(id, "恢复超时，连接已停止")
	}
	return !expired
}

func (c *Controller) clientConnectLoop(ctx context.Context) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return
	}
	id := hex.EncodeToString(random[:])
	c.mu.Lock()
	c.clientConnectionID = id
	c.clientConnectUntil = time.Now().Add(connectionRecoveryWindow)
	c.mu.Unlock()
	if !signalingReady(ctx, c.Signaling) {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		c.clientConnectionRequest(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Controller) clientConnectionRequest(ctx context.Context) {
	c.mu.RLock()
	sessionID := c.clientConnectionID
	until := c.clientConnectUntil
	acknowledged := c.clientInfoReceived
	c.mu.RUnlock()
	records := c.Records()
	healthy := false
	for _, r := range records {
		if p, ok := c.lookupPeer(r.DeviceID); ok && p.Path() != PathNone {
			healthy = true
		}
	}
	if healthy && acknowledged {
		return
	}
	// Retry on the same fixed lease. A recovery lease replaces a completed one.
	for _, r := range records {
		c.mu.Lock()
		w, ok := c.connections[r.DeviceID]
		if !ok {
			w = connectionWindow{id: sessionID, until: until}
			c.connections[r.DeviceID] = w
		}
		if w.id == "" {
			w.id = sessionID
			c.connections[r.DeviceID] = w
		}
		if w.recovering && w.id == sessionID && w.until.After(until) {
			var random [16]byte
			if _, err := rand.Read(random[:]); err == nil {
				sessionID = hex.EncodeToString(random[:])
				c.clientConnectionID = sessionID
				w.id = sessionID
				c.connections[r.DeviceID] = w
			}
			until = w.until
			c.clientConnectUntil = until
		}
		c.mu.Unlock()
		if w.closed {
			return
		}
	}
	if time.Now().After(until) {
		return
	}
	own, err := c.buildRecord(ctx)
	if err != nil {
		return
	}
	raw, err := own.Marshal()
	if err != nil {
		return
	}
	info := protocol.PeerInfo{Record: raw, WantReply: true, ConnectionID: sessionID, ConnectUntil: until.Unix()}
	if len(records) > 0 {
		for _, r := range records {
			c.Signaling.SetPeerAddress(r.DeviceID, r.NKNAddress)
			_ = c.send(ctx, r.DeviceID, protocol.TypePeerInfo, info)
		}
	} else if c.Rendezvous != nil {
		addresses, err := c.Rendezvous.Addresses(ctx)
		if err != nil {
			return
		}
		envelope, err := protocol.Seal(c.Device, c.Config.NetworkID, "", protocol.TypePeerInfo, info)
		if err != nil {
			return
		}
		for _, address := range addresses {
			_ = c.Signaling.SendAddress(ctx, address, envelope)
		}
	}
}

func (c *Controller) ownerConnectLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, r := range c.Records() {
				c.mu.RLock()
				w := c.connections[r.DeviceID]
				c.mu.RUnlock()
				if w.closed {
					continue
				}
				if !w.online && !w.until.IsZero() && !now.Before(w.until) {
					c.stopOwnerConnection(r.DeviceID, w.id, "恢复超时，连接已停止")
					continue
				}
				if !c.ownerConnectionActive(r.DeviceID, now) || w.online {
					continue
				}
				own, err := c.buildRecord(ctx)
				if err != nil {
					continue
				}
				raw, err := own.Marshal()
				if err != nil {
					continue
				}
				_ = c.send(ctx, r.DeviceID, protocol.TypePeerInfo, protocol.PeerInfo{Record: raw, ConnectionID: w.id, ConnectUntil: w.until.Unix()})
			}
		}
	}
}

// Called before canceling the session so the transport is still available.
func (c *Controller) NotifyDisconnect(ctx context.Context) {
	if c.Signaling == nil {
		return
	}
	c.mu.RLock()
	id := c.clientConnectionID
	c.mu.RUnlock()
	for _, r := range c.Records() {
		_ = c.send(ctx, r.DeviceID, protocol.TypeDisconnect, protocol.Disconnect{ConnectionID: id})
	}
}
