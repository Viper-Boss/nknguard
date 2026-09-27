package relay

import (
	"context"
	"net"
	"sync"
)

// Hub is an in-process relay network. Each device gets an endpoint that can
// Open a stream to any other device on the hub and Accept streams opened to
// it. The streams are net.Pipe, so a test exercises exactly the bytes the NKN
// relay would carry.
type Hub struct {
	mu        sync.Mutex
	endpoints map[string]*HubEndpoint
	// Down makes every Open fail, to simulate the relay being unreachable.
	Down bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{endpoints: make(map[string]*HubEndpoint)} }

// Endpoint returns (creating if needed) the relay for one device.
func (h *Hub) Endpoint(deviceID string) *HubEndpoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.endpoints[deviceID]; ok {
		return existing
	}
	created := &HubEndpoint{hub: h, deviceID: deviceID, inbox: make(chan Session, 8)}
	h.endpoints[deviceID] = created
	return created
}

// SetDown toggles the simulated outage.
func (h *Hub) SetDown(down bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Down = down
}

// HubEndpoint is one device's view of a Hub.
type HubEndpoint struct {
	hub      *Hub
	deviceID string
	inbox    chan Session
}

// Open creates a stream to another device on the hub.
func (e *HubEndpoint) Open(ctx context.Context, peer Peer) (net.Conn, error) {
	e.hub.mu.Lock()
	down := e.hub.Down
	target, ok := e.hub.endpoints[peer.DeviceID]
	e.hub.mu.Unlock()
	if down || !ok {
		return nil, ErrNoRelay
	}
	local, remote := net.Pipe()
	select {
	case target.inbox <- Session{DeviceID: e.deviceID, Conn: remote}:
		return local, nil
	case <-ctx.Done():
		_ = local.Close()
		_ = remote.Close()
		return nil, ctx.Err()
	}
}

// Accept returns the next inbound stream.
func (e *HubEndpoint) Accept(ctx context.Context) (Session, error) {
	select {
	case session := <-e.inbox:
		return session, nil
	case <-ctx.Done():
		return Session{}, ctx.Err()
	}
}
