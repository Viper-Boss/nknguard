// Package controlhub keeps discovery, signaling and relay lifetimes independent
// of the time NKN takes to connect. Backends remain owned by their callers.
package controlhub

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

type Hub struct {
	mu                 sync.RWMutex
	primary, secondary signaling.Transport
	data               relay.Relay
	source             rendezvous.Source
	addresses          map[string]string
	inbound            chan signaling.Inbound
	ready              chan struct{}
	ctx                context.Context
	cancel             context.CancelFunc
	attached           bool
}

func New(ctx context.Context, secondary signaling.Transport, source rendezvous.Source) *Hub {
	ctx, cancel := context.WithCancel(ctx)
	h := &Hub{secondary: secondary, source: source, addresses: make(map[string]string),
		inbound: make(chan signaling.Inbound, 128), ready: make(chan struct{}), ctx: ctx, cancel: cancel}
	if secondary != nil {
		go h.pump(secondary)
	}
	return h
}

// Attach is called once, after NKN opens. No controller field changes while
// its workers run; an already authenticated direct tunnel stays in place.
func (h *Hub) Attach(primary signaling.Transport, data relay.Relay, source rendezvous.Source) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.attached || primary == nil {
		return errors.New("controlhub: invalid or repeated attachment")
	}
	for id, address := range h.addresses {
		primary.SetPeerAddress(id, address)
	}
	h.primary, h.data = primary, data
	if source != nil {
		h.source = source
	}
	h.attached = true
	close(h.ready)
	go h.pump(primary)
	return nil
}

func (h *Hub) pump(t signaling.Transport) {
	for {
		select {
		case <-h.ctx.Done():
			return
		case value, ok := <-t.Receive():
			if !ok {
				return
			}
			select {
			case h.inbound <- value:
			case <-h.ctx.Done():
				return
			}
		}
	}
}

func (h *Hub) LocalAddress() string {
	h.mu.RLock()
	p := h.primary
	h.mu.RUnlock()
	if p != nil {
		return p.LocalAddress()
	}
	return ""
}
func (h *Hub) SetPeerAddress(id, address string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.addresses) < 512 || h.addresses[id] != "" {
		h.addresses[id] = address
	}
	if h.primary != nil {
		h.primary.SetPeerAddress(id, address)
	}
}
func (h *Hub) Send(ctx context.Context, id string, envelope protocol.Envelope) error {
	if h.ctx.Err() != nil {
		return signaling.ErrClosed
	}
	h.mu.RLock()
	primary, secondary := h.primary, h.secondary
	h.mu.RUnlock()
	// An established DHT stream carries only signed control envelopes. Fresh
	// connections are bootstrapped separately, never on the send critical path.
	if secondary != nil {
		fast, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := secondary.Send(fast, id, envelope)
		cancel()
		if err == nil {
			return nil
		}
	}
	if primary == nil {
		return signaling.ErrUnknownPeer
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return primary.Send(bounded, id, envelope)
}
func (h *Hub) SendAddress(ctx context.Context, address string, envelope protocol.Envelope) error {
	h.mu.RLock()
	p := h.primary
	h.mu.RUnlock()
	if p == nil {
		return signaling.ErrUnknownPeer
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.SendAddress(bounded, address, envelope)
}
func (h *Hub) Receive() <-chan signaling.Inbound { return h.inbound }
func (h *Hub) Close() error                      { h.cancel(); return nil }

// Ready closes when the primary transport attaches. A controller may run
// cached direct paths earlier, but must defer NKN introductions until then.
func (h *Hub) Ready() <-chan struct{} { return h.ready }
func (h *Hub) Open(ctx context.Context, peer relay.Peer) (net.Conn, error) {
	h.mu.RLock()
	data := h.data
	h.mu.RUnlock()
	if data == nil {
		return nil, relay.ErrNoRelay
	}
	return data.Open(ctx, peer)
}
func (h *Hub) Accept(ctx context.Context) (relay.Session, error) {
	select {
	case <-ctx.Done():
		return relay.Session{}, ctx.Err()
	case <-h.ctx.Done():
		return relay.Session{}, signaling.ErrClosed
	case <-h.ready:
	}
	h.mu.RLock()
	data := h.data
	h.mu.RUnlock()
	if acceptor, ok := data.(relay.Acceptor); ok {
		return acceptor.Accept(ctx)
	}
	// A node configured without relay must not spin an accept error loop.
	select {
	case <-ctx.Done():
		return relay.Session{}, ctx.Err()
	case <-h.ctx.Done():
		return relay.Session{}, signaling.ErrClosed
	}
}
func (h *Hub) Announce(ctx context.Context) error {
	h.mu.RLock()
	source := h.source
	h.mu.RUnlock()
	if source == nil {
		return nil
	}
	return source.Announce(ctx)
}
func (h *Hub) Addresses(ctx context.Context) ([]string, error) {
	h.mu.RLock()
	source := h.source
	h.mu.RUnlock()
	if source == nil {
		return nil, nil
	}
	return source.Addresses(ctx)
}

func (h *Hub) Available() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.data != nil && h.ctx.Err() == nil
}
