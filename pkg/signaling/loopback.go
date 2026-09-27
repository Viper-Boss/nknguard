package signaling

import (
	"context"
	"sync"

	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

// Switch wires several Loopback transports together in one process.
//
// It is how the state machine and the handshake are tested without a network:
// the envelopes are the real ones, signed and verified by the real code, and
// only the wire is fake.
type Switch struct {
	mu    sync.Mutex
	ports map[string]*Loopback
}

// NewSwitch returns an empty switch.
func NewSwitch() *Switch { return &Switch{ports: make(map[string]*Loopback)} }

// Attach creates a transport for a device and registers it.
func (s *Switch) Attach(deviceID string) *Loopback {
	port := &Loopback{
		deviceID:  deviceID,
		inbox:     make(chan Inbound, 64),
		addresses: make(map[string]string),
		owner:     s,
	}
	s.mu.Lock()
	s.ports[deviceID] = port
	s.mu.Unlock()
	return port
}

func (s *Switch) deliver(to string, message Inbound) error {
	s.mu.Lock()
	port, ok := s.ports[to]
	s.mu.Unlock()
	if !ok {
		return ErrUnknownPeer
	}
	return port.accept(message)
}

// Loopback is an in-process Transport.
type Loopback struct {
	deviceID string
	owner    *Switch

	mu        sync.Mutex
	addresses map[string]string
	closed    bool
	inbox     chan Inbound
	drop      bool
}

// SetDrop makes the port discard outbound envelopes. Tests use it to simulate
// a signalling outage while an established tunnel keeps running, which is the
// behaviour section 58 of the specification requires.
func (l *Loopback) SetDrop(drop bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drop = drop
}

// LocalAddress returns the device id, which doubles as the loopback address.
func (l *Loopback) LocalAddress() string { return l.deviceID }

// SetPeerAddress records a peer address. The loopback routes by device id and
// keeps the map only so tests can assert discovery wired it up.
func (l *Loopback) SetPeerAddress(deviceID, address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addresses[deviceID] = address
}

// PeerAddress returns what SetPeerAddress stored.
func (l *Loopback) PeerAddress(deviceID string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	address, ok := l.addresses[deviceID]
	return address, ok
}

// Send delivers through the switch.
func (l *Loopback) Send(ctx context.Context, deviceID string, envelope protocol.Envelope) error {
	l.mu.Lock()
	closed, drop := l.closed, l.drop
	l.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if drop {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Round-trip through the wire format so a test exercises Marshal and
	// Unmarshal exactly as the NKN transport would.
	raw, err := envelope.Marshal()
	if err != nil {
		return err
	}
	decoded, err := protocol.Unmarshal(raw)
	if err != nil {
		return err
	}
	return l.owner.deliver(deviceID, Inbound{Envelope: decoded, Source: l.deviceID})
}

// SendAddress delivers to a raw address, which on the loopback is a device id.
func (l *Loopback) SendAddress(ctx context.Context, address string, envelope protocol.Envelope) error {
	return l.Send(ctx, address, envelope)
}

func (l *Loopback) accept(message Inbound) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	select {
	case l.inbox <- message:
		return nil
	default:
		// A full inbox is backpressure, not a crash. The sender learns the
		// message did not land and retries under its own backoff.
		return context.DeadlineExceeded
	}
}

// Receive returns the inbound stream.
func (l *Loopback) Receive() <-chan Inbound { return l.inbox }

// Close shuts the port down.
func (l *Loopback) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.inbox)
	return nil
}
