// Package signaling carries authenticated control messages between devices.
//
// The transport is deliberately an interface with one production implementation
// (NKN) and one test implementation (Loopback). Everything above this package
// deals in signed envelopes, so swapping the transport changes how a message
// travels and nothing about what it means or who is allowed to send it.
package signaling

import (
	"context"
	"errors"

	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

// ErrClosed is returned by a transport that has been shut down.
var ErrClosed = errors.New("signaling: transport closed")

// ErrUnknownPeer means the transport has no address for that device. It is an
// ordinary condition — the peer has not been discovered yet — not a failure.
var ErrUnknownPeer = errors.New("signaling: no transport address for device")

// Inbound is a received envelope together with the transport-level source.
// The source is a hint for the log and for learning a peer's address; it is
// never what authenticates the message. FromDeviceID inside the verified
// envelope is.
type Inbound struct {
	Envelope protocol.Envelope
	Source   string
}

// Transport moves envelopes. Implementations must be safe for concurrent use.
type Transport interface {
	// LocalAddress is this node's address on the transport, e.g. an NKN
	// address. It goes into the peer record so others can reach us.
	LocalAddress() string
	// SetPeerAddress teaches the transport where a device is. It is called
	// from discovery, after the record carrying the address was verified.
	SetPeerAddress(deviceID, address string)
	// Send delivers one envelope to a known device. It must not block
	// indefinitely.
	Send(ctx context.Context, deviceID string, envelope protocol.Envelope) error
	// SendAddress delivers to a raw transport address whose device is not yet
	// known. Only PEER_INFO introductions use it.
	SendAddress(ctx context.Context, address string, envelope protocol.Envelope) error
	// Receive returns the stream of inbound envelopes. The channel is closed
	// when the transport shuts down.
	Receive() <-chan Inbound
	Close() error
}

// Dispatcher verifies inbound envelopes and hands the survivors to handlers.
// It is the single place where a message becomes trusted, which is why the
// acceptance rules are not duplicated anywhere else.
type Dispatcher struct {
	Acceptor *protocol.Acceptor
	// Authorized reports whether a verified device is allowed to talk to us at
	// all. Membership, not authenticity — a correctly signed envelope from a
	// device that was revoked still gets dropped here.
	Authorized func(deviceID string) bool
	// OnRejected is called for every dropped envelope. Wiring it to a counter
	// is how a node notices it is being probed.
	OnRejected func(inbound Inbound, err error)
	// Open lists message types accepted from devices that are not yet
	// members. Their handlers must establish membership from the payload
	// itself. They are rate limited by OpenLimit, because anyone who knows
	// our transport address can send them.
	Open      map[protocol.MessageType]bool
	OpenLimit *RateLimiter

	handlers map[protocol.MessageType]Handler
}

// Handler processes one verified envelope.
type Handler func(ctx context.Context, envelope protocol.Envelope) error

type sourceContextKey struct{}

// Source reports the transport address the current message arrived from. It
// is untrusted metadata; handlers may use it to bind a reply address to the
// sender, never as a replacement for envelope signature verification.
func Source(ctx context.Context) string {
	value, _ := ctx.Value(sourceContextKey{}).(string)
	return value
}

// Handle registers a handler for a message type. Registering twice for the
// same type replaces the first, which keeps wiring order from mattering.
func (d *Dispatcher) Handle(messageType protocol.MessageType, handler Handler) {
	if d.handlers == nil {
		d.handlers = make(map[protocol.MessageType]Handler)
	}
	d.handlers[messageType] = handler
}

// ErrNotAuthorized is the dispatcher's refusal for a non-member.
var ErrNotAuthorized = errors.New("signaling: sender is not a member of this network")

// ErrRateLimited means an open message type arrived faster than allowed.
var ErrRateLimited = errors.New("signaling: rate limited")

// ErrNoHandler means the message type is valid but nothing is registered for
// it. A newer peer sending a type we do not implement lands here and is
// dropped quietly rather than failing the connection.
var ErrNoHandler = errors.New("signaling: no handler for message type")

// Dispatch verifies and routes one inbound envelope.
func (d *Dispatcher) Dispatch(ctx context.Context, inbound Inbound) error {
	open := d.Open[inbound.Envelope.Type]
	if open && d.OpenLimit != nil && !d.OpenLimit.Allow() {
		// Checked before signature verification on purpose: an Ed25519 verify
		// is the expensive part, and a flood should not get to make us do it.
		d.reject(inbound, ErrRateLimited)
		return ErrRateLimited
	}
	if err := d.Acceptor.Verify(inbound.Envelope); err != nil {
		d.reject(inbound, err)
		return err
	}
	if !open && d.Authorized != nil && !d.Authorized(inbound.Envelope.FromDeviceID) {
		d.reject(inbound, ErrNotAuthorized)
		return ErrNotAuthorized
	}
	handler, ok := d.handlers[inbound.Envelope.Type]
	if !ok {
		d.reject(inbound, ErrNoHandler)
		return ErrNoHandler
	}
	if err := handler(context.WithValue(ctx, sourceContextKey{}, inbound.Source), inbound.Envelope); err != nil {
		d.reject(inbound, err)
		return err
	}
	return nil
}

// Run pumps a transport through the dispatcher until ctx is done or the
// transport closes. It returns when the receive channel is drained, so a
// caller that waits on it knows no handler is still running.
func (d *Dispatcher) Run(ctx context.Context, transport Transport) error {
	inbound := transport.Receive()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message, open := <-inbound:
			if !open {
				return ErrClosed
			}
			_ = d.Dispatch(ctx, message)
		}
	}
}

func (d *Dispatcher) reject(inbound Inbound, err error) {
	if d.OnRejected != nil {
		d.OnRejected(inbound, err)
	}
}
