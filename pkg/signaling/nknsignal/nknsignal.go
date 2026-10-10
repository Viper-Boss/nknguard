//go:build nknsdk

// Package nknsignal is the NKN transport for control messages.
//
// NKN carries the envelope; it does not authenticate it. MultiClient messages
// are end-to-end encrypted to the destination's NKN key, which keeps relay
// nodes from reading them, but the envelope's own Ed25519 signature is what
// the dispatcher trusts. An unencrypted message is dropped here anyway,
// because nothing in this protocol has a reason to be sent in the clear.
package nknsignal

import (
	"context"
	"sync"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

// Connection state has no offline queue. Reconnecting peers exchange current
// signed records, not old ports and expired ICE sessions. Pairing alone keeps
// a short delivery window while the phone moves from scanning to connecting.
const MaxHoldingSeconds = 0

func holdingSeconds(kind protocol.MessageType) int32 {
	if kind == protocol.TypePairRequest || kind == protocol.TypePairApproval {
		return 30
	}
	return MaxHoldingSeconds
}

// Transport implements signaling.Transport over an NKN MultiClient.
type Transport struct {
	client *nkn.MultiClient

	mu        sync.RWMutex
	addresses map[string]string // device id -> NKN address
	devices   map[string]string // NKN address -> device id

	inbox      chan signaling.Inbound
	done       chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
	health     healthState
	healthOnce sync.Once
}

// New wraps a connected client and starts the receive pump.
func New(client *nkn.MultiClient) *Transport {
	transport := &Transport{
		client:    client,
		addresses: make(map[string]string),
		devices:   make(map[string]string),
		inbox:     make(chan signaling.Inbound, 256),
		done:      make(chan struct{}),
	}
	transport.health.init(nknclient.NormaliseAddress(client.Address()))
	transport.wg.Add(1)
	go transport.pump()
	return transport
}

// LocalAddress is this node's NKN address.
func (t *Transport) LocalAddress() string { return nknclient.NormaliseAddress(t.client.Address()) }

// SetPeerAddress records where a verified device lives.
func (t *Transport) SetPeerAddress(deviceID, address string) {
	address = nknclient.NormaliseAddress(address)
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous, ok := t.addresses[deviceID]; ok && previous != address {
		delete(t.devices, previous)
	}
	t.addresses[deviceID] = address
	t.devices[address] = deviceID
}

// DeviceFor maps an NKN address back to a device, for the relay's inbound
// sessions. The answer is only as good as the verified records behind it.
func (t *Transport) DeviceFor(address string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	device, ok := t.devices[nknclient.NormaliseAddress(address)]
	return device, ok
}

// AddressOf returns a device's NKN address.
func (t *Transport) AddressOf(deviceID string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	address, ok := t.addresses[deviceID]
	return address, ok
}

// Send delivers to a known device.
func (t *Transport) Send(ctx context.Context, deviceID string, envelope protocol.Envelope) error {
	address, ok := t.AddressOf(deviceID)
	if !ok {
		return signaling.ErrUnknownPeer
	}
	return t.SendAddress(ctx, address, envelope)
}

// SendAddress delivers to a raw NKN address.
func (t *Transport) SendAddress(ctx context.Context, address string, envelope protocol.Envelope) error {
	select {
	case <-t.done:
		return signaling.ErrClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := envelope.Marshal()
	if err != nil {
		return err
	}
	_, err = t.client.Send(nkn.NewStringArray(address), raw, &nkn.MessageConfig{NoReply: true, MaxHoldingSeconds: holdingSeconds(envelope.Type)})
	return err
}

// Receive returns the inbound stream.
func (t *Transport) Receive() <-chan signaling.Inbound { return t.inbox }

func (t *Transport) pump() {
	defer t.wg.Done()
	defer close(t.inbox)
	for {
		select {
		case <-t.done:
			return
		case message, ok := <-t.client.OnMessage.C:
			if !ok {
				return
			}
			if message == nil || !message.Encrypted || len(message.Data) > protocol.MaxEnvelopeBytes {
				continue
			}
			if t.health.accept(nknclient.NormaliseAddress(message.Src), message.Data, time.Now()) {
				continue
			}
			envelope, err := protocol.Unmarshal(message.Data)
			if err != nil {
				continue
			}
			select {
			case t.inbox <- signaling.Inbound{Envelope: envelope, Source: nknclient.NormaliseAddress(message.Src)}:
			default:
				// A full inbox drops rather than blocks: the NKN client's
				// own buffers must keep draining, and the sender retries.
			}
		}
	}
}

// Close stops the pump and closes the client.
func (t *Transport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)
		t.health.failed("closed", time.Now())
		err = t.client.Close()
		t.wg.Wait()
	})
	return err
}
