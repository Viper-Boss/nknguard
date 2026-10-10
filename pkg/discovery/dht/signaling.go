//go:build libp2pdht

package dht

import (
	"context"
	"io"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	nkgprotocol "github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const SignalProtocol = protocol.ID("/nknguard/signal/1.0.0")

// RegisterPeer accepts ONLY records already verified and admitted by the mesh.
// The signed record binds a libp2p identity to the paired device identity.
func (b *Backend) RegisterPeer(record discovery.PeerRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.bindings) >= discovery.DefaultCacheLimit && b.bindings[record.DeviceID] == "" {
		return
	}
	delete(b.bindings, record.DeviceID)
	for i, address := range record.DHTAddresses {
		if i >= 8 {
			break
		}
		if info, err := parse(address); err == nil && info.ID != b.host.ID() {
			b.bindings[record.DeviceID] = info.ID
			return
		}
	}
}

func (b *Backend) LocalAddress() string              { return "" } // NKN address is supplied by the hub.
func (b *Backend) SetPeerAddress(string, string)     {}            // Raw NKN addresses cannot establish DHT trust.
func (b *Backend) Receive() <-chan signaling.Inbound { return b.inbound }
func (b *Backend) SendAddress(context.Context, string, nkgprotocol.Envelope) error {
	return signaling.ErrUnknownPeer
}

func (b *Backend) Send(ctx context.Context, id string, envelope nkgprotocol.Envelope) error {
	b.mu.RLock()
	target := b.bindings[id]
	b.mu.RUnlock()
	if target == "" || b.host.Network().Connectedness(target) != network.Connected {
		return signaling.ErrUnknownPeer
	}
	raw, err := envelope.Marshal()
	if err != nil {
		return err
	}
	stream, err := b.host.NewStream(ctx, target, SignalProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	deadline := time.Now().Add(2 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = stream.Reset() })
	defer stop()
	if _, err = stream.Write(raw); err != nil {
		return err
	}
	if err = stream.CloseWrite(); err != nil {
		return err
	}
	var ack [1]byte
	if _, err = io.ReadFull(stream, ack[:]); err != nil {
		return err
	}
	if ack[0] != 1 {
		return signaling.ErrClosed
	}
	return nil
}

func (b *Backend) serveSignal(stream network.Stream) {
	select {
	case b.slots <- struct{}{}:
	default:
		_ = stream.Reset()
		return
	}
	defer func() { <-b.slots }()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(stream, nkgprotocol.MaxEnvelopeBytes+1))
	if err != nil {
		_ = stream.Reset()
		return
	}
	envelope, err := nkgprotocol.Unmarshal(raw)
	if err != nil {
		_ = stream.Reset()
		return
	}
	b.mu.RLock()
	target := b.bindings[envelope.FromDeviceID]
	b.mu.RUnlock()
	if target == "" || target != stream.Conn().RemotePeer() {
		_ = stream.Reset()
		return
	}
	// No transport-specific trust shortcut: both transports feed the SAME
	// dispatcher, signature verification, replay cache and live approval ACL.
	select {
	case b.inbound <- signaling.Inbound{Envelope: envelope}:
		_, _ = stream.Write([]byte{1})
	default:
		_ = stream.Reset()
	}
}
