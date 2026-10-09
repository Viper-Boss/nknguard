package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// MaxDatagram is the largest WireGuard datagram the bridge will frame. It is
// the UDP maximum; WireGuard's own packets are MTU-sized, and anything larger
// would be a bug somewhere else.
const MaxDatagram = 65535

// Bridge carries WireGuard's UDP datagrams over a relay stream.
//
// Framing is two bytes of big-endian length and the datagram. There is no
// encryption here and there should not be: the payload is already a WireGuard
// packet, and wrapping ciphertext in more ciphertext buys nothing.
type Bridge struct {
	stream net.Conn
	udp    *net.UDPConn
	wg     netip.AddrPort

	sent     atomic.Int64
	received atomic.Int64
	standby  atomic.Bool
	gate     sync.RWMutex
	openedAt time.Time

	closeOnce sync.Once
	done      chan struct{}
}

// NewBridge binds a loopback UDP socket for one relayed peer. wireguard is the
// local WireGuard listen address (127.0.0.1:<listen_port>): the bridge only
// accepts datagrams from it, so a process on this host cannot inject traffic
// into the relay by guessing the bridge port.
func NewBridge(stream net.Conn, wireguard netip.AddrPort) (*Bridge, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("relay: bind bridge: %w", err)
	}
	return &Bridge{stream: stream, udp: udp, wg: wireguard, openedAt: time.Now(), done: make(chan struct{})}, nil
}

// LocalAddr is what WireGuard's endpoint for this peer is set to while the
// relay carries it.
func (b *Bridge) LocalAddr() netip.AddrPort { return b.udp.LocalAddr().(*net.UDPAddr).AddrPort() }

// SetStandby drains but discards relay datagrams while direct is selected.
// Inbound stragglers must not make WireGuard roam back to loopback.
func (b *Bridge) SetStandby(standby bool) {
	b.gate.Lock()
	b.standby.Store(standby)
	b.gate.Unlock()
}

func (b *Bridge) Standby() bool { return b.standby.Load() }

// Stats reports the traffic moved.
func (b *Bridge) Stats() Stats {
	open := true
	select {
	case <-b.done:
		open = false
	default:
	}
	return Stats{Open: open, Standby: b.Standby(), OpenedAt: b.openedAt, BytesSent: b.sent.Load(), BytesRecv: b.received.Load()}
}

// Done is closed when the bridge stops.
func (b *Bridge) Done() <-chan struct{} { return b.done }

// Run pumps in both directions until ctx is done or either side fails. It
// always closes both the socket and the stream before returning, so a caller
// that waits on Run knows nothing is left open.
func (b *Bridge) Run(ctx context.Context) error {
	errs := make(chan error, 2)
	go func() { errs <- b.udpToStream() }()
	go func() { errs <- b.streamToUDP() }()

	var first error
	select {
	case <-ctx.Done():
		first = ctx.Err()
	case first = <-errs:
	}
	b.Close()
	// Wait for the other pump; Close has unblocked it.
	<-errs
	if first == nil {
		first = <-errs
	}
	return first
}

// Close stops the bridge. It is safe to call more than once.
func (b *Bridge) Close() {
	b.closeOnce.Do(func() {
		close(b.done)
		_ = b.udp.Close()
		_ = b.stream.Close()
	})
}

func (b *Bridge) udpToStream() error {
	buffer := make([]byte, 2+MaxDatagram)
	for {
		read, from, err := b.udp.ReadFromUDPAddrPort(buffer[2:])
		if err != nil {
			return err
		}
		if from.Addr().Unmap() != b.wg.Addr().Unmap() || from.Port() != b.wg.Port() {
			continue
		}
		if b.Standby() {
			continue
		}
		binary.BigEndian.PutUint16(buffer[:2], uint16(read))
		// A stalled stream must not hold the UDP pump indefinitely.
		if err := b.stream.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		frame := buffer[:2+read]
		for len(frame) > 0 {
			n, err := b.stream.Write(frame)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			frame = frame[n:]
		}
		if err := b.stream.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
		b.sent.Add(int64(read))
	}
}

func (b *Bridge) streamToUDP() error {
	header := make([]byte, 2)
	buffer := make([]byte, MaxDatagram)
	for {
		if _, err := io.ReadFull(b.stream, header); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(header))
		if size == 0 {
			return errors.New("relay: zero-length frame")
		}
		if _, err := io.ReadFull(b.stream, buffer[:size]); err != nil {
			return err
		}
		b.gate.RLock()
		if b.Standby() {
			b.gate.RUnlock()
			continue
		}
		_, err := b.udp.WriteToUDPAddrPort(buffer[:size], b.wg)
		b.gate.RUnlock()
		if err != nil {
			return err
		}
		b.received.Add(int64(size))
	}
}
