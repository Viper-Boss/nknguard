package userspace

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nat"
	"golang.zx2c4.com/wireguard/conn"
)

// stunBind demultiplexes STUN replies from WireGuard's actual UDP socket.
// Probing a separate socket cannot discover a carrier NAT's WireGuard port.
type stunBind struct {
	conn.Bind
	mu      sync.Mutex
	probeMu sync.Mutex
	port    uint16
	probe   *stunProbe
}
type stunPacket struct {
	data []byte
	addr net.Addr
}
type stunProbe struct {
	bind     *stunBind
	packets  chan stunPacket
	closed   chan struct{}
	deadline time.Time
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receivers, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	if actual == 0 {
		actual = port
	}
	b.mu.Lock()
	b.port = actual
	b.mu.Unlock()
	for i, receive := range receivers {
		receive := receive
		receivers[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			for j := 0; j < n; j++ {
				if sizes[j] < 20 {
					continue
				}
				packet := packets[j][:sizes[j]]
				if packet[0]&0xc0 != 0 || binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
					continue
				}
				sizes[j] = 0 // STUN must never enter WireGuard's packet queues.
				if len(packet) > 2048 || endpoints[j] == nil {
					continue
				}
				addr, e := net.ResolveUDPAddr("udp", endpoints[j].DstToString())
				if e != nil {
					continue
				}
				b.mu.Lock()
				if p := b.probe; p != nil {
					select {
					case p.packets <- stunPacket{append([]byte(nil), packet...), addr}:
					default:
					}
				}
				b.mu.Unlock()
			}
			return n, err
		}
	}
	return receivers, actual, nil
}
func (b *stunBind) Close() error {
	b.mu.Lock()
	if b.probe != nil {
		close(b.probe.closed)
		b.probe = nil
	}
	b.port = 0
	b.mu.Unlock()
	return b.Bind.Close()
}
func (b *stunBind) gather(ctx context.Context, g nat.Gatherer) ([]nat.EndpointCandidate, nat.Behaviour, error) {
	b.probeMu.Lock()
	defer b.probeMu.Unlock()
	b.mu.Lock()
	if b.port == 0 {
		b.mu.Unlock()
		return nil, nat.BehaviourUnknown, net.ErrClosed
	}
	p := &stunProbe{bind: b, packets: make(chan stunPacket, 16), closed: make(chan struct{})}
	b.probe = p
	b.mu.Unlock()
	defer p.Close()
	return g.Gather(ctx, p)
}
func (p *stunProbe) ReadFrom(dst []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	if !p.deadline.IsZero() {
		timer := time.NewTimer(time.Until(p.deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case packet := <-p.packets:
		return copy(dst, packet.data), packet.addr, nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: context.DeadlineExceeded}
	}
}
func (p *stunProbe) WriteTo(data []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	ep, err := p.bind.ParseEndpoint(addr.String())
	if err != nil {
		return 0, err
	}
	if err = p.bind.Send([][]byte{data}, ep); err != nil {
		return 0, err
	}
	return len(data), nil
}
func (p *stunProbe) Close() error {
	p.bind.mu.Lock()
	defer p.bind.mu.Unlock()
	if p.bind.probe == p {
		close(p.closed)
		p.bind.probe = nil
	}
	return nil
}
func (p *stunProbe) LocalAddr() net.Addr {
	p.bind.mu.Lock()
	defer p.bind.mu.Unlock()
	return &net.UDPAddr{IP: net.IPv4zero, Port: int(p.bind.port)}
}
func (p *stunProbe) SetDeadline(t time.Time) error     { p.deadline = t; return nil }
func (p *stunProbe) SetReadDeadline(t time.Time) error { p.deadline = t; return nil }
func (p *stunProbe) SetWriteDeadline(time.Time) error  { return nil }

// CandidateSource probes the same socket used by WireGuard, preserving the
// external port returned by STUN rather than assuming port-preserving NAT.
type CandidateSource struct {
	Manager  *Manager
	Gatherer nat.Gatherer
}

func (s *CandidateSource) Gather(ctx context.Context) ([]nat.EndpointCandidate, nat.PortMapping, error) {
	s.Manager.mu.Lock()
	bind := s.Manager.stun
	s.Manager.mu.Unlock()
	if bind == nil {
		return nil, nat.PortMapping{Behaviour: nat.BehaviourUnknown}, net.ErrClosed
	}
	candidates, behaviour, err := bind.gather(ctx, s.Gatherer)
	mapping := nat.PortMapping{Behaviour: behaviour}
	for _, candidate := range candidates {
		if candidate.Type == nat.CandidateReflexive {
			mapping.PublicIP, _ = netip.ParseAddr(candidate.IP)
			break
		}
	}
	return candidates, mapping, err
}
