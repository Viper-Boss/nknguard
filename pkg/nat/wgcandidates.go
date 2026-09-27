package nat

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Candidates for a kernel WireGuard interface.
//
// The problem: kernel WireGuard owns its UDP socket, so NKNGuard cannot send a
// STUN request from WireGuard's port and cannot read what arrives on it. What
// we can do is measure the NAT from a probe socket of our own and infer what
// it does to WireGuard's port.
//
// The inference that makes this work is port preservation: most home routers
// and Linux MASQUERADE keep the source port when it is free. If the probe
// socket's port comes back unchanged, WireGuard's almost certainly does too,
// and "public IP : WireGuard listen port" is a real candidate. If the probe's
// port was rewritten, the NAT is remapping and that candidate is a long shot —
// it is still advertised, at lower priority, because trying costs a few
// packets and the relay remains the fallback.
//
// The v0.2 userspace data plane (wireguard-go with a shared bind) removes the
// inference entirely: STUN, punching and WireGuard then share one socket.

// PortMapping describes how the NAT treated the probe socket.
type PortMapping struct {
	Behaviour      Behaviour
	PortPreserving bool
	PublicIP       netip.Addr
}

// WireGuardGatherer builds candidates for a WireGuard listen port.
type WireGuardGatherer struct {
	STUNServers []string
	// ListenPort returns WireGuard's current listen port. It is a function
	// because the port is only known after the interface exists, and with
	// listen_port: 0 it is chosen by the kernel.
	ListenPort func(ctx context.Context) (int, error)
	// Inner is the gatherer run on the probe socket. Zero value is fine.
	Inner Gatherer
}

// Gather returns candidates for WireGuard's port, together with what was
// learned about the NAT.
func (g *WireGuardGatherer) Gather(ctx context.Context) ([]EndpointCandidate, PortMapping, error) {
	port, err := g.ListenPort(ctx)
	if err != nil {
		return nil, PortMapping{Behaviour: BehaviourUnknown}, err
	}
	if port <= 0 || port > 65535 {
		return nil, PortMapping{Behaviour: BehaviourUnknown}, fmt.Errorf("nat: wireguard listen port %d is not usable", port)
	}
	probe, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, PortMapping{Behaviour: BehaviourUnknown}, fmt.Errorf("nat: open probe socket: %w", err)
	}
	defer probe.Close()

	inner := g.Inner
	inner.STUNServers = g.STUNServers
	probed, behaviour, err := inner.Gather(ctx, probe)
	if err != nil {
		return nil, PortMapping{Behaviour: behaviour}, err
	}
	probePort := probe.LocalAddr().(*net.UDPAddr).Port
	return RewriteForWireGuard(probed, behaviour, probePort, uint16(port))
}

// RewriteForWireGuard converts probe-socket candidates into WireGuard-port
// candidates. It is a pure function so the inference can be tested without a
// NAT.
func RewriteForWireGuard(probed []EndpointCandidate, behaviour Behaviour, probePort int, wgPort uint16) ([]EndpointCandidate, PortMapping, error) {
	mapping := PortMapping{Behaviour: behaviour}
	out := make([]EndpointCandidate, 0, len(probed))
	seenReflexive := false
	for _, candidate := range probed {
		switch candidate.Type {
		case CandidateHost:
			candidate.Port = wgPort
			out = append(out, candidate)
		case CandidateReflexive:
			if seenReflexive {
				// Several STUN servers report the same public IP; one
				// WireGuard-port candidate per IP is enough.
				continue
			}
			seenReflexive = true
			addr, err := netip.ParseAddr(candidate.IP)
			if err == nil {
				mapping.PublicIP = addr
			}
			mapping.PortPreserving = int(candidate.Port) == probePort
			candidate.Port = wgPort
			if !mapping.PortPreserving {
				candidate.Priority /= 2
			}
			out = append(out, candidate)
		}
	}
	SortCandidates(out)
	return out, mapping, nil
}
