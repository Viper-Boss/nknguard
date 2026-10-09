package nat

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// CandidateLifetime is how long a gathered candidate is considered current.
// A NAT mapping is not a property of the host, it is a row in a middlebox's
// table that can vanish, so the number is minutes rather than hours.
const CandidateLifetime = 5 * time.Minute

// Mapping describes what the NAT did to one socket, as seen from outside.
type Mapping struct {
	Local    netip.AddrPort
	Observed []netip.AddrPort
}

// Behaviour classifies a NAT from the mappings observed through two different
// servers. It is a hint for the log and the doctor command, never a decision:
// the code always tries to punch, because the classification can be wrong and
// the cost of trying is a few packets.
type Behaviour string

const (
	// BehaviourUnknown means we could not learn enough to say.
	BehaviourUnknown Behaviour = "unknown"
	// BehaviourOpen means the observed address equals the local one — no NAT
	// in the path, or a full-cone one that behaves like it.
	BehaviourOpen Behaviour = "open"
	// BehaviourEndpointIndependent means the same external port was reported
	// by every server. Hole punching usually works.
	BehaviourEndpointIndependent Behaviour = "endpoint-independent"
	// BehaviourAddressDependent means the external port changed per server:
	// classic symmetric NAT. A direct path is possible but far less likely,
	// and the relay is what will carry this peer.
	BehaviourAddressDependent Behaviour = "address-dependent"
)

// Classify turns observed mappings into a behaviour hint.
func Classify(local netip.AddrPort, observed []netip.AddrPort) Behaviour {
	if len(observed) == 0 {
		return BehaviourUnknown
	}
	first := observed[0]
	if first.Addr().Unmap() == local.Addr().Unmap() && first.Port() == local.Port() {
		return BehaviourOpen
	}
	if len(observed) == 1 {
		return BehaviourUnknown
	}
	for _, candidate := range observed[1:] {
		if candidate != first {
			return BehaviourAddressDependent
		}
	}
	return BehaviourEndpointIndependent
}

// Gatherer collects the local candidate set for one UDP socket.
type Gatherer struct {
	// STUNServers is ordered; every one that answers contributes an observed
	// mapping, which is what makes the behaviour classification possible.
	STUNServers []string
	// STUNTimeout bounds each individual query.
	STUNTimeout time.Duration
	// Interfaces is injectable for tests. Nil uses net.Interfaces.
	Interfaces func() ([]net.Addr, error)
	// Now is injectable for tests. Nil uses time.Now.
	Now func() time.Time
}

func (g *Gatherer) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gatherer) stunTimeout() time.Duration {
	if g.STUNTimeout > 0 {
		return g.STUNTimeout
	}
	return 3 * time.Second
}

// Gather returns the candidates for conn together with what the NAT appears to
// be doing. A STUN failure is not an error: a host with no reflexive candidate
// can still be reached on its LAN, and reporting "no candidates at all" for a
// blocked UDP/3478 would be wrong.
func (g *Gatherer) Gather(ctx context.Context, conn net.PacketConn) ([]EndpointCandidate, Behaviour, error) {
	local, err := localAddrPort(conn)
	if err != nil {
		return nil, BehaviourUnknown, err
	}
	now := g.now()
	candidates := make([]EndpointCandidate, 0, MaxCandidates)
	for _, host := range g.hostAddresses(local.Port()) {
		candidates = append(candidates, NewCandidate(CandidateHost, host, CandidateLifetime, now))
	}
	// Docker bridges and IPv6 interfaces must not fill the entire bounded
	// list before the public mappings are appended.
	SortCandidates(candidates)
	if len(candidates) > MaxCandidates-4 {
		candidates = candidates[:MaxCandidates-4]
	}

	observed := make([]netip.AddrPort, 0, len(g.STUNServers))
	for _, server := range g.STUNServers {
		if ctx.Err() != nil {
			break
		}
		mapped, err := STUNQuery(ctx, conn, server, g.stunTimeout())
		if err != nil {
			continue
		}
		observed = append(observed, mapped)
	}
	for _, mapped := range observed {
		candidates = append(candidates, NewCandidate(CandidateReflexive, mapped, CandidateLifetime, now))
	}
	return SanitiseCandidates(candidates, now), Classify(local, observed), nil
}

// hostAddresses lists the unicast addresses of this machine, paired with the
// port the socket is bound to.
func (g *Gatherer) hostAddresses(port uint16) []netip.AddrPort {
	lister := g.Interfaces
	if lister == nil {
		lister = net.InterfaceAddrs
	}
	addrs, err := lister()
	if err != nil {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, raw := range addrs {
		network, ok := raw.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		out = append(out, netip.AddrPortFrom(addr, port))
	}
	return out
}

func localAddrPort(conn net.PacketConn) (netip.AddrPort, error) {
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("nat: socket is %T, expected a UDP address", conn.LocalAddr())
	}
	return udp.AddrPort(), nil
}
