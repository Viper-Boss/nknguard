package mesh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// DirectAttempt is everything a strategy needs to try one peer.
type DirectAttempt struct {
	DeviceID           string
	WireGuardPublicKey string
	VirtualIP          netip.Addr
	Candidates         []nat.EndpointCandidate
	LocalCandidates    []nat.EndpointCandidate
	// StartAt is the rendezvous both sides agreed on over signalling.
	StartAt time.Time
	Token   nat.SessionToken
}

// DirectStrategy establishes a direct path. It returns the endpoint that
// worked, as observed by the data plane.
type DirectStrategy interface {
	Attempt(ctx context.Context, attempt DirectAttempt) (netip.AddrPort, error)
}

// ErrNoDirectPath is the ordinary "did not work" outcome.
var ErrNoDirectPath = errors.New("mesh: no direct path to peer")

// WireGuardStrategy punches with WireGuard's own handshake packets.
//
// Kernel WireGuard owns its socket, so NKNGuard cannot send probes from it.
// It does not need to: a handshake initiation is a UDP packet from exactly the
// right port. Both sides set the other's candidate as the peer endpoint at the
// same rendezvous instant; each side's initiation opens its own NAT mapping,
// and the other side's initiation then arrives at a mapping that exists. The
// handshake completing is simultaneously the punch succeeding and the tunnel
// coming up, and it is observed, not inferred.
//
// WireGuard holds one endpoint per peer at a time, so candidates are tried in
// sequence, best first, each for a short window. Both sides order candidates
// the same way, so their windows line up; when they do not, the NAT mapping
// opened in an earlier window is usually still alive for the later one.
type WireGuardStrategy struct {
	WireGuard wireguard.Manager
	// PerCandidate is how long each candidate gets. WireGuard retries an
	// unanswered initiation every five seconds, so a window much shorter than
	// that relies on the nudge.
	PerCandidate time.Duration
	// PollInterval is how often the handshake time is read back.
	PollInterval time.Duration
	// MaxCandidates bounds the attempt.
	MaxCandidates int
	// Nudge makes WireGuard send an initiation now instead of at the next
	// keepalive. The daemon points it at a UDP send to the peer's overlay
	// address; nil relies on the keepalive alone.
	Nudge func(ctx context.Context, virtualIP netip.Addr)
}

// Attempt runs the sequence. It is bounded: MaxCandidates × PerCandidate plus
// the rendezvous wait, and it returns on ctx cancellation immediately.
func (s *WireGuardStrategy) Attempt(ctx context.Context, attempt DirectAttempt) (netip.AddrPort, error) {
	perCandidate := s.PerCandidate
	if perCandidate <= 0 {
		perCandidate = 6 * time.Second
	}
	poll := s.PollInterval
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	limit := s.MaxCandidates
	if limit <= 0 {
		limit = 4
	}
	if attempt.WireGuardPublicKey == "" {
		return netip.AddrPort{}, ErrNoDirectPath
	}
	if wait := time.Until(attempt.StartAt); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return netip.AddrPort{}, ctx.Err()
		case <-timer.C:
		}
	}
	candidates := directCandidates(attempt.Candidates, attempt.LocalCandidates, limit)
	for _, candidate := range candidates {
		target, err := candidate.AddrPort()
		if err != nil {
			continue
		}
		if err := s.WireGuard.UpdateEndpoint(ctx, attempt.WireGuardPublicKey, target.String()); err != nil {
			return netip.AddrPort{}, err
		}
		// Read the baseline after assigning the candidate. A relay packet
		// received between a pre-assignment snapshot and UpdateEndpoint
		// would otherwise look like new direct traffic at the assigned IP.
		// Nudge only after this snapshot so replies prove this candidate.
		baseline := s.snapshot(ctx, attempt.WireGuardPublicKey)
		if s.Nudge != nil && attempt.VirtualIP.IsValid() {
			s.Nudge(ctx, attempt.VirtualIP)
		}
		deadline := time.Now().Add(perCandidate)
		for time.Now().Before(deadline) {
			if endpoint, ok := s.handshakeAfter(ctx, attempt.WireGuardPublicKey, baseline); ok {
				if !endpoint.IsValid() {
					endpoint = target
				}
				return endpoint, nil
			}
			select {
			case <-ctx.Done():
				return netip.AddrPort{}, ctx.Err()
			case <-time.After(poll):
			}
		}
	}
	return netip.AddrPort{}, ErrNoDirectPath
}

func directCandidates(remote, local []nat.EndpointCandidate, limit int) []nat.EndpointCandidate {
	out := nat.SanitiseCandidates(remote, time.Now())
	score := func(candidate nat.EndpointCandidate) int {
		addr, err := netip.ParseAddr(candidate.IP)
		if err != nil {
			return 0
		}
		if addr.Is6() && addr.IsGlobalUnicast() && !addr.IsPrivate() {
			return 8000
		}
		if addr.IsPrivate() {
			bits := 24
			if addr.Is6() {
				bits = 64
			}
			for _, own := range local {
				ip, err := netip.ParseAddr(own.IP)
				if err == nil && own.Type == nat.CandidateHost && ip.BitLen() == addr.BitLen() && netip.PrefixFrom(ip, bits).Contains(addr) {
					if addr.Is6() {
						return 8000
					}
					return 10000
				}
			}
			return 0
		}
		if addr.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
			return 0
		}
		// Prefer usable IPv4 mappings before IPv6, retaining IPv6 as a
		// fallback when NAT or filtering prevents an IPv4 handshake.
		if addr.Is4() {
			return 9000
		}
		return 8000
	}
	filtered := out[:0]
	for _, candidate := range out {
		if score(candidate) > 0 {
			filtered = append(filtered, candidate)
		}
	}
	out = filtered
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) > score(out[j]) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *WireGuardStrategy) snapshot(ctx context.Context, publicKey string) wireguard.PeerStats {
	stats, err := s.WireGuard.Stats(ctx)
	if err != nil {
		return wireguard.PeerStats{}
	}
	for _, stat := range stats {
		if stat.PublicKey == publicKey {
			return stat
		}
	}
	return wireguard.PeerStats{}
}

// handshakeAfter reports whether the direct path has been proven since the
// baseline. Two observations count, both read from WireGuard:
//
//   - a handshake newer than the baseline, or
//   - bytes received since the baseline while WireGuard's endpoint for the
//     peer is a non-loopback address.
//
// The second matters when a relayed session is already up: WireGuard then
// sends data with its current keys instead of a new handshake, and the peer's
// reply arriving directly makes WireGuard roam its endpoint to the direct
// address. Either way, traffic arriving through the relay bridge does not
// count — the bridge is loopback, and it proves only that the peer is alive.
func (s *WireGuardStrategy) handshakeAfter(ctx context.Context, publicKey string, baseline wireguard.PeerStats) (netip.AddrPort, bool) {
	stat := s.snapshot(ctx, publicKey)
	endpoint, err := netip.ParseAddrPort(stat.Endpoint)
	if err != nil || endpoint.Addr().IsLoopback() {
		return netip.AddrPort{}, false
	}
	if stat.LastHandshake > baseline.LastHandshake || stat.TransferRxBytes > baseline.TransferRxBytes {
		return endpoint, true
	}
	return netip.AddrPort{}, false
}

// UDPNudge sends one byte to a peer's overlay address on the discard port.
// The packet is routed into the WireGuard interface, which has to start a
// handshake to deliver it — that is the whole purpose; the byte itself is
// thrown away at the far end.
func UDPNudge(ctx context.Context, virtualIP netip.Addr) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", netip.AddrPortFrom(virtualIP, 9).String())
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
}
