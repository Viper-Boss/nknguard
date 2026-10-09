// Package nat discovers how this host can be reached from outside and drives
// the UDP hole punch that turns two such views into one working path.
//
// The honest framing, which the documentation repeats and the code enforces:
// hole punching works for most NATs and fails for some. Nothing here claims a
// direct path it has not observed traffic on, and every attempt is bounded —
// no unlimited retries, no goroutine per peer that outlives its context.
package nat

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// CandidateType says how an address was learned, which is what its priority
// is based on.
type CandidateType string

const (
	// CandidateHost is an address on a local interface.
	CandidateHost CandidateType = "host"
	// CandidateReflexive is the public mapping a STUN server observed.
	CandidateReflexive CandidateType = "srflx"
	// CandidateRelay is a path through the relay plane. It is last resort and
	// is carried as a candidate only so the selector can reason about all the
	// options in one list.
	CandidateRelay CandidateType = "relay"
)

// MaxCandidates bounds what a peer may advertise. A peer with a hundred
// interfaces is either unusual or hostile, and probing all of them costs us,
// not them.
const MaxCandidates = 16

// EndpointCandidate is one way a device might be reachable.
type EndpointCandidate struct {
	Type     CandidateType `json:"type"`
	IP       string        `json:"ip"`
	Port     uint16        `json:"port"`
	Priority uint32        `json:"priority"`
	Protocol string        `json:"protocol"`

	ObservedAt int64 `json:"observed_at"`
	ExpiresAt  int64 `json:"expires_at"`
}

// AddrPort parses the candidate into a comparable address.
func (c EndpointCandidate) AddrPort() (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(c.IP)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: candidate ip %q: %w", c.IP, err)
	}
	return netip.AddrPortFrom(addr, c.Port), nil
}

// String renders the candidate for a log line.
func (c EndpointCandidate) String() string {
	return fmt.Sprintf("%s/%s", c.Type, net.JoinHostPort(c.IP, fmt.Sprint(c.Port)))
}

// Expired reports whether the candidate is past its useful life. A NAT mapping
// that was observed ten minutes ago is a guess, not an address.
func (c EndpointCandidate) Expired(now time.Time) bool {
	return c.ExpiresAt != 0 && now.Unix() > c.ExpiresAt
}

// Usable rejects candidates that cannot be a peer endpoint: unspecified,
// loopback, multicast, and anything that fails to parse. Link-local is kept —
// two machines on the same segment often have nothing else in common.
func (c EndpointCandidate) Usable() bool {
	if c.Port == 0 || c.Protocol != "udp" {
		return false
	}
	addr, err := netip.ParseAddr(c.IP)
	if err != nil {
		return false
	}
	// IPv6 link-local needs a scope id, which the wire format cannot carry.
	return !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsMulticast() && !(addr.Is6() && addr.IsLinkLocalUnicast())
}

// priorityFor ranks candidate types. The ordering is the whole point of the
// transport policy expressed as a number: a private address that might be a
// same-LAN shortcut beats a public mapping that must traverse the internet,
// and both beat a relay.
func priorityFor(kind CandidateType, addr netip.Addr) uint32 {
	switch kind {
	case CandidateHost:
		if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return 1000
		}
		return 900
	case CandidateReflexive:
		return 500
	case CandidateRelay:
		return 100
	default:
		return 1
	}
}

// NewCandidate builds a candidate with a computed priority and lifetime.
func NewCandidate(kind CandidateType, addr netip.AddrPort, lifetime time.Duration, now time.Time) EndpointCandidate {
	return EndpointCandidate{
		Type:       kind,
		IP:         addr.Addr().Unmap().String(),
		Port:       addr.Port(),
		Priority:   priorityFor(kind, addr.Addr()),
		Protocol:   "udp",
		ObservedAt: now.Unix(),
		ExpiresAt:  now.Add(lifetime).Unix(),
	}
}

// SortCandidates orders best-first and is stable, so an unchanged candidate
// set produces an unchanged probe order and a log diff means something really
// moved.
func SortCandidates(candidates []EndpointCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		if candidates[i].IP != candidates[j].IP {
			return candidates[i].IP < candidates[j].IP
		}
		return candidates[i].Port < candidates[j].Port
	})
}

// SanitiseCandidates drops what we will not probe and caps the list. It is
// applied to anything that arrives from the network before it reaches the
// punch loop.
func SanitiseCandidates(candidates []EndpointCandidate, now time.Time) []EndpointCandidate {
	seen := make(map[string]struct{}, len(candidates))
	kept := make([]EndpointCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Usable() || candidate.Expired(now) {
			continue
		}
		key := strings.ToLower(candidate.IP) + "/" + fmt.Sprint(candidate.Port)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, candidate)
		if len(kept) == MaxCandidates {
			break
		}
	}
	SortCandidates(kept)
	return kept
}
