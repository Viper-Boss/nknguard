package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// The punch protocol on the wire is four bytes of magic, one byte of kind, and
// an eight-byte session token both sides derived from the same signalling
// exchange. It is not a security boundary — WireGuard is — it only has to be
// distinguishable from a STUN response and from a real WireGuard packet
// sharing the socket.
const (
	punchMagic0 byte = 'N'
	punchMagic1 byte = 'K'
	punchMagic2 byte = 'G'
	punchMagic3 byte = 'P'

	punchKindProbe byte = 1
	punchKindReply byte = 2

	punchPacketBytes = 13
)

// Punch pacing. The numbers are a starting point that the integration tests
// tune; they are named constants rather than literals so that tuning is one
// edit and the reasoning stays attached to the value.
const (
	// DefaultProbesPerRound is how many packets go to each candidate per
	// round. More than one because the first packet through a fresh NAT
	// mapping is the one most likely to be dropped.
	DefaultProbesPerRound = 4
	// DefaultRounds bounds the attempt. Punching is either going to work in a
	// few seconds or it is not going to work, and a node that keeps trying
	// forever never falls back to the relay.
	DefaultRounds = 4
	// DefaultRoundInterval spaces the rounds.
	DefaultRoundInterval = 700 * time.Millisecond
	// DefaultProbeSpacing staggers packets inside a round so a rate limiter
	// on the path does not see a burst.
	DefaultProbeSpacing = 40 * time.Millisecond
	// DefaultTotalTimeout is the hard ceiling for one Punch call.
	DefaultTotalTimeout = 15 * time.Second
)

// ErrPunchFailed means no candidate answered inside the budget. It is an
// ordinary outcome, not a malfunction: the caller falls back to the relay.
var ErrPunchFailed = errors.New("nat: no candidate answered")

// SessionToken ties a punch exchange to the signalling that set it up.
type SessionToken [8]byte

// NewSessionToken returns a random token for a punch round.
func NewSessionToken() (SessionToken, error) {
	var token SessionToken
	if _, err := rand.Read(token[:]); err != nil {
		return token, fmt.Errorf("nat: session token: %w", err)
	}
	return token, nil
}

// PunchConfig parameterises one attempt.
type PunchConfig struct {
	Token           SessionToken
	Candidates      []EndpointCandidate
	ProbesPerRound  int
	Rounds          int
	RoundInterval   time.Duration
	ProbeSpacing    time.Duration
	TotalTimeout    time.Duration
	StartAt         time.Time
	ObservedTraffic func(from netip.AddrPort)
}

func (c PunchConfig) withDefaults() PunchConfig {
	if c.ProbesPerRound <= 0 {
		c.ProbesPerRound = DefaultProbesPerRound
	}
	if c.Rounds <= 0 {
		c.Rounds = DefaultRounds
	}
	if c.RoundInterval <= 0 {
		c.RoundInterval = DefaultRoundInterval
	}
	if c.ProbeSpacing <= 0 {
		c.ProbeSpacing = DefaultProbeSpacing
	}
	if c.TotalTimeout <= 0 {
		c.TotalTimeout = DefaultTotalTimeout
	}
	return c
}

// PunchResult is what a successful attempt learned.
type PunchResult struct {
	// Endpoint is the peer address that answered. It is what gets configured
	// on the WireGuard peer, and it is an address we have seen a packet from
	// rather than one a peer claimed.
	Endpoint netip.AddrPort
	// Round is which round succeeded, for the metrics.
	Round int
	// Elapsed is how long the attempt took.
	Elapsed time.Duration
}

// Punch drives a bidirectional hole punch on conn and returns the first
// candidate that answers.
//
// Both sides run this at the same time — that simultaneity is the mechanism,
// not an optimisation. Each side's outbound probe opens its own NAT mapping;
// the peer's probe then arrives at a mapping that already exists and is let
// through. StartAt is the rendezvous the two sides agreed on in signalling.
//
// The function owns no goroutine that outlives it: the reader stops when the
// context is cancelled or the deadline passes, and Punch does not return until
// it has.
func Punch(ctx context.Context, conn net.PacketConn, config PunchConfig) (PunchResult, error) {
	config = config.withDefaults()

	ctx, cancel := context.WithTimeout(ctx, config.TotalTimeout)
	defer cancel()

	if !config.StartAt.IsZero() {
		wait := time.Until(config.StartAt)
		if wait > 0 && wait < config.TotalTimeout {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return PunchResult{}, ctx.Err()
			case <-timer.C:
			}
		}
	}

	targets := make([]netip.AddrPort, 0, len(config.Candidates))
	for _, candidate := range SanitiseCandidates(config.Candidates, time.Now()) {
		addr, err := candidate.AddrPort()
		if err != nil {
			continue
		}
		targets = append(targets, addr)
	}
	return punchTargets(ctx, conn, config, targets)
}

// punchTargets is Punch after candidate filtering. It is separate so the test
// suite can drive the mechanics over loopback, which the production filter
// correctly refuses to treat as a peer address.
func punchTargets(ctx context.Context, conn net.PacketConn, config PunchConfig, targets []netip.AddrPort) (PunchResult, error) {
	config = config.withDefaults()
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, config.TotalTimeout)
	defer cancel()
	if len(targets) == 0 {
		return PunchResult{}, ErrPunchFailed
	}

	answered := make(chan netip.AddrPort, 1)
	var readerDone sync.WaitGroup
	readerDone.Add(1)
	go func() {
		defer readerDone.Done()
		readProbes(ctx, conn, config, answered)
	}()

	// Unblock the reader when we return, whatever the reason: a PacketConn
	// read does not observe context cancellation on its own.
	defer func() {
		cancel()
		_ = conn.SetReadDeadline(time.Now())
		readerDone.Wait()
		_ = conn.SetReadDeadline(time.Time{})
	}()

	probe := buildPunchPacket(punchKindProbe, config.Token)
	for round := 1; round <= config.Rounds; round++ {
		for attempt := 0; attempt < config.ProbesPerRound; attempt++ {
			for _, target := range targets {
				_, _ = conn.WriteTo(probe, net.UDPAddrFromAddrPort(target))
			}
			select {
			case <-ctx.Done():
				return PunchResult{}, ctx.Err()
			case from := <-answered:
				return PunchResult{Endpoint: from, Round: round, Elapsed: time.Since(started)}, nil
			case <-time.After(jitter(config.ProbeSpacing)):
			}
		}
		select {
		case <-ctx.Done():
			return PunchResult{}, ctx.Err()
		case from := <-answered:
			return PunchResult{Endpoint: from, Round: round, Elapsed: time.Since(started)}, nil
		case <-time.After(jitter(config.RoundInterval)):
		}
	}
	select {
	case from := <-answered:
		return PunchResult{Endpoint: from, Round: config.Rounds, Elapsed: time.Since(started)}, nil
	default:
	}
	return PunchResult{}, ErrPunchFailed
}

// readProbes answers the peer's probes and reports the first packet that
// belongs to this session. Answering is half the job: our reply is what tells
// the peer its own punch succeeded.
func readProbes(ctx context.Context, conn net.PacketConn, config PunchConfig, answered chan<- netip.AddrPort) {
	reply := buildPunchPacket(punchKindReply, config.Token)
	buffer := make([]byte, 128)
	reported := false
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		read, from, err := conn.ReadFrom(buffer)
		if err != nil {
			continue
		}
		kind, token, ok := parsePunchPacket(buffer[:read])
		if !ok || token != config.Token {
			continue
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		source := udp.AddrPort()
		if config.ObservedTraffic != nil {
			config.ObservedTraffic(source)
		}
		if kind == punchKindProbe {
			_, _ = conn.WriteTo(reply, from)
		}
		if !reported {
			reported = true
			select {
			case answered <- source:
			default:
			}
		}
	}
}

func buildPunchPacket(kind byte, token SessionToken) []byte {
	packet := make([]byte, punchPacketBytes)
	packet[0], packet[1], packet[2], packet[3] = punchMagic0, punchMagic1, punchMagic2, punchMagic3
	packet[4] = kind
	copy(packet[5:], token[:])
	return packet
}

func parsePunchPacket(packet []byte) (kind byte, token SessionToken, ok bool) {
	if len(packet) != punchPacketBytes {
		return 0, token, false
	}
	if packet[0] != punchMagic0 || packet[1] != punchMagic1 || packet[2] != punchMagic2 || packet[3] != punchMagic3 {
		return 0, token, false
	}
	if packet[4] != punchKindProbe && packet[4] != punchKindReply {
		return 0, token, false
	}
	copy(token[:], packet[5:])
	return packet[4], token, true
}

// jitter spreads retries so that a mesh whose nodes all lost connectivity at
// the same moment does not resynchronise into a thundering herd. The spread is
// +/- 25%, which is enough to decorrelate without making the pacing vague.
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return base
	}
	fraction := float64(binary.BigEndian.Uint64(raw[:])%1000) / 1000.0
	return time.Duration(float64(base) * (0.75 + 0.5*fraction))
}
