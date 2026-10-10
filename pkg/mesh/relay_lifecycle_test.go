package mesh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type preAssignmentPacketWG struct{ revokeWG }

func (w *preAssignmentPacketWG) UpdateEndpoint(_ context.Context, key, endpoint string) error {
	// A relay reply arrives immediately before endpoint assignment. The
	// next Stats reports the manually assigned IP with the old reply's bytes.
	w.stats = []wireguard.PeerStats{{PublicKey: key, Endpoint: endpoint, LastHandshake: time.Now().Unix(), TransferRxBytes: 132}}
	return nil
}

func TestDirectProbeRejectsPreAssignmentRelayReply(t *testing.T) {
	w := &preAssignmentPacketWG{revokeWG: revokeWG{stats: []wireguard.PeerStats{{PublicKey: "key", Endpoint: "127.0.0.1:51820", LastHandshake: time.Now().Unix(), TransferRxBytes: 100}}}}
	s := WireGuardStrategy{WireGuard: w, PerCandidate: 20 * time.Millisecond, PollInterval: time.Millisecond}
	_, err := s.Attempt(context.Background(), DirectAttempt{WireGuardPublicKey: "key", Candidates: []nat.EndpointCandidate{nat.NewCandidate(nat.CandidateReflexive, netip.MustParseAddrPort("198.51.100.2:51820"), time.Minute, time.Now())}})
	if !errors.Is(err, ErrNoDirectPath) {
		t.Fatalf("old relay reply proved a manually assigned direct endpoint: %v", err)
	}
}

func TestRelayHandshakeCannotPromoteUnprovenAttempt(t *testing.T) {
	c := New()
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "key"}
	p.markInstalled("key")
	p.path, p.selector.current = PathNKNRelay, PathNKNRelay
	p.selector.directGoodAt = time.Now().Add(-time.Minute)
	if !p.BeginAttempt() {
		t.Fatal("attempt did not start")
	}
	// The worker just assigned a public endpoint; this handshake was earned
	// through the relay, and no new packet has arrived on the public path.
	c.WireGuard = &revokeWG{stats: []wireguard.PeerStats{{PublicKey: "key", Endpoint: "198.51.100.2:51820", LastHandshake: time.Now().Unix(), TransferRxBytes: 100}}}
	a, b := net.Pipe()
	defer b.Close()
	bridge, err := relay.NewBridge(a, netip.MustParseAddrPort("127.0.0.1:51820"))
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	c.bridges[p.DeviceID()] = bridge
	for i := 0; i < 3; i++ {
		c.reconcileOnce(context.Background())
	}
	if p.Path() != PathNKNRelay || c.bridgeFor(p.DeviceID()) != bridge || !bridge.Stats().Open {
		t.Fatal("unproven direct probe displaced or destroyed working relay")
	}
	if c.Metrics().PeersDirect != 0 {
		t.Fatal("unproven endpoint counted as direct")
	}
}

type endpointHandoffWG struct {
	revokeWG
	calls          int
	bridgeEndpoint string
}

func (w *endpointHandoffWG) Stats(context.Context) ([]wireguard.PeerStats, error) {
	w.calls++
	endpoint := "198.51.100.2:51820"
	if w.calls > 1 {
		endpoint = w.bridgeEndpoint
	}
	return []wireguard.PeerStats{{PublicKey: "key", Endpoint: endpoint, LastHandshake: time.Now().Unix(), TransferRxBytes: 100}}, nil
}

func TestReconcileRefreshesEndpointAfterProbeHandoff(t *testing.T) {
	c := New()
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "key"}
	p.markInstalled("key")
	p.path, p.selector.current = PathNKNRelay, PathNKNRelay
	p.selector.DirectRecoveryHold = 0
	// The shared snapshot saw an unproven candidate just before the worker
	// restored the relay. That old endpoint must not become direct evidence.
	w := &endpointHandoffWG{}
	c.WireGuard = w
	a, b := net.Pipe()
	defer b.Close()
	bridge, err := relay.NewBridge(a, netip.MustParseAddrPort("127.0.0.1:51820"))
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	w.bridgeEndpoint = bridge.LocalAddr().String()
	c.bridges[p.DeviceID()] = bridge
	c.reconcileOnce(context.Background())
	if p.Path() != PathNKNRelay || c.Metrics().PeersDirect != 0 || bridge.Standby() {
		t.Fatal("snapshot from the completed probe promoted relay handshake to direct")
	}
}

func TestVerifiedRelayTrafficOverridesDirectLossGrace(t *testing.T) {
	s := DefaultSelector()
	now := time.Now()
	s.Select(Observation{Now: now, DirectHealthy: true})
	if got := s.Select(Observation{Now: now.Add(time.Millisecond), RelayOpen: true, RelayActive: true}); got != PathNKNRelay {
		t.Fatal("actual relay traffic remained labelled direct during grace")
	}
	// A standby stream by itself remains subject to the normal grace.
	s.Reset()
	s.Select(Observation{Now: now, DirectHealthy: true})
	if got := s.Select(Observation{Now: now.Add(time.Millisecond), RelayOpen: true}); got != PathDirectWG {
		t.Fatal("unconfirmed standby stream bypassed direct loss grace")
	}
}

func TestDirectProbeBudgetIncludesPublicCandidate(t *testing.T) {
	now := time.Now()
	var remote []nat.EndpointCandidate
	for i := 1; i <= 12; i++ {
		remote = append(remote, nat.NewCandidate(nat.CandidateHost, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 55, 0, byte(i)}), 51820), time.Minute, now))
	}
	public := nat.NewCandidate(nat.CandidateReflexive, netip.MustParseAddrPort("198.51.100.2:41000"), time.Minute, now)
	remote = append(remote, public)
	selected := directCandidates(remote, nil, 4)
	if len(selected) != 1 || selected[0].IP != public.IP || selected[0].Port != public.Port {
		t.Fatalf("public mapping excluded by virtual interfaces: %+v", selected)
	}
}

func TestPrivateCandidatesRequireSharedHostNetwork(t *testing.T) {
	now := time.Now()
	lan := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("192.168.120.190:51820"), time.Minute, now)
	modem := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("10.55.0.1:51820"), time.Minute, now)
	if got := directCandidates([]nat.EndpointCandidate{modem, lan}, nil, 4); len(got) != 0 {
		t.Fatalf("cellular probe tried NAS local interfaces: %+v", got)
	}
	local := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("192.168.120.50:1234"), time.Minute, now)
	got := directCandidates([]nat.EndpointCandidate{modem, lan}, []nat.EndpointCandidate{local}, 4)
	if len(got) != 1 || got[0].IP != lan.IP {
		t.Fatalf("same LAN direct lost: %+v", got)
	}
}

func TestIPv4PreferredAndUnrelatedIPv6ULARejected(t *testing.T) {
	now := time.Now()
	v4 := nat.NewCandidate(nat.CandidateReflexive, netip.MustParseAddrPort("198.51.100.2:51820"), time.Minute, now)
	v6 := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("[2001:db8::2]:51820"), time.Minute, now)
	ula := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("[fd7a:115c:a1e0::2]:51820"), time.Minute, now)
	local := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("[2001:db8:1::1]:1234"), time.Minute, now)
	got := directCandidates([]nat.EndpointCandidate{ula, v6, v4}, []nat.EndpointCandidate{local}, 4)
	if len(got) != 2 || got[0].IP != v4.IP || got[1].IP != v6.IP {
		t.Fatalf("invalid IPv4 preference / ULA filtering: %+v", got)
	}
	if got := directCandidates([]nat.EndpointCandidate{v6}, []nat.EndpointCandidate{local}, 4); len(got) != 1 {
		t.Fatal("IPv6 fallback lost")
	}
	localULA := nat.NewCandidate(nat.CandidateHost, netip.MustParseAddrPort("[fd7a:115c:a1e0::3]:1234"), time.Minute, now)
	if got := directCandidates([]nat.EndpointCandidate{ula}, []nat.EndpointCandidate{localULA}, 4); len(got) != 1 {
		t.Fatal("shared IPv6 LAN lost")
	}
}

func TestLateRelayCannotReplaceReceivingDirectEndpoint(t *testing.T) {
	c := New()
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "key"}
	p.SetEndpoint(netip.MustParseAddrPort("198.51.100.2:51820"))
	w := newFakeWG(t, newFakeNet(), "local", netip.MustParseAddrPort("198.51.100.1:51820"))
	_ = w.AddPeer(context.Background(), wireguard.PeerConfig{PublicKey: "key"})
	w.mu.Lock()
	w.endpoints["key"] = p.Endpoint().String()
	w.handshakes["key"] = time.Now()
	w.received["key"] = 100
	w.mu.Unlock()
	c.WireGuard = w
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.closeBridges(); c.wg.Wait() }()
	if !c.attachBridge(ctx, p, a) {
		t.Fatal("standby relay not retained")
	}
	bridge := c.bridgeFor(p.DeviceID())
	if bridge == nil || !bridge.Standby() || w.endpointFor("key") != p.Endpoint().String() {
		t.Fatal("standby displaced direct endpoint")
	}
}

func TestUnprovenRelayExpiresWithoutAnyHandshake(t *testing.T) {
	c := New()
	c.Config.Timing.ReceiveTimeout = time.Second
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "key"}
	p.markInstalled("key")
	a, b := net.Pipe()
	defer b.Close()
	bridge, err := relay.NewBridge(a, netip.MustParseAddrPort("127.0.0.1:51820"))
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	c.bridges[p.DeviceID()] = bridge
	c.WireGuard = &revokeWG{stats: []wireguard.PeerStats{{PublicKey: "key", Endpoint: bridge.LocalAddr().String()}}}
	p.NoteReceive(0, time.Now().Add(-time.Minute))
	c.reconcileOnce(context.Background())
	if c.bridgeFor(p.DeviceID()) != nil || bridge.Stats().Open {
		t.Fatal("unproven relay kept waiting indefinitely")
	}
}

func TestRelayRecoveryHoldCannotBeBypassedByMissingBridgeObservation(t *testing.T) {
	s := DefaultSelector()
	s.current = PathNKNRelay
	now := time.Now()
	for _, elapsed := range []time.Duration{0, time.Second, 4 * time.Second} {
		if got := s.Select(Observation{Now: now.Add(elapsed), DirectHealthy: true}); got != PathNKNRelay {
			t.Fatalf("hold bypassed at %s: %s", elapsed, got)
		}
	}
	if got := s.Select(Observation{Now: now.Add(5 * time.Second), DirectHealthy: true}); got != PathDirectWG {
		t.Fatal("held recovery not promoted")
	}
}

func TestNewRelayGetsItsOwnReceiveWindow(t *testing.T) {
	c := New()
	c.WireGuard = newFakeWG(t, newFakeNet(), "local", netip.MustParseAddrPort("198.51.100.1:51820"))
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "remote-key"}
	p.NoteReceive(0, time.Now().Add(-time.Minute))
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.closeBridges(); c.wg.Wait() }()
	if !c.attachBridge(ctx, p, a) {
		t.Fatal("relay was not attached")
	}
	if silent := p.NoteReceive(0, time.Now()); silent >= time.Second {
		t.Fatalf("new relay inherited old path silence: %s", silent)
	}
}

func TestDirectGraceDoesNotCloseUnprovenRelay(t *testing.T) {
	c := New()
	p := c.peerFor("remote")
	p.record = discovery.PeerRecord{DeviceID: "remote", WireGuardPublicKey: "key"}
	p.markInstalled("key")
	c.Config.Timing.ReceiveTimeout = time.Second
	c.WireGuard = &revokeWG{stats: []wireguard.PeerStats{{PublicKey: "key", Endpoint: "198.51.100.2:51820", LastHandshake: time.Now().Unix()}}}
	p.SelectPath(Observation{Now: time.Now(), DirectHealthy: true})
	p.NoteReceive(0, time.Now().Add(-time.Minute))
	a, b := net.Pipe()
	defer b.Close()
	bridge, err := relay.NewBridge(a, netip.MustParseAddrPort("127.0.0.1:51820"))
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	c.bridges[p.DeviceID()] = bridge
	c.reconcileOnce(context.Background())
	if c.bridgeFor(p.DeviceID()) != bridge {
		t.Fatal("direct loss grace closed relay without a healthy direct observation")
	}
}
