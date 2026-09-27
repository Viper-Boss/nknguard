package mesh

import (
	"net/netip"
	"testing"
	"time"
)

func TestStateMachineHappyAndFallbackPaths(t *testing.T) {
	now := time.Now()
	peer := NewPeer("nkg_x")
	for _, event := range []Event{EventRecordSeen, EventHelloSent, EventCandidatesGot, EventPunchStarted, EventPunchSucceeded, EventHandshakeOK} {
		if _, err := peer.Apply(event, now); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
	}
	if peer.State() != StateDirect {
		t.Fatalf("happy path ended in %s", peer.State())
	}

	relayed := NewPeer("nkg_y")
	for _, event := range []Event{EventRecordSeen, EventHelloSent, EventCandidatesGot, EventPunchStarted, EventPunchFailed, EventRelayOpen, EventPunchSucceeded, EventHandshakeOK} {
		if _, err := relayed.Apply(event, now); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
	}
	if relayed.State() != StateDirect {
		t.Fatalf("relay recovery ended in %s", relayed.State())
	}
}

func TestObservedHandshakeWinsFromAnyLiveState(t *testing.T) {
	for state := range transitions {
		if state == StateUnknown || state == StateOffline {
			continue
		}
		if next, err := Next(state, EventHandshakeOK); err != nil || next != StateDirect {
			t.Errorf("an observed handshake in %s led to %s (%v); the data plane is the source of truth", state, next, err)
		}
	}
}

func TestIllegalTransitionIsReported(t *testing.T) {
	peer := NewPeer("nkg_x")
	if _, err := peer.Apply(EventHandshakeOK, time.Now()); err == nil {
		t.Fatal("UNKNOWN accepted a handshake event")
	}
	if peer.State() != StateUnknown {
		t.Fatal("illegal event changed state")
	}
}

func TestEveryStateHandlesShutdown(t *testing.T) {
	for state := range transitions {
		if next, err := Next(state, EventShutdown); err != nil || next != StateOffline {
			t.Errorf("%s does not shut down cleanly: %s %v", state, next, err)
		}
	}
}

func TestExpiredRecordDoesNotDropEstablishedPaths(t *testing.T) {
	for _, state := range []PeerState{StateDirect, StateRelay} {
		if next, _ := Next(state, EventRecordExpired); next != state {
			t.Errorf("record expiry moved %s to %s — a DHT outage would tear down a working tunnel", state, next)
		}
	}
}

func TestHistoryIsBounded(t *testing.T) {
	peer := NewPeer("nkg_x")
	now := time.Now()
	_, _ = peer.Apply(EventRecordSeen, now)
	for i := 0; i < 500; i++ {
		_, _ = peer.Apply(EventHelloSent, now)
		_, _ = peer.Apply(EventRecordExpired, now)
		_, _ = peer.Apply(EventRecordSeen, now)
	}
	if len(peer.Snapshot().History) > maxTransitionHistory {
		t.Fatal("transition history grew without bound")
	}
}

func TestSelectorHysteresis(t *testing.T) {
	selector := &Selector{DirectLossGrace: 10 * time.Second, DirectRecoveryHold: 5 * time.Second, DirectRetryInterval: time.Second, current: PathNone}
	start := time.Now()
	at := func(seconds int) time.Time { return start.Add(time.Duration(seconds) * time.Second) }

	if selector.Select(Observation{Now: at(0), DirectHealthy: true}) != PathDirectWG {
		t.Fatal("healthy direct not selected")
	}
	// A short blip must not move traffic.
	if selector.Select(Observation{Now: at(1), RelayOpen: true}) != PathDirectWG {
		t.Fatal("left direct on a single bad observation")
	}
	if selector.Select(Observation{Now: at(5), RelayOpen: true}) != PathDirectWG {
		t.Fatal("left direct inside the grace period")
	}
	if selector.Select(Observation{Now: at(12), RelayOpen: true}) != PathNKNRelay {
		t.Fatal("did not fall back after the grace period")
	}
	// Recovery must be sustained before traffic moves back.
	if selector.Select(Observation{Now: at(13), DirectHealthy: true, RelayOpen: true}) != PathNKNRelay {
		t.Fatal("returned to direct without a hold period — this is flapping")
	}
	if selector.Select(Observation{Now: at(19), DirectHealthy: true, RelayOpen: true}) != PathDirectWG {
		t.Fatal("did not return to direct after the hold period")
	}
}

func TestDirectRetryBacksOff(t *testing.T) {
	selector := &Selector{DirectRetryInterval: time.Second, DirectRetryMax: 8 * time.Second, current: PathNKNRelay}
	now := time.Now()
	if !selector.ShouldRetryDirect(now) {
		t.Fatal("first retry refused")
	}
	for i := 0; i < 10; i++ {
		selector.RecordDirectFailure()
	}
	if selector.ShouldRetryDirect(now.Add(7 * time.Second)) {
		t.Fatal("retried before the capped interval")
	}
	if !selector.ShouldRetryDirect(now.Add(8 * time.Second)) {
		t.Fatal("backoff exceeded its cap")
	}
	selector.RecordDirectSuccess()
	if selector.retryInterval() != time.Second {
		t.Fatal("success did not reset the backoff")
	}
}

func TestVirtualIPIsDeterministicAndAvoidsCollisions(t *testing.T) {
	cidr := netip.MustParsePrefix("10.88.0.0/16")
	first, err := AllocateVirtualIP(cidr, "net", "nkg_a", nil)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := AllocateVirtualIP(cidr, "net", "nkg_a", nil)
	if first != again {
		t.Fatal("same device got different addresses")
	}
	if !cidr.Contains(first) || first == cidr.Addr() {
		t.Fatalf("%s is not a usable host in %s", first, cidr)
	}
	moved, _ := AllocateVirtualIP(cidr, "net", "nkg_a", map[netip.Addr]string{first: "nkg_b"})
	if moved == first {
		t.Fatal("collision not avoided")
	}
	kept, _ := AllocateVirtualIP(cidr, "net", "nkg_a", map[netip.Addr]string{first: "nkg_a"})
	if kept != first {
		t.Fatal("a device's own record counted as a collision")
	}
	tiny := netip.MustParsePrefix("10.0.0.0/30")
	taken := map[netip.Addr]string{}
	for _, host := range []string{"10.0.0.1", "10.0.0.2"} {
		taken[netip.MustParseAddr(host)] = "other"
	}
	if _, err := AllocateVirtualIP(tiny, "net", "nkg_a", taken); err == nil {
		t.Fatal("full pool did not report exhaustion")
	}
	if ResolveCollision("nkg_a", "nkg_b") != true || ResolveCollision("nkg_b", "nkg_a") != false {
		t.Fatal("collision resolution is not deterministic")
	}
}
