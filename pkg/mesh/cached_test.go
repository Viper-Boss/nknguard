package mesh

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
)

func TestCachedDirectWorksBeforeSignalingExists(t *testing.T) {
	e := newEnv(t)
	local, _ := identity.Generate()
	nas, _ := identity.Generate()
	localWG := newFakeWG(t, e.fake, "LOCAL-WG", netip.MustParseAddrPort("198.51.100.10:51820"))
	nasWG := newFakeWG(t, e.fake, "NAS-WG", netip.MustParseAddrPort("198.51.100.20:51820"))
	// The NAS keeps the authorized client and its most recent endpoint.
	_ = nasWG.UpdateEndpoint(context.Background(), localWG.key, localWG.public.String())
	c := New()
	c.Device, c.Membership, c.WireGuard = local, e.key, localWG
	c.Config.NetworkID = e.networkID
	c.Config.RequireApproval = true
	c.Config.Members = []string{nas.DeviceID()}
	c.Config.Timing = testTiming()
	record, err := discovery.Sign(nas, discovery.PeerRecord{
		NetworkID: e.networkID, WireGuardPublicKey: nasWG.key, VirtualIPs: []string{"10.88.0.2"},
		MembershipProof: e.key.Proof(nas.DeviceID(), nas.PublicKey()),
	}, 1, time.Minute, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c.IngestCached(context.Background(), record)
	if c.RestoreLinkHint("unknown", nasWG.key, nasWG.public.String(), time.Now()) {
		t.Fatal("hint authorized unknown device")
	}
	if c.RestoreLinkHint(nas.DeviceID(), "wrong-key", nasWG.public.String(), time.Now()) {
		t.Fatal("hint changed pinned key")
	}
	if c.RestoreLinkHint(nas.DeviceID(), nasWG.key, nasWG.public.String(), time.Now().Add(-8*24*time.Hour)) {
		t.Fatal("expired hint accepted")
	}
	if !c.RestoreLinkHint(nas.DeviceID(), nasWG.key, nasWG.public.String(), time.Now()) {
		t.Fatal("verified cache not restored")
	}
	e.fake.setBlocked(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.RunCached(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(time.Second)
	for localWG.endpointFor(nasWG.key) == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if localWG.endpointFor(nasWG.key) != nasWG.public.String() {
		t.Fatal("did not probe cached endpoint before NKN")
	}
	peer, _ := c.lookupPeer(nas.DeviceID())
	if peer.Path() == PathDirectWG {
		t.Fatal("unanswered probe falsely marked connected")
	}
	e.fake.setBlocked(false)
	deadline = time.Now().Add(time.Second)
	for peer.Path() != PathDirectWG && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peer.Path() != PathDirectWG || c.Signaling != nil {
		t.Fatal("direct path still depended on signaling")
	}
}
