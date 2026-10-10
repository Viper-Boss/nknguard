package mesh

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type staleRelayObservation struct {
	wireguard.Manager
	stat wireguard.PeerStats
}

func TestFailedAttemptAllowsRelayReconciliationBeforeRetry(t *testing.T) {
	p := NewPeer("remote")
	p.selector.DirectRetryInterval = time.Second
	p.selector.DirectRetryMax = time.Second
	p.selector.lastDirectTry = time.Now().Add(-time.Minute)
	p.attempting = true
	p.EndAttempt(false)
	if p.ShouldRetryDirect(time.Now()) {
		t.Fatal("slow failed attempt immediately stole restored relay endpoint")
	}
}

func (w staleRelayObservation) Stats(context.Context) ([]wireguard.PeerStats, error) {
	return []wireguard.PeerStats{w.stat}, nil
}

// The shared statistics snapshot can still describe a relay while an ICE
// worker owns and authenticates a different endpoint. It must not select a
// path or change WG_CONNECTING based on that stale snapshot.
func TestReconcileCannotPromoteStaleRelayWhileEndpointOwned(t *testing.T) {
	c := New()
	p := c.peerFor("remote")
	p.record.WireGuardPublicKey = "remote-key"
	p.installedKey = "remote-key"
	p.state = StateWGConnecting
	p.attempting = true
	one, two := net.Pipe()
	defer two.Close()
	bridge, err := relay.NewBridge(one, netip.MustParseAddrPort("127.0.0.1:40001"))
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	c.bridges["remote"] = bridge
	c.WireGuard = staleRelayObservation{stat: wireguard.PeerStats{PublicKey: "remote-key", Endpoint: bridge.LocalAddr().String(), LastHandshake: time.Now().Unix(), TransferRxBytes: 128}}
	p.endpointMu.Lock()
	defer p.endpointMu.Unlock()
	c.reconcileOnce(context.Background())
	if p.Path() != PathNone || p.State() != StateWGConnecting {
		t.Fatalf("stale relay replaced pending authentication: %s/%s", p.Path(), p.State())
	}
}
