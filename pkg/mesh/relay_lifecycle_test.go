package mesh

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

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
