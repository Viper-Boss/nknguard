//go:build libp2pdht

package mesh

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/controlhub"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/discovery/dht"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

// Real libp2p TCP + real ICE UDP, no NKN transport or public bootstrap server.
// The WG test adapter still requires a new authenticated packet exchange.
func TestDHTCachedBootstrapEstablishesICEWithoutNKN(t *testing.T) {
	e := newEnv(t)
	e.fake.setBlocked(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var controllers [2]*Controller
	var backends [2]*dht.Backend
	var records [2]discovery.PeerRecord
	for i := range controllers {
		backend, err := dht.Open(ctx, dht.Options{StateDir: t.TempDir(), Rendezvous: e.key.Rendezvous()})
		if err != nil {
			t.Fatal(err)
		}
		backends[i] = backend
		defer backend.Close()
		device, _ := identity.Generate()
		c := New()
		c.Config.NetworkID, c.Config.DeviceName = e.networkID, "dht-test"
		c.Config.RequireApproval = true
		c.Config.Timing = testTiming()
		c.Device, c.Membership, c.Logger = device, e.key, slog.New(slog.NewTextHandler(io.Discard, nil))
		c.WireGuard = newFakeWG(t, e.fake, "DHT-WG-"+device.DeviceID(), netip.MustParseAddrPort("198.51.100.1:51820"))
		c.Direct = &WireGuardStrategy{WireGuard: c.WireGuard}
		c.SetVirtualIP(netip.AddrFrom4([4]byte{10, 88, 0, byte(i + 1)}))
		enableTestICE(c)
		hub := controlhub.New(ctx, backend, nil)
		defer hub.Close()
		c.Signaling, c.Relay, c.Discovery = hub, hub, backend
		controllers[i] = c
		records[i], err = discovery.Sign(device, discovery.PeerRecord{
			NetworkID: e.networkID, DHTAddresses: backend.LocalAddresses(),
			WireGuardPublicKey: c.WireGuard.(*fakeWG).key, VirtualIPs: []string{c.VirtualIP().String()},
			MembershipProof: e.key.Proof(device.DeviceID(), device.PublicKey()), Capabilities: []string{protocol.CapICEUDPV1},
		}, 1, time.Minute, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		c.SetSequence(1)
	}
	var done [2]chan error
	for i, c := range controllers {
		c.Config.Members = []string{records[1-i].DeviceID}
		c.IngestCached(ctx, records[1-i])
		done[i] = make(chan error, 1)
		go func(i int, c *Controller) { done[i] <- c.Run(ctx) }(i, c)
	}
	defer func() {
		cancel()
		for _, ch := range done {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Error("DHT controller shutdown stalled")
			}
		}
	}()
	waitFor(t, 15*time.Second, "DHT-only ICE path", func() bool {
		for i, c := range controllers {
			p, ok := c.lookupPeer(records[1-i].DeviceID)
			if !ok || p.Path() != PathDirectWG || c.icePathFor(p.DeviceID()) == nil {
				return false
			}
		}
		return true
	})
	for _, c := range controllers {
		if c.Signaling.LocalAddress() != "" {
			t.Fatal("test accidentally used NKN")
		}
		if c.Metrics().PeersRelay != 0 {
			t.Fatal("DHT carried user data as relay")
		}
	}
	// A revoked member cannot regain a path through its retained DHT binding.
	controllers[0].RevokeDevice(ctx, records[1].DeviceID)
	if controllers[0].Authorized(records[1].DeviceID) {
		t.Fatal("DHT bypassed revocation")
	}
}
