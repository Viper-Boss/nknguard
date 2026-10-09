package mesh

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/directice"
)

func enableTestICE(c *Controller) {
	c.ICE = &directice.Config{IncludeLoopback: true, Interfaces: func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}}
	c.Config.Timing.ReceiveTimeout = time.Second
	w := c.WireGuard.(*fakeWG)
	c.Nudge = func(_ context.Context, _ netip.Addr) {
		w.mu.Lock()
		var endpoints []string
		for _, endpoint := range w.endpoints {
			endpoints = append(endpoints, endpoint)
		}
		w.mu.Unlock()
		for _, endpoint := range endpoints {
			w.initiate(endpoint)
		}
	}
}

func TestICEViaSignallingAuthenticatesWGAndKeepsRelayStandby(t *testing.T) {
	e := newEnv(t)
	e.fake.setBlocked(true)
	a := e.startWith(t, "ice-a", "198.51.100.1:51820", e.key, enableTestICE)
	b := e.startWith(t, "ice-b", "198.51.100.2:51820", e.key, enableTestICE)
	waitPath(t, 8*time.Second, a, b, PathDirectWG, StateDirect)
	for _, pair := range [][2]*node{{a, b}, {b, a}} {
		path := pair[0].ctrl.icePathFor(pair[1].ctrl.Device.DeviceID())
		if path == nil || path.bridge.Stats().BytesRecv == 0 {
			t.Fatal("ICE path lacks WG receive proof")
		}
		waitFor(t, time.Second, "relay standby", func() bool {
			bridge := pair[0].ctrl.bridgeFor(pair[1].ctrl.Device.DeviceID())
			return bridge != nil && bridge.Standby()
		})
	}
	// A dead ICE proxy must never be mistaken for a live NKN relay merely
	// because both present a loopback endpoint to the kernel.
	a.ctrl.closeICEPath(b.ctrl.Device.DeviceID())
	b.ctrl.closeICEPath(a.ctrl.Device.DeviceID())
	waitPath(t, 5*time.Second, a, b, PathNKNRelay, StateRelay)
}

func TestFailedICEGatherLeavesEndpointAssigned(t *testing.T) {
	e := newEnv(t)
	e.fake.setBlocked(true)
	a := e.start(t, "relay-a", "198.51.100.1:51820", e.key)
	b := e.start(t, "relay-b", "198.51.100.2:51820", e.key)
	waitPath(t, 10*time.Second, a, b, PathNKNRelay, StateRelay)
	// Test the independent operation directly after stopping scheduled work.
	a.stop(t)
	b.stop(t)
	c := New()
	c.WireGuard = a.wg
	c.ICE = &directice.Config{Interfaces: func() ([]net.Addr, error) { return nil, nil }}
	p := c.peerFor("remote")
	p.record.WireGuardPublicKey = b.wg.key
	before := a.wg.endpointFor(b.wg.key)
	p.BeginAttempt()
	c.runICEOffer(context.Background(), p)
	if got := a.wg.endpointFor(b.wg.key); got != before {
		t.Fatalf("failed gather changed endpoint: %s -> %s", before, got)
	}
}
