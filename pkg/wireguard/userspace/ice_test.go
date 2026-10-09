package userspace

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/directice"
	"github.com/Viper-Boss/nknguard/pkg/relay"
)

func TestRealWireGuardDatagramsOverICE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := directice.Config{IncludeLoopback: true, Interfaces: func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}}
	a, ad, err := cfg.Prepare(ctx, strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, bd, err := cfg.Prepare(ctx, ad.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := b.Connect(ctx, ad, false)
		if err != nil {
			acceptErr <- err
		} else {
			accepted <- conn
		}
	}()
	ac, err := a.Connect(ctx, bd, true)
	if err != nil {
		t.Fatal(err)
	}
	var bc net.Conn
	select {
	case bc = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("ICE accept timed out")
	}
	wgA, wgB := newNode(t, "10.88.0.1"), newNode(t, "10.88.0.2")
	ab, err := relay.NewDatagramBridge(ac, wgA.loopback())
	if err != nil {
		t.Fatal(err)
	}
	bb, err := relay.NewDatagramBridge(bc, wgB.loopback())
	if err != nil {
		t.Fatal(err)
	}
	defer ab.Close()
	defer bb.Close()
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- ab.Run(ctx) }()
	go func() { doneB <- bb.Run(ctx) }()
	wgA.addPeer(t, wgB, ab.LocalAddr().String())
	wgB.addPeer(t, wgA, bb.LocalAddr().String())
	expectPing(t, wgA, wgB)
	expectPing(t, wgB, wgA)
	if !peerStats(t, wgA, wgB.key).Current || !peerStats(t, wgB, wgA.key).Current {
		t.Fatal("ICE did not carry authenticated WireGuard handshakes")
	}
	cancel()
	for _, done := range []chan error{doneA, doneB} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("ICE datagram bridge leaked after disconnect")
		}
	}
}
