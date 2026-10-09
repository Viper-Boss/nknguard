package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Two fake "WireGuard" sockets talk to each other through two bridges joined
// by a hub stream — the full relay data path, minus NKN.
func TestBridgeCarriesDatagramsBothWays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wgA, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	wgB, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer wgA.Close()
	defer wgB.Close()

	hub := NewHub()
	a, b := hub.Endpoint("a"), hub.Endpoint("b")
	streamA, err := a.Open(ctx, Peer{DeviceID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := b.Accept(ctx)
	if err != nil || session.DeviceID != "a" {
		t.Fatalf("accept: %+v %v", session, err)
	}

	bridgeA, _ := NewBridge(streamA, wgA.LocalAddr().(*net.UDPAddr).AddrPort())
	bridgeB, _ := NewBridge(session.Conn, wgB.LocalAddr().(*net.UDPAddr).AddrPort())
	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() { doneA <- bridgeA.Run(ctx) }()
	go func() { doneB <- bridgeB.Run(ctx) }()

	// WireGuard A sends to its local bridge; WireGuard B receives it from its
	// local bridge. That is all WireGuard ever sees of the relay.
	if _, err := wgA.WriteToUDPAddrPort([]byte("handshake-init"), bridgeA.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_ = wgB.SetReadDeadline(time.Now().Add(2 * time.Second))
	read, from, err := wgB.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:read]) != "handshake-init" || from != bridgeB.LocalAddr() {
		t.Fatalf("B got %q from %s: %v", buffer[:read], from, err)
	}
	if _, err := wgB.WriteToUDPAddrPort([]byte("handshake-resp"), bridgeB.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = wgA.SetReadDeadline(time.Now().Add(2 * time.Second))
	read, _, err = wgA.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:read]) != "handshake-resp" {
		t.Fatalf("A got %q: %v", buffer[:read], err)
	}
	// The reader can receive before the sender goroutine updates accounting.
	deadline := time.Now().Add(time.Second)
	for bridgeA.Stats().BytesSent != int64(len("handshake-init")) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if bridgeA.Stats().BytesSent != int64(len("handshake-init")) {
		t.Fatalf("accounting: %+v", bridgeA.Stats())
	}

	cancel()
	for _, done := range []chan error{doneA, doneB} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("bridge did not stop on cancel")
		}
	}
}

func TestBridgeIgnoresStrangers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	bridge, _ := NewBridge(local, netip.MustParseAddrPort("127.0.0.1:1"))
	go func() { _ = bridge.Run(ctx) }()
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()
	_, _ = stranger.WriteToUDPAddrPort([]byte("inject"), bridge.LocalAddr())
	_ = remote.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := remote.Read(make([]byte, 16)); err == nil {
		t.Fatalf("stranger's datagram reached the relay (%d bytes)", n)
	}
}

func TestHubDown(t *testing.T) {
	hub := NewHub()
	hub.Endpoint("b")
	hub.SetDown(true)
	if _, err := hub.Endpoint("a").Open(context.Background(), Peer{DeviceID: "b"}); err != ErrNoRelay {
		t.Fatalf("got %v", err)
	}
}
