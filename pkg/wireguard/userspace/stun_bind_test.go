package userspace

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nat"
)

func TestSTUNUsesWireGuardSocketAndKeepsMappedPort(t *testing.T) {
	node := newNode(t, "10.88.0.2")
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	source := make(chan int, 1)
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, 1280)
		n, addr, err := server.ReadFrom(request)
		if err != nil || n < 20 {
			return
		}
		source <- addr.(*net.UDPAddr).Port
		response := make([]byte, 32)
		copy(response[:20], request[:20])
		binary.BigEndian.PutUint16(response[0:2], 0x0101)
		binary.BigEndian.PutUint16(response[2:4], 12)
		binary.BigEndian.PutUint16(response[20:22], 0x0020)
		binary.BigEndian.PutUint16(response[22:24], 8)
		response[25] = 1
		binary.BigEndian.PutUint16(response[26:28], uint16(45678)^0x2112)
		binary.BigEndian.PutUint32(response[28:32], uint32(0xcb007101)^0x2112a442)
		_, _ = server.WriteTo(response, addr)
	}()
	candidates, _, err := (&CandidateSource{Manager: node.manager, Gatherer: nat.Gatherer{
		STUNServers: []string{server.LocalAddr().String()}, STUNTimeout: time.Second,
	}}).Gather(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case port := <-source:
		if port != node.port {
			t.Fatalf("STUN source port %d != WireGuard port %d", port, node.port)
		}
	case <-time.After(time.Second):
		t.Fatal("no STUN request received")
	}
	for _, candidate := range candidates {
		if candidate.Type == nat.CandidateReflexive && candidate.IP == "203.0.113.1" && candidate.Port == 45678 {
			return
		}
	}
	t.Fatalf("mapped port was not preserved: %+v", candidates)
}
