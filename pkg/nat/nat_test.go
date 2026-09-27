package nat

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeSTUN answers Binding Requests with the observed source address, exactly
// as a real server does, so the client's XOR decoding is tested end to end.
func fakeSTUN(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1500)
		for {
			read, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if read < 20 || binary.BigEndian.Uint16(buffer[0:2]) != stunBindingRequest {
				continue
			}
			source := from.(*net.UDPAddr).AddrPort()
			response := make([]byte, 20+12)
			binary.BigEndian.PutUint16(response[0:2], stunBindingResponse)
			binary.BigEndian.PutUint16(response[2:4], 12)
			copy(response[4:20], buffer[4:20])
			binary.BigEndian.PutUint16(response[20:22], stunAttrXORMapped)
			binary.BigEndian.PutUint16(response[22:24], 8)
			response[25] = 0x01
			binary.BigEndian.PutUint16(response[26:28], source.Port()^uint16(stunMagicCookie>>16))
			ip := source.Addr().As4()
			for i := 0; i < 4; i++ {
				response[28+i] = ip[i] ^ buffer[4+i]
			}
			_, _ = conn.WriteTo(response, from)
		}
	}()
	return conn.LocalAddr().String(), func() { _ = conn.Close(); <-done }
}

func TestSTUNQueryDecodesMappedAddress(t *testing.T) {
	server, stop := fakeSTUN(t)
	defer stop()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mapped, err := STUNQuery(context.Background(), client, server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if mapped != client.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("mapped %s, socket is %s", mapped, client.LocalAddr())
	}
}

func TestSTUNTimesOutWithoutServer(t *testing.T) {
	silent, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer silent.Close()
	client, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer client.Close()
	if _, err := STUNQuery(context.Background(), client, silent.LocalAddr().String(), 200*time.Millisecond); err != ErrNoSTUNResponse {
		t.Fatalf("got %v", err)
	}
}

func TestParseRejectsForeignTransaction(t *testing.T) {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingResponse)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	if _, err := parseSTUNResponse(packet, make([]byte, 12)); err == nil {
		t.Fatal("response with no mapped address accepted")
	}
	copy(packet[8:20], "abcdefghijkl")
	if _, err := parseSTUNResponse(packet, []byte("zzzzzzzzzzzz")); err == nil {
		t.Fatal("response for another transaction accepted")
	}
}

func TestClassify(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.2:5000")
	a := netip.MustParseAddrPort("203.0.113.1:40000")
	b := netip.MustParseAddrPort("203.0.113.1:40001")
	if got := Classify(local, []netip.AddrPort{a, a}); got != BehaviourEndpointIndependent {
		t.Fatal(got)
	}
	if got := Classify(local, []netip.AddrPort{a, b}); got != BehaviourAddressDependent {
		t.Fatal(got)
	}
	if got := Classify(local, []netip.AddrPort{local}); got != BehaviourOpen {
		t.Fatal(got)
	}
	if got := Classify(local, nil); got != BehaviourUnknown {
		t.Fatal(got)
	}
}

func TestSanitiseDropsJunkAndCaps(t *testing.T) {
	now := time.Now()
	var input []EndpointCandidate
	input = append(input,
		EndpointCandidate{Type: CandidateHost, IP: "127.0.0.1", Port: 1, Protocol: "udp"},
		EndpointCandidate{Type: CandidateHost, IP: "0.0.0.0", Port: 1, Protocol: "udp"},
		EndpointCandidate{Type: CandidateHost, IP: "10.0.0.1", Port: 0, Protocol: "udp"},
		EndpointCandidate{Type: CandidateHost, IP: "10.0.0.1", Port: 9, Protocol: "tcp"},
		EndpointCandidate{Type: CandidateHost, IP: "10.0.0.1", Port: 9, Protocol: "udp", ExpiresAt: now.Add(-time.Second).Unix()},
	)
	for i := 0; i < 40; i++ {
		input = append(input, NewCandidate(CandidateReflexive, netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), uint16(1000+i)), time.Minute, now))
	}
	out := SanitiseCandidates(input, now)
	if len(out) != MaxCandidates {
		t.Fatalf("kept %d, cap %d", len(out), MaxCandidates)
	}
	for _, c := range out {
		if c.IP != "198.51.100.7" {
			t.Fatalf("junk candidate survived: %s", c)
		}
	}
}

func TestPunchBetweenTwoSockets(t *testing.T) {
	a, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	b, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer a.Close()
	defer b.Close()
	token, _ := NewSessionToken()
	now := time.Now()
	candidateFor := func(conn net.PacketConn) []EndpointCandidate {
		// Loopback is filtered as unusable in production; use the host type
		// with a documentation address rewritten to loopback for the test by
		// calling Punch's internals through a candidate the sanitiser keeps.
		addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
		return []EndpointCandidate{{Type: CandidateHost, IP: addr.Addr().String(), Port: addr.Port(), Protocol: "udp", Priority: 1000, ExpiresAt: now.Add(time.Minute).Unix()}}
	}
	// Loopback candidates are rejected by Usable, which is correct in
	// production. The punch mechanics are exercised directly here.
	results := make(chan error, 2)
	run := func(self net.PacketConn, peer net.PacketConn) {
		config := PunchConfig{Token: token, Candidates: candidateFor(peer), TotalTimeout: 3 * time.Second}
		_, err := punchTargets(context.Background(), self, config, []netip.AddrPort{peer.LocalAddr().(*net.UDPAddr).AddrPort()})
		results <- err
	}
	go run(a, b)
	go run(b, a)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("punch %d failed: %v", i, err)
		}
	}
}

func TestPunchGivesUpWithinBudget(t *testing.T) {
	a, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer a.Close()
	dead, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	target := dead.LocalAddr().(*net.UDPAddr).AddrPort()
	dead.Close()
	token, _ := NewSessionToken()
	started := time.Now()
	_, err := punchTargets(context.Background(), a, PunchConfig{Token: token, Rounds: 2, ProbesPerRound: 2, RoundInterval: 50 * time.Millisecond, ProbeSpacing: 10 * time.Millisecond, TotalTimeout: 2 * time.Second}, []netip.AddrPort{target})
	if err != ErrPunchFailed {
		t.Fatalf("got %v, want ErrPunchFailed", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("punch overran its budget")
	}
}

func TestPunchPacketFormat(t *testing.T) {
	token, _ := NewSessionToken()
	kind, got, ok := parsePunchPacket(buildPunchPacket(punchKindProbe, token))
	if !ok || kind != punchKindProbe || got != token {
		t.Fatal("punch packet did not round trip")
	}
	if _, _, ok := parsePunchPacket([]byte("not a punch packet")); ok {
		t.Fatal("garbage parsed as punch packet")
	}
}

func TestRewriteForWireGuard(t *testing.T) {
	now := time.Now()
	probed := []EndpointCandidate{
		NewCandidate(CandidateHost, netip.MustParseAddrPort("192.168.1.10:40000"), time.Minute, now),
		NewCandidate(CandidateReflexive, netip.MustParseAddrPort("203.0.113.9:40000"), time.Minute, now),
		NewCandidate(CandidateReflexive, netip.MustParseAddrPort("203.0.113.9:40000"), time.Minute, now),
	}
	out, mapping, err := RewriteForWireGuard(probed, BehaviourEndpointIndependent, 40000, 51820)
	if err != nil {
		t.Fatal(err)
	}
	if !mapping.PortPreserving || mapping.PublicIP.String() != "203.0.113.9" {
		t.Fatalf("mapping: %+v", mapping)
	}
	if len(out) != 2 {
		t.Fatalf("expected host + one reflexive, got %v", out)
	}
	for _, candidate := range out {
		if candidate.Port != 51820 {
			t.Fatalf("candidate not rewritten to the wireguard port: %s", candidate)
		}
	}

	remapped := []EndpointCandidate{NewCandidate(CandidateReflexive, netip.MustParseAddrPort("203.0.113.9:61234"), time.Minute, now)}
	out, mapping, _ = RewriteForWireGuard(remapped, BehaviourAddressDependent, 40000, 51820)
	if mapping.PortPreserving {
		t.Fatal("remapping NAT reported as port preserving")
	}
	if out[0].Priority >= 500 {
		t.Fatal("inferred candidate behind a remapping NAT kept full priority")
	}
}
