package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// A minimal RFC 5389 STUN client.
//
// Why not a library: the only thing NKNGuard needs from STUN is a Binding
// Request and the XOR-MAPPED-ADDRESS that comes back — about eighty lines. A
// dependency for that would pull a transitive tree into a program whose whole
// point is to be a single static binary on an ARM NAS, and it would not make
// the parsing any more correct.
//
// What STUN is NOT, and the code keeps it that way: a coordination server. It
// is asked one question — "what source address do you see?" — and is never
// told who we are, what network we are in, or who we are trying to reach.

const (
	stunBindingRequest   uint16 = 0x0001
	stunBindingResponse  uint16 = 0x0101
	stunMagicCookie      uint32 = 0x2112A442
	stunAttrXORMapped    uint16 = 0x0020
	stunAttrMappedLegacy uint16 = 0x0001
	stunHeaderBytes             = 20
	stunMaxResponseBytes        = 1280
)

// ErrNoSTUNResponse is returned when no server answered in time.
var ErrNoSTUNResponse = errors.New("nat: no STUN server answered")

// DefaultSTUNServers is a starting point, not a hard-coded dependency: the
// config file overrides it, and a deployment that wants to run its own puts
// them here. Two operators are listed rather than one so that a single
// provider's outage does not look like a broken NAT.
func DefaultSTUNServers() []string {
	return []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}
}

// STUNQuery asks one server what public address it sees for conn, reusing the
// caller's socket. Reusing it is essential rather than tidy: the mapping a
// STUN server reports is only the mapping WireGuard will use if both go out of
// the same local port.
func STUNQuery(ctx context.Context, conn net.PacketConn, server string, timeout time.Duration) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: invalid stun server: %w", err)
	}
	family := "ip"
	if local, ok := conn.LocalAddr().(*net.UDPAddr); ok && local.IP.To4() != nil {
		family = "ip4"
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, family, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: resolve stun server %q: %w", server, err)
	}
	if len(addresses) == 0 {
		return netip.AddrPort{}, fmt.Errorf("nat: stun server %q has no usable address", server)
	}
	// Resolve only the numeric address here; the cancellable lookup above
	// bounds DNS together with the socket I/O rather than before its deadline.
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addresses[0].String(), port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: resolve stun server %q: %w", server, err)
	}
	transaction := make([]byte, 12)
	if _, err := rand.Read(transaction); err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: stun transaction id: %w", err)
	}
	request := make([]byte, stunHeaderBytes)
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(request[2:4], 0)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	copy(request[8:20], transaction)

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: set stun deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if _, err := conn.WriteTo(request, target); err != nil {
		return netip.AddrPort{}, fmt.Errorf("nat: send stun request: %w", err)
	}

	buffer := make([]byte, stunMaxResponseBytes)
	for {
		read, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return netip.AddrPort{}, ErrNoSTUNResponse
		}
		mapped, err := parseSTUNResponse(buffer[:read], transaction)
		if err != nil {
			// Not our response — a punch probe or a stray packet can arrive on
			// this socket at any time. Keep reading until the deadline.
			if ctx.Err() != nil {
				return netip.AddrPort{}, ctx.Err()
			}
			continue
		}
		return mapped, nil
	}
}

func parseSTUNResponse(packet []byte, transaction []byte) (netip.AddrPort, error) {
	if len(packet) < stunHeaderBytes {
		return netip.AddrPort{}, errors.New("nat: short stun packet")
	}
	if binary.BigEndian.Uint16(packet[0:2]) != stunBindingResponse {
		return netip.AddrPort{}, errors.New("nat: not a binding response")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, errors.New("nat: bad magic cookie")
	}
	if string(packet[8:20]) != string(transaction) {
		return netip.AddrPort{}, errors.New("nat: transaction id mismatch")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if stunHeaderBytes+length > len(packet) {
		return netip.AddrPort{}, errors.New("nat: truncated stun body")
	}
	body := packet[stunHeaderBytes : stunHeaderBytes+length]
	for len(body) >= 4 {
		attribute := binary.BigEndian.Uint16(body[0:2])
		size := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+size > len(body) {
			return netip.AddrPort{}, errors.New("nat: truncated stun attribute")
		}
		value := body[4 : 4+size]
		switch attribute {
		case stunAttrXORMapped:
			return decodeAddress(value, packet[4:20], true)
		case stunAttrMappedLegacy:
			return decodeAddress(value, packet[4:20], false)
		}
		advance := 4 + size
		if pad := advance % 4; pad != 0 {
			advance += 4 - pad
		}
		if advance > len(body) {
			break
		}
		body = body[advance:]
	}
	return netip.AddrPort{}, errors.New("nat: stun response carried no mapped address")
}

// decodeAddress reads a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute.
// cookieAndTransaction is the 16 bytes following the message length, which is
// what the XOR variant masks with.
func decodeAddress(value []byte, cookieAndTransaction []byte, xored bool) (netip.AddrPort, error) {
	if len(value) < 4 {
		return netip.AddrPort{}, errors.New("nat: short mapped address")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	raw := value[4:]
	if xored {
		port ^= uint16(stunMagicCookie >> 16)
	}
	var size int
	switch family {
	case 0x01:
		size = 4
	case 0x02:
		size = 16
	default:
		return netip.AddrPort{}, fmt.Errorf("nat: unknown address family %#x", family)
	}
	if len(raw) < size {
		return netip.AddrPort{}, errors.New("nat: short mapped address body")
	}
	octets := make([]byte, size)
	copy(octets, raw[:size])
	if xored {
		for index := range octets {
			octets[index] ^= cookieAndTransaction[index]
		}
	}
	addr, ok := netip.AddrFromSlice(octets)
	if !ok {
		return netip.AddrPort{}, errors.New("nat: mapped address is not an ip")
	}
	return netip.AddrPortFrom(addr.Unmap(), port), nil
}
