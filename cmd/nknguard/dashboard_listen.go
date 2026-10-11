package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type lanCandidate struct {
	name    string
	up      bool
	address netip.Addr
}

func selectLANAddress(candidates []lanCandidate, preferred netip.Addr) (netip.Addr, error) {
	var fallback netip.Addr
	for _, c := range candidates {
		excluded := false
		for _, prefix := range []string{"lo", "docker", "br-", "veth", "tailscale", "nkg", "wg", "tun", "tap", "virbr"} {
			if strings.HasPrefix(strings.ToLower(c.name), prefix) {
				excluded = true
				break
			}
		}
		if excluded || !c.up || !c.address.Is4() || !c.address.IsPrivate() {
			continue
		}
		if c.address == preferred {
			return c.address, nil
		}
		if !fallback.IsValid() {
			fallback = c.address
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.Addr{}, fmt.Errorf("no active private LAN IPv4 address for dashboard")
}

func resolveDashboardListen(value string) (string, error) {
	if !strings.HasPrefix(value, "auto-lan:") {
		addr, err := netip.ParseAddrPort(value)
		if err != nil || addr.Port() == 0 || !(addr.Addr().IsPrivate() || addr.Addr().IsLoopback()) {
			return "", fmt.Errorf("dashboard listener must be a specific private or loopback IP and nonzero port")
		}
		return addr.String(), nil
	}
	port, err := strconv.ParseUint(strings.TrimPrefix(value, "auto-lan:"), 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("invalid auto-lan dashboard port")
	}
	var preferred netip.Addr
	// UDP connect selects the default-route source address without sending packets.
	if conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err == nil {
		preferred, _ = netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
		preferred = preferred.Unmap()
		_ = conn.Close()
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("dashboard LAN interfaces: %w", err)
	}
	var candidates []lanCandidate
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil {
				candidates = append(candidates, lanCandidate{iface.Name, iface.Flags&net.FlagUp != 0, prefix.Addr().Unmap()})
			}
		}
	}
	address, err := selectLANAddress(candidates, preferred)
	if err != nil {
		return "", err
	}
	return netip.AddrPortFrom(address, uint16(port)).String(), nil
}
