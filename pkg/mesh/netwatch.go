package mesh

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// NetworkPollInterval is how often WatchNetwork looks at the host's addresses.
const NetworkPollInterval = 5 * time.Second

// WatchNetwork tells the controller when the host's own addresses change: a
// laptop moving to another Wi-Fi, a cable plugged in, a new DHCP lease. It
// blocks until ctx ends.
//
// Polling the address list is deliberately simple. It needs no platform API,
// behaves the same on Windows and Linux, and the cost of a spurious change is
// one packet per peer and one candidate gathering (see NetworkChanged). A
// change of the public address behind an unchanged local one (a router
// redialling) is not visible here; the republish loop finds it through STUN.
//
// list is net.InterfaceAddrs in production. A phone does not use this: Go
// cannot list interfaces on Android, and the app reports changes itself.
func (c *Controller) WatchNetwork(ctx context.Context, interval time.Duration, list func() ([]net.Addr, error)) {
	if list == nil {
		list = net.InterfaceAddrs
	}
	ticker := time.NewTicker(orDefault(interval, NetworkPollInterval))
	defer ticker.Stop()
	last, known := "", false
	for {
		if addrs, err := list(); err == nil {
			current := addressFingerprint(addrs, c.Config.OverlayCIDR)
			if known && current != last {
				c.logger().Info("local addresses changed", "component", "mesh")
				changeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				c.NetworkChanged(changeCtx)
				cancel()
			}
			last, known = current, true
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// addressFingerprint reduces an address list to the part that matters for
// reachability: global and private unicast addresses, sorted. Loopback,
// link-local and the overlay's own addresses are left out, so bringing the
// tunnel up or down is not mistaken for a network change.
func addressFingerprint(addrs []net.Addr, overlay netip.Prefix) string {
	var out []string
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		parsed, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		parsed = parsed.Unmap()
		if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() || parsed.IsUnspecified() {
			continue
		}
		if overlay.IsValid() && overlay.Contains(parsed) {
			continue
		}
		out = append(out, parsed.String())
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
