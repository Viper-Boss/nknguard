package mobile

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Go's pure resolver reads /etc/resolv.conf, which Android does not have, and
// falls back to a resolver on localhost that does not exist. The app reports
// the DNS servers of the phone's current network instead; the fallbacks cover
// the window before it does and networks that hide their resolvers.
var fallbackDNS = []string{"223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"}

var (
	dnsMu      sync.Mutex
	dnsServers = append([]string(nil), fallbackDNS...)
	dnsNext    atomic.Uint32
)

// SetDNSServers replaces the resolvers used after InstallResolver.
func SetDNSServers(servers []string) {
	clean := make([]string, 0, len(servers)+len(fallbackDNS))
	seen := make(map[string]bool)
	for _, server := range append(append([]string(nil), servers...), fallbackDNS...) {
		addr, err := netip.ParseAddr(server)
		if err != nil || addr.IsUnspecified() || OverlayCIDR.Contains(addr.Unmap()) || seen[addr.String()] {
			continue
		}
		seen[addr.String()] = true
		clean = append(clean, addr.String())
	}
	dnsMu.Lock()
	dnsServers = clean
	dnsMu.Unlock()
}

func pickDNS(attempt uint32) string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if len(dnsServers) == 0 {
		return net.JoinHostPort(fallbackDNS[0], "53")
	}
	return net.JoinHostPort(dnsServers[int(attempt)%len(dnsServers)], "53")
}

// InstallResolver points Go's default resolver at the servers the app reports.
// Only the Android entry point calls it; tests and the desktop builds keep the
// system resolver.
func InstallResolver() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, pickDNS(dnsNext.Add(1)))
		},
	}
}
