package mobile

import (
	"net/netip"
	"testing"
)

func TestCachedEndpointDoesNotProbeOldLANOnMobile(t *testing.T) {
	for _, test := range []struct {
		endpoint, local string
		want            bool
	}{
		{"192.168.120.190:39971", "192.168.120.156", true},
		{"192.168.120.190:39971", "10.115.160.133", false},
		{"[fd7a:115c:a1e0::2]:39971", "2409:892c::1", false},
		{"[2001:db8::2]:39971", "2409:892c::1", true},
		{"198.51.100.2:39971", "10.115.160.133", true},
		{"100.64.1.1:39971", "10.115.160.133", false},
	} {
		if got := cachedEndpointFitsNetwork(test.endpoint, []netip.Addr{netip.MustParseAddr(test.local)}); got != test.want {
			t.Errorf("endpoint %s on %s = %v", test.endpoint, test.local, got)
		}
	}
}
