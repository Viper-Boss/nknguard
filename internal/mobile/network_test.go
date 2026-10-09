package mobile

import "testing"

func TestRepeatedNetworkNotificationsDoNotRebind(t *testing.T) {
	a := &Agent{}
	handle := "1234"
	args := networkArgs{NetworkHandle: &handle, LocalAddresses: []string{"192.168.1.5", "2001:db8::5"}}
	if !a.applyNetwork(args) {
		t.Fatal("initial network missing")
	}
	args.LocalAddresses = []string{"2001:db8::5", "192.168.1.5"}
	if a.applyNetwork(args) {
		t.Fatal("same addresses reordered caused socket rebuild")
	}
	if a.applyNetwork(networkArgs{}) {
		t.Fatal("notification without interface changes caused WireGuard rebind")
	}
	other := "4567"
	args.NetworkHandle = &other
	if !a.applyNetwork(args) {
		t.Fatal("network change with same addresses was ignored")
	}
}
