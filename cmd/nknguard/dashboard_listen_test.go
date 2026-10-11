package main

import (
	"net/netip"
	"testing"
)

func TestDashboardLANSelection(t *testing.T) {
	ip := netip.MustParseAddr
	candidates := []lanCandidate{{"docker0", true, ip("172.17.0.1")}, {"nkg0", true, ip("10.88.0.1")}, {"eth1", true, ip("10.55.0.1")}, {"eth0", true, ip("192.168.120.190")}}
	got, err := selectLANAddress(candidates, ip("192.168.120.190"))
	if err != nil || got != ip("192.168.120.190") {
		t.Fatalf("default-route LAN: %v %v", got, err)
	}
	if _, err := selectLANAddress(candidates[:2], ip("172.17.0.1")); err == nil {
		t.Fatal("selected overlay/container address")
	}
	if _, err := selectLANAddress([]lanCandidate{{"eth0", false, ip("192.168.1.1")}, {"eth1", true, ip("8.8.8.8")}}, netip.Addr{}); err == nil {
		t.Fatal("selected inactive/public address")
	}
}

func TestDashboardListenValidation(t *testing.T) {
	for _, value := range []string{"0.0.0.0:7878", "8.8.8.8:7878", "127.0.0.1:0", "auto-lan:0", "auto-lan:65536"} {
		if _, err := resolveDashboardListen(value); err == nil {
			t.Errorf("accepted %s", value)
		}
	}
	got, err := resolveDashboardListen("192.168.120.190:7878")
	if err != nil || got != "192.168.120.190:7878" {
		t.Fatalf("private listener: %q %v", got, err)
	}
}
