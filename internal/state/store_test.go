package state

import (
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
)

func TestSequenceNeverGoesBackwardsAcrossRestart(t *testing.T) {
	store := New(t.TempDir())
	if err := store.SaveRuntime(Runtime{Sequence: 100, VirtualIP: "10.88.0.5"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Sequence <= 100 {
		t.Fatalf("sequence %d did not advance past the stored value", loaded.Sequence)
	}
	if loaded.VirtualIP != "10.88.0.5" {
		t.Fatal("virtual ip lost across restart")
	}
}

func TestMissingFilesMeanNotJoined(t *testing.T) {
	store := New(t.TempDir())
	membership, err := store.LoadMembership()
	if err != nil || membership.NetworkID != "" {
		t.Fatalf("fresh store: %+v %v", membership, err)
	}
}

func TestPeerCacheRetainsRecentHintsAndDropsAncient(t *testing.T) {
	store := New(t.TempDir())
	device, _ := identity.Generate()
	live, _ := discovery.Sign(device, discovery.PeerRecord{NetworkID: "n"}, 1, time.Minute, time.Now())
	recent, _ := discovery.Sign(device, discovery.PeerRecord{NetworkID: "n"}, 2, time.Minute, time.Now().Add(-time.Hour))
	ancient, _ := discovery.Sign(device, discovery.PeerRecord{NetworkID: "n"}, 3, time.Minute, time.Now().Add(-8*24*time.Hour))
	if err := store.SavePeerCache([]discovery.PeerRecord{live, recent, ancient}); err != nil {
		t.Fatal(err)
	}
	records, _ := store.LoadPeerCache()
	if len(records) != 2 || records[0].DeviceID != device.DeviceID() || records[1].Sequence != 2 {
		t.Fatalf("cache: %+v", records)
	}
}
