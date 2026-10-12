//go:build libp2pdht

package dht

import (
	"context"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	"io"
	"testing"
	"time"
)

func TestPublicNeighborDoesNotGainPrivateRecordAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := Open(ctx, Options{StateDir: t.TempDir(), Rendezvous: "private"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, Options{StateDir: t.TempDir(), Rendezvous: "private", RecordAllowed: func(r discovery.PeerRecord) bool { return r.NetworkID == "approved" }})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = a.host.Connect(ctx, peer.AddrInfo{ID: b.host.ID(), Addrs: b.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	_ = b.StoreRecord(discovery.PeerRecord{NetworkID: "private", DeviceID: "owner", DHTAddresses: b.LocalAddresses()})
	_ = a.StoreRecord(discovery.PeerRecord{NetworkID: "foreign", DeviceID: "stranger", DHTAddresses: a.LocalAddresses()})
	if record, err := a.fetch(ctx, peer.AddrInfo{ID: b.host.ID()}); err == nil {
		t.Fatalf("stranger obtained record: %+v", record)
	}
	stream, err := a.host.NewStream(ctx, b.host.ID(), RecordProtocol)
	if err == nil {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		raw, _ := io.ReadAll(stream)
		if len(raw) > 0 {
			t.Fatal("legacy protocol leaked record")
		}
	}
	_ = a.StoreRecord(discovery.PeerRecord{NetworkID: "approved", DeviceID: "member", DHTAddresses: a.LocalAddresses()})
	if record, err := a.fetch(ctx, peer.AddrInfo{ID: b.host.ID()}); err != nil || record.DeviceID != "owner" {
		t.Fatalf("approved fetch: %+v %v", record, err)
	}
}
