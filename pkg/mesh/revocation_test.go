package mesh

import (
	"context"
	"errors"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
	"testing"
)

type revokeWG struct {
	wireguard.Manager
	removeErr, downErr error
	removed            []string
	downCalls          int
	stats              []wireguard.PeerStats
	add                func()
}

func (w *revokeWG) RemovePeer(_ context.Context, key string) error {
	w.removed = append(w.removed, key)
	return w.removeErr
}
func (w *revokeWG) Down(context.Context) error                           { w.downCalls++; return w.downErr }
func (w *revokeWG) Stats(context.Context) ([]wireguard.PeerStats, error) { return w.stats, nil }
func (w *revokeWG) AddPeer(context.Context, wireguard.PeerConfig) error {
	if w.add != nil {
		w.add()
	}
	return nil
}

func TestRevocationFailureClosesTunnelAndReportsError(t *testing.T) {
	for _, downFails := range []bool{false, true} {
		c := New()
		c.Config.RequireApproval = true
		c.ApproveDevice("device")
		peer := c.peerFor("device")
		peer.record = discovery.PeerRecord{DeviceID: "device", WireGuardPublicKey: "public"}
		w := &revokeWG{removeErr: errors.New("cannot remove key")}
		if downFails {
			w.downErr = errors.New("cannot remove interface")
		}
		c.WireGuard = w
		var fatal error
		c.OnSecurityFailure = func(err error) { fatal = err }
		_, err := c.RevokeDevice(context.Background(), "device")
		if err == nil || fatal == nil || w.downCalls != 1 || c.Authorized("device") {
			t.Fatalf("unsafe revoke: %v, %v, down=%d", err, fatal, w.downCalls)
		}
		if downFails && !errors.Is(err, w.downErr) {
			t.Fatal("interface cleanup failure lost")
		}
	}
}

func TestLatePeerInstallUsesSecureRevocationCleanup(t *testing.T) {
	c := New()
	peer := c.peerFor("device")
	peer.record = discovery.PeerRecord{DeviceID: "device", WireGuardPublicKey: "public", VirtualIPs: []string{"10.88.0.2"}}
	w := &revokeWG{removeErr: errors.New("remove denied"), add: peer.Revoke}
	c.WireGuard = w
	c.ensureWireGuardPeer(context.Background(), peer)
	if w.downCalls != 1 {
		t.Fatal("late installation left revoked key without closing tunnel")
	}
}

func TestStartupPrunesOnlyUnapprovedOrUntrackedKeys(t *testing.T) {
	c := New()
	c.Config.OwnerDevice, c.Config.RequireApproval = true, true
	c.ApproveDevice("allowed")
	c.peerFor("allowed").record = discovery.PeerRecord{DeviceID: "allowed", WireGuardPublicKey: "keep"}
	w := &revokeWG{stats: []wireguard.PeerStats{{PublicKey: "keep"}, {PublicKey: "orphan"}}}
	c.WireGuard = w
	if err := c.PruneUntrackedPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.removed) != 1 || w.removed[0] != "orphan" {
		t.Fatalf("wrong keys removed: %v", w.removed)
	}
}
