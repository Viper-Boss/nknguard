package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

func TestNetworkJSONFeedsLANHostCandidatesWithoutNetlink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := startPhone(t, ctx, signaling.NewSwitch(), relay.NewHub())
	p.must("init", map[string]any{"network_handle": "wifi", "local_addresses": []string{"192.168.120.196", "10.88.2.245"}}, nil)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	g := nat.Gatherer{Interfaces: p.agent.interfaceAddrs}
	candidates, _, err := g.Gather(ctx, socket)
	if err != nil || len(candidates) != 1 || candidates[0].Type != nat.CandidateHost || candidates[0].IP != "192.168.120.196" {
		t.Fatalf("physical LAN address missing or overlay advertised: %+v %v", candidates, err)
	}
	// An idempotent init after pairing must not clear the network report.
	p.must("init", nil, nil)
	candidates, _, err = g.Gather(ctx, socket)
	if err != nil || len(candidates) != 1 || candidates[0].IP != "192.168.120.196" {
		t.Fatal("empty init erased physical address")
	}
	var report struct {
		Text string `json:"text"`
	}
	p.must("diagnostics", nil, &report)
	if !strings.Contains(report.Text, "underlying_address: 192.168.120.196") {
		t.Fatal("network report missing from diagnostics")
	}
}

func TestNKNStatusRequiresRecentDeliveryAndKeepsDirectPhase(t *testing.T) {
	for _, phase := range []string{PhaseWaiting, PhaseDirect} {
		for _, state := range []string{"checking", "reconnecting", "closed", "connected"} {
			a := &Agent{StateDir: t.TempDir()}
			a.session = &session{phase: phase, nknAddress: "nknguard.public", started: time.Now(), nknHealth: func() nknclient.ConnectionStatus { return nknclient.ConnectionStatus{State: state} }}
			status := a.status()
			if status.NKNConnected != (state == "connected") {
				t.Fatalf("address mistaken for delivery: %+v", status)
			}
			if phase == PhaseDirect && status.Phase != PhaseDirect {
				t.Fatal("control check stopped direct phase")
			}
			if phase == PhaseWaiting && state != "connected" && status.Phase != PhaseNKN {
				t.Fatal("unhealthy control path still displayed waiting for NAS")
			}
		}
	}
}

func TestInitializationRequiresSavedIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := startPhone(t, ctx, signaling.NewSwitch(), relay.NewHub())
	p.mu.Lock()
	p.saveSecrets = func(map[string]string) bool { return false }
	p.mu.Unlock()
	_, message := p.call("init", nil)
	if !strings.Contains(message, "cannot save device keys") {
		t.Fatalf("init accepted failed save: %s", message)
	}
	if p.agent.Secrets.Has(SecretRoot) {
		t.Fatal("failed persistent identity committed in memory")
	}
	p.mu.Lock()
	p.saveSecrets = nil
	p.mu.Unlock()
	p.must("init", nil, nil)
}

func TestPairApprovalRequiresSavedJoinSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire, hub := signaling.NewSwitch(), relay.NewHub()
	home := startNAS(t, ctx, wire, hub)
	p := startPhone(t, ctx, wire, hub)
	var info InitResult
	p.must("init", nil, &info)
	p.mu.Lock()
	p.saveSecrets = func(values map[string]string) bool { _, joined := values[SecretJoinSecret]; return !joined }
	p.mu.Unlock()
	invite, err := home.pairing.NewInvite()
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := invite.URI()
	p.must("pair", map[string]string{"uri": uri, "name": "save-failure"}, nil)
	deadline := time.Now().Add(3 * time.Second)
	for len(home.pairing.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := home.pairing.Approve(ctx, info.DeviceID); err != nil {
		t.Fatal(err)
	}
	failure := p.waitEvent("pair_status", 3*time.Second, func(raw json.RawMessage) bool {
		var s PairStatus
		_ = json.Unmarshal(raw, &s)
		return s.Stage == PairApproved || s.Stage == PairFailed
	})
	var progress PairStatus
	_ = json.Unmarshal(failure, &progress)
	if progress.Stage != PairFailed {
		t.Fatal("pairing reported success before encrypted save")
	}
	var status Status
	p.must("status", nil, &status)
	if status.Paired || p.agent.Secrets.Has(SecretJoinSecret) {
		t.Fatal("failed save left a paired phone")
	}
}

func TestSessionProbesCachedPeerWhileNKNIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire, hub := signaling.NewSwitch(), relay.NewHub()
	home := startNAS(t, ctx, wire, hub)
	opening := make(chan struct{})
	p := startPhoneWith(t, ctx, wire, hub, func(agent *Agent) {
		agent.OpenPlane = func(ctx context.Context, _ []byte, _ []string) (*Plane, error) {
			close(opening)
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	p.must("init", nil, nil)
	invite, err := home.pairing.NewInvite()
	if err != nil {
		t.Fatal(err)
	}
	device, _, _ := p.agent.identity()
	if err := p.agent.savePairing(invite, device, "cached", home.secret); err != nil {
		t.Fatal(err)
	}
	key, _, _ := home.node.MembershipKey()
	wgKey, err := wireguard.EnsureKeyPair(wireguard.FromIdentityKeystore(home.node.Keystore))
	if err != nil {
		t.Fatal(err)
	}
	record, err := discovery.Sign(home.node.Device, discovery.PeerRecord{
		NetworkID: invite.NetworkID, WireGuardPublicKey: wgKey, VirtualIPs: []string{home.virtual.String()},
		MembershipProof: key.Proof(invite.NASID, home.node.Device.PublicKey()),
	}, 1, time.Minute, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := p.agent.store()
	if err := store.SavePeerCache([]discovery.PeerRecord{record}); err != nil {
		t.Fatal(err)
	}
	endpoint := "198.51.100.20:51820"
	if err := store.SaveLinkHints([]state.LinkHint{{DeviceID: invite.NASID, PublicKey: wgKey, Endpoint: endpoint, SeenAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	p.must("connect", map[string]string{"token": "tun-token"}, nil)
	select {
	case <-opening:
	case <-time.After(time.Second):
		t.Fatal("NKN open never started")
	}
	deadline := time.Now().Add(2 * time.Second)
	var status Status
	for time.Now().Before(deadline) {
		p.must("status", nil, &status)
		if status.Endpoint == endpoint {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status.Endpoint != endpoint || status.NKNConnected || status.Phase == PhaseDirect {
		t.Fatalf("cached probe/NKN state: %+v", status)
	}
	p.must("disconnect", nil, nil)
	p.must("status", nil, &status)
	if status.Connected {
		t.Fatal("blocked NKN left a VPN session after disconnect")
	}
}

func TestSecretWriteFailurePreservesOldIdentity(t *testing.T) {
	store := NewSecretStore()
	_ = store.WriteSecret(SecretRoot, []byte("old"))
	store.SetOnChange(func(map[string][]byte) error { return errors.New("full disk") })
	if err := store.WriteSecret(SecretRoot, []byte("new")); err == nil {
		t.Fatal("failed save returned success")
	}
	root, _ := store.ReadSecret(SecretRoot)
	if string(root) != "old" {
		t.Fatal("failed save replaced existing identity")
	}
}
