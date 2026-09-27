package userspace

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type memoryKeystore struct {
	mu      sync.Mutex
	secrets map[string][]byte
}

func (k *memoryKeystore) ReadSecret(name string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.secrets[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func (k *memoryKeystore) WriteSecret(name string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.secrets == nil {
		k.secrets = make(map[string][]byte)
	}
	k.secrets[name] = append([]byte(nil), data...)
	return nil
}

func (k *memoryKeystore) Has(name string) bool {
	_, err := k.ReadSecret(name)
	return err == nil
}

type node struct {
	manager *Manager
	tun     *tuntest.ChannelTUN
	key     string
	ip      netip.Addr
	port    int
}

func newNode(t *testing.T, ip string) *node {
	t.Helper()
	channel := tuntest.NewChannelTUN()
	manager := New(&memoryKeystore{}, func() (tun.Device, error) { return channel.TUN(), nil }, nil)
	ctx := context.Background()
	if err := manager.EnsureInterface(ctx, wireguard.InterfaceConfig{Name: "test", Address: ip + "/16"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Down(context.Background()) })
	key, err := manager.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status := manager.Status(ctx)
	if status.State != wireguard.StateUp || status.ListenPort == 0 || status.PublicKey != key {
		t.Fatalf("status after up = %+v", status)
	}
	return &node{manager: manager, tun: channel, key: key, ip: netip.MustParseAddr(ip), port: status.ListenPort}
}

func (n *node) loopback() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(n.port))
}

func (n *node) addPeer(t *testing.T, peer *node, endpoint string) {
	t.Helper()
	err := n.manager.AddPeer(context.Background(), wireguard.PeerConfig{
		DeviceID: "nkg_peer", Name: "peer", PublicKey: peer.key, Endpoint: endpoint,
		AllowedIPs: []string{netip.PrefixFrom(peer.ip, 32).String()},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func expectPing(t *testing.T, from, to *node) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case from.tun.Outbound <- tuntest.Ping(to.ip, from.ip):
		case <-deadline:
			t.Fatal("timed out sending")
		}
		select {
		case packet := <-to.tun.Inbound:
			if len(packet) >= 20 && netip.AddrFrom4([4]byte(packet[12:16])) == from.ip {
				return
			}
		case <-ticker.C:
		case <-deadline:
			t.Fatal("ping did not arrive through WireGuard")
		}
	}
}

func peerStats(t *testing.T, n *node, key string) wireguard.PeerStats {
	t.Helper()
	stats, err := n.manager.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, stat := range stats {
		if stat.PublicKey == key {
			return stat
		}
	}
	t.Fatalf("peer %s missing from %+v", key, stats)
	return wireguard.PeerStats{}
}

func TestDirectHandshakeAndStats(t *testing.T) {
	a := newNode(t, "10.88.0.1")
	b := newNode(t, "10.88.0.2")
	a.addPeer(t, b, b.loopback().String())
	b.addPeer(t, a, "")

	expectPing(t, a, b)
	stat := peerStats(t, a, b.key)
	if !stat.Current || stat.LastHandshake == 0 || stat.TransferTxBytes == 0 || stat.DeviceID != "nkg_peer" {
		t.Fatalf("stats after handshake = %+v", stat)
	}
	// B learned A's endpoint from the authenticated handshake, as roaming
	// WireGuard does.
	if got := peerStats(t, b, a.key).Endpoint; got != a.loopback().String() {
		t.Fatalf("B endpoint for A = %q", got)
	}
}

func TestUpdateEndpointAndRemove(t *testing.T) {
	a := newNode(t, "10.88.0.1")
	b := newNode(t, "10.88.0.2")
	a.addPeer(t, b, "")
	b.addPeer(t, a, "")
	if err := a.manager.UpdateEndpoint(context.Background(), b.key, b.loopback().String()); err != nil {
		t.Fatal(err)
	}
	if got := peerStats(t, a, b.key).Endpoint; got != b.loopback().String() {
		t.Fatalf("endpoint = %q", got)
	}
	a.manager.Nudge(context.Background(), b.ip)
	deadline := time.Now().Add(5 * time.Second)
	for peerStats(t, a, b.key).LastHandshake == 0 {
		if time.Now().After(deadline) {
			t.Fatal("nudge did not produce a handshake")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := a.manager.RemovePeer(context.Background(), b.key); err != nil {
		t.Fatal(err)
	}
	stats, _ := a.manager.Stats(context.Background())
	if len(stats) != 0 {
		t.Fatalf("peer still present: %+v", stats)
	}
}

// TestRelayBridgeCarriesWireGuard runs the production relay bridge between
// two userspace devices: the stream in the middle carries only framed
// WireGuard ciphertext, and the handshake still completes end to end.
func TestRelayBridgeCarriesWireGuard(t *testing.T) {
	a := newNode(t, "10.88.0.1")
	b := newNode(t, "10.88.0.2")
	left, right := net.Pipe()
	recorder := &recordingConn{Conn: left}
	bridgeA, err := relay.NewBridge(recorder, a.loopback())
	if err != nil {
		t.Fatal(err)
	}
	bridgeB, err := relay.NewBridge(right, b.loopback())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = bridgeA.Run(ctx) }()
	go func() { _ = bridgeB.Run(ctx) }()

	a.addPeer(t, b, bridgeA.LocalAddr().String())
	b.addPeer(t, a, bridgeB.LocalAddr().String())
	expectPing(t, a, b)
	if !strings.HasPrefix(peerStats(t, a, b.key).Endpoint, "127.0.0.1:") {
		t.Fatal("relayed peer should have a loopback endpoint")
	}
	if bridgeA.Stats().BytesSent == 0 || bridgeA.Stats().BytesRecv == 0 {
		t.Fatalf("bridge stats = %+v", bridgeA.Stats())
	}
	// The ICMP payload built by tuntest must never appear in clear on the
	// relay stream.
	if recorder.contains(tuntest.Ping(b.ip, a.ip)[20:]) {
		t.Fatal("plaintext IP payload crossed the relay")
	}
}

type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (r *recordingConn) Write(data []byte) (int, error) {
	r.mu.Lock()
	r.written = append(r.written, data...)
	r.mu.Unlock()
	return r.Conn.Write(data)
}

func (r *recordingConn) contains(needle []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Contains(string(r.written), string(needle))
}

func TestDownClosesDevice(t *testing.T) {
	a := newNode(t, "10.88.0.1")
	if err := a.manager.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := a.manager.Status(context.Background()); status.State != wireguard.StateDown {
		t.Fatalf("status after down = %+v", status)
	}
	if err := a.manager.AddPeer(context.Background(), wireguard.PeerConfig{PublicKey: a.key, AllowedIPs: []string{"10.88.0.9/32"}}); err == nil {
		t.Fatal("AddPeer on a closed device must fail")
	}
}

func TestOpenTUNFailureIsReported(t *testing.T) {
	manager := New(&memoryKeystore{}, func() (tun.Device, error) { return nil, errors.New("no vpn permission") }, nil)
	if err := manager.EnsureInterface(context.Background(), wireguard.InterfaceConfig{}); err == nil {
		t.Fatal("expected error")
	}
	if status := manager.Status(context.Background()); status.State != wireguard.StateDown || !strings.Contains(status.Error, "no vpn permission") {
		t.Fatalf("status = %+v", status)
	}
}

func TestParseUAPISkipsPrivateKey(t *testing.T) {
	raw := "private_key=" + strings.Repeat("a", 64) + "\nlisten_port=51820\npublic_key=" + strings.Repeat("0", 64) +
		"\nendpoint=192.0.2.1:51820\nlast_handshake_time_sec=100\nrx_bytes=5\ntx_bytes=7\n"
	status := parseUAPI(raw, time.Unix(150, 0))
	if status.ListenPort != 51820 || len(status.Peers) != 1 {
		t.Fatalf("status = %+v", status)
	}
	peer := status.Peers[0]
	if peer.Endpoint != "192.0.2.1:51820" || peer.LastHandshake != 100 || peer.TransferRxBytes != 5 || peer.TransferTxBytes != 7 || !peer.Current {
		t.Fatalf("peer = %+v", peer)
	}
	if strings.Contains(status.PublicKey+peer.PublicKey, "aaaa") {
		t.Fatal("private key leaked into status")
	}
}
