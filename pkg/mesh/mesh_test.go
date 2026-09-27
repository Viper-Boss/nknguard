package mesh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/acl"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// ---- simulated WireGuard ---------------------------------------------------
//
// fakeWG stands in for a kernel interface. The direct path is simulated by a
// rule — "both sides point at each other's public endpoint and direct traffic
// is not blocked" — because a real NAT cannot be built in a unit test. The
// relay path is NOT simulated: the fake has a real UDP socket on loopback and
// exchanges real datagrams through the real relay bridges, so the fallback is
// tested byte for byte.

type fakeNet struct {
	mu          sync.Mutex
	nodes       map[string]*fakeWG
	blockDirect bool
}

func newFakeNet() *fakeNet { return &fakeNet{nodes: make(map[string]*fakeWG)} }

func (n *fakeNet) setBlocked(blocked bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blockDirect = blocked
}

func (n *fakeNet) evaluate() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.blockDirect {
		return
	}
	now := time.Now()
	for _, a := range n.nodes {
		for _, b := range n.nodes {
			if a == b {
				continue
			}
			if a.endpointFor(b.key) == b.public.String() && b.endpointFor(a.key) == a.public.String() {
				a.noteHandshake(b.key, now)
			}
		}
	}
}

type fakeWG struct {
	net    *fakeNet
	key    string
	public netip.AddrPort
	sock   *net.UDPConn

	mu         sync.Mutex
	endpoints  map[string]string
	handshakes map[string]time.Time
	peers      map[string]wireguard.PeerConfig
}

func newFakeWG(t *testing.T, network *fakeNet, key string, public netip.AddrPort) *fakeWG {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWG{
		net: network, key: key, public: public, sock: sock,
		endpoints: map[string]string{}, handshakes: map[string]time.Time{}, peers: map[string]wireguard.PeerConfig{},
	}
	network.mu.Lock()
	network.nodes[key] = fake
	network.mu.Unlock()
	go fake.serve()
	t.Cleanup(func() { _ = sock.Close() })
	return fake
}

// serve plays WireGuard's handshake over whatever reaches the socket, which
// in these tests is only ever the relay bridge.
func (f *fakeWG) serve() {
	buffer := make([]byte, 256)
	for {
		read, from, err := f.sock.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		message := string(buffer[:read])
		if len(message) < 2 {
			continue
		}
		peerKey := message[1:]
		f.mu.Lock()
		f.handshakes[peerKey] = time.Now()
		// Real WireGuard roams to the source of the latest authenticated
		// packet. Once a direct path is up, direct packets keep arriving and
		// win over any relay stragglers; the fake models that converged
		// result by not roaming off a direct endpoint onto the bridge.
		if current, err := netip.ParseAddrPort(f.endpoints[peerKey]); err != nil || current.Addr().IsLoopback() {
			f.endpoints[peerKey] = from.String()
		}
		f.mu.Unlock()
		if message[0] == 'I' {
			_, _ = f.sock.WriteToUDPAddrPort([]byte("R"+f.key), from)
		}
	}
}

func (f *fakeWG) endpointFor(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.endpoints[key]
}

func (f *fakeWG) noteHandshake(key string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handshakes[key] = at
}

func (f *fakeWG) initiate(endpoint string) {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil || !addr.Addr().IsLoopback() {
		return
	}
	_, _ = f.sock.WriteToUDPAddrPort([]byte("I"+f.key), addr)
}

func (f *fakeWG) Supported(context.Context) (wireguard.State, string) { return wireguard.StateDown, "" }
func (f *fakeWG) PublicKey(context.Context) (string, error)           { return f.key, nil }
func (f *fakeWG) EnsureInterface(context.Context, wireguard.InterfaceConfig) error {
	return nil
}
func (f *fakeWG) AddPeer(_ context.Context, peer wireguard.PeerConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[peer.PublicKey] = peer
	return nil
}
func (f *fakeWG) UpdateEndpoint(_ context.Context, key, endpoint string) error {
	f.mu.Lock()
	f.endpoints[key] = endpoint
	f.mu.Unlock()
	f.initiate(endpoint)
	return nil
}
func (f *fakeWG) RemovePeer(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}
func (f *fakeWG) Stats(context.Context) ([]wireguard.PeerStats, error) {
	f.net.evaluate()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]wireguard.PeerStats, 0, len(f.peers))
	for key := range f.peers {
		stat := wireguard.PeerStats{PublicKey: key, Endpoint: f.endpoints[key]}
		if at, ok := f.handshakes[key]; ok {
			stat.LastHandshake = at.Unix()
		}
		out = append(out, stat)
		// Persistent keepalive keeps a relayed session's handshake fresh.
		go f.initiate(f.endpoints[key])
	}
	return out, nil
}
func (f *fakeWG) Status(context.Context) wireguard.Status {
	return wireguard.Status{State: wireguard.StateUp, ListenPort: f.sock.LocalAddr().(*net.UDPAddr).Port}
}
func (f *fakeWG) Down(context.Context) error { return nil }

// ---- harness ---------------------------------------------------------------

// roster is a rendezvous source listing every node in the env — the in-test
// equivalent of an NKN topic's subscriber list.
type roster struct {
	mu        sync.Mutex
	addresses []string
}

func (r *roster) add(address string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addresses = append(r.addresses, address)
}
func (r *roster) Announce(context.Context) error { return nil }
func (r *roster) Addresses(context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addresses...), nil
}
func (r *roster) Close() error { return nil }

type env struct {
	roster    *roster
	networkID string
	key       *membership.Key
	discovery *discovery.Memory
	switchNet *signaling.Switch
	hub       *relay.Hub
	fake      *fakeNet
}

func newEnv(t *testing.T) *env {
	t.Helper()
	networkID, _ := membership.NewNetworkID()
	secret, _ := membership.NewJoinSecret()
	key, err := membership.Derive(networkID, secret)
	if err != nil {
		t.Fatal(err)
	}
	return &env{
		roster:    &roster{},
		networkID: networkID, key: key,
		discovery: discovery.NewMemory(networkID),
		switchNet: signaling.NewSwitch(),
		hub:       relay.NewHub(),
		fake:      newFakeNet(),
	}
}

type node struct {
	ctrl   *Controller
	wg     *fakeWG
	sig    *signaling.Loopback
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func testTiming() Timing {
	return Timing{
		RepublishInterval: 100 * time.Millisecond,
		ReconcileInterval: 50 * time.Millisecond,
		PollInterval:      200 * time.Millisecond,
		PunchLead:         100 * time.Millisecond,
		RelayAfter:        time.Second,
		Selector: Selector{
			DirectLossGrace:     time.Second,
			DirectRecoveryHold:  200 * time.Millisecond,
			DirectRetryInterval: 300 * time.Millisecond,
			DirectRetryMax:      time.Second,
			current:             PathNone,
		},
	}
}

func (e *env) start(t *testing.T, name, public string, key *membership.Key) *node {
	t.Helper()
	return e.startWith(t, name, public, key, nil)
}

// startWith builds a node and lets the test adjust it before it runs. Every
// node on the env gets a rendezvous source listing every other node started
// so far and every node started later, which is how a static peer list
// behaves.
func (e *env) startWith(t *testing.T, name, public string, key *membership.Key, adjust func(*Controller)) *node {
	t.Helper()
	device, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort(public)
	fake := newFakeWG(t, e.fake, "WG-"+name+"=", endpoint)
	loop := e.switchNet.Attach(device.DeviceID())

	ctrl := New()
	ctrl.Config.NetworkID = e.networkID
	ctrl.Config.DeviceName = name
	ctrl.Config.Timing = testTiming()
	ctrl.Device = device
	ctrl.Membership = key
	ctrl.Discovery = e.discovery
	ctrl.Signaling = loop
	ctrl.WireGuard = fake
	ctrl.Relay = e.hub.Endpoint(device.DeviceID())
	ctrl.Direct = &WireGuardStrategy{WireGuard: fake, PerCandidate: 1500 * time.Millisecond, PollInterval: 50 * time.Millisecond}
	ctrl.Candidates = StaticCandidates{nat.NewCandidate(nat.CandidateReflexive, endpoint, time.Hour, time.Now())}
	ctrl.Policy = acl.Policy{Default: acl.Allow}
	ctrl.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := ctrl.AssignVirtualIP(); err != nil {
		t.Fatal(err)
	}
	ctrl.Rendezvous = e.roster
	e.roster.add(device.DeviceID())
	if adjust != nil {
		adjust(ctrl)
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := &node{ctrl: ctrl, wg: fake, sig: loop, cancel: cancel, done: make(chan error, 1)}
	go func() { n.done <- ctrl.Run(ctx) }()
	t.Cleanup(func() { n.stop(t) })
	return n
}

func (n *node) stop(t *testing.T) {
	t.Helper()
	n.once.Do(func() { n.waitStopped(t) })
}

func (n *node) waitStopped(t *testing.T) {
	t.Helper()
	n.cancel()
	select {
	case <-n.done:
	case <-time.After(5 * time.Second):
		buffer := make([]byte, 1<<20)
		t.Fatalf("controller did not stop within 5s of cancel:\n%s", buffer[:runtime.Stack(buffer, true)])
	}
}

func (n *node) peer(deviceID string) (Snapshot, bool) {
	for _, snapshot := range n.ctrl.Peers() {
		if snapshot.DeviceID == deviceID {
			return snapshot, true
		}
	}
	return Snapshot{}, false
}

func waitFor(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func dump(nodes ...*node) string {
	var out strings.Builder
	for _, n := range nodes {
		out.WriteString("\n== " + n.ctrl.Config.DeviceName + " " + n.ctrl.Device.DeviceID() + "\n")
		for _, p := range n.ctrl.Peers() {
			out.WriteString("  peer " + p.Name + " state=" + string(p.State) + " path=" + string(p.Path) + " ep=" + p.Endpoint + " err=" + p.LastError + "\n")
			for _, h := range p.History {
				out.WriteString("    " + h.At.Format("15:04:05.000") + " " + string(h.From) + " -" + string(h.Event) + "-> " + string(h.To) + "\n")
			}
		}
		n.wg.mu.Lock()
		for k, v := range n.wg.endpoints {
			out.WriteString("  wg endpoint " + k + " = " + v + " hs=" + n.wg.handshakes[k].Format("15:04:05.000") + "\n")
		}
		n.wg.mu.Unlock()
	}
	return out.String()
}

func waitPath(t *testing.T, timeout time.Duration, a, b *node, path PathType, state PeerState) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pathIs(a, b, path, state)() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s/%s:%s", path, state, dump(a, b))
}

func pathIs(a, b *node, path PathType, state PeerState) func() bool {
	return func() bool {
		ab, ok1 := a.peer(b.ctrl.Device.DeviceID())
		ba, ok2 := b.peer(a.ctrl.Device.DeviceID())
		return ok1 && ok2 && ab.Path == path && ba.Path == path && ab.State == state && ba.State == state
	}
}

// ---- tests -----------------------------------------------------------------

func TestTwoNodesDiscoverAndGoDirect(t *testing.T) {
	e := newEnv(t)
	a := e.start(t, "laptop", "203.0.113.1:51820", e.key)
	b := e.start(t, "nas-home", "203.0.113.2:51820", e.key)

	waitPath(t, 10*time.Second, a, b, PathDirectWG, StateDirect)

	ab, _ := a.peer(b.ctrl.Device.DeviceID())
	if ab.Endpoint != "203.0.113.2:51820" {
		t.Fatalf("direct endpoint is %q, want the peer's public candidate", ab.Endpoint)
	}
	if ab.VirtualIP != b.ctrl.VirtualIP().String() {
		t.Fatalf("peer overlay address %s, peer says %s", ab.VirtualIP, b.ctrl.VirtualIP())
	}
	if metrics := a.ctrl.Metrics(); metrics.RelayFallbacks != 0 {
		t.Fatalf("relay was used on a path that works directly: %+v", metrics)
	}
	a.wg.mu.Lock()
	installed := a.wg.peers[b.wg.key]
	a.wg.mu.Unlock()
	if len(installed.AllowedIPs) != 1 || !strings.HasSuffix(installed.AllowedIPs[0], "/32") {
		t.Fatalf("peer allowed-ips %v, want exactly the peer's /32", installed.AllowedIPs)
	}
}

func TestRelayFallbackThenRecoverToDirect(t *testing.T) {
	e := newEnv(t)
	e.fake.setBlocked(true)
	a := e.start(t, "a", "198.51.100.1:51820", e.key)
	b := e.start(t, "b", "198.51.100.2:51820", e.key)

	waitPath(t, 15*time.Second, a, b, PathNKNRelay, StateRelay)
	initiator := a
	if b.ctrl.Device.DeviceID() < a.ctrl.Device.DeviceID() {
		initiator = b
	}
	if initiator.ctrl.Metrics().RelayFallbacks == 0 {
		t.Fatal("initiator reports no relay fallback")
	}
	if initiator.ctrl.bridgeFor(otherID(initiator, a, b)).Stats().BytesSent == 0 {
		t.Fatal("relay bridge is open but carried no traffic")
	}

	// UDP comes back. The relayed peers must find the direct path again on
	// their own and move off the relay.
	e.fake.setBlocked(false)
	waitPath(t, 15*time.Second, a, b, PathDirectWG, StateDirect)
	waitFor(t, 5*time.Second, "relay bridges closed", func() bool {
		return a.ctrl.bridgeFor(b.ctrl.Device.DeviceID()) == nil && b.ctrl.bridgeFor(a.ctrl.Device.DeviceID()) == nil
	})
}

func otherID(self, a, b *node) string {
	if self == a {
		return b.ctrl.Device.DeviceID()
	}
	return a.ctrl.Device.DeviceID()
}

func TestNonMemberIsNeverAdmitted(t *testing.T) {
	e := newEnv(t)
	outsiderSecret, _ := membership.NewJoinSecret()
	outsiderKey, _ := membership.Derive(e.networkID, outsiderSecret)

	a := e.start(t, "a", "203.0.113.1:51820", e.key)
	outsider := e.start(t, "outsider", "203.0.113.66:51820", outsiderKey)

	waitFor(t, 5*time.Second, "outsider's records rejected", func() bool { return a.ctrl.Metrics().RecordsRejected > 0 })
	time.Sleep(300 * time.Millisecond)
	if _, found := a.peer(outsider.ctrl.Device.DeviceID()); found {
		t.Fatal("a device that does not know the join secret became a peer")
	}
	a.wg.mu.Lock()
	defer a.wg.mu.Unlock()
	if _, installed := a.wg.peers[outsider.wg.key]; installed {
		t.Fatal("non-member was installed on the WireGuard interface")
	}
}

func TestSignalingOutageDoesNotTearDownDirect(t *testing.T) {
	e := newEnv(t)
	a := e.start(t, "a", "203.0.113.1:51820", e.key)
	b := e.start(t, "b", "203.0.113.2:51820", e.key)
	waitPath(t, 10*time.Second, a, b, PathDirectWG, StateDirect)

	// Principle 4: the control plane going away must not take a healthy
	// tunnel with it.
	a.sig.SetDrop(true)
	b.sig.SetDrop(true)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !pathIs(a, b, PathDirectWG, StateDirect)() {
			t.Fatal("direct tunnel dropped during a signalling outage")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestShutdownLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	func() {
		e := newEnv(t)
		a := e.start(t, "a", "203.0.113.1:51820", e.key)
		b := e.start(t, "b", "203.0.113.2:51820", e.key)
		waitPath(t, 10*time.Second, a, b, PathDirectWG, StateDirect)
		a.stop(t)
		b.stop(t)
		_ = a.wg.sock.Close()
		_ = b.wg.sock.Close()
		_ = e.discovery.Close()
	}()
	waitFor(t, 3*time.Second, "goroutines to drain", func() bool { return runtime.NumGoroutine() <= before+2 })
}

// Two nodes with no shared discovery store at all: each knows only the other's
// transport address, as it would from a static list, an NKN topic or a QR
// code. PEER_INFO introductions must be enough to reach DIRECT.
func TestRendezvousIntroductionWithoutDiscovery(t *testing.T) {
	e := newEnv(t)
	a := e.startWith(t, "a", "203.0.113.1:51820", e.key, func(ctrl *Controller) { ctrl.Discovery = nil })
	b := e.startWith(t, "b", "203.0.113.2:51820", e.key, func(ctrl *Controller) { ctrl.Discovery = nil })
	waitPath(t, 10*time.Second, a, b, PathDirectWG, StateDirect)
}

func TestStrangerIntroductionIsRefused(t *testing.T) {
	e := newEnv(t)
	otherSecret, _ := membership.NewJoinSecret()
	otherKey, _ := membership.Derive(e.networkID, otherSecret)
	a := e.startWith(t, "a", "203.0.113.1:51820", e.key, func(ctrl *Controller) { ctrl.Discovery = nil })
	stranger := e.startWith(t, "stranger", "203.0.113.9:51820", otherKey, func(ctrl *Controller) { ctrl.Discovery = nil })
	waitFor(t, 5*time.Second, "introduction rejected", func() bool { return a.ctrl.Metrics().RecordsRejected > 0 })
	if _, found := a.peer(stranger.ctrl.Device.DeviceID()); found {
		t.Fatal("a stranger's PEER_INFO created a peer")
	}
}

func TestRunRefusesWithoutMembership(t *testing.T) {
	ctrl := New()
	ctrl.Config.NetworkID = "nkgnet_x"
	ctrl.Device, _ = identity.Generate()
	ctrl.Discovery = discovery.NewMemory("nkgnet_x")
	ctrl.Signaling = signaling.NewSwitch().Attach("x")
	if err := ctrl.Run(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("controller started with no way to admit anyone: %v", err)
	}
	if err := New().Run(context.Background()); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("unjoined controller: %v", err)
	}
}
