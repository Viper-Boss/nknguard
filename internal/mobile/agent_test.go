package mobile

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
	"github.com/Viper-Boss/nknguard/pkg/wireguard/userspace"
)

func fastTiming() *mesh.Timing {
	timing := mesh.DefaultConfig().Timing
	timing.RepublishInterval = 300 * time.Millisecond
	timing.ReconcileInterval = 100 * time.Millisecond
	timing.PollInterval = 300 * time.Millisecond
	timing.PunchLead = 50 * time.Millisecond
	timing.RelayAfter = 300 * time.Millisecond
	return &timing
}

// nas is an in-process NAS built from the production pieces: node identity,
// Pairing, the mesh controller as an approving owner, and wireguard-go.
type nas struct {
	node       *app.Node
	pairing    *app.Pairing
	controller *mesh.Controller
	tun        *tuntest.ChannelTUN
	secret     string
	virtual    netip.Addr
}

func startNAS(t *testing.T, ctx context.Context, wire *signaling.Switch, hub *relay.Hub) *nas {
	t.Helper()
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := app.OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	networkID, secret, err := node.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := node.MembershipKey()
	if err != nil {
		t.Fatal(err)
	}
	channel := tuntest.NewChannelTUN()
	wg := userspace.New(wireguard.FromIdentityKeystore(node.Keystore), func() (tun.Device, error) { return channel.TUN(), nil }, nil)
	transport := wire.Attach(node.Device.DeviceID())

	controller := mesh.New()
	controller.Config.NetworkID = networkID
	controller.Config.DeviceName = "nas-home"
	controller.Config.RequireApproval = true
	controller.Config.OwnerDevice = true
	controller.Config.Timing = *fastTiming()
	controller.Device = node.Device
	controller.Membership = key
	controller.Signaling = transport
	controller.Relay = hub.Endpoint(node.Device.DeviceID())
	controller.Rendezvous = rendezvous.Static{}
	controller.WireGuard = wg
	controller.Candidates = mesh.StaticCandidates{}
	controller.Direct = &mesh.WireGuardStrategy{WireGuard: wg, Nudge: wg.Nudge}
	controller.Nudge = wg.Nudge
	virtual, err := controller.AssignVirtualIP()
	if err != nil {
		t.Fatal(err)
	}
	if err := wg.EnsureInterface(ctx, wireguard.InterfaceConfig{Name: "nkg0", Address: netip.PrefixFrom(virtual, 16).String()}); err != nil {
		t.Fatal(err)
	}
	pairing := app.NewPairing(node, controller, transport)
	controller.PairRequest = pairing.HandleRequest
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = controller.Run(ctx)
	}()
	t.Cleanup(func() {
		<-done
		_ = wg.Down(context.Background())
	})
	return &nas{node: node, pairing: pairing, controller: controller, tun: channel, secret: secret, virtual: virtual}
}

// phone drives an Agent over its real JSON-lines interface.
type phone struct {
	t      *testing.T
	in     *io.PipeWriter
	mu     sync.Mutex
	nextID int64
	waits  map[int64]chan Response
	events chan Event
	raw    chan map[string]any
	tun    *tuntest.ChannelTUN
	agent  *Agent
}

func startPhone(t *testing.T, ctx context.Context, wire *signaling.Switch, hub *relay.Hub) *phone {
	t.Helper()
	return startPhoneWith(t, ctx, wire, hub, nil)
}

func startPhoneWith(t *testing.T, ctx context.Context, wire *signaling.Switch, hub *relay.Hub, configure func(*Agent)) *phone {
	t.Helper()
	channel := tuntest.NewChannelTUN()
	agent := &Agent{StateDir: t.TempDir(), Timing: fastTiming(), Candidates: mesh.StaticCandidates{}}
	if configure != nil {
		configure(agent)
	}
	agent.OpenPlane = func(ctx context.Context, seed []byte, _ []string) (*Plane, error) {
		device, _, err := agent.identity()
		if err != nil {
			return nil, err
		}
		transport := wire.Attach(device.DeviceID())
		return &Plane{Signaling: transport, Relay: hub.Endpoint(device.DeviceID()), Close: transport.Close}, nil
	}
	agent.OpenTUN = func(ctx context.Context, token string) (tun.Device, error) {
		if token != "tun-token" {
			t.Errorf("token = %q", token)
		}
		return channel.TUN(), nil
	}
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	p := &phone{t: t, in: inWriter, waits: make(map[int64]chan Response), events: make(chan Event, 1024), tun: channel, agent: agent}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = agent.Serve(ctx, inReader, outWriter)
		_ = outWriter.Close()
	}()
	go p.readLoop(outReader)
	t.Cleanup(func() {
		_ = inWriter.Close()
		<-served
	})
	return p
}

func (p *phone) readLoop(out io.Reader) {
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var probe struct {
			ID    *int64 `json:"id"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &probe); err != nil {
			p.t.Errorf("core wrote a non-JSON line: %q", scanner.Text())
			continue
		}
		if probe.Event != "" {
			var event struct {
				Event string          `json:"event"`
				Data  json.RawMessage `json:"data"`
			}
			_ = json.Unmarshal(scanner.Bytes(), &event)
			p.events <- Event{Event: event.Event, Data: event.Data}
			continue
		}
		var response struct {
			ID     int64           `json:"id"`
			OK     bool            `json:"ok"`
			Error  string          `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		_ = json.Unmarshal(scanner.Bytes(), &response)
		p.mu.Lock()
		wait := p.waits[response.ID]
		p.mu.Unlock()
		if wait != nil {
			wait <- Response{ID: response.ID, OK: response.OK, Error: response.Error, Result: response.Result}
		}
	}
}

func (p *phone) call(cmd string, args any) (json.RawMessage, string) {
	p.t.Helper()
	p.mu.Lock()
	p.nextID++
	id := p.nextID
	wait := make(chan Response, 1)
	p.waits[id] = wait
	p.mu.Unlock()
	raw, _ := json.Marshal(args)
	line, _ := json.Marshal(Request{ID: id, Cmd: cmd, Args: raw})
	if _, err := p.in.Write(append(line, '\n')); err != nil {
		p.t.Fatal(err)
	}
	select {
	case response := <-wait:
		result, _ := response.Result.(json.RawMessage)
		return result, response.Error
	case <-time.After(20 * time.Second):
		p.t.Fatalf("%s: no response", cmd)
		return nil, ""
	}
}

func (p *phone) must(cmd string, args any, target any) {
	p.t.Helper()
	result, errText := p.call(cmd, args)
	if errText != "" {
		p.t.Fatalf("%s: %s", cmd, errText)
	}
	if target != nil {
		if err := json.Unmarshal(result, target); err != nil {
			p.t.Fatalf("%s result: %v", cmd, err)
		}
	}
}

// waitEvent returns the first event named name whose data satisfies match.
func (p *phone) waitEvent(name string, timeout time.Duration, match func(json.RawMessage) bool) json.RawMessage {
	p.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case event := <-p.events:
			data, _ := event.Data.(json.RawMessage)
			if event.Event == name && (match == nil || match(data)) {
				return data
			}
		case <-deadline:
			p.t.Fatalf("no %s event within %s", name, timeout)
			return nil
		}
	}
}

func TestPairConnectRelayAndRevoke(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := signaling.NewSwitch()
	hub := relay.NewHub()
	home := startNAS(t, ctx, wire, hub)
	p := startPhone(t, ctx, wire, hub)

	var initResult InitResult
	p.must("init", map[string]any{"device_name": "Pixel"}, &initResult)
	if initResult.Paired || !strings.HasPrefix(initResult.DeviceID, "nkg_") {
		t.Fatalf("init = %+v", initResult)
	}
	firstSecrets := p.waitEvent("secrets", time.Second, nil)
	if !strings.Contains(string(firstSecrets), SecretRoot) {
		t.Fatalf("root key was not handed to the app for storage: %s", firstSecrets)
	}

	invite, err := home.pairing.NewInvite()
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := invite.URI()
	var info InviteInfo
	p.must("parse_invite", map[string]string{"uri": uri}, &info)
	if info.NASID != home.node.Device.DeviceID() {
		t.Fatalf("invite info = %+v", info)
	}
	if _, errText := p.call("prepare", nil); errText == "" {
		t.Fatal("prepare before pairing must fail")
	}
	p.must("pair", map[string]string{"uri": uri, "name": "Pixel"}, nil)
	waiting := p.waitEvent("pair_status", 5*time.Second, func(raw json.RawMessage) bool {
		var status PairStatus
		return json.Unmarshal(raw, &status) == nil && status.Stage == PairWaiting
	})
	var pending PairStatus
	_ = json.Unmarshal(waiting, &pending)
	deadline := time.Now().Add(5 * time.Second)
	for len(home.pairing.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	nasSide := home.pairing.Pending()
	if len(nasSide) != 1 || nasSide[0].Code != pending.Code || nasSide[0].DeviceID != initResult.DeviceID || nasSide[0].Name != "Pixel" {
		t.Fatalf("NAS pending %+v, phone shows code %s", nasSide, pending.Code)
	}
	if err := home.pairing.Approve(ctx, initResult.DeviceID); err != nil {
		t.Fatal(err)
	}
	secrets := p.waitEvent("secrets", 5*time.Second, func(raw json.RawMessage) bool {
		return strings.Contains(string(raw), SecretJoinSecret)
	})
	var stored struct {
		Values map[string]string `json:"values"`
	}
	_ = json.Unmarshal(secrets, &stored)
	if joined, _ := base64.StdEncoding.DecodeString(stored.Values[SecretJoinSecret]); string(joined) != home.secret {
		t.Fatal("join secret handed to the app does not match the NAS")
	}
	p.waitEvent("pair_status", 5*time.Second, func(raw json.RawMessage) bool {
		var status PairStatus
		return json.Unmarshal(raw, &status) == nil && status.Stage == PairApproved
	})

	var prepared Prepared
	p.must("prepare", nil, &prepared)
	phoneIP := netip.MustParseAddr(prepared.VirtualIP)
	if !OverlayCIDR.Contains(phoneIP) || prepared.MTU != TunnelMTU || prepared.OverlayCIDR != "10.88.0.0/16" {
		t.Fatalf("prepare = %+v", prepared)
	}
	p.must("connect", map[string]string{"token": "tun-token"}, nil)
	p.waitEvent("status", 20*time.Second, func(raw json.RawMessage) bool {
		var status Status
		return json.Unmarshal(raw, &status) == nil && status.Phase == PhaseRelay && status.HandshakeOK && status.Path == string(mesh.PathNKNRelay)
	})

	// Traffic from the phone's TUN reaches the NAS's TUN through the relay.
	deadline = time.Now().Add(10 * time.Second)
	for delivered := false; !delivered; {
		if time.Now().After(deadline) {
			t.Fatal("ping from phone did not reach the NAS")
		}
		p.tun.Outbound <- tuntest.Ping(home.virtual, phoneIP)
		select {
		case packet := <-home.tun.Inbound:
			delivered = len(packet) >= 20 && netip.AddrFrom4([4]byte(packet[12:16])) == phoneIP
		case <-time.After(200 * time.Millisecond):
		}
	}
	var status Status
	p.must("status", nil, &status)
	if status.NASVirtualIP != home.virtual.String() || status.VirtualIP != phoneIP.String() || status.TxBytes == 0 || !status.Connected {
		t.Fatalf("status = %+v", status)
	}

	// The owner revokes the phone. The NAS tells it so, signed with the
	// identity the phone pinned at pairing, and the phone stops claiming a
	// connection.
	if err := home.pairing.Revoke(ctx, initResult.DeviceID); err != nil {
		t.Fatal(err)
	}
	p.waitEvent("revoked", 10*time.Second, nil)
	p.waitEvent("status", 10*time.Second, func(raw json.RawMessage) bool {
		var status Status
		return json.Unmarshal(raw, &status) == nil && status.Phase == PhaseRevoked && !status.Connected && status.Revoked
	})
	if _, errText := p.call("prepare", nil); !strings.Contains(errText, "撤销") {
		t.Fatalf("prepare after revocation = %q", errText)
	}
	var diagnostics map[string]string
	p.must("diagnostics", nil, &diagnostics)
	if strings.Contains(diagnostics["text"], home.secret) || strings.Contains(diagnostics["text"], stored.Values[SecretRoot]) {
		t.Fatal("diagnostics contain a secret")
	}

	// Forgetting the pairing keeps the device identity for a new pairing.
	p.must("forget", nil, nil)
	var again InitResult
	p.must("init", map[string]any{}, &again)
	if again.Paired || again.DeviceID != initResult.DeviceID {
		t.Fatalf("after forget = %+v", again)
	}
}

func TestPairingRejectsSubstitutedApproval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := signaling.NewSwitch()
	hub := relay.NewHub()
	home := startNAS(t, ctx, wire, hub)
	impostor := startNAS(t, ctx, wire, hub)
	p := startPhone(t, ctx, wire, hub)
	p.agent.PairWait = 2 * time.Second
	var initResult InitResult
	p.must("init", map[string]any{"device_name": "Pixel"}, &initResult)
	invite, _ := home.pairing.NewInvite()
	uri, _ := invite.URI()
	p.must("pair", map[string]string{"uri": uri}, nil)
	p.waitEvent("pair_status", 5*time.Second, func(raw json.RawMessage) bool {
		return strings.Contains(string(raw), PairWaiting)
	})
	// Another NAS that saw the token cannot answer for the pinned one: its
	// approval is signed by the wrong identity, and claiming the pinned
	// device id with its own key breaks the id binding.
	impostorWire := wire.Attach("impostor-address")
	approval := protocol.PairApproval{JoinSecret: impostor.secret, NASID: invite.NASID, NASAddress: invite.NASAddress, InviteToken: invite.Token}
	own, err := protocol.Seal(impostor.node.Device, invite.NetworkID, initResult.DeviceID, protocol.TypePairApproval, approval)
	if err != nil {
		t.Fatal(err)
	}
	forged := own
	forged.FromDeviceID = invite.NASID
	for _, envelope := range []protocol.Envelope{own, forged} {
		if err := impostorWire.SendAddress(ctx, initResult.DeviceID, envelope); err != nil {
			t.Fatal(err)
		}
	}
	failed := p.waitEvent("pair_status", 10*time.Second, func(raw json.RawMessage) bool {
		return strings.Contains(string(raw), PairFailed)
	})
	if !strings.Contains(string(failed), "过期") {
		t.Fatalf("failure = %s", failed)
	}
	var status Status
	p.must("status", nil, &status)
	if status.Paired || status.Phase != PhaseNotPaired {
		t.Fatalf("status after unapproved pairing = %+v", status)
	}
}

func TestSecretStoreReportsChanges(t *testing.T) {
	store := NewSecretStore()
	var seen map[string][]byte
	store.SetOnChange(func(values map[string][]byte) { seen = values })
	if err := store.Load(map[string]string{"a": base64.StdEncoding.EncodeToString([]byte("x"))}); err != nil {
		t.Fatal(err)
	}
	if seen != nil {
		t.Fatal("loading the app's copy must not echo it back")
	}
	_ = store.WriteSecret("b", []byte("y"))
	if string(seen["a"]) != "x" || string(seen["b"]) != "y" {
		t.Fatalf("change = %v", seen)
	}
	store.Delete("a")
	if _, ok := seen["a"]; ok {
		t.Fatal("delete not reported")
	}
	if err := store.Load(map[string]string{"bad": "%%%"}); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}

func TestRedact(t *testing.T) {
	address := "nknguard." + strings.Repeat("ab", 32)
	out := redact("peer " + address + " key " + base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if strings.Contains(out, strings.Repeat("ab", 20)) || strings.Contains(out, strings.Repeat("A", 30)) {
		t.Fatalf("not redacted: %s", out)
	}
	if !strings.Contains(out, "nknguard.ababab") {
		t.Fatalf("over-redacted: %s", out)
	}
}

func TestInterfaceAddressesExcludeOverlay(t *testing.T) {
	agent := &Agent{}
	agent.applyNetwork(networkArgs{LocalAddresses: []string{"192.168.1.20", "10.88.3.4", "2001:db8::1", "garbage"}})
	addrs, _ := agent.interfaceAddrs()
	gatherer := nat.Gatherer{Interfaces: agent.interfaceAddrs}
	_ = gatherer
	if len(addrs) != 2 || !strings.HasPrefix(addrs[0].String(), "192.168.1.20") {
		t.Fatalf("addresses = %v", addrs)
	}
}

type usageChain struct {
	mu     sync.Mutex
	topics map[string]bool
}

func (c *usageChain) Subscribe(_ context.Context, topic string, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topics[topic] = true
	return nil
}

func (c *usageChain) Unsubscribe(_ context.Context, topic string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.topics, topic)
	return nil
}

func (c *usageChain) Count(_ context.Context, topic string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.topics[topic] {
		return 1, nil
	}
	return 0, nil
}

func (c *usageChain) Address() string { return "usage-key" }

func TestUsageStatistics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain := &usageChain{topics: map[string]bool{}}
	var seenSeed []byte
	p := startPhoneWith(t, ctx, signaling.NewSwitch(), relay.NewHub(), func(agent *Agent) {
		agent.UsageChain = func(seed []byte, _ []string) (usagestats.Chain, error) {
			seenSeed = append([]byte(nil), seed...)
			return chain, nil
		}
	})
	if _, errText := p.call("usage", nil); errText == "" {
		t.Fatal("usage answered before init")
	}
	p.must("init", map[string]any{"device_name": "Pixel"}, nil)
	if len(seenSeed) != 32 {
		t.Fatalf("usage chain got seed of %d bytes", len(seenSeed))
	}
	// On by default: the reporter checks in by itself.
	deadline := time.Now().Add(5 * time.Second)
	var status usagestats.Status
	for {
		p.must("usage", map[string]bool{"refresh": true}, &status)
		if status.Counts.Day != nil && *status.Counts.Day == 1 && status.Counts.Quarter != nil && *status.Counts.Quarter == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no check-in: %+v", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !status.Enabled || status.Address != "usage-key" {
		t.Fatalf("status = %+v", status)
	}
	p.must("usage_set", map[string]bool{"enabled": false}, &status)
	if status.Enabled {
		t.Fatal("still enabled")
	}
	chain.mu.Lock()
	left := len(chain.topics)
	chain.mu.Unlock()
	if left != 0 {
		t.Fatalf("not unsubscribed: %d topics", left)
	}
	// A second init (after pairing) does not start a second reporter.
	p.must("init", map[string]any{}, nil)
	p.must("usage", nil, &status)
	if status.Enabled {
		t.Fatal("choice lost")
	}
}
