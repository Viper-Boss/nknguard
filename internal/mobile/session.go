package mobile

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/backoff"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
	"github.com/Viper-Boss/nknguard/pkg/wireguard/userspace"
)

// Prepared is what the app needs to build the VpnService interface.
type Prepared struct {
	VirtualIP   string `json:"virtual_ip"`
	PrefixBits  int    `json:"prefix_bits"`
	OverlayCIDR string `json:"overlay_cidr"`
	MTU         int    `json:"mtu"`
	NASID       string `json:"nas_id"`
	NASAddress  string `json:"nas_address"`
	RouteCIDR   string `json:"route_cidr"`
}

var errRevoked = errors.New("本机授权已被 NAS 撤销，请重新配对")
var mobileDiscovery func(context.Context, *session) (discovery.Discovery, error)

func (a *Agent) pairedProfile() (Profile, error) {
	profile, paired, err := loadProfile(a.StateDir)
	if err != nil {
		return Profile{}, err
	}
	if !paired || !a.Secrets.Has(SecretJoinSecret) {
		return Profile{}, errors.New("请先完成 NAS 配对")
	}
	if profile.RevokedAt != nil {
		return Profile{}, errRevoked
	}
	return profile, nil
}

// prepare derives the overlay address before the VPN exists. It is the same
// deterministic allocation the daemon uses, restored from runtime state when
// the phone has connected before.
func (a *Agent) prepare() (any, error) {
	profile, err := a.pairedProfile()
	if err != nil {
		return nil, err
	}
	device, _, err := a.identity()
	if err != nil {
		return nil, err
	}
	virtual, err := a.virtualIP(profile, device.DeviceID())
	if err != nil {
		return nil, err
	}
	route := nasRoute(profile.NASVirtualIP)
	return Prepared{
		VirtualIP: virtual.String(), PrefixBits: OverlayCIDR.Bits(), OverlayCIDR: OverlayCIDR.String(),
		MTU: TunnelMTU, NASID: profile.NASID, NASAddress: profile.NASAddress,
		RouteCIDR: route,
	}, nil
}

func (a *Agent) virtualIP(profile Profile, deviceID string) (netip.Addr, error) {
	runtime, err := a.store().LoadRuntime()
	if err != nil {
		return netip.Addr{}, err
	}
	if addr, err := netip.ParseAddr(runtime.VirtualIP); err == nil && OverlayCIDR.Contains(addr) {
		return addr, nil
	}
	taken := make(map[netip.Addr]string)
	cached, _ := a.store().LoadPeerCache()
	for _, record := range cached {
		for _, text := range record.VirtualIPs {
			if addr, err := netip.ParseAddr(text); err == nil {
				taken[addr] = record.DeviceID
			}
		}
	}
	return mesh.AllocateVirtualIP(OverlayCIDR, profile.NetworkID, deviceID, taken)
}

// session is one connection: from the TUN device arriving to disconnect.
type session struct {
	agent   *Agent
	profile Profile
	virtual netip.Addr
	wg      *userspace.Manager
	cancel  context.CancelFunc
	done    chan struct{}
	started time.Time

	mu         sync.Mutex
	controller *mesh.Controller
	nknAddress string
	phase      string
	lastError  string
	revoked    bool
}

// Session phases, reported in status events. Only "direct" and "relay" mean
// that WireGuard has completed a handshake with the NAS recently.
const (
	PhaseIdle       = "idle"
	PhaseNKN        = "connecting_nkn"
	PhaseWaiting    = "waiting"
	PhaseDirect     = "direct"
	PhaseRelay      = "relay"
	PhaseRevoked    = "revoked"
	PhaseError      = "error"
	PhaseNotPaired  = "not_paired"
	PhaseConnecting = "connecting"
)

func (a *Agent) connect(ctx context.Context, token string) (any, error) {
	profile, err := a.pairedProfile()
	if err != nil {
		return nil, err
	}
	device, _, err := a.identity()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.session != nil {
		a.mu.Unlock()
		return nil, errors.New("已经在连接中")
	}
	if a.pairCancel != nil {
		a.mu.Unlock()
		return nil, errors.New("配对进行中，请稍后再连接")
	}
	if a.OpenTUN == nil {
		a.mu.Unlock()
		return nil, errors.New("this core cannot receive a TUN device")
	}
	virtual, err := a.virtualIP(profile, device.DeviceID())
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	// The session outlives this request; it is stopped by disconnect or by
	// the app closing our standard input, not by the request context.
	sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	current := &session{agent: a, profile: profile, virtual: virtual, cancel: cancel, done: make(chan struct{}), started: time.Now(), phase: PhaseConnecting}
	a.session = current
	a.mu.Unlock()

	openCtx, openCancel := context.WithTimeout(ctx, 15*time.Second)
	defer openCancel()
	tunDevice, err := a.OpenTUN(openCtx, token)
	if err == nil {
		current.wg = userspace.New(a.Secrets, func() (tun.Device, error) { return tunDevice, nil }, a.Logger)
		err = current.wg.EnsureInterface(ctx, wireguard.InterfaceConfig{
			Name: "nkg0", Address: netip.PrefixFrom(virtual, OverlayCIDR.Bits()).String(), MTU: TunnelMTU,
		})
		if err != nil {
			_ = tunDevice.Close()
		}
	}
	if err != nil {
		cancel()
		close(current.done)
		a.mu.Lock()
		a.session = nil
		a.mu.Unlock()
		return nil, err
	}
	a.Logger.Info("vpn interface handed to wireguard", "component", "session", "virtual_ip", virtual.String())
	go current.run(sessionCtx, device)
	return a.status(), nil
}

func (a *Agent) disconnect() {
	a.mu.Lock()
	current := a.session
	a.mu.Unlock()
	if current == nil {
		return
	}
	current.cancel()
	<-current.done
	a.mu.Lock()
	if a.session == current {
		a.session = nil
	}
	a.mu.Unlock()
	a.emit("status", a.status())
}

func (s *session) setPhase(phase, lastError string) {
	s.mu.Lock()
	s.phase, s.lastError = phase, lastError
	s.mu.Unlock()
}

func (s *session) run(ctx context.Context, device interface{ DeviceID() string }) {
	a := s.agent
	defer close(s.done)
	defer func() {
		downCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.wg.Down(downCtx)
		a.Logger.Info("vpn session stopped", "component", "session")
	}()

	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		s.statusLoop(ctx)
	}()
	defer func() { s.cancel(); <-statusDone }()
	controller, err := s.prepareController(ctx)
	if err != nil {
		s.setPhase(PhaseError, err.Error())
		return
	}
	if mobileDiscovery != nil {
		if backend, err := mobileDiscovery(ctx, s); err == nil {
			controller.Discovery = backend
			defer backend.Close()
		} else {
			a.Logger.Warn("DHT unavailable; continuing with NKN", "error", err)
		}
	}
	s.mu.Lock()
	s.controller = controller
	s.mu.Unlock()
	cacheCtx, cacheCancel := context.WithCancel(ctx)
	cacheDone := make(chan struct{})
	go func() { defer close(cacheDone); controller.RunCached(cacheCtx) }()
	stopCache := func() { cacheCancel(); <-cacheDone }
	defer stopCache()
	defer s.persist(controller)

	seed, err := a.nknSeed()
	if err != nil {
		s.setPhase(PhaseError, err.Error())
		<-ctx.Done()
		return
	}
	a.mu.Lock()
	seedRPC := a.seedRPC
	a.mu.Unlock()
	retry := backoff.Policy{Initial: 2 * time.Second, Max: time.Minute}
	for attempt := 0; ctx.Err() == nil; attempt++ {
		s.setPhase(PhaseNKN, "")
		if a.OpenPlane == nil {
			s.setPhase(PhaseError, "this core was built without NKN support")
			<-ctx.Done()
			return
		}
		plane, err := a.OpenPlane(ctx, seed, seedRPC)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.setPhase(PhaseNKN, "NKN 连接失败，稍后重试："+err.Error())
			a.Logger.Warn("NKN connection failed", "component", "session", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry.Delay(attempt)):
			}
			continue
		}
		stopCache()
		s.runController(ctx, plane, controller)
		return
	}
}

func (s *session) prepareController(ctx context.Context) (*mesh.Controller, error) {
	a := s.agent
	identityDevice, _, err := a.identity()
	if err != nil {
		return nil, err
	}
	key, err := a.membershipKey(s.profile)
	if err != nil {
		return nil, err
	}
	store := a.store()
	runtime, err := store.LoadRuntime()
	if err != nil {
		return nil, err
	}

	controller := mesh.New()
	if a.Timing != nil {
		controller.Config.Timing = *a.Timing
	}
	controller.Config.NetworkID = s.profile.NetworkID
	controller.Config.DeviceName = s.profile.DeviceName
	controller.Config.OverlayCIDR = OverlayCIDR
	controller.Config.Keepalive = 25
	controller.Config.Members = []string{s.profile.NASID}
	controller.Config.RequireApproval = true
	controller.Config.ClientDevice = true
	controller.Device = identityDevice
	controller.Membership = key
	controller.Logger = a.Logger
	controller.SetSequence(runtime.Sequence)
	controller.ReserveSequence = store.ReserveSequence
	controller.SetVirtualIP(s.virtual)
	controller.WireGuard = s.wg
	if a.Candidates != nil {
		controller.Candidates = a.Candidates
	} else {
		controller.Candidates = &userspace.CandidateSource{
			Manager:  s.wg,
			Gatherer: nat.Gatherer{STUNServers: a.stunList(), Interfaces: a.interfaceAddrs},
		}
	}
	controller.Direct = &mesh.WireGuardStrategy{WireGuard: s.wg, Nudge: s.wg.Nudge}
	controller.Nudge = s.wg.Nudge
	controller.Rendezvous = rendezvous.Static{s.profile.NASAddress}
	controller.OnPeerError = func(deviceID string, report protocol.Error) {
		if deviceID == s.profile.NASID && report.Code == protocol.ErrorNotAuthorized {
			s.markRevoked()
		}
	}

	cached, _ := store.LoadPeerCache()
	for _, record := range cached {
		if record.DeviceID == s.profile.NASID {
			controller.IngestCached(ctx, record)
		}
	}
	hints, _ := store.LoadLinkHints()
	for _, hint := range hints {
		if hint.DeviceID == s.profile.NASID && controller.RestoreLinkHint(hint.DeviceID, hint.PublicKey, hint.Endpoint, hint.SeenAt) {
			a.Logger.Info("trying last verified direct endpoint first", "component", "session")
		}
	}

	return controller, nil
}

func (s *session) runController(ctx context.Context, plane *Plane, controller *mesh.Controller) {
	controller.Signaling = plane.Signaling
	controller.Relay = plane.Relay
	for _, record := range controller.Records() {
		plane.Signaling.SetPeerAddress(record.DeviceID, record.NKNAddress)
	}
	s.mu.Lock()
	s.nknAddress = plane.Signaling.LocalAddress()
	s.phase = PhaseWaiting
	s.mu.Unlock()
	s.agent.Logger.Info("connected to NKN", "component", "session", "nkn_address", redact(plane.Signaling.LocalAddress()))
	var closeOnce sync.Once
	closePlane := func() { closeOnce.Do(func() { _ = plane.Close() }) }
	stopClose := context.AfterFunc(ctx, closePlane)
	defer stopClose()
	defer closePlane()
	persistDone := make(chan struct{})
	go func() {
		defer close(persistDone)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.persist(controller)
			}
		}
	}()
	_ = controller.Run(ctx)
	s.cancel()
	<-persistDone
	s.persist(controller)
}

func (s *session) markRevoked() {
	s.mu.Lock()
	if s.revoked {
		s.mu.Unlock()
		return
	}
	s.revoked = true
	s.phase = PhaseRevoked
	s.lastError = errRevoked.Error()
	s.mu.Unlock()
	a := s.agent
	a.Logger.Warn("the NAS reports this device is no longer approved", "component", "session")
	if profile, paired, err := loadProfile(a.StateDir); err == nil && paired {
		now := time.Now().UTC()
		profile.RevokedAt = &now
		if err := saveProfile(a.StateDir, profile); err != nil {
			a.Logger.Warn("saving revocation failed", "component", "session", "error", err)
		}
	}
	a.emit("revoked", map[string]string{"nas_id": s.profile.NASID, "message": errRevoked.Error()})
	// Tear down from a separate goroutine: this runs inside the controller's
	// dispatcher, which disconnect waits for.
	go a.disconnect()
}

func (s *session) persist(controller *mesh.Controller) {
	store := s.agent.store()
	runtime := state.Runtime{Sequence: controller.Sequence(), ProtocolVersion: protocol.Version, VirtualIP: s.virtual.String()}
	if err := store.SaveRuntime(runtime); err != nil {
		s.agent.Logger.Warn("saving runtime state failed", "component", "state", "error", err)
	}
	_ = store.SavePeerCache(controller.Records())
	for _, peer := range controller.Peers() {
		if peer.DeviceID == s.profile.NASID && peer.VirtualIP != "" && peer.VirtualIP != s.profile.NASVirtualIP {
			if profile, paired, err := loadProfile(s.agent.StateDir); err == nil && paired && profile.NASID == s.profile.NASID && profile.RevokedAt == nil && profile.NASVirtualIP != peer.VirtualIP {
				profile.NASVirtualIP = peer.VirtualIP
				_ = saveProfile(s.agent.StateDir, profile)
			}
		}
	}
	previous, _ := store.LoadLinkHints()
	hints := make([]state.LinkHint, 0, 1)
	for _, hint := range previous {
		if hint.DeviceID == s.profile.NASID && time.Since(hint.SeenAt) < 7*24*time.Hour {
			hints = append(hints[:0], hint)
		}
	}
	for _, peer := range controller.Peers() {
		if peer.DeviceID == s.profile.NASID && peer.Path == mesh.PathDirectWG && peer.Endpoint != "" {
			hints = []state.LinkHint{{DeviceID: peer.DeviceID, PublicKey: peer.WireGuardPublicKey, Endpoint: peer.Endpoint, SeenAt: time.Now()}}
		}
	}
	_ = store.SaveLinkHints(hints)
}

func (s *session) networkChanged(ctx context.Context) {
	if s.wg != nil {
		if err := s.wg.Rebind(); err != nil {
			s.agent.Logger.Warn("rebinding WireGuard after a network change failed", "component", "session", "error", err)
		}
	}
	s.mu.Lock()
	controller := s.controller
	online := s.nknAddress != ""
	s.mu.Unlock()
	if controller == nil || !online {
		return
	}
	go func() {
		refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		// Sends a packet to the NAS at once (so its WireGuard roams to the
		// phone's new address), gathers fresh candidates, pushes them to the
		// NAS and clears the direct-retry backoff.
		controller.NetworkChanged(refreshCtx)
	}()
	s.agent.Logger.Info("network changed; retrying the direct path", "component", "session")
}

func (s *session) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last Status
	lastSent := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := s.agent.status()
		// Byte counters change every second while traffic flows; send those
		// at most every few seconds, and any state change at once.
		changed := current.Phase != last.Phase || current.Path != last.Path || current.LastError != last.LastError ||
			current.Endpoint != last.Endpoint || current.NASVirtualIP != last.NASVirtualIP || current.NKNAddress != last.NKNAddress
		if changed || time.Since(lastSent) >= 3*time.Second {
			s.agent.emit("status", current)
			last, lastSent = current, time.Now()
		}
	}
}

func nasRoute(value string) string {
	if ip, err := netip.ParseAddr(value); err == nil && ip.Is4() && OverlayCIDR.Contains(ip) {
		return netip.PrefixFrom(ip, 32).String()
	}
	return OverlayCIDR.String()
}
