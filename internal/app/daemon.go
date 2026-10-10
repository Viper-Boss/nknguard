package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/controlhub"
	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
	"github.com/Viper-Boss/nknguard/pkg/directice"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// Version is set at build time with -ldflags "-X .../internal/app.Version=v0.1.0".
var Version = "0.1.0-dev"

// PersistInterval is how often runtime state and the peer cache are written.
const PersistInterval = 5 * time.Minute

// Daemon is a running node.
type Daemon struct {
	Config     config.Config
	Node       *Node
	Controller *mesh.Controller
	WireGuard  wireguard.Manager
	Pairing    *Pairing
	Logger     *slog.Logger
	Logs       *LogRing
	Started    time.Time
	// Usage counts active installations anonymously; see pkg/usagestats.
	Usage *usagestats.Reporter

	down       context.CancelFunc
	downOnce   sync.Once
	nknAddress atomic.Value
	nknStatus  atomic.Value // func() nknclient.ConnectionStatus, published once
}

// NewLogger builds the daemon logger: text to w, and a redacted copy into the
// ring the diagnostics bundle reads.
func NewLogger(w io.Writer, level string) (*slog.Logger, *LogRing) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	ring := NewLogRing(2000)
	options := &slog.HandlerOptions{Level: lvl}
	return slog.New(teeHandler{slog.NewTextHandler(w, options), slog.NewTextHandler(ring, options)}), ring
}

// RunDaemon brings the node up and blocks until ctx is cancelled or a local
// `nknguard down` arrives. The shutdown order is the one in spec §62: stop
// discovery, signalling, NAT workers and relay (the controller), then remove
// the interface.
func RunDaemon(ctx context.Context, cfg config.Config, logOut io.Writer) error {
	if controlPlaneFactory == nil {
		return ErrNoNKN
	}
	if !hasTunnelPrivilege() {
		return errors.New("the daemon needs administrator privileges to manage WireGuard")
	}
	return runDaemon(ctx, cfg, logOut, wireguard.NewHostManager)
}

func runDaemon(ctx context.Context, cfg config.Config, logOut io.Writer, newManager func(wireguard.Keystore, string, string) wireguard.Manager) (resultErr error) {
	logger, ring := NewLogger(logOut, cfg.Logging.Level)
	if controlPlaneFactory == nil {
		return ErrNoNKN
	}
	instanceLock, err := acquireInstanceLock(filepath.Join(cfg.Paths.StateDir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer instanceLock.Close()
	node, err := OpenNode(cfg)
	if err != nil {
		return err
	}
	key, current, err := node.MembershipKey()
	if err != nil {
		return err
	}
	logger = logger.With("device_id", node.Device.DeviceID())

	wg := newManager(wireguard.FromIdentityKeystore(node.Keystore), cfg.WireGuard.Interface, cfg.Paths.StateDir)
	if supported, reason := wg.Supported(ctx); supported == wireguard.StateUnsupported || supported == wireguard.StateToolsMissing {
		return fmt.Errorf("WireGuard is not usable on this host: %s", reason)
	}

	runtime, err := node.State.LoadRuntime()
	if err != nil {
		return err
	}
	controller := mesh.New()
	controller.Config.NetworkID = current.NetworkID
	controller.Config.DeviceName = cfg.Device.Name
	controller.Config.DeviceTags = cfg.Device.Tags
	controller.Config.OverlayCIDR = cfg.OverlayPrefix()
	controller.Config.Keepalive = cfg.WireGuard.PersistentKeepalive
	controller.Config.RecordTTL = cfg.RecordTTL()
	controller.Config.Members = current.Members
	controller.Config.RequireApproval = cfg.Pairing.ApprovalRequired
	controller.Config.OwnerDevice = current.IsOwner
	controller.Config.ClientDevice = !current.IsOwner
	for deviceID, address := range current.MemberAddresses {
		controller.RememberApprovedAddress(deviceID, address)
	}
	controller.Device = node.Device
	controller.Membership = key
	controller.Policy = cfg.ACL
	controller.Logger = logger
	controller.SetSequence(runtime.Sequence)
	controller.ReserveSequence = node.State.ReserveSequence

	virtual, err := restoreVirtualIP(controller, runtime, cfg.OverlayPrefix())
	if err != nil {
		return err
	}

	interfaceConfig := wireguard.InterfaceConfig{
		Name:       cfg.WireGuard.Interface,
		Address:    netip.PrefixFrom(virtual, cfg.OverlayPrefix().Bits()).String(),
		ListenPort: cfg.WireGuard.ListenPort,
		MTU:        cfg.WireGuard.MTU,
	}
	if err := node.State.SaveRuntime(state.Runtime{Sequence: controller.Sequence(), ProtocolVersion: protocol.Version, VirtualIP: virtual.String()}); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	securityErrors := make(chan error, 1)
	controller.OnSecurityFailure = func(err error) {
		select {
		case securityErrors <- err:
		default:
		}
		cancel()
	}
	defer func() {
		select {
		case err := <-securityErrors:
			resultErr = errors.Join(resultErr, err)
		default:
		}
	}()
	controller.WireGuard = wg
	controller.Direct = &mesh.WireGuardStrategy{WireGuard: wg, Nudge: mesh.UDPNudge}
	controller.Nudge = mesh.UDPNudge
	daemon := &Daemon{Config: cfg, Node: node, Controller: controller, WireGuard: wg, Logger: logger, Logs: ring, Started: time.Now(), down: cancel}
	// Keep the control API alive until interface cleanup completes. A client's
	// disconnect waits for this socket to disappear, not just for the stop ACK.
	apiCtx, apiCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer apiCancel()
	api, err := daemon.ServeAPI(apiCtx)
	if err != nil {
		return err
	}
	defer api.Close()
	if err := node.State.SaveShutdown(state.Shutdown{}); err != nil {
		return err
	}
	defer func() {
		cleanupErr := cleanupTunnel(wg, node.State)
		resultErr = errors.Join(resultErr, cleanupErr)
		if cleanupErr != nil {
			logger.Error("removing interface failed", "component", "wireguard", "error", cleanupErr)
		}
	}()
	if current.IsOwner {
		if policy, ok := wg.(interface{ SetNASOnlyPolicy(context.Context) error }); ok {
			if err := policy.SetNASOnlyPolicy(runCtx); err != nil {
				return err
			}
		}
	}
	if err := wg.EnsureInterface(runCtx, interfaceConfig); err != nil {
		return fmt.Errorf("bring up %s: %w", cfg.WireGuard.Interface, err)
	}
	logger.Info("wireguard interface up", "component", "wireguard", "interface", cfg.WireGuard.Interface, "address", interfaceConfig.Address)

	servers := cfg.NAT.STUNServers
	if !cfg.NAT.STUNEnabled {
		servers = nil
	}
	controller.ICE = &directice.Config{STUNServers: servers}
	controller.Candidates = &nat.WireGuardGatherer{
		STUNServers: servers,
		ListenPort: func(ctx context.Context) (int, error) {
			if port := wg.Status(ctx).ListenPort; port > 0 {
				return port, nil
			}
			return 0, errors.New("wireguard listen port not yet known")
		},
	}
	if cfg.NAT.PortMapping && current.IsOwner && portMapperFactory != nil {
		base := controller.Candidates.(*nat.WireGuardGatherer)
		mapped, closer := portMapperFactory(runCtx, base, base.ListenPort, logger)
		controller.Candidates = mapped
		defer closer.Close()
	}
	cached, _ := node.State.LoadPeerCache()
	for _, record := range cached {
		controller.IngestCached(runCtx, record)
		// Migrate transport hints from previously verified caches as well as
		// newly paired devices. The hint itself grants no tunnel access.
		if controller.PeerPublicKey(record.DeviceID) == record.WireGuardPublicKey && record.WireGuardPublicKey != "" {
			controller.RememberApprovedAddress(record.DeviceID, record.NKNAddress)
		}
	}
	hints, _ := node.State.LoadLinkHints()
	for _, hint := range hints {
		controller.RestoreLinkHint(hint.DeviceID, hint.PublicKey, hint.Endpoint, hint.SeenAt)
	}
	pairing := NewPairing(node, controller, nil)
	daemon.Pairing = pairing
	controller.PairRequest = pairing.HandleRequest
	if err := pairing.CleanPending(runCtx); err != nil {
		return err
	}
	if err := controller.PruneUntrackedPeers(runCtx); err != nil {
		return err
	}
	daemon.Usage = NewUsageReporter(cfg, node.Keystore, logger)
	panel, err := daemon.ServeDashboard(runCtx)
	if err != nil {
		logger.Warn("dashboard unavailable", "component", "dashboard", "error", err)
	} else {
		defer func() { _ = panel.Close() }()
		logger.Info("dashboard listening", "component", "dashboard", "address", cfg.Dashboard.Listen)
	}
	if cfg.Discovery.DHT && discoveryFactory != nil {
		backend, err := discoveryFactory(runCtx, cfg, key, logger)
		if err != nil {
			// The DHT is one discovery source among several; its absence is
			// logged, not fatal.
			logger.Warn("DHT discovery unavailable", "component", "discovery", "error", err)
		} else {
			controller.SetDiscovery(backend)
			defer func() { _ = backend.Close() }()
		}
	}

	var alternate signaling.Transport
	if transport, ok := controller.Discovery.(signaling.Transport); ok {
		alternate = transport
	}
	hub := controlhub.New(runCtx, alternate, rendezvous.Static(cfg.Discovery.StaticPeers))
	defer hub.Close()
	controller.Signaling, controller.Relay, controller.Rendezvous = hub, hub, hub
	controllerDone := make(chan struct{})
	var controllerErr error
	go func() { controllerErr = controller.Run(runCtx); cancel(); close(controllerDone) }()
	defer func() { cancel(); <-controllerDone }()
	plane, err := openControlPlane(runCtx, func(ctx context.Context) (*ControlPlane, error) {
		return controlPlaneFactory(ctx, cfg, node.Keystore, key, logger)
	}, logger)
	if err != nil {
		return err
	}
	var closePlane sync.Once
	closeNKN := func() { closePlane.Do(func() { _ = plane.Close() }) }
	defer closeNKN()
	if err := hub.Attach(plane.Signaling, plane.Relay, plane.Rendezvous); err != nil {
		return err
	}
	// Records loaded before the transport existed must teach it their addresses.
	for _, record := range controller.Records() {
		plane.Signaling.SetPeerAddress(record.DeviceID, record.NKNAddress)
	}
	daemon.nknAddress.Store(plane.Signaling.LocalAddress())
	if transport, ok := plane.Signaling.(interface {
		ConnectionStatus() nknclient.ConnectionStatus
	}); ok {
		daemon.nknStatus.Store(transport.ConnectionStatus)
	}
	pairing.SetTransport(plane.Signaling)

	// The NKN SDK's session Accept has no context argument. Closing the client
	// unblocks it before Controller.Run waits for its workers on shutdown.
	planeStopped := make(chan struct{})
	go func() {
		defer close(planeStopped)
		<-runCtx.Done()
		closeNKN()
	}()
	go daemon.Usage.Run(runCtx)
	// A laptop that moves to another network, or a NAS that gets a new DHCP
	// lease, tells its peers at once instead of waiting for a path to fail.
	go controller.WatchNetwork(runCtx, 0, nil)

	persistDone := make(chan struct{})
	go func() {
		defer close(persistDone)
		daemon.persistLoop(runCtx)
	}()

	logger.Info("nknguard running", "component", "app", "version", Version, "network", current.NetworkID, "virtual_ip", virtual.String())
	<-controllerDone
	runErr := controllerErr
	cancel()
	<-planeStopped
	<-persistDone
	daemon.persist()

	logger.Info("nknguard stopped", "component", "app")
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

func restoreVirtualIP(controller *mesh.Controller, runtime state.Runtime, cidr netip.Prefix) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(runtime.VirtualIP); err == nil && cidr.Contains(addr) {
		controller.SetVirtualIP(addr)
		return addr, nil
	}
	return controller.AssignVirtualIP()
}

// Stop asks the daemon to shut down, as `nknguard down` does.
func (d *Daemon) Stop() { d.downOnce.Do(d.down) }

func (d *Daemon) persistLoop(ctx context.Context) {
	ticker := time.NewTicker(PersistInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.persist()
		}
	}
}

func (d *Daemon) persist() {
	runtime := state.Runtime{Sequence: d.Controller.Sequence(), ProtocolVersion: protocol.Version}
	if virtual := d.Controller.VirtualIP(); virtual.IsValid() {
		runtime.VirtualIP = virtual.String()
	}
	if err := d.Node.State.SaveRuntime(runtime); err != nil {
		d.Logger.Warn("saving runtime state failed", "component", "state", "error", err)
	}
	if err := d.Node.State.SavePeerCache(d.Controller.Records()); err != nil {
		d.Logger.Warn("saving peer cache failed", "component", "state", "error", err)
	}
	d.persistLinkHints()
}

func (d *Daemon) persistLinkHints() {
	current, err := d.Node.State.LoadMembership()
	if err != nil {
		return
	}
	allowed := make(map[string]bool, len(current.Members))
	for _, id := range current.Members {
		allowed[id] = true
	}
	previous, _ := d.Node.State.LoadLinkHints()
	hints := make(map[string]state.LinkHint)
	for _, hint := range previous {
		if allowed[hint.DeviceID] && time.Since(hint.SeenAt) < 7*24*time.Hour {
			hints[hint.DeviceID] = hint
		}
	}
	for _, peer := range d.Controller.Peers() {
		if peer.Path == mesh.PathDirectWG && peer.DirectTransport != "ice-udp" && allowed[peer.DeviceID] && peer.Endpoint != "" {
			hints[peer.DeviceID] = state.LinkHint{DeviceID: peer.DeviceID, PublicKey: peer.WireGuardPublicKey, Endpoint: peer.Endpoint, SeenAt: time.Now()}
		}
	}
	out := make([]state.LinkHint, 0, len(hints))
	for _, hint := range hints {
		out = append(out, hint)
	}
	if err := d.Node.State.SaveLinkHints(out); err != nil {
		d.Logger.Warn("saving direct endpoint hints failed", "component", "state", "error", err)
	}
}

// Status renders the node for the local API.
func (d *Daemon) Status(ctx context.Context) diagnostics.Status {
	status := diagnostics.Status{
		Version:   Version,
		DeviceID:  d.Node.Device.DeviceID(),
		Device:    d.Config.Device.Name,
		NetworkID: d.Controller.Config.NetworkID,
		StartedAt: d.Started,
		Uptime:    time.Since(d.Started).Round(time.Second).String(),
		NAT:       d.Controller.PortMapping().Behaviour,
		WireGuard: d.WireGuard.Status(ctx),
		Peers:     d.Controller.Peers(),
		Metrics:   d.Controller.Metrics(),
	}
	if address, ok := d.nknAddress.Load().(string); ok {
		status.NKNAddress = address
	}
	if query, ok := d.nknStatus.Load().(func() nknclient.ConnectionStatus); ok {
		status.NKNConnection = query()
		status.NKNConnected = status.NKNConnection.State == "connected"
	}
	if virtual := d.Controller.VirtualIP(); virtual.IsValid() {
		status.VirtualIP = virtual.String()
	}
	status.OverlayCIDR = d.Config.OverlayPrefix().String()
	status.RouterMapping = nat.RouterMappingStatus{State: "disabled", Message: "路由器自动映射未启用"}
	if d.Config.NAT.PortMapping {
		status.RouterMapping = nat.RouterMappingStatus{State: "unavailable", Message: "本节点未启用路由器映射"}
	}
	if source, ok := d.Controller.Candidates.(interface {
		MappingStatus() nat.RouterMappingStatus
	}); ok {
		status.RouterMapping = source.MappingStatus()
	}
	status.DHTEnabled, status.DHTPeers, status.DHTRoutes = d.Controller.DiscoveryStatus()
	status.DHTLANPeers = d.Controller.DiscoveryLANPeers()
	return status
}

// Records is exported for the diagnostics bundle only.
func (d *Daemon) Records() []discovery.PeerRecord { return d.Controller.Records() }
