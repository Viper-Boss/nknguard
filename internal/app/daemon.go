package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// Version is set at build time with -ldflags "-X .../internal/app.Version=v0.1.0".
var Version = "0.1.0-dev"

// PersistInterval is how often runtime state and the peer cache are written.
const PersistInterval = 30 * time.Second

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

	down     context.CancelFunc
	downOnce sync.Once
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
	logger, ring := NewLogger(logOut, cfg.Logging.Level)
	if controlPlaneFactory == nil {
		return ErrNoNKN
	}
	if !hasTunnelPrivilege() {
		return errors.New("the daemon needs administrator privileges to manage WireGuard")
	}
	node, err := OpenNode(cfg)
	if err != nil {
		return err
	}
	key, current, err := node.MembershipKey()
	if err != nil {
		return err
	}
	logger = logger.With("device_id", node.Device.DeviceID())

	wg := wireguard.NewHostManager(wireguard.FromIdentityKeystore(node.Keystore), cfg.WireGuard.Interface, cfg.Paths.StateDir)
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
	controller.Device = node.Device
	controller.Membership = key
	controller.Policy = cfg.ACL
	controller.Logger = logger
	controller.SetSequence(runtime.Sequence)

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
	if err := wg.EnsureInterface(ctx, interfaceConfig); err != nil {
		return fmt.Errorf("bring up %s: %w", cfg.WireGuard.Interface, err)
	}
	logger.Info("wireguard interface up", "component", "wireguard", "interface", cfg.WireGuard.Interface, "address", interfaceConfig.Address)

	servers := cfg.NAT.STUNServers
	if !cfg.NAT.STUNEnabled {
		servers = nil
	}
	controller.WireGuard = wg
	controller.Candidates = &nat.WireGuardGatherer{
		STUNServers: servers,
		ListenPort: func(ctx context.Context) (int, error) {
			if port := wg.Status(ctx).ListenPort; port > 0 {
				return port, nil
			}
			return 0, errors.New("wireguard listen port not yet known")
		},
	}
	controller.Direct = &mesh.WireGuardStrategy{WireGuard: wg, Nudge: mesh.UDPNudge}
	controller.Nudge = mesh.UDPNudge

	plane, err := controlPlaneFactory(ctx, cfg, node.Keystore, key, logger)
	if err != nil {
		_ = wg.Down(context.WithoutCancel(ctx))
		return fmt.Errorf("NKN control plane: %w", err)
	}
	var closePlane sync.Once
	closeNKN := func() { closePlane.Do(func() { _ = plane.Close() }) }
	defer closeNKN()
	controller.Signaling = plane.Signaling
	controller.Relay = plane.Relay
	controller.Rendezvous = plane.Rendezvous
	pairing := NewPairing(node, controller, plane.Signaling)
	controller.PairRequest = pairing.HandleRequest

	if cfg.Discovery.DHT && discoveryFactory != nil {
		backend, err := discoveryFactory(ctx, cfg, key, logger)
		if err != nil {
			// The DHT is one discovery source among several; its absence is
			// logged, not fatal.
			logger.Warn("DHT discovery unavailable", "component", "discovery", "error", err)
		} else {
			controller.Discovery = backend
			defer func() { _ = backend.Close() }()
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The NKN SDK's session Accept has no context argument. Closing the client
	// unblocks it before Controller.Run waits for its workers on shutdown.
	planeStopped := make(chan struct{})
	go func() {
		defer close(planeStopped)
		<-runCtx.Done()
		closeNKN()
	}()
	daemon := &Daemon{Config: cfg, Node: node, Controller: controller, WireGuard: wg, Pairing: pairing, Logger: logger, Logs: ring, Started: time.Now(), down: cancel}

	api, err := daemon.ServeAPI(runCtx)
	if err != nil {
		_ = wg.Down(context.WithoutCancel(ctx))
		return err
	}
	defer func() { _ = api.Close() }()
	panel, err := daemon.ServeDashboard(runCtx)
	if err != nil {
		logger.Warn("dashboard unavailable", "component", "dashboard", "error", err)
	} else {
		defer func() { _ = panel.Close() }()
		logger.Info("dashboard listening", "component", "dashboard", "address", cfg.Dashboard.Listen)
	}

	// Replay the peer cache: records still inside their TTL come back
	// immediately, which is what lets a quick restart resume without waiting
	// for discovery.
	cached, _ := node.State.LoadPeerCache()
	for _, record := range cached {
		controller.IngestCached(runCtx, record)
	}
	hints, _ := node.State.LoadLinkHints()
	for _, hint := range hints {
		if controller.RestoreLinkHint(hint.DeviceID, hint.PublicKey, hint.Endpoint, hint.SeenAt) {
			logger.Info("probing last direct endpoint", "component", "mesh", "peer", hint.DeviceID)
		}
	}

	persistDone := make(chan struct{})
	go func() {
		defer close(persistDone)
		daemon.persistLoop(runCtx)
	}()

	logger.Info("nknguard running", "component", "app", "version", Version, "network", current.NetworkID, "virtual_ip", virtual.String())
	runErr := controller.Run(runCtx)
	cancel()
	<-planeStopped
	<-persistDone
	daemon.persist()

	downCtx, downCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer downCancel()
	if err := wg.Down(downCtx); err != nil {
		logger.Warn("removing interface failed", "component", "wireguard", "error", err)
	}
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
		if peer.Path == mesh.PathDirectWG && allowed[peer.DeviceID] && peer.Endpoint != "" {
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
		Version:    Version,
		DeviceID:   d.Node.Device.DeviceID(),
		Device:     d.Config.Device.Name,
		NetworkID:  d.Controller.Config.NetworkID,
		StartedAt:  d.Started,
		Uptime:     time.Since(d.Started).Round(time.Second).String(),
		NKNAddress: d.Controller.Signaling.LocalAddress(),
		NAT:        d.Controller.PortMapping().Behaviour,
		WireGuard:  d.WireGuard.Status(ctx),
		Peers:      d.Controller.Peers(),
		Metrics:    d.Controller.Metrics(),
	}
	if virtual := d.Controller.VirtualIP(); virtual.IsValid() {
		status.VirtualIP = virtual.String()
	}
	return status
}

// Records is exported for the diagnostics bundle only.
func (d *Daemon) Records() []discovery.PeerRecord { return d.Controller.Records() }
