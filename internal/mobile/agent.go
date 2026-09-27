package mobile

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// OverlayCIDR is the overlay network every v1 node uses by default. The
// pairing invitation does not carry the NAS's prefix, so a phone uses the
// shipped default, exactly as the Windows client does.
var OverlayCIDR = netip.MustParsePrefix("10.88.0.0/16")

// TunnelMTU is the MTU the app gives the VPN interface. 1280 is the IPv6
// minimum and leaves room for WireGuard's 80 bytes of overhead on mobile
// networks that shrink the path MTU.
const TunnelMTU = 1280

// Plane is the NKN side of a session: signalling and, when available, relay.
type Plane struct {
	Signaling signaling.Transport
	Relay     relay.Relay
	Close     func() error
}

// PlaneFactory connects to NKN with the device's NKN seed.
type PlaneFactory func(ctx context.Context, seed []byte, seedRPC []string) (*Plane, error)

// DefaultPlaneFactory is set by the nknsdk build.
var DefaultPlaneFactory PlaneFactory

// Agent is one running core process.
type Agent struct {
	StateDir  string
	Secrets   *SecretStore
	OpenPlane PlaneFactory
	// OpenTUN turns the token of a connect command into the TUN device the
	// app created. Production receives the file descriptor over a Unix
	// socket; tests hand in an in-memory device.
	OpenTUN func(ctx context.Context, token string) (tun.Device, error)
	// Direct overrides the candidate source used by sessions. Nil uses STUN
	// and the local addresses reported by the app.
	Candidates mesh.CandidateSource
	Logger     *slog.Logger
	Logs       *app.LogRing
	// Timing overrides the controller schedule; tests compress it.
	Timing *mesh.Timing
	// PairWait bounds how long a pairing request waits for approval beyond
	// the invitation's own expiry. Zero means until the invitation expires.
	PairWait time.Duration
	// UsageChain opens the NKN chain client for the anonymous usage
	// statistics (usagestats.NewNKNChain in production). Nil disables them,
	// which is what tests use so they never touch the real network.
	UsageChain func(nknSeed []byte, seedRPC []string) (usagestats.Chain, error)

	usageOnce sync.Once
	usage     *usagestats.Reporter

	writeMu sync.Mutex
	out     *json.Encoder
	// cmdMu runs state-changing commands one at a time, in the order the app
	// sent them. Read-only commands bypass it so status stays responsive
	// while, say, a connect waits for the VPN file descriptor.
	cmdMu sync.Mutex

	mu          sync.Mutex
	device      *identity.DeviceIdentity
	name        string
	seedRPC     []string
	localAddrs  []netip.Addr
	stunServers []string
	pairCancel  context.CancelFunc
	pairDone    chan struct{}
	session     *session
}

// Request is one command from the app.
type Request struct {
	ID   int64           `json:"id"`
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response answers exactly one request.
type Response struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Result any    `json:"result,omitempty"`
}

// Event is unsolicited: status changes, pairing progress, secrets to store.
type Event struct {
	Event string `json:"event"`
	Data  any    `json:"data,omitempty"`
}

// MaxRequestBytes bounds one command line from the app.
const MaxRequestBytes = 256 * 1024

// Serve processes commands from in until it is closed or a shutdown command
// arrives, then tears down any session. Closing in — which is what happens
// when the app process dies — therefore always stops the VPN.
func (a *Agent) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if a.Logger == nil {
		a.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if a.Secrets == nil {
		a.Secrets = NewSecretStore()
	}
	if a.OpenPlane == nil {
		a.OpenPlane = DefaultPlaneFactory
	}
	a.out = json.NewEncoder(out)
	a.Secrets.SetOnChange(func(values map[string][]byte) {
		a.emit("secrets", map[string]any{"values": Encode(values)})
	})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.stopAll()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), MaxRequestBytes)
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			a.reply(Response{ID: 0, Error: "malformed request"})
			continue
		}
		if request.Cmd == "shutdown" {
			a.reply(Response{ID: request.ID, OK: true})
			return nil
		}
		serial := !concurrentCommands[request.Cmd]
		if serial {
			// Taking the lock here, before the goroutine starts, keeps
			// state-changing commands in arrival order.
			a.cmdMu.Lock()
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			if serial {
				defer a.cmdMu.Unlock()
			}
			result, err := a.handle(ctx, request)
			if err != nil {
				a.reply(Response{ID: request.ID, Error: err.Error()})
				return
			}
			a.reply(Response{ID: request.ID, OK: true, Result: result})
		}()
	}
	return scanner.Err()
}

func (a *Agent) reply(response Response) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.out != nil {
		_ = a.out.Encode(response)
	}
}

func (a *Agent) emit(name string, data any) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.out != nil {
		_ = a.out.Encode(Event{Event: name, Data: data})
	}
}

func decode[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(raw) == 0 {
		return value, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fmt.Errorf("invalid arguments: %w", err)
	}
	return value, nil
}

// concurrentCommands never wait behind a state-changing command.
var concurrentCommands = map[string]bool{"status": true, "diagnostics": true, "pair_cancel": true, "parse_invite": true, "usage": true}

func (a *Agent) handle(ctx context.Context, request Request) (any, error) {
	switch request.Cmd {
	case "init":
		args, err := decode[initArgs](request.Args)
		if err != nil {
			return nil, err
		}
		return a.init(ctx, args)
	case "network":
		args, err := decode[networkArgs](request.Args)
		if err != nil {
			return nil, err
		}
		return a.network(ctx, args)
	case "parse_invite":
		args, err := decode[struct {
			URI string `json:"uri"`
		}](request.Args)
		if err != nil {
			return nil, err
		}
		return parseInvite(args.URI)
	case "pair":
		args, err := decode[pairArgs](request.Args)
		if err != nil {
			return nil, err
		}
		return a.pair(ctx, args)
	case "pair_cancel":
		a.cancelPairing()
		return map[string]bool{"cancelled": true}, nil
	case "prepare":
		return a.prepare()
	case "connect":
		args, err := decode[struct {
			Token string `json:"token"`
		}](request.Args)
		if err != nil {
			return nil, err
		}
		return a.connect(ctx, args.Token)
	case "disconnect":
		a.disconnect()
		return map[string]bool{"disconnected": true}, nil
	case "status":
		return a.status(), nil
	case "forget":
		return a.forget()
	case "diagnostics":
		return map[string]string{"text": a.diagnostics()}, nil
	case "usage":
		args, err := decode[struct {
			Refresh bool `json:"refresh"`
		}](request.Args)
		if err != nil {
			return nil, err
		}
		reporter, err := a.usageReporter()
		if err != nil {
			return nil, err
		}
		queryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return reporter.Status(queryCtx, args.Refresh), nil
	case "usage_set":
		args, err := decode[struct {
			Enabled *bool `json:"enabled"`
		}](request.Args)
		if err != nil {
			return nil, err
		}
		if args.Enabled == nil {
			return nil, errors.New("enabled is required")
		}
		reporter, err := a.usageReporter()
		if err != nil {
			return nil, err
		}
		setCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := reporter.SetEnabled(setCtx, *args.Enabled); err != nil {
			return nil, err
		}
		return reporter.Status(setCtx, false), nil
	default:
		return nil, fmt.Errorf("unknown command %q", request.Cmd)
	}
}

type initArgs struct {
	Secrets    map[string]string `json:"secrets"`
	DeviceName string            `json:"device_name"`
	SeedRPC    []string          `json:"seed_rpc,omitempty"`
	networkArgs
}

type networkArgs struct {
	// LocalAddresses are the unicast addresses of the phone's current
	// underlying network (not the VPN). Go cannot enumerate interfaces on
	// Android 11+, so the app reports them.
	LocalAddresses []string `json:"local_addresses,omitempty"`
	DNSServers     []string `json:"dns_servers,omitempty"`
	STUNServers    []string `json:"stun_servers,omitempty"`
}

// InitResult tells the app who this device is and whether it is paired.
type InitResult struct {
	Version         string   `json:"version"`
	DeviceID        string   `json:"device_id"`
	WireGuardPublic string   `json:"wireguard_public_key"`
	Paired          bool     `json:"paired"`
	Revoked         bool     `json:"revoked"`
	Profile         *Profile `json:"profile,omitempty"`
}

func (a *Agent) init(ctx context.Context, args initArgs) (any, error) {
	if args.Secrets != nil {
		if err := a.Secrets.Load(args.Secrets); err != nil {
			return nil, err
		}
	}
	device, err := a.ensureIdentity()
	if err != nil {
		return nil, err
	}
	wgPublic, err := wireguard.EnsureKeyPair(a.Secrets)
	if err != nil {
		return nil, err
	}
	nknSeed, err := a.nknSeed()
	if err != nil {
		return nil, err
	}
	a.startUsage(ctx, nknSeed, args.SeedRPC)
	a.mu.Lock()
	a.device = device
	if name := cleanName(args.DeviceName); name != "" {
		a.name = name
	}
	a.seedRPC = args.SeedRPC
	a.mu.Unlock()
	a.applyNetwork(args.networkArgs)
	result := InitResult{Version: app.Version, DeviceID: device.DeviceID(), WireGuardPublic: wgPublic}
	profile, paired, err := loadProfile(a.StateDir)
	if err != nil {
		return nil, err
	}
	if paired {
		result.Paired = a.Secrets.Has(SecretJoinSecret)
		result.Revoked = profile.RevokedAt != nil
		result.Profile = &profile
	}
	return result, nil
}

// UsageStatsFile holds the statistics switch and last check-ins (no secrets).
const UsageStatsFile = "usage-stats.json"

// startUsage starts the anonymous usage statistics once per core process. The
// key is derived from the NKN seed, so it needs no secret of its own.
func (a *Agent) startUsage(ctx context.Context, nknSeed []byte, seedRPC []string) {
	a.usageOnce.Do(func() {
		reporter := &usagestats.Reporter{DefaultEnabled: true, Logger: a.Logger}
		if a.StateDir != "" {
			reporter.Path = filepath.Join(a.StateDir, UsageStatsFile)
		}
		if a.UsageChain != nil {
			chain, err := a.UsageChain(nknSeed, seedRPC)
			if err != nil {
				a.Logger.Warn("usage statistics unavailable", "component", "usage", "error", err)
			} else {
				reporter.Chain = chain
			}
		}
		a.mu.Lock()
		a.usage = reporter
		a.mu.Unlock()
		go reporter.Run(ctx)
	})
}

func (a *Agent) usageReporter() (*usagestats.Reporter, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.usage == nil {
		return nil, errors.New("core not initialized")
	}
	return a.usage, nil
}

func cleanName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

func (a *Agent) ensureIdentity() (*identity.DeviceIdentity, error) {
	seed, err := a.Secrets.ReadSecret(SecretRoot)
	if err == nil {
		return identity.FromSeed(seed)
	}
	device, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	if err := a.Secrets.WriteSecret(SecretRoot, device.Seed()); err != nil {
		return nil, err
	}
	return device, nil
}

func (a *Agent) nknSeed() ([]byte, error) {
	seed, err := a.Secrets.ReadSecret(SecretNKN)
	if err == nil && len(seed) == 32 {
		return seed, nil
	}
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, a.Secrets.WriteSecret(SecretNKN, seed)
}

func (a *Agent) identity() (*identity.DeviceIdentity, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.device == nil {
		return nil, "", errors.New("core is not initialised")
	}
	name := a.name
	if name == "" {
		name = "android"
	}
	return a.device, name, nil
}

func (a *Agent) applyNetwork(args networkArgs) {
	addresses := make([]netip.Addr, 0, len(args.LocalAddresses))
	for _, text := range args.LocalAddresses {
		if addr, err := netip.ParseAddr(text); err == nil && !OverlayCIDR.Contains(addr) {
			addresses = append(addresses, addr.Unmap())
		}
	}
	a.mu.Lock()
	// An absent list leaves the last report in place; an empty one means
	// the phone has no network right now.
	if args.LocalAddresses != nil {
		a.localAddrs = addresses
	}
	if len(args.STUNServers) > 0 {
		a.stunServers = args.STUNServers
	}
	a.mu.Unlock()
	if len(args.DNSServers) > 0 {
		SetDNSServers(args.DNSServers)
	}
}

// network is called when the phone changes network. A running session
// rebinds WireGuard's sockets, refreshes its candidates and retries the direct
// path at once instead of waiting for the next scheduled attempt.
func (a *Agent) network(ctx context.Context, args networkArgs) (any, error) {
	a.applyNetwork(args)
	a.mu.Lock()
	current := a.session
	a.mu.Unlock()
	if current != nil {
		current.networkChanged(ctx)
	}
	return map[string]bool{"ok": true}, nil
}

func (a *Agent) stunList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.stunServers) > 0 {
		return append([]string(nil), a.stunServers...)
	}
	return append([]string{"stun.miwifi.com:3478"}, nat.DefaultSTUNServers()...)
}

func (a *Agent) interfaceAddrs() ([]net.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]net.Addr, 0, len(a.localAddrs))
	for _, addr := range a.localAddrs {
		out = append(out, &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())})
	}
	return out, nil
}

// InviteInfo is what the app shows before sending a pairing request.
type InviteInfo struct {
	NetworkID  string    `json:"network_id"`
	NASID      string    `json:"nas_id"`
	NASAddress string    `json:"nas_address"`
	ExpiresAt  time.Time `json:"expires_at"`
}

var errInvalidInvite = errors.New("二维码内容无效或已过期；请在 NAS 面板重新生成")

func parseInvite(uri string) (InviteInfo, error) {
	invite, err := app.ParsePairInvite(strings.TrimSpace(uri))
	if err != nil {
		return InviteInfo{}, errInvalidInvite
	}
	return InviteInfo{NetworkID: invite.NetworkID, NASID: invite.NASID, NASAddress: invite.NASAddress, ExpiresAt: invite.ExpiresAt}, nil
}

func (a *Agent) membershipKey(profile Profile) (*membership.Key, error) {
	secret, err := a.Secrets.ReadSecret(SecretJoinSecret)
	if err != nil {
		return nil, errors.New("本机没有入网材料，请重新配对")
	}
	return membership.Derive(profile.NetworkID, strings.TrimSpace(string(secret)))
}

func (a *Agent) store() *state.Store { return state.New(a.StateDir) }

// forget drops the pairing but keeps the device identity, so the phone keeps
// its device id when it pairs again. It is the app's "重新配对" action.
func (a *Agent) forget() (any, error) {
	a.disconnect()
	a.cancelPairing()
	if err := removeState(a.StateDir); err != nil {
		return nil, err
	}
	a.Secrets.Delete(SecretJoinSecret)
	return map[string]bool{"forgotten": true}, nil
}

func (a *Agent) stopAll() {
	a.cancelPairing()
	a.disconnect()
}
