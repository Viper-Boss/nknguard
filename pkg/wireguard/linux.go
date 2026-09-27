package wireguard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
)

// PrivateKeyName is the keystore entry holding the interface private key.
const PrivateKeyName = "wireguard.key"

// ErrNoPrivateKey means the key has not been generated yet.
var ErrNoPrivateKey = errors.New("wireguard: no private key")

// LinuxManager drives a kernel or wireguard-go interface through the standard
// `wg` and `ip` tools.
//
// Shelling out rather than speaking netlink directly is a deliberate trade.
// The netlink route needs a library and a kernel-version matrix; `wg` and `ip`
// are present on every distribution that can run WireGuard at all, they are
// what an operator will use to check our work, and the argument-slice Runner
// keeps the shell-injection class of bug out of reach. The cost is one process
// per operation, on a control path that runs every few seconds at most.
type LinuxManager struct {
	keystore  Keystore
	runner    Runner
	ifaceName string

	mu      sync.Mutex
	current InterfaceConfig
	applied bool
	lastErr string
}

// Keystore is the subset of the identity keystore this package needs. Taking
// an interface rather than the concrete type keeps the dependency one-way and
// makes the manager testable with a temporary directory.
type Keystore interface {
	ReadSecret(name string) ([]byte, error)
	WriteSecret(name string, data []byte) error
	Has(name string) bool
}

// NewLinuxManager returns a manager for the named interface.
func NewLinuxManager(keystore Keystore, interfaceName string) *LinuxManager {
	return NewLinuxManagerWithRunner(keystore, interfaceName, ExecRunner{})
}

// NewLinuxManagerWithRunner is the injectable constructor used by tests.
func NewLinuxManagerWithRunner(keystore Keystore, interfaceName string, runner Runner) *LinuxManager {
	return &LinuxManager{keystore: keystore, runner: runner, ifaceName: interfaceName}
}

// Supported probes what this host can do. It answers before anything is
// attempted so that `nknguard doctor` can tell an operator their kernel has no
// WireGuard rather than showing a tunnel that will never come up.
func (m *LinuxManager) Supported(ctx context.Context) (State, string) {
	for _, tool := range []string{"wg", "ip"} {
		if _, err := m.runner.Look(tool); err != nil {
			return StateToolsMissing, fmt.Sprintf("%s is not on PATH", tool)
		}
	}
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return StateDown, ""
	}
	// No kernel module is not fatal: wireguard-go provides the same interface
	// from userspace, and many NAS kernels ship without the module.
	if _, err := m.runner.Look("wireguard-go"); err == nil {
		return StateDown, ""
	}
	if _, err := m.runner.Run(ctx, "wg", "show", "interfaces"); err == nil {
		return StateDown, ""
	}
	return StateUnsupported, "kernel has no WireGuard support and wireguard-go is not installed"
}

// PublicKey returns the interface public key, generating the private half on
// first use.
func (m *LinuxManager) PublicKey(ctx context.Context) (string, error) {
	private, err := m.ensurePrivateKey(ctx)
	if err != nil {
		return "", err
	}
	out, err := m.runner.RunStdin(ctx, private, "wg", "pubkey")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (m *LinuxManager) ensurePrivateKey(ctx context.Context) (string, error) {
	if raw, err := m.keystore.ReadSecret(PrivateKeyName); err == nil {
		key := strings.TrimSpace(string(raw))
		if key != "" {
			return key, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	generated, err := m.runner.Run(ctx, "wg", "genkey")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(generated)
	if key == "" {
		return "", ErrNoPrivateKey
	}
	if err := m.keystore.WriteSecret(PrivateKeyName, []byte(key+"\n")); err != nil {
		return "", err
	}
	return key, nil
}

// EnsureInterface makes the live interface match cfg. It is idempotent: the
// daemon calls it whenever the peer set changes, and an unchanged call is a
// handful of no-op commands rather than a tunnel that blinks.
func (m *LinuxManager) EnsureInterface(ctx context.Context, cfg InterfaceConfig) error {
	if cfg.Name == "" {
		cfg.Name = m.ifaceName
	}
	private, err := m.ensurePrivateKey(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existed := m.interfaceExists(ctx, cfg.Name)
	if !existed {
		if _, err := m.runner.Run(ctx, "ip", "link", "add", "dev", cfg.Name, "type", "wireguard"); err != nil {
			// wireguard-go is the fallback when the kernel has no module. It
			// creates the interface itself, so the add failing is expected on
			// those hosts rather than an error to report.
			if _, fallbackErr := m.runner.Run(ctx, "wireguard-go", cfg.Name); fallbackErr != nil {
				m.lastErr = err.Error()
				return err
			}
		}
	}
	if cfg.MTU > 0 {
		if _, err := m.runner.Run(ctx, "ip", "link", "set", "dev", cfg.Name, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	if existed {
		// The interface outlived a daemon restart or crash, and its peers are
		// carrying traffic. `wg setconf` would replace the peer list with the
		// (empty) configured one and cut every tunnel until the next
		// reconcile, so only the key and port are reasserted here; peers are
		// then added one by one below. Principle 4: a control-plane restart
		// must not tear down a healthy data plane.
		args := []string{"set", cfg.Name, "private-key", "/dev/stdin"}
		if cfg.ListenPort > 0 {
			args = append(args, "listen-port", strconv.Itoa(cfg.ListenPort))
		}
		if _, err := m.runner.RunStdin(ctx, private+"\n", "wg", args...); err != nil {
			m.lastErr = err.Error()
			return err
		}
		for _, peer := range cfg.Peers {
			if err := m.addPeerLocked(ctx, cfg.Name, peer); err != nil {
				return err
			}
		}
	} else {
		configuration, err := renderConf(private, cfg)
		if err != nil {
			return err
		}
		if _, err := m.runner.RunStdin(ctx, configuration, "wg", "setconf", cfg.Name, "/dev/stdin"); err != nil {
			m.lastErr = err.Error()
			return err
		}
	}
	if cfg.Address != "" {
		// `add` fails when the address is already there, which is the common
		// case on a re-apply and is not worth reporting.
		_, _ = m.runner.Run(ctx, "ip", "address", "add", cfg.Address, "dev", cfg.Name)
	}
	if _, err := m.runner.Run(ctx, "ip", "link", "set", "up", "dev", cfg.Name); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.current = cfg
	m.applied = true
	m.lastErr = ""
	return nil
}

func (m *LinuxManager) interfaceExists(ctx context.Context, name string) bool {
	_, err := m.runner.Run(ctx, "ip", "link", "show", "dev", name)
	return err == nil
}

// renderConf produces a `wg setconf` document. It is a pure function of the
// configuration so it can be unit tested without touching the system, and the
// private key is the only secret in it — which is why it goes to stdin and
// never to a file.
func renderConf(privateKey string, cfg InterfaceConfig) (string, error) {
	var out strings.Builder
	out.WriteString("[Interface]\n")
	out.WriteString("PrivateKey = " + strings.TrimSpace(privateKey) + "\n")
	if cfg.ListenPort > 0 {
		out.WriteString("ListenPort = " + strconv.Itoa(cfg.ListenPort) + "\n")
	}
	for _, peer := range cfg.Peers {
		if strings.TrimSpace(peer.PublicKey) == "" {
			return "", fmt.Errorf("wireguard: peer %q has no public key", peer.DeviceID)
		}
		out.WriteString("\n[Peer]\n")
		out.WriteString("PublicKey = " + peer.PublicKey + "\n")
		if len(peer.AllowedIPs) > 0 {
			out.WriteString("AllowedIPs = " + strings.Join(peer.AllowedIPs, ", ") + "\n")
		}
		if peer.Endpoint != "" {
			out.WriteString("Endpoint = " + peer.Endpoint + "\n")
		}
		if peer.PersistentKeepalive > 0 {
			out.WriteString("PersistentKeepalive = " + strconv.Itoa(peer.PersistentKeepalive) + "\n")
		}
	}
	return out.String(), nil
}

// AddPeer installs or replaces a single peer without rewriting the interface.
func (m *LinuxManager) AddPeer(ctx context.Context, peer PeerConfig) error {
	if err := m.addPeerLocked(ctx, m.ifaceName, peer); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for index, existing := range m.current.Peers {
		if existing.PublicKey == peer.PublicKey {
			m.current.Peers[index] = peer
			return nil
		}
	}
	m.current.Peers = append(m.current.Peers, peer)
	return nil
}

func (m *LinuxManager) addPeerLocked(ctx context.Context, iface string, peer PeerConfig) error {
	if strings.TrimSpace(peer.PublicKey) == "" {
		return fmt.Errorf("wireguard: peer %q has no public key", peer.DeviceID)
	}
	args := []string{"set", iface, "peer", peer.PublicKey}
	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}
	_, err := m.runner.Run(ctx, "wg", args...)
	return err
}

// UpdateEndpoint moves a peer to a new address.
//
// This is the roaming hot path, and it is one command on purpose: WireGuard
// keeps its session keys across an endpoint change, so a laptop moving from
// Wi-Fi to a phone hotspot resumes on the existing tunnel instead of
// renegotiating. Tearing the peer down and re-adding it would work and would
// also drop every connection through it.
func (m *LinuxManager) UpdateEndpoint(ctx context.Context, publicKey, endpoint string) error {
	if strings.TrimSpace(publicKey) == "" || strings.TrimSpace(endpoint) == "" {
		return errors.New("wireguard: UpdateEndpoint needs a public key and an endpoint")
	}
	_, err := m.runner.Run(ctx, "wg", "set", m.ifaceName, "peer", publicKey, "endpoint", endpoint)
	return err
}

// RemovePeer drops a peer from the interface.
func (m *LinuxManager) RemovePeer(ctx context.Context, publicKey string) error {
	_, err := m.runner.Run(ctx, "wg", "set", m.ifaceName, "peer", publicKey, "remove")
	return err
}

// Stats reads the live counters.
func (m *LinuxManager) Stats(ctx context.Context) ([]PeerStats, error) {
	out, err := m.runner.Run(ctx, "wg", "show", m.ifaceName, "dump")
	if err != nil {
		return nil, err
	}
	return parseDump(out, time.Now()).Peers, nil
}

// Status reports the interface as a whole, naming the peers from the applied
// configuration so the output carries device names rather than bare keys.
func (m *LinuxManager) Status(ctx context.Context) Status {
	m.mu.Lock()
	cfg, applied, lastErr := m.current, m.applied, m.lastErr
	m.mu.Unlock()

	if !applied {
		state, reason := m.Supported(ctx)
		return Status{State: state, Interface: m.ifaceName, Error: reason, UpdatedAt: time.Now()}
	}
	out, err := m.runner.Run(ctx, "wg", "show", m.ifaceName, "dump")
	if err != nil {
		return Status{State: StateDown, Interface: m.ifaceName, Error: err.Error(), Revision: cfg.Revision, UpdatedAt: time.Now()}
	}
	status := parseDump(out, time.Now())
	status.Interface = m.ifaceName
	status.Address = cfg.Address
	status.Revision = cfg.Revision
	status.Error = lastErr
	names := make(map[string]PeerConfig, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		names[peer.PublicKey] = peer
	}
	for index := range status.Peers {
		if known, ok := names[status.Peers[index].PublicKey]; ok {
			status.Peers[index].DeviceID = known.DeviceID
			status.Peers[index].Name = known.Name
		}
	}
	return status
}

// Down removes the interface. It is called on shutdown and must leave nothing
// behind: a stale wg interface after `nknguard down` is a routing black hole.
func (m *LinuxManager) Down(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = false
	if !m.interfaceExists(ctx, m.ifaceName) {
		return nil
	}
	_, err := m.runner.Run(ctx, "ip", "link", "delete", "dev", m.ifaceName)
	return err
}

// keystoreAdapter lets an *identity.Keystore satisfy the Keystore interface
// without identity importing this package.
type keystoreAdapter struct{ inner *identity.Keystore }

func (a keystoreAdapter) ReadSecret(name string) ([]byte, error) { return a.inner.ReadSecret(name) }
func (a keystoreAdapter) WriteSecret(name string, data []byte) error {
	return a.inner.WriteSecret(name, data)
}
func (a keystoreAdapter) Has(name string) bool { return a.inner.Has(name) }

// FromIdentityKeystore adapts the identity keystore for this package.
func FromIdentityKeystore(store *identity.Keystore) Keystore { return keystoreAdapter{inner: store} }
