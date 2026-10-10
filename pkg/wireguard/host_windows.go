//go:build windows

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsManager controls an official WireGuard for Windows tunnel service.
// The service creates routes and the adapter; wg.exe changes peers in place.
type WindowsManager struct {
	store         Keystore
	runner        Runner
	name          string
	dir           string
	mu            sync.Mutex
	current       InterfaceConfig
	applied       bool
	serviceExists func(string) (bool, error)
}

func NewHostManager(store Keystore, interfaceName, stateDir string) Manager {
	return &WindowsManager{store: store, runner: ExecRunner{}, name: interfaceName, dir: filepath.Join(stateDir, "tunnels"), serviceExists: tunnelServiceExists}
}

func tunnelServiceExists(name string) (bool, error) {
	scm, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer scm.Disconnect()
	service, err := scm.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer service.Close()
	return true, nil
}

func (m *WindowsManager) tool(name string) (string, error) {
	if found, err := m.runner.Look(name); err == nil {
		return found, nil
	}
	path := filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", name+".exe")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("%s.exe is missing; install official WireGuard for Windows", name)
}

func (m *WindowsManager) Supported(context.Context) (State, string) {
	for _, tool := range []string{"wireguard", "wg"} {
		if _, err := m.tool(tool); err != nil {
			return StateToolsMissing, err.Error()
		}
	}
	return StateDown, ""
}

func (m *WindowsManager) PublicKey(context.Context) (string, error) {
	return EnsureKeyPair(m.store)
}

func validTunnelName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (m *WindowsManager) confPath() string { return filepath.Join(m.dir, m.name+".conf") }

func (m *WindowsManager) secureDirectory(ctx context.Context) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	// SIDs avoid depending on the language of a Windows installation. A
	// tunnel configuration contains the WireGuard private key, so a failed
	// ACL change stops the installation before any secret file is created.
	_, err := m.runner.Run(ctx, "icacls", m.dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	return err
}

func (m *WindowsManager) EnsureInterface(ctx context.Context, cfg InterfaceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.Name == "" {
		cfg.Name = m.name
	}
	if cfg.Name != m.name || !validTunnelName(cfg.Name) || !strings.HasPrefix(strings.ToLower(cfg.Name), "nknguard") {
		return errors.New("wireguard: unsafe Windows tunnel name")
	}
	if _, err := netip.ParsePrefix(cfg.Address); err != nil {
		return fmt.Errorf("wireguard: invalid interface address: %w", err)
	}
	wg, err := m.tool("wg")
	if err != nil {
		return err
	}
	wireguard, err := m.tool("wireguard")
	if err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, wg, "show", m.name, "dump"); err == nil {
		if _, err := m.runner.Run(ctx, "sc.exe", "config", "WireGuardTunnel$"+m.name, "start=", "demand"); err != nil {
			return err
		}
		m.current, m.applied = cfg, true
		return m.installPeers(ctx, wg, cfg.Peers)
	}
	if err := m.secureDirectory(ctx); err != nil {
		return fmt.Errorf("wireguard: restrict tunnel directory: %w", err)
	}
	if _, err := EnsureKeyPair(m.store); err != nil {
		return err
	}
	raw, err := m.store.ReadSecret(PrivateKeyName)
	if err != nil {
		return err
	}
	var conf strings.Builder
	conf.WriteString("[Interface]\nPrivateKey = ")
	conf.WriteString(strings.TrimSpace(string(raw)))
	conf.WriteString("\nAddress = ")
	conf.WriteString(cfg.Address)
	conf.WriteByte('\n')
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&conf, "ListenPort = %d\n", cfg.ListenPort)
	}
	if cfg.MTU > 0 {
		fmt.Fprintf(&conf, "MTU = %d\n", cfg.MTU)
	}
	for _, peer := range cfg.Peers {
		if peer.PublicKey == "" {
			return errors.New("wireguard: peer has no public key")
		}
		fmt.Fprintf(&conf, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", peer.PublicKey, strings.Join(peer.AllowedIPs, ", "))
		if peer.Endpoint != "" {
			fmt.Fprintf(&conf, "Endpoint = %s\n", peer.Endpoint)
		}
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&conf, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
		}
	}
	if err := os.WriteFile(m.confPath(), []byte(conf.String()), 0o600); err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, wireguard, "/installtunnelservice", m.confPath()); err != nil {
		_ = os.Remove(m.confPath())
		return err
	}
	if _, err := m.runner.Run(ctx, "sc.exe", "config", "WireGuardTunnel$"+m.name, "start=", "demand"); err != nil {
		_, _ = m.runner.Run(ctx, wireguard, "/uninstalltunnelservice", m.name)
		_ = os.Remove(m.confPath())
		return fmt.Errorf("wireguard: make tunnel on-demand: %w", err)
	}
	readyUntil := time.NewTimer(10 * time.Second)
	defer readyUntil.Stop()
	for {
		if _, err := m.runner.Run(ctx, wg, "show", m.name, "dump"); err == nil {
			m.current, m.applied = cfg, true
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-readyUntil.C:
			return errors.New("wireguard: Windows tunnel service did not become ready")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (m *WindowsManager) installPeers(ctx context.Context, wg string, peers []PeerConfig) error {
	for _, peer := range peers {
		if err := m.addPeer(ctx, wg, peer); err != nil {
			return err
		}
	}
	return nil
}

func (m *WindowsManager) addPeer(ctx context.Context, wg string, peer PeerConfig) error {
	if strings.TrimSpace(peer.PublicKey) == "" {
		return errors.New("wireguard: peer has no public key")
	}
	args := []string{"set", m.name, "peer", peer.PublicKey}
	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.PersistentKeepalive >= 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}
	_, err := m.runner.Run(ctx, wg, args...)
	return err
}

func (m *WindowsManager) AddPeer(ctx context.Context, peer PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wg, err := m.tool("wg")
	if err != nil {
		return err
	}
	if err := m.addPeer(ctx, wg, peer); err != nil {
		return err
	}
	for i := range m.current.Peers {
		if m.current.Peers[i].PublicKey == peer.PublicKey {
			m.current.Peers[i] = peer
			return nil
		}
	}
	m.current.Peers = append(m.current.Peers, peer)
	return nil
}

func (m *WindowsManager) UpdateEndpoint(ctx context.Context, publicKey, endpoint string) error {
	if publicKey == "" || endpoint == "" {
		return errors.New("wireguard: endpoint and public key required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	wg, err := m.tool("wg")
	if err != nil {
		return err
	}
	_, err = m.runner.Run(ctx, wg, "set", m.name, "peer", publicKey, "endpoint", endpoint)
	return err
}

func (m *WindowsManager) RemovePeer(ctx context.Context, publicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wg, err := m.tool("wg")
	if err != nil {
		return err
	}
	_, err = m.runner.Run(ctx, wg, "set", m.name, "peer", publicKey, "remove")
	if err == nil {
		kept := m.current.Peers[:0]
		for _, peer := range m.current.Peers {
			if peer.PublicKey != publicKey {
				kept = append(kept, peer)
			}
		}
		m.current.Peers = kept
	}
	return err
}

func (m *WindowsManager) Stats(ctx context.Context) ([]PeerStats, error) {
	wg, err := m.tool("wg")
	if err != nil {
		return nil, err
	}
	out, err := m.runner.Run(ctx, wg, "show", m.name, "dump")
	if err != nil {
		return nil, err
	}
	return parseDump(out, time.Now()).Peers, nil
}

func (m *WindowsManager) Status(ctx context.Context) Status {
	m.mu.Lock()
	cfg := m.current
	m.mu.Unlock()
	wg, err := m.tool("wg")
	if err != nil {
		return Status{State: StateToolsMissing, Interface: m.name, Error: err.Error(), UpdatedAt: time.Now()}
	}
	out, err := m.runner.Run(ctx, wg, "show", m.name, "dump")
	if err != nil {
		return Status{State: StateDown, Interface: m.name, UpdatedAt: time.Now()}
	}
	status := parseDump(out, time.Now())
	status.Interface, status.Address, status.Revision = m.name, cfg.Address, cfg.Revision
	for i := range status.Peers {
		for _, peer := range cfg.Peers {
			if status.Peers[i].PublicKey == peer.PublicKey {
				status.Peers[i].DeviceID, status.Peers[i].Name = peer.DeviceID, peer.Name
				break
			}
		}
	}
	return status
}

func (m *WindowsManager) Down(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTunnelName(m.name) || !strings.HasPrefix(strings.ToLower(m.name), "nknguard") {
		return errors.New("wireguard: refusing to remove an unrelated Windows tunnel")
	}
	// A user may already have removed the shared WireGuard installation.
	// SCM absence is authoritative; missing tools alone are not proof.
	exists, verifyErr := m.serviceExists("WireGuardTunnel$" + m.name)
	if verifyErr != nil {
		return fmt.Errorf("wireguard: cannot verify service removal: %w", verifyErr)
	}
	if !exists {
		m.applied = false
		if err := os.Remove(m.confPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	wireguard, err := m.tool("wireguard")
	if err != nil {
		return err
	}
	_, uninstallErr := m.runner.Run(ctx, wireguard, "/uninstalltunnelservice", m.name)
	for {
		exists, err := m.serviceExists("WireGuardTunnel$" + m.name)
		if err != nil {
			return fmt.Errorf("wireguard: cannot verify service removal: %w", err)
		}
		if !exists {
			break
		}
		if uninstallErr != nil {
			return uninstallErr
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wireguard: tunnel service still exists: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	m.applied = false
	if err := os.Remove(m.confPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
