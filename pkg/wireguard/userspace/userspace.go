// Package userspace runs WireGuard in-process with wireguard-go.
//
// It is the data plane for platforms where NKNGuard cannot create a kernel
// interface: on Android the operating system hands a VpnService TUN file
// descriptor to the app, and this package runs the WireGuard protocol on it.
// The cryptography and handshake are still wireguard-go's; this package only
// translates the wireguard.Manager contract into the UAPI configuration
// protocol and reads the live counters back.
//
// Address, routes and MTU are not set here. They belong to whoever created the
// TUN device (Android's VpnService.Builder), which is why EnsureInterface only
// applies the key and listen port.
package userspace

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// OpenTUN returns the TUN device the manager runs on. It is called once, the
// first time the interface is brought up.
type OpenTUN func() (tun.Device, error)

// Manager implements wireguard.Manager on a wireguard-go device.
type Manager struct {
	keystore wireguard.Keystore
	openTUN  OpenTUN
	logger   *slog.Logger
	// NewBind creates the UDP bind. Nil uses conn.NewDefaultBind.
	NewBind func() conn.Bind

	mu      sync.Mutex
	dev     *device.Device
	stun    *stunBind
	config  wireguard.InterfaceConfig
	peers   map[string]wireguard.PeerConfig
	lastErr string
}

// New returns a manager that opens its TUN device with open.
func New(keystore wireguard.Keystore, open OpenTUN, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{keystore: keystore, openTUN: open, logger: logger, peers: make(map[string]wireguard.PeerConfig)}
}

var _ wireguard.Manager = (*Manager)(nil)

// Supported reports that the userspace implementation can run whenever it has
// a way to obtain a TUN device.
func (m *Manager) Supported(context.Context) (wireguard.State, string) {
	if m.openTUN == nil {
		return wireguard.StateUnsupported, "no TUN device available"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev != nil {
		return wireguard.StateUp, ""
	}
	return wireguard.StateDown, ""
}

// PublicKey returns the interface public key, generating the key on first use.
func (m *Manager) PublicKey(context.Context) (string, error) {
	return wireguard.EnsureKeyPair(m.keystore)
}

func (m *Manager) privateKeyHex() (string, error) {
	if _, err := wireguard.EnsureKeyPair(m.keystore); err != nil {
		return "", err
	}
	raw, err := m.keystore.ReadSecret(wireguard.PrivateKeyName)
	if err != nil {
		return "", err
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(private) != 32 {
		return "", wireguard.ErrNoPrivateKey
	}
	return hex.EncodeToString(private), nil
}

func keyHex(publicKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("wireguard: invalid public key")
	}
	return hex.EncodeToString(raw), nil
}

func keyBase64(hexKey string) string {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (m *Manager) deviceLogger() *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			m.logger.Debug(fmt.Sprintf(format, args...), "component", "wireguard")
		},
		Errorf: func(format string, args ...any) {
			m.logger.Warn(fmt.Sprintf(format, args...), "component", "wireguard")
		},
	}
}

// EnsureInterface brings the device up on first call and applies the listen
// port. Peers are managed with AddPeer and RemovePeer.
func (m *Manager) EnsureInterface(_ context.Context, cfg wireguard.InterfaceConfig) error {
	if m.openTUN == nil {
		return wireguard.ErrNotSupported
	}
	private, err := m.privateKeyHex()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev == nil {
		tunDevice, err := m.openTUN()
		if err != nil {
			m.lastErr = err.Error()
			return fmt.Errorf("wireguard: open tun: %w", err)
		}
		bind := conn.NewDefaultBind()
		if m.NewBind != nil {
			bind = m.NewBind()
		}
		port := cfg.ListenPort
		if port == 0 {
			// wireguard-go reports listen port 0 when it asked for an
			// ephemeral port and IPv6 is unavailable, and the relay bridge
			// and the candidate gatherer both need the real number. Choose
			// a free port up front instead.
			if port, err = freeUDPPort(); err != nil {
				_ = tunDevice.Close()
				return err
			}
		}
		shared := &stunBind{Bind: bind}
		dev := device.NewDevice(tunDevice, portBind{shared}, m.deviceLogger())
		if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", private, port)); err != nil {
			dev.Close()
			m.lastErr = err.Error()
			return fmt.Errorf("wireguard: configure device: %w", err)
		}
		if err := dev.Up(); err != nil {
			dev.Close()
			m.lastErr = err.Error()
			return fmt.Errorf("wireguard: bring device up: %w", err)
		}
		m.dev = dev
		m.stun = shared
		m.config = cfg
		m.lastErr = ""
		return nil
	}
	if cfg.ListenPort != m.config.ListenPort {
		if err := m.dev.IpcSet(fmt.Sprintf("listen_port=%d\n", cfg.ListenPort)); err != nil {
			m.lastErr = err.Error()
			return err
		}
	}
	m.config = cfg
	return nil
}

// portBind corrects the port StdNetBind reports. When IPv6 is unavailable
// it returns 0 for the port it actually bound on IPv4, the device then shows
// listen port 0, and the next rebind after a network change would pick a new
// random port. The manager always asks for an explicit port, so that request
// is the truth.
type portBind struct{ conn.Bind }

func (b portBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err == nil && actual == 0 {
		actual = port
	}
	return fns, actual, err
}

func freeUDPPort() (int, error) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return 0, fmt.Errorf("wireguard: choose listen port: %w", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	return port, nil
}

func (m *Manager) set(config string) error {
	m.mu.Lock()
	dev := m.dev
	m.mu.Unlock()
	if dev == nil {
		return errors.New("wireguard: device is not up")
	}
	return dev.IpcSet(config)
}

// AddPeer installs or replaces one peer. The endpoint is left alone unless
// the config carries one, so a relay or direct attempt in flight is not
// disturbed by a reconcile tick.
func (m *Manager) AddPeer(_ context.Context, peer wireguard.PeerConfig) error {
	key, err := keyHex(peer.PublicKey)
	if err != nil {
		return err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "public_key=%s\nreplace_allowed_ips=true\n", key)
	for _, allowed := range peer.AllowedIPs {
		prefix, err := netip.ParsePrefix(allowed)
		if err != nil {
			return fmt.Errorf("wireguard: allowed ip %q: %w", allowed, err)
		}
		fmt.Fprintf(&out, "allowed_ip=%s\n", prefix.Masked())
	}
	if peer.Endpoint != "" {
		endpoint, err := netip.ParseAddrPort(peer.Endpoint)
		if err != nil {
			return fmt.Errorf("wireguard: endpoint %q: %w", peer.Endpoint, err)
		}
		fmt.Fprintf(&out, "endpoint=%s\n", endpoint)
	}
	fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", max(peer.PersistentKeepalive, 0))
	if err := m.set(out.String()); err != nil {
		return err
	}
	m.mu.Lock()
	m.peers[peer.PublicKey] = peer
	m.mu.Unlock()
	return nil
}

// UpdateEndpoint moves an existing peer without touching its session.
func (m *Manager) UpdateEndpoint(_ context.Context, publicKey, endpoint string) error {
	key, err := keyHex(publicKey)
	if err != nil {
		return err
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf("wireguard: endpoint %q: %w", endpoint, err)
	}
	return m.set(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", key, address))
}

// RemovePeer drops a peer.
func (m *Manager) RemovePeer(_ context.Context, publicKey string) error {
	key, err := keyHex(publicKey)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.peers, publicKey)
	dev := m.dev
	m.mu.Unlock()
	if dev == nil {
		return nil
	}
	return dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", key))
}

// Nudge makes WireGuard send a handshake initiation to the peer that owns
// virtualIP now, instead of waiting for traffic or the next keepalive. It is
// the userspace equivalent of mesh.UDPNudge, which cannot work on Android: the
// app's own sockets are excluded from its VPN, so a datagram it sends to an
// overlay address never reaches the TUN device.
func (m *Manager) Nudge(_ context.Context, virtualIP netip.Addr) {
	m.mu.Lock()
	dev := m.dev
	var publicKey string
	for key, peer := range m.peers {
		for _, allowed := range peer.AllowedIPs {
			if prefix, err := netip.ParsePrefix(allowed); err == nil && prefix.Contains(virtualIP) {
				publicKey = key
			}
		}
	}
	m.mu.Unlock()
	if dev == nil || publicKey == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 32 {
		return
	}
	var key device.NoisePublicKey
	copy(key[:], raw)
	if peer := dev.LookupPeer(key); peer != nil {
		_ = peer.SendHandshakeInitiation(false)
	}
}

// Rebind reopens the UDP sockets after the phone changes network, so traffic
// leaves through the new interface immediately.
func (m *Manager) Rebind() error {
	m.mu.Lock()
	dev := m.dev
	m.mu.Unlock()
	if dev == nil {
		return nil
	}
	return dev.BindUpdate()
}

// Stats reads the live counters from the device.
func (m *Manager) Stats(context.Context) ([]wireguard.PeerStats, error) {
	status, err := m.read(time.Now())
	if err != nil {
		return nil, err
	}
	return status.Peers, nil
}

// Status is the interface-level view.
func (m *Manager) Status(context.Context) wireguard.Status {
	now := time.Now()
	status, err := m.read(now)
	if err != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.dev == nil {
			return wireguard.Status{State: wireguard.StateDown, Error: m.lastErr, UpdatedAt: now}
		}
		return wireguard.Status{State: wireguard.StateError, Error: err.Error(), UpdatedAt: now}
	}
	return status
}

func (m *Manager) read(now time.Time) (wireguard.Status, error) {
	m.mu.Lock()
	dev := m.dev
	config := m.config
	known := make(map[string]wireguard.PeerConfig, len(m.peers))
	for key, peer := range m.peers {
		known[key] = peer
	}
	m.mu.Unlock()
	if dev == nil {
		return wireguard.Status{}, errors.New("wireguard: device is not up")
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return wireguard.Status{}, err
	}
	status := parseUAPI(raw, now)
	status.Interface = config.Name
	status.Address = config.Address
	status.Revision = config.Revision
	if public, err := wireguard.EnsureKeyPair(m.keystore); err == nil {
		status.PublicKey = public
	}
	for index := range status.Peers {
		if peer, ok := known[status.Peers[index].PublicKey]; ok {
			status.Peers[index].DeviceID = peer.DeviceID
			status.Peers[index].Name = peer.Name
		}
	}
	return status, nil
}

// parseUAPI reads the "get" output of the configuration protocol. The private
// key line is skipped without being stored anywhere.
func parseUAPI(raw string, now time.Time) wireguard.Status {
	status := wireguard.Status{State: wireguard.StateUp, UpdatedAt: now}
	var current *wireguard.PeerStats
	var handshakeSec int64
	flush := func() {
		if current == nil {
			return
		}
		current.LastHandshake = handshakeSec
		current.Current = handshakeSec > 0 && now.Sub(time.Unix(handshakeSec, 0)) < wireguard.HandshakeFreshness
		status.Peers = append(status.Peers, *current)
		current = nil
		handshakeSec = 0
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			status.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			flush()
			current = &wireguard.PeerStats{PublicKey: keyBase64(value)}
		case "endpoint":
			if current != nil {
				current.Endpoint = value
			}
		case "last_handshake_time_sec":
			handshakeSec, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			if current != nil {
				current.TransferRxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.TransferTxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		}
	}
	flush()
	return status
}

// Down closes the device, which also closes the TUN file descriptor and the
// UDP sockets. The manager can be brought up again with a new TUN.
func (m *Manager) Down(context.Context) error {
	m.mu.Lock()
	dev := m.dev
	m.dev = nil
	m.peers = make(map[string]wireguard.PeerConfig)
	m.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	return nil
}
