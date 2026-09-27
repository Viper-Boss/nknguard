// Package wireguard configures the data plane.
//
// NKNGuard does not implement WireGuard. It creates an interface, installs
// peers, and updates endpoints; the cryptography, the handshake and the
// transport are WireGuard's, which is the whole reason to use it. If this
// package ever grows a function that encrypts a packet, something has gone
// badly wrong.
package wireguard

import (
	"context"
	"errors"
	"time"
)

// HandshakeFreshness is how long a handshake stays meaningful. WireGuard
// rekeys roughly every two minutes, so silence beyond three means the path is
// gone even though the interface is still up and the peer is still listed.
const HandshakeFreshness = 3 * time.Minute

// State is what the interface is actually doing. Every value is a thing a real
// machine can be in; there is no "connected" that is inferred rather than
// observed.
type State string

const (
	// StateUnsupported means the kernel cannot do WireGuard at all.
	StateUnsupported State = "unsupported"
	// StateToolsMissing means the kernel may be fine but wg or ip is absent.
	StateToolsMissing State = "tools_missing"
	// StateDisabled means WireGuard is switched off in configuration.
	StateDisabled State = "disabled"
	// StateDown means it should be up but the interface does not exist.
	StateDown State = "down"
	// StateUp means the interface exists and carries the configured peers.
	StateUp State = "up"
	// StateError means applying configuration failed; Error says why.
	StateError State = "error"
)

// ErrNotSupported is returned by the manager for the current platform when it
// cannot manage an interface here.
var ErrNotSupported = errors.New("wireguard: not supported on this platform")

// PeerConfig is one counterpart. Endpoint may be empty, which is the normal
// case for a peer behind NAT that has to reach us first.
type PeerConfig struct {
	DeviceID            string   `json:"device_id"`
	Name                string   `json:"name,omitempty"`
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// InterfaceConfig is everything needed to bring the interface up. It carries
// no private key on purpose: the key lives in the keystore and is read at
// apply time, so this struct can be logged and returned from the local API.
type InterfaceConfig struct {
	Name       string       `json:"name"`
	Address    string       `json:"address"`
	ListenPort int          `json:"listen_port"`
	MTU        int          `json:"mtu,omitempty"`
	Peers      []PeerConfig `json:"peers"`
	Revision   int64        `json:"revision"`
}

// PeerStats is what the running interface reports back. It never carries key
// material beyond the public key, which is not secret.
type PeerStats struct {
	DeviceID        string `json:"device_id,omitempty"`
	Name            string `json:"name,omitempty"`
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint,omitempty"`
	LastHandshake   int64  `json:"last_handshake_unix,omitempty"`
	TransferRxBytes int64  `json:"transfer_rx_bytes"`
	TransferTxBytes int64  `json:"transfer_tx_bytes"`
	// Current reports whether the last handshake is inside HandshakeFreshness.
	// It is the single most useful field in the struct: it is the difference
	// between a peer that is configured and a peer that is working.
	Current bool `json:"current"`
}

// Status is the interface as a whole.
type Status struct {
	State      State       `json:"state"`
	Interface  string      `json:"interface,omitempty"`
	PublicKey  string      `json:"public_key,omitempty"`
	ListenPort int         `json:"listen_port,omitempty"`
	Address    string      `json:"address,omitempty"`
	Peers      []PeerStats `json:"peers,omitempty"`
	Revision   int64       `json:"revision,omitempty"`
	Error      string      `json:"error,omitempty"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// Manager is the data-plane contract the mesh controller depends on. Keeping
// it an interface is what lets the controller be tested without root, a
// kernel module, or a TUN device.
type Manager interface {
	// Supported reports what this host can do before anything is attempted,
	// so `nknguard doctor` can answer honestly on a machine where the tunnel
	// will never come up.
	Supported(ctx context.Context) (State, string)
	// PublicKey returns the interface public key, generating the private half
	// on first use and storing it 0600.
	PublicKey(ctx context.Context) (string, error)
	// EnsureInterface makes the running interface match cfg.
	EnsureInterface(ctx context.Context, cfg InterfaceConfig) error
	// AddPeer installs or replaces one peer.
	AddPeer(ctx context.Context, peer PeerConfig) error
	// UpdateEndpoint moves an existing peer to a new endpoint. This is the hot
	// path for roaming: it must not tear the tunnel down.
	UpdateEndpoint(ctx context.Context, publicKey, endpoint string) error
	// RemovePeer drops a peer.
	RemovePeer(ctx context.Context, publicKey string) error
	// Stats reads the live counters.
	Stats(ctx context.Context) ([]PeerStats, error)
	// Status is Stats plus the interface-level view.
	Status(ctx context.Context) Status
	// Down removes the interface.
	Down(ctx context.Context) error
}
