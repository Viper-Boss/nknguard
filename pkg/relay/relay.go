// Package relay is the fallback data path.
//
// Its job is "connected at all", not "connected fast". Relayed traffic crosses
// somebody else's machine and pays for it in throughput and latency, so the
// mesh controller keeps looking for a direct path the whole time a relay is
// carrying a peer, and WireGuard moves back on its own the moment a direct
// handshake arrives.
//
// The mechanism: WireGuard does not know it is being relayed. Its endpoint for
// the peer is set to a Bridge on 127.0.0.1, and the Bridge frames WireGuard's
// datagrams into a stream that the relay transport (an NKN session in
// production) carries to the peer's Bridge, which hands them to the peer's
// WireGuard. The traffic is still end-to-end WireGuard-encrypted; the relay
// sees ciphertext and sizes.
//
// Nothing in this package is a default. A build where every peer ends up on
// the relay is a broken build, not a working one.
package relay

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrNoRelay means no relay transport is configured or reachable.
var ErrNoRelay = errors.New("relay: no relay transport available")

// Stats is what the mesh reports about a relayed peer.
type Stats struct {
	Open      bool      `json:"open"`
	Standby   bool      `json:"standby"`
	OpenedAt  time.Time `json:"opened_at,omitempty"`
	BytesSent int64     `json:"bytes_sent"`
	BytesRecv int64     `json:"bytes_received"`
	LastError string    `json:"last_error,omitempty"`
}

// Peer is the addressing a relay needs. It is intentionally not the mesh's
// peer type: the relay does not need WireGuard keys or virtual IPs, and giving
// it them would invite it to make decisions that are not its.
type Peer struct {
	DeviceID string
	Address  string
}

// Relay opens a stream to a peer through an intermediary.
type Relay interface {
	Open(ctx context.Context, peer Peer) (net.Conn, error)
}

// Session is an inbound relayed stream, already attributed to a device by the
// transport. Attribution is a hint: the controller still checks membership,
// and WireGuard still authenticates every packet inside.
type Session struct {
	DeviceID string
	Conn     net.Conn
}

// Acceptor is implemented by relays that can receive sessions.
type Acceptor interface {
	Accept(ctx context.Context) (Session, error)
}
