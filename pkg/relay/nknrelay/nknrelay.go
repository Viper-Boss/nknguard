//go:build nknsdk

// Package nknrelay carries relayed WireGuard traffic over NKN sessions.
//
// A session is nkn-sdk-go's reliable stream over the NKN overlay (ncp). The
// bridge in pkg/relay frames WireGuard datagrams into it; this package only
// opens and accepts sessions and attributes inbound ones to a device. It is
// the part of nkn-tunnel's job NKNGuard needs, reused from the SDK rather
// than reimplemented.
package nknrelay

import (
	"context"
	"errors"
	"net"
	"sync"

	nkn "github.com/nknorg/nkn-sdk-go"

	"github.com/Viper-Boss/nknguard/pkg/relay"
)

// Resolver maps an NKN address to a verified device.
type Resolver func(address string) (deviceID string, ok bool)

// Relay implements relay.Relay and relay.Acceptor.
type Relay struct {
	client   *nkn.MultiClient
	resolve  Resolver
	listenMu sync.Once
	listenEr error
}

// New returns a relay over client. resolve attributes inbound sessions;
// sessions from addresses it does not know are closed immediately.
func New(client *nkn.MultiClient, resolve Resolver) *Relay {
	return &Relay{client: client, resolve: resolve}
}

func (r *Relay) listen() error {
	r.listenMu.Do(func() { r.listenEr = r.client.Listen(nil) })
	return r.listenEr
}

// Open dials a session to the peer's NKN address.
func (r *Relay) Open(ctx context.Context, peer relay.Peer) (net.Conn, error) {
	if peer.Address == "" {
		return nil, relay.ErrNoRelay
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		session, err := r.client.Dial(peer.Address)
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{conn: session}
	}()
	select {
	case out := <-done:
		return out.conn, out.err
	case <-ctx.Done():
		// The dial goroutine finishes on its own; if it succeeds late, the
		// session is closed rather than leaked.
		go func() {
			if out := <-done; out.conn != nil {
				_ = out.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// Accept returns the next inbound session from a known device.
func (r *Relay) Accept(ctx context.Context) (relay.Session, error) {
	if err := r.listen(); err != nil {
		return relay.Session{}, err
	}
	for {
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			conn, err := r.client.Accept()
			done <- result{conn: conn, err: err}
		}()
		var out result
		select {
		case out = <-done:
		case <-ctx.Done():
			return relay.Session{}, ctx.Err()
		}
		if out.err != nil {
			return relay.Session{}, out.err
		}
		device, ok := r.resolve(out.conn.RemoteAddr().String())
		if !ok {
			_ = out.conn.Close()
			continue
		}
		return relay.Session{DeviceID: device, Conn: out.conn}, nil
	}
}

// ErrClosed is returned after the client is gone.
var ErrClosed = errors.New("nknrelay: client closed")
