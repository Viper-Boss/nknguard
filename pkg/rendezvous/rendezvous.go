// Package rendezvous answers one question: "what transport addresses might
// belong to members of my network?"
//
// It is deliberately weaker than discovery. A rendezvous source returns bare
// addresses, not records, and nothing it returns is trusted: the controller
// sends each address a signed PEER_INFO introduction, and only a reply carrying
// a valid signed record and membership proof creates a peer. So a rendezvous
// source can be a public NKN topic, a hand-written list, or a QR code, and a
// hostile one can waste a few messages but cannot add a peer.
package rendezvous

import (
	"context"
	"strings"
)

// Source is a rendezvous mechanism.
type Source interface {
	// Announce makes this node findable. Implementations rate-limit
	// themselves: the controller calls it on every tick.
	Announce(ctx context.Context) error
	// Addresses returns candidate transport addresses, possibly including
	// this node's own.
	Addresses(ctx context.Context) ([]string, error)
	Close() error
}

// Static is a fixed address list, from the config file's
// discovery.static_peers. It is the zero-infrastructure option: two nodes that
// have each other's NKN address need nothing else at all.
type Static []string

// Announce does nothing; a static list has nobody to tell.
func (Static) Announce(context.Context) error { return nil }

// Addresses returns the list with blanks removed.
func (s Static) Addresses(context.Context) ([]string, error) {
	out := make([]string, 0, len(s))
	for _, address := range s {
		if address = strings.TrimSpace(address); address != "" {
			out = append(out, address)
		}
	}
	return out, nil
}

// Close does nothing.
func (Static) Close() error { return nil }

// Multi combines sources. An error from one does not hide the others'
// results, because the whole point of having several is that some are down.
type Multi []Source

// Announce announces on every source and returns the first error.
func (m Multi) Announce(ctx context.Context) error {
	var first error
	for _, source := range m {
		if err := source.Announce(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Addresses merges and de-duplicates every source's addresses.
func (m Multi) Addresses(ctx context.Context) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	var first error
	for _, source := range m {
		addresses, err := source.Addresses(ctx)
		if err != nil && first == nil {
			first = err
		}
		for _, address := range addresses {
			if _, dup := seen[address]; !dup {
				seen[address] = struct{}{}
				out = append(out, address)
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	return nil, first
}

// Close closes every source.
func (m Multi) Close() error {
	var first error
	for _, source := range m {
		if err := source.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
