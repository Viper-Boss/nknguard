//go:build libp2pdht

package dht

import (
	"context"
	"encoding/json"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"os"
	"path/filepath"
	"time"
)

type bootstrapHint struct {
	Peer      string    `json:"peer"`
	Addresses []string  `json:"addresses"`
	Seen      time.Time `json:"seen"`
}

func (b *Backend) rememberBootstrap(id peer.ID, addresses []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.publicHints) >= 8 && b.publicHints[id].Peer == "" {
		for candidate := range b.publicHints {
			if b.host.Network().Connectedness(candidate) != network.Connected {
				delete(b.publicHints, candidate)
				break
			}
		}
	}
	if len(b.publicHints) >= 8 && b.publicHints[id].Peer == "" {
		return
	}
	b.publicHints[id] = bootstrapHint{id.String(), append([]string(nil), addresses...), time.Now().UTC()}
	b.saveBootstrapHintsLocked()
}

func (b *Backend) saveBootstrapHintsLocked() {
	var hints []bootstrapHint
	for id, hint := range b.publicHints {
		if b.host.Network().Connectedness(id) == network.Connected {
			hint.Seen = time.Now().UTC()
			b.publicHints[id] = hint
		}
		hints = append(hints, hint)
	}
	raw, _ := json.Marshal(hints)
	f, err := os.CreateTemp(b.opts.StateDir, ".bootstrap-*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	_ = f.Chmod(0600)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		_ = os.Rename(f.Name(), filepath.Join(b.opts.StateDir, "bootstrap-cache.json"))
	}
}

func (b *Backend) restoreBootstrapHints(ctx context.Context) {
	raw, err := os.ReadFile(filepath.Join(b.opts.StateDir, "bootstrap-cache.json"))
	var hints []bootstrapHint
	if err == nil && len(raw) < 65536 && json.Unmarshal(raw, &hints) == nil && len(hints) <= 8 {
		for _, hint := range hints {
			id, err := peer.Decode(hint.Peer)
			if err != nil || len(hint.Addresses) == 0 || len(hint.Addresses) > 8 || time.Since(hint.Seen) > 7*24*time.Hour || time.Until(hint.Seen) > time.Minute {
				continue
			}
			valid := true
			for _, address := range hint.Addresses {
				if !publicBootstrapAddress(address, id) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			// A cache is a dial hint only. libp2p must prove this peer ID again;
			// this cannot grant membership or permit private-record access.
			b.ConnectPeer(ctx, hint.Addresses)
			if b.host.Network().Connectedness(id) == network.Connected {
				b.mu.Lock()
				b.publicPeers[id] = true
				b.mu.Unlock()
				b.rememberBootstrap(id, hint.Addresses)
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			if len(b.publicHints) > 0 {
				b.saveBootstrapHintsLocked()
			}
			b.mu.Unlock()
		}
	}
}
