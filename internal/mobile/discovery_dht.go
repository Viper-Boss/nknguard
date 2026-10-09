//go:build libp2pdht

package mobile

import (
	"context"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/discovery/dht"
	"path/filepath"
)

func init() {
	mobileDiscovery = func(ctx context.Context, s *session) (discovery.Discovery, error) {
		key, err := s.agent.membershipKey(s.profile)
		if err != nil {
			return nil, err
		}
		return dht.Open(ctx, dht.Options{StateDir: filepath.Join(s.agent.StateDir, "dht"),
			Rendezvous: key.Rendezvous(), LANDiscovery: true, Logger: s.agent.Logger, ClientMode: true})
	}
}
