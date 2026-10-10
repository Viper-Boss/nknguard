//go:build libp2pdht

package app

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/discovery/dht"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nat"
)

func init() { discoveryFactory = openDHT; portMapperFactory = nat.NewRouterCandidates }

func openDHT(ctx context.Context, cfg config.Config, key *membership.Key, logger *slog.Logger) (discovery.Discovery, error) {
	return dht.Open(ctx, dht.Options{
		StateDir:       filepath.Join(cfg.Paths.StateDir, "dht"),
		BootstrapPeers: cfg.Discovery.BootstrapPeers,
		LANDiscovery:   cfg.Discovery.LANDiscovery,
		Rendezvous:     key.Rendezvous(),
		Logger:         logger,
		MapPorts:       cfg.NAT.PortMapping,
	})
}
