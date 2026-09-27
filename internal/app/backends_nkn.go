//go:build nknsdk

package app

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"log/slog"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/relay/nknrelay"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous/nkntopic"
	"github.com/Viper-Boss/nknguard/pkg/signaling/nknsignal"
)

func init() {
	controlPlaneFactory = openNKN
	usageSeed = nknSeed
}

func nknSeed(keystore *identity.Keystore) ([]byte, error) {
	seed, err := keystore.ReadSecret(nknclient.SeedName)
	if err == nil && len(seed) == 32 {
		return seed, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, keystore.WriteSecret(nknclient.SeedName, seed)
}

func openNKN(ctx context.Context, cfg config.Config, keystore *identity.Keystore, key *membership.Key, logger *slog.Logger) (*ControlPlane, error) {
	seed, err := nknSeed(keystore)
	if err != nil {
		return nil, err
	}
	client, err := nknclient.Open(ctx, nknclient.Options{Seed: seed, SeedRPC: cfg.NKN.SeedRPC})
	if err != nil {
		return nil, err
	}
	transport := nknsignal.New(client)
	sources := rendezvous.Multi{rendezvous.Static(cfg.Discovery.StaticPeers)}
	if cfg.Discovery.NKNTopic {
		sources = append(sources, nkntopic.New(client, key.Rendezvous(), nknclient.SeedRPCList(cfg.NKN.SeedRPC)))
	}
	plane := &ControlPlane{
		Signaling:  transport,
		Rendezvous: sources,
		Close: func() error {
			_ = sources.Close()
			return transport.Close()
		},
	}
	if cfg.Relay.NKNEnabled {
		plane.Relay = nknrelay.New(client, transport.DeviceFor)
	}
	logger.Info("connected to NKN", "component", "signaling", "address", transport.LocalAddress())
	return plane, nil
}
