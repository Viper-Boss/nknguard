//go:build nknsdk

package mobile

import (
	"context"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/relay/nknrelay"
	"github.com/Viper-Boss/nknguard/pkg/signaling/nknsignal"
)

func init() { DefaultPlaneFactory = openNKN }

// openNKN opens the same MultiClient, signalling transport and ncp relay the
// daemon uses. The phone does not join the NKN pub/sub topic or the private
// DHT: the NAS address pinned at pairing time is its rendezvous, and the NAS
// answers the introduction with its current signed record.
func openNKN(ctx context.Context, seed []byte, seedRPC []string) (*Plane, error) {
	client, err := nknclient.Open(ctx, nknclient.Options{Seed: seed, SeedRPC: seedRPC})
	if err != nil {
		return nil, err
	}
	transport := nknsignal.New(client)
	transport.StartHealthMonitor()
	return &Plane{
		Signaling: transport,
		Relay:     nknrelay.New(client, transport.DeviceFor),
		Close:     transport.Close,
		Health:    transport.ConnectionStatus,
	}, nil
}
