package app

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

// ErrNoNKN is what a binary built without the nknsdk tag reports when asked
// to run the daemon. The NKN transport is not optional for a working mesh —
// it is the signalling plane — so this is a hard stop with instructions, not
// a degraded mode.
var ErrNoNKN = errors.New("this nknguard binary was built without NKN support; rebuild with `make build` (go build -tags \"nknsdk libp2pdht\")")

// ControlPlane is everything the NKN side of the build provides.
type ControlPlane struct {
	Signaling  signaling.Transport
	Relay      relay.Relay
	Rendezvous rendezvous.Source
	Close      func() error
}

// controlPlaneFactory and discoveryFactory are set by build-tagged files.
// The default build leaves them nil, which the daemon turns into ErrNoNKN or
// "no DHT" respectively.
var (
	portMapperFactory   func(context.Context, nat.CandidateProvider, func(context.Context) (int, error), *slog.Logger) (nat.CandidateProvider, io.Closer)
	controlPlaneFactory func(ctx context.Context, cfg config.Config, keystore *identity.Keystore, key *membership.Key, logger *slog.Logger) (*ControlPlane, error)
	discoveryFactory    func(ctx context.Context, cfg config.Config, key *membership.Key, logger *slog.Logger) (discovery.Discovery, error)
	pairDeviceFactory   func(context.Context, config.Config, string, io.Writer) (PairResult, error)
)

type PairResult struct {
	NetworkID  string
	NASID      string
	NASAddress string
}

// PairDevice enrolls this device using an owner-approved QR invitation.
func PairDevice(ctx context.Context, cfg config.Config, invitation string, progress io.Writer) (PairResult, error) {
	if pairDeviceFactory == nil {
		return PairResult{}, ErrNoNKN
	}
	return pairDeviceFactory(ctx, cfg, invitation, progress)
}

// BuildFeatures reports which optional planes this binary contains.
func BuildFeatures() (nkn, dht bool) {
	return controlPlaneFactory != nil, discoveryFactory != nil
}
