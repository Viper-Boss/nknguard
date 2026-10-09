package app

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
)

// UsageStatsFile holds legacy preferences and last check-ins (no secrets).
const UsageStatsFile = "usage-stats.json"

// usageSeed returns the device's NKN seed; set by the nknsdk build.
var usageSeed func(keystore *identity.Keystore) ([]byte, error)

// NewUsageReporter builds the anonymous usage-statistics reporter for a node.
// In a build without NKN support it reports the counts as unavailable and
// sends nothing.
func NewUsageReporter(cfg config.Config, keystore *identity.Keystore, logger *slog.Logger) *usagestats.Reporter {
	reporter := &usagestats.Reporter{
		Path:           filepath.Join(cfg.Paths.StateDir, UsageStatsFile),
		DefaultEnabled: true,
		AlwaysEnabled:  true,
		Logger:         logger,
	}
	if usageSeed == nil {
		return reporter
	}
	seed, err := usageSeed(keystore)
	if err != nil {
		if logger != nil {
			logger.Warn("usage statistics unavailable", "component", "usage", "error", err)
		}
		return reporter
	}
	chain, err := usagestats.NewNKNChain(seed, cfg.NKN.SeedRPC)
	if err != nil {
		if logger != nil {
			logger.Warn("usage statistics unavailable", "component", "usage", "error", err)
		}
		return reporter
	}
	reporter.Chain = chain
	return reporter
}

// usageStatus is what the dashboard shows.
func (d *Daemon) usageStatus(ctx context.Context, force bool) usagestats.Status {
	if d.Usage == nil {
		return usagestats.Status{Counts: usagestats.Counts{Error: usagestats.ErrUnavailable.Error()}}
	}
	return d.Usage.Status(ctx, force)
}
