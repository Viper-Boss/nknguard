package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/backoff"
)

// openControlPlane retries independently of cached WireGuard connections.
// The early local API cancels ctx even while the NKN factory is opening.
func openControlPlane(ctx context.Context, open func(context.Context) (*ControlPlane, error), logger *slog.Logger) (*ControlPlane, error) {
	retry := backoff.Policy{Initial: 2 * time.Second, Max: time.Minute}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		plane, err := open(ctx)
		if err == nil {
			if ctx.Err() != nil {
				_ = plane.Close()
				return nil, ctx.Err()
			}
			return plane, nil
		}
		logger.Warn("NKN unavailable; cached direct paths remain active", "error", err)
		timer := time.NewTimer(retry.Delay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
