package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
)

func TestDisconnectWaitsThroughStartupAndCleanup(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := waitForClientStop(ctx, func() (bool, error) { return calls >= 3, nil }, func() error {
		calls++
		switch calls {
		case 1:
			return app.ErrDaemonNotRunning // Starting, not exited.
		case 2, 3:
			return nil // Stop ACK; cleanup still owns the API.
		default:
			return app.ErrDaemonNotRunning
		}
	})
	if err != nil || calls != 4 {
		t.Fatalf("stop returned after %d probes: %v", calls, err)
	}
}

func TestDisconnectDoesNotClaimSuccessForStalledChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitForClientStop(ctx, func() (bool, error) { return false, nil }, func() error { return app.ErrDaemonNotRunning })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing API was treated as exited: %v", err)
	}
}
