package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
)

// A missing API during startup is not proof that the child process exited.
// After a stop ACK, the API remains alive until WireGuard cleanup completes.
func waitForClientStop(ctx context.Context, exited func() (bool, error), down func() error) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("后台尚未确认退出，请重试断开: %w", ctx.Err())
		}
		done, err := exited()
		if err != nil {
			return err
		}
		err = down()
		if errors.Is(err, app.ErrDaemonNotRunning) && done {
			return nil
		}
		if err != nil && !errors.Is(err, app.ErrDaemonNotRunning) {
			return err
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}
