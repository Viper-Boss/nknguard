package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestCancelWhileNKNOpening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := openControlPlane(ctx, func(ctx context.Context) (*ControlPlane, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup ignored disconnect")
	}
}

func TestCancelClosesPlaneThatArrivesTooLate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closed := false
	_, err := openControlPlane(ctx, func(context.Context) (*ControlPlane, error) {
		cancel()
		return &ControlPlane{Close: func() error { closed = true; return nil }}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !closed || !errors.Is(err, context.Canceled) {
		t.Fatalf("late plane leaked: %v, closed=%t", err, closed)
	}
}
