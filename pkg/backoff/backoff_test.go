package backoff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDelayGrowsCapsAndJitters(t *testing.T) {
	policy := Policy{Initial: time.Second, Max: 30 * time.Second, Factor: 2, Jitter: 0.25}
	for attempt := 0; attempt < 20; attempt++ {
		delay := policy.Delay(attempt)
		if delay > time.Duration(float64(30*time.Second)*1.25) {
			t.Fatalf("attempt %d delay %s exceeds cap", attempt, delay)
		}
	}
	first := policy.Delay(0)
	if first < 750*time.Millisecond || first > 1250*time.Millisecond {
		t.Fatalf("first delay %s outside jitter band", first)
	}
	distinct := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		distinct[policy.Delay(3)] = true
	}
	if len(distinct) < 2 {
		t.Fatal("delays are not jittered — every node would retry in lockstep")
	}
}

func TestRetryStopsOnCancelAndOnLimit(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	err := Retry(context.Background(), Policy{Initial: time.Millisecond, MaxAttempts: 3}, func(context.Context) error { calls++; return boom })
	if !errors.Is(err, boom) || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_ = Retry(ctx, Policy{Initial: time.Hour}, func(context.Context) error { return boom })
	if time.Since(started) > time.Second {
		t.Fatal("retry ignored a cancelled context")
	}
}
