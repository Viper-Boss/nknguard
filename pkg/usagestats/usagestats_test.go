package usagestats

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeChain struct {
	mu           sync.Mutex
	subscribed   map[string]int
	subscribes   []string
	unsubscribes []string
	failTopic    string
	counts       map[string]int
	countCalls   int
	countErr     error
}

func newFakeChain() *fakeChain {
	return &fakeChain{subscribed: map[string]int{}, counts: map[string]int{}}
}

func (f *fakeChain) Subscribe(_ context.Context, topic string, blocks int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if topic == f.failTopic {
		return errors.New("not confirmed")
	}
	f.subscribed[topic] = blocks
	f.subscribes = append(f.subscribes, topic)
	return nil
}

func (f *fakeChain) Unsubscribe(_ context.Context, topic string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.subscribed, topic)
	f.unsubscribes = append(f.unsubscribes, topic)
	return nil
}

func (f *fakeChain) Count(_ context.Context, topic string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.countCalls++
	if f.countErr != nil {
		return 0, f.countErr
	}
	return f.counts[topic], nil
}

func (f *fakeChain) Address() string { return "0123abcd" }

func TestWindowsCoverTheirSpan(t *testing.T) {
	seen := map[string]bool{}
	for _, window := range Windows {
		if seen[window.Topic] {
			t.Fatalf("duplicate topic %s", window.Topic)
		}
		seen[window.Topic] = true
		duration := time.Duration(window.Blocks) * BlockTime
		if guaranteed := duration - RenewInterval; guaranteed < window.Span {
			t.Errorf("%s guarantees %v, advertised %v", window.Topic, guaranteed, window.Span)
		}
		if window.Blocks > MaxBlocks {
			t.Errorf("%s exceeds NKN's maximum duration", window.Topic)
		}
		if len(window.Topic) < len("nknguard.") || window.Topic[:len("nknguard.")] != "nknguard." {
			t.Errorf("%s is not an NKNGuard topic", window.Topic)
		}
	}
}

func TestDeriveSeed(t *testing.T) {
	a := DeriveSeed(bytes.Repeat([]byte{1}, 32))
	b := DeriveSeed(bytes.Repeat([]byte{1}, 32))
	c := DeriveSeed(bytes.Repeat([]byte{2}, 32))
	if len(a) != 32 || !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("seed derivation is not a stable 32-byte function of its input")
	}
	if bytes.Equal(a, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("derived seed equals the NKN seed")
	}
}

func TestCheckInRenewsDailyAndPersists(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "usage-stats.json")
	chain := newFakeChain()
	r := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	if !r.checkIn(context.Background()) || len(chain.subscribes) != len(Windows) {
		t.Fatalf("first check-in: %v", chain.subscribes)
	}
	for _, window := range Windows {
		if chain.subscribed[window.Topic] != window.Blocks {
			t.Fatalf("%s subscribed for %d blocks", window.Topic, chain.subscribed[window.Topic])
		}
	}
	// Within a day nothing is due, also after a restart.
	now = now.Add(23 * time.Hour)
	again := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	again.checkIn(context.Background())
	if len(chain.subscribes) != len(Windows) {
		t.Fatalf("renewed too early: %v", chain.subscribes)
	}
	now = now.Add(2 * time.Hour)
	again.checkIn(context.Background())
	if len(chain.subscribes) != 2*len(Windows) {
		t.Fatalf("not renewed after a day: %v", chain.subscribes)
	}
}

func TestFailedWindowIsRetriedAlone(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	chain := newFakeChain()
	chain.failTopic = Windows[1].Topic
	r := &Reporter{Chain: chain, Path: filepath.Join(t.TempDir(), "s.json"), DefaultEnabled: true, Now: func() time.Time { return now }}
	if r.checkIn(context.Background()) {
		t.Fatal("failure not reported")
	}
	if status := r.Status(context.Background(), false); status.LastError == "" {
		t.Fatal("error not shown")
	}
	chain.failTopic = ""
	chain.subscribes = nil
	if !r.checkIn(context.Background()) {
		t.Fatal("retry failed")
	}
	if len(chain.subscribes) != 1 || chain.subscribes[0] != Windows[1].Topic {
		t.Fatalf("retry renewed %v, want only the failed window", chain.subscribes)
	}
}

func TestDisableUnsubscribesAndStops(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "usage-stats.json")
	chain := newFakeChain()
	r := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	r.checkIn(context.Background())
	if err := r.SetEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(chain.unsubscribes) != len(Windows) || len(chain.subscribed) != 0 {
		t.Fatalf("not unsubscribed: %v", chain.unsubscribes)
	}
	// The choice survives a restart and overrides the default.
	restarted := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	if restarted.Enabled() {
		t.Fatal("disabled choice lost")
	}
	// Enabling again checks in at once, not after a day.
	if err := restarted.SetEnabled(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	chain.subscribes = nil
	restarted.checkIn(context.Background())
	if len(chain.subscribes) != len(Windows) {
		t.Fatalf("re-enabled check-in: %v", chain.subscribes)
	}
}

func TestDefaultOff(t *testing.T) {
	r := &Reporter{Chain: newFakeChain(), Path: filepath.Join(t.TempDir(), "s.json")}
	if r.Enabled() {
		t.Fatal("enabled without default or choice")
	}
}

func TestCountsCached(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	chain := newFakeChain()
	chain.counts = map[string]int{Windows[0].Topic: 3, Windows[1].Topic: 10, Windows[2].Topic: 42}
	r := &Reporter{Chain: chain, DefaultEnabled: true, Now: func() time.Time { return now }}
	counts := r.Counts(context.Background(), false)
	if counts.Day == nil || *counts.Day != 3 || *counts.Month != 10 || *counts.Quarter != 42 || counts.Error != "" {
		t.Fatalf("counts = %+v", counts)
	}
	calls := chain.countCalls
	now = now.Add(time.Minute)
	r.Counts(context.Background(), false)
	if chain.countCalls != calls {
		t.Fatal("cache not used")
	}
	r.Counts(context.Background(), true)
	if chain.countCalls == calls {
		t.Fatal("forced refresh ignored")
	}
	calls = chain.countCalls
	now = now.Add(time.Second)
	r.Counts(context.Background(), true)
	if chain.countCalls != calls {
		t.Fatal("forced refreshes not rate limited")
	}
}

func TestCountsFailureIsNotZero(t *testing.T) {
	chain := newFakeChain()
	chain.countErr = errors.New("no seed answered")
	r := &Reporter{Chain: chain}
	counts := r.Counts(context.Background(), false)
	if counts.Day != nil || counts.Month != nil || counts.Quarter != nil || counts.Error == "" {
		t.Fatalf("failed query reported as %+v", counts)
	}
	// Nothing answered, so the next read tries again.
	r.Counts(context.Background(), false)
	if chain.countCalls != 2*len(Windows) {
		t.Fatalf("failed result cached: %d calls", chain.countCalls)
	}
}

func TestNoChain(t *testing.T) {
	r := &Reporter{DefaultEnabled: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Run(ctx) // returns at once
	if status := r.Status(context.Background(), false); status.Counts.Error == "" {
		t.Fatal("missing NKN support not reported")
	}
}

func TestSharedFileKeepsTheOtherProcessChoice(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "usage-stats.json")
	chain := newFakeChain()
	service := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	window := &Reporter{Chain: chain, Path: path, DefaultEnabled: true, Now: func() time.Time { return now }}
	service.checkIn(context.Background())
	if err := window.SetEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	chain.subscribes = nil
	now = now.Add(48 * time.Hour)
	service.checkIn(context.Background())
	if len(chain.subscribes) != 0 || service.Enabled() {
		t.Fatalf("the other process ignored the switch: %v", chain.subscribes)
	}
}
