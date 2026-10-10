package wireguard

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type overlapRunner struct {
	Runner
	active, overlap atomic.Int32
}

func (r *overlapRunner) Run(context.Context, string, ...string) (string, error) {
	if r.active.Add(1) != 1 {
		r.overlap.Add(1)
	}
	time.Sleep(time.Millisecond)
	r.active.Add(-1)
	return "", nil
}
func TestPeerMutationsAndStatsSerializeKernelCommands(t *testing.T) {
	r := &overlapRunner{}
	m := NewLinuxManagerWithRunner(nil, "nkg0", r)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_ = m.UpdateEndpoint(context.Background(), "key", "192.0.2.1:1234")
			case 1:
				_ = m.RemovePeer(context.Background(), "key")
			case 2:
				_, _ = m.Stats(context.Background())
			}
		}(i)
	}
	wg.Wait()
	if r.overlap.Load() != 0 {
		t.Fatal("concurrent kernel mutations observed")
	}
}
