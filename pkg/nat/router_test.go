//go:build libp2pdht

package nat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mappingRouter struct {
	mu       sync.Mutex
	mappings map[int]bool
	closed   bool
	fail     int
}

func (r *mappingRouter) AddMapping(_ context.Context, _ string, port int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if port == r.fail {
		return errors.New("router refused")
	}
	r.mappings[port] = true
	return nil
}
func (r *mappingRouter) RemoveMapping(_ context.Context, _ string, port int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.mappings, port)
	return nil
}
func (r *mappingRouter) GetMapping(_ string, port int) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(port)), r.mappings[port]
}
func (r *mappingRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	clear(r.mappings)
	return nil
}

type mappingBase struct{}

func (mappingBase) Gather(context.Context) ([]EndpointCandidate, PortMapping, error) {
	return nil, PortMapping{}, errors.New("STUN unavailable")
}
func TestRouterDynamicPortAndCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	router := &mappingRouter{mappings: make(map[int]bool), fail: 9999}
	var port atomic.Int32
	port.Store(40001)
	r := &RouterCandidates{interval: time.Millisecond * 5, inner: mappingBase{}, port: func(context.Context) (int, error) { return int(port.Load()), nil }, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cancel: cancel, done: make(chan struct{}), discover: func(context.Context) (routerGateway, error) { return router, nil }}
	go r.run(ctx)
	defer r.Close()
	wait := func(expected int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			a := r.endpoint.Load()
			if (expected == 0 && a == nil) || (a != nil && int(a.Port()) == expected) {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("expected mapping %d, got %v", expected, r.endpoint.Load())
	}
	wait(40001)
	candidates, _, err := r.Gather(ctx)
	if err != nil || len(candidates) != 1 || candidates[0].Type != CandidateMapped {
		t.Fatal("mapping did not survive STUN failure", candidates, err)
	}
	port.Store(40002)
	wait(40002)
	router.mu.Lock()
	old := router.mappings[40001]
	router.mu.Unlock()
	if old {
		t.Fatal("old dynamic port still mapped")
	}
	port.Store(9999)
	wait(0) // never advertise the old mapping for a new failed port.
	port.Store(40003)
	wait(40003)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if !router.closed || len(router.mappings) != 0 {
		t.Fatal("mapping cleanup failed")
	}
}
func TestRouterRejectsUpstreamCGNAT(t *testing.T) {
	for _, text := range []string{"100.64.0.1", "192.168.1.1", "10.0.0.1", "::1", "fd00::1", "0.0.0.0"} {
		if publicRouterIP(netip.MustParseAddr(text)) {
			t.Fatal("non-public router mapping accepted", text)
		}
	}
}

func TestRouterDiscoveryCancellationDoesNotUseTypedNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	r := &RouterCandidates{inner: mappingBase{}, port: func(context.Context) (int, error) { t.Error("port queried after failed discovery"); return 0, nil }, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cancel: cancel, done: make(chan struct{}), discover: func(ctx context.Context) (routerGateway, error) {
		close(entered)
		<-ctx.Done()
		var typedNil *mappingRouter
		return typedNil, ctx.Err()
	}}
	go r.run(ctx)
	<-entered
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.endpoint.Load() != nil {
		t.Fatal("failed discovery advertised an endpoint")
	}
}
