//go:build libp2pdht

package nat

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	libnat "github.com/libp2p/go-libp2p/p2p/net/nat"
)

// RouterCandidates maps the actual dynamically assigned WG UDP port. Mapping
// discovery and renewal never block signaling or candidate gathering.
type routerGateway interface {
	AddMapping(context.Context, string, int) error
	RemoveMapping(context.Context, string, int) error
	GetMapping(string, int) (netip.AddrPort, bool)
	Close() error
}

type RouterCandidates struct {
	interval time.Duration
	discover func(context.Context) (routerGateway, error)
	inner    CandidateProvider
	port     func(context.Context) (int, error)
	logger   *slog.Logger
	endpoint atomic.Pointer[netip.AddrPort]
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewRouterCandidates(ctx context.Context, inner CandidateProvider, port func(context.Context) (int, error), logger *slog.Logger) (CandidateProvider, io.Closer) {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &RouterCandidates{inner: inner, port: port, logger: logger, cancel: cancel, done: make(chan struct{}), discover: func(ctx context.Context) (routerGateway, error) { return libnat.DiscoverNAT(ctx) }}
	go r.run(ctx)
	return r, r
}

func (r *RouterCandidates) Gather(ctx context.Context) ([]EndpointCandidate, PortMapping, error) {
	candidates, mapping, err := r.inner.Gather(ctx)
	if address := r.endpoint.Load(); address != nil && address.IsValid() {
		now := time.Now()
		candidate := EndpointCandidate{Type: CandidateMapped, IP: address.Addr().String(), Port: address.Port(), Protocol: "udp", Priority: 1100, ObservedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
		candidates = append([]EndpointCandidate{candidate}, candidates...)
		if len(candidates) > MaxCandidates {
			candidates = candidates[:MaxCandidates]
		}
		mapping.PublicIP = address.Addr()
		return candidates, mapping, nil
	}
	return candidates, mapping, err
}

func (r *RouterCandidates) run(ctx context.Context) {
	defer close(r.done)
	var router routerGateway
	defer func() {
		r.endpoint.Store(nil)
		if router != nil {
			_ = router.Close()
		}
	}()
	currentPort := 0
	interval := r.interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		operation, cancel := context.WithTimeout(ctx, 5*time.Second)
		if router == nil {
			var err error
			router, err = r.discover(operation)
			if err != nil && ctx.Err() == nil {
				r.logger.Debug("router mapping unavailable; ICE retained", "component", "nat", "error", err)
			}
		}
		if router != nil {
			port, err := r.port(operation)
			if err == nil && port > 0 && port <= 65535 {
				if port != currentPort {
					r.endpoint.Store(nil)
					if router.AddMapping(operation, "udp", port) == nil {
						if currentPort > 0 {
							_ = router.RemoveMapping(operation, "udp", currentPort)
						}
						currentPort = port
					}
				}
				if port != currentPort {
					r.endpoint.Store(nil)
				} else if mapped, ok := router.GetMapping("udp", currentPort); ok && publicRouterIP(mapped.Addr()) {
					r.endpoint.Store(&mapped)
				} else {
					r.endpoint.Store(nil)
				}
			} else {
				r.endpoint.Store(nil)
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *RouterCandidates) Close() error { r.cancel(); <-r.done; return nil }

func publicRouterIP(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
