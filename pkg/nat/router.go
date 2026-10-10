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
	status   atomic.Pointer[RouterMappingStatus]
	cancel   context.CancelFunc
	done     chan struct{}
}

func (r *RouterCandidates) MappingStatus() RouterMappingStatus {
	if s := r.status.Load(); s != nil {
		return *s
	}
	return RouterMappingStatus{State: "discovering", Message: "正在发现路由器映射服务"}
}
func (r *RouterCandidates) setStatus(state, message string, port int, endpoint string) {
	r.status.Store(&RouterMappingStatus{State: state, Message: message, InternalPort: port, Endpoint: endpoint})
}

func NewRouterCandidates(ctx context.Context, inner CandidateProvider, port func(context.Context) (int, error), logger *slog.Logger) (CandidateProvider, io.Closer) {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &RouterCandidates{inner: inner, port: port, logger: logger, cancel: cancel, done: make(chan struct{}), discover: func(ctx context.Context) (routerGateway, error) {
		n, err := libnat.DiscoverNAT(ctx)
		// A typed nil *NAT must not become a non-nil interface on cancellation.
		if n == nil {
			return nil, err
		}
		return n, err
	}}
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
		r.setStatus("closed", "映射已释放", 0, "")
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
		timeout := 5 * time.Second
		if router == nil {
			timeout = libnat.DiscoveryTimeout
		}
		operation, cancel := context.WithTimeout(ctx, timeout)
		if router == nil {
			r.setStatus("discovering", "正在发现 UPnP / NAT-PMP 路由器", 0, "")
			discovered, err := r.discover(operation)
			if err == nil {
				router = discovered
			}
			if err != nil && ctx.Err() == nil {
				r.setStatus("unavailable", "路由器未响应映射服务；继续尝试直连和中继", 0, "")
				r.logger.Debug("router mapping unavailable; ICE retained", "component", "nat", "error", err)
			}
		}
		if router != nil {
			port, err := r.port(operation)
			if err == nil && port > 0 && port <= 65535 {
				if port != currentPort {
					r.endpoint.Store(nil)
					if err := router.AddMapping(operation, "udp", port); err == nil {
						if currentPort > 0 {
							_ = router.RemoveMapping(operation, "udp", currentPort)
						}
						currentPort = port
					} else {
						r.setStatus("failed", "路由器未能建立 UDP 映射", port, "")
					}
				}
				if port != currentPort {
					r.endpoint.Store(nil)
				} else if mapped, ok := router.GetMapping("udp", currentPort); ok && publicRouterIP(mapped.Addr()) {
					r.setStatus("mapped", "公网 UDP 映射可用，租约自动续期", port, mapped.String())
					r.endpoint.Store(&mapped)
				} else {
					r.endpoint.Store(nil)
					r.setStatus("no_public_mapping", "未取得公网映射；可能存在上级 NAT，继续尝试其他链路", port, "")
				}
			} else {
				r.endpoint.Store(nil)
				r.setStatus("waiting", "等待 WireGuard 监听端口", 0, "")
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
