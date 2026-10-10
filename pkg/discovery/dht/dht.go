//go:build libp2pdht

// Package dht is a Discovery backend on a private Kademlia DHT.
//
// It is NasSimHub's agent/internal/dht carried over: a libp2p host with a
// persistent identity, Kademlia in server mode under a project-private
// protocol prefix (never the public IPFS DHT), circuit relay disabled, mDNS for
// zero-configuration LAN bootstrap, and a stream-handler allowlist enforced by
// reading the mux back.
//
// What NKNGuard adds on top: records. Each node Provides a content id derived
// from the network's rendezvous key, and serves its latest signed PeerRecord
// on one stream protocol. Lookup finds providers and fetches their records.
// Nothing fetched is trusted — the controller verifies every record — so a
// hostile DHT participant can withhold or waste, but not redirect.
package dht

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	libp2p "github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

// ProtocolPrefix scopes every DHT protocol. With the library default a node
// in server mode would join the public IPFS DHT and store records for the
// whole world; under our own prefix it only ever talks to NKNGuard nodes.
const ProtocolPrefix = "/nknguard"

// RecordProtocol serves this node's signed peer record.
const RecordProtocol = protocol.ID("/nknguard/record/1.0.0")

// LANServiceName scopes mDNS announcements to this project.
const LANServiceName = "nknguard"

var allowedProtocols = []string{
	"/ipfs/id/1.0.0",
	"/ipfs/id/push/1.0.0",
	"/ipfs/ping/1.0.0",
	ProtocolPrefix + "/kad/1.0.0",
	string(RecordProtocol),
	string(SignalProtocol),
}

// Options configures the backend.
type Options struct {
	StateDir       string
	ListenPort     int
	BootstrapPeers []string
	LANDiscovery   bool
	// Phones participate without serving a permanent routing table.
	ClientMode bool
	MapPorts   bool
	// Rendezvous is membership.Key.Rendezvous(): the providers key. Derived
	// from the join secret, so a network id alone does not enumerate members.
	Rendezvous string
	Logger     *slog.Logger
	// Android supplies underlying addresses because net.Interfaces is restricted.
	InterfaceAddresses func() ([]net.Addr, error)
}

// Backend implements discovery.Discovery.
type Backend struct {
	opts   Options
	host   host.Host
	kad    *kaddht.IpfsDHT
	key    cid.Cid
	mdns   io.Closer
	cancel context.CancelFunc

	mu       sync.RWMutex
	own      []byte
	bindings map[string]peer.ID
	dialing  map[peer.ID]bool
	inbound  chan signaling.Inbound
	slots    chan struct{}
}

// Open starts the host.
func Open(ctx context.Context, opts Options) (*Backend, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	identity, err := loadOrCreateIdentity(filepath.Join(opts.StateDir, "libp2p.key"))
	if err != nil {
		return nil, err
	}
	hostOptions := []libp2p.Option{
		libp2p.Identity(identity),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", opts.ListenPort), fmt.Sprintf("/ip6/::/tcp/%d", opts.ListenPort)),
		// This node never carries anyone else's bytes over libp2p.
		libp2p.DisableRelay(),
	}
	if opts.MapPorts {
		hostOptions = append(hostOptions, libp2p.NATPortMap())
	}
	created, err := libp2p.New(hostOptions...)
	if err != nil {
		return nil, fmt.Errorf("dht: start host: %w", err)
	}
	mode := kaddht.ModeServer
	if opts.ClientMode {
		mode = kaddht.ModeClient
	}
	kad, err := kaddht.New(created, kaddht.Mode(mode), kaddht.ProtocolPrefix(ProtocolPrefix))
	if err != nil {
		_ = created.Close()
		return nil, fmt.Errorf("dht: start kademlia: %w", err)
	}
	hash, err := multihash.Sum([]byte(opts.Rendezvous), multihash.SHA2_256, -1)
	if err != nil {
		_ = created.Close()
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	backend := &Backend{opts: opts, host: created, kad: kad, key: cid.NewCidV1(cid.Raw, hash), cancel: cancel,
		bindings: make(map[string]peer.ID), dialing: make(map[peer.ID]bool), inbound: make(chan signaling.Inbound, 128), slots: make(chan struct{}, 16)}
	created.SetStreamHandler(RecordProtocol, backend.serveRecord)
	created.SetStreamHandler(SignalProtocol, backend.serveSignal)
	prune(created, opts.Logger)

	if opts.LANDiscovery {
		service := mdns.NewMdnsService(created, LANServiceName, &notifee{backend: backend, ctx: runCtx})
		if err := service.Start(); err == nil {
			backend.mdns = service
		} else {
			opts.Logger.Warn("LAN discovery unavailable", "component", "dht", "error", err)
		}
	}
	_ = kad.Bootstrap(runCtx)
	for _, address := range opts.BootstrapPeers {
		if info, err := parse(address); err == nil {
			go func(info peer.AddrInfo) {
				dialCtx, cancelDial := context.WithTimeout(runCtx, 15*time.Second)
				defer cancelDial()
				_ = created.Connect(dialCtx, info)
			}(info)
		}
	}
	return backend, nil
}

// DiscoveryStatus is local telemetry, never a count of the global network.
func (b *Backend) DiscoveryStatus() (int, int) {
	return len(b.host.Network().Peers()), b.kad.RoutingTable().Size()
}

// DiscoveryLANPeers counts each connected peer once, even with multiple links.
func (b *Backend) DiscoveryLANPeers() int {
	count := 0
	for _, id := range b.host.Network().Peers() {
		for _, conn := range b.host.Network().ConnsToPeer(id) {
			address := conn.RemoteMultiaddr()
			raw, err := address.ValueForProtocol(multiaddr.P_IP4)
			if err != nil {
				raw, err = address.ValueForProtocol(multiaddr.P_IP6)
			}
			if err != nil {
				continue
			}
			ip, err := netip.ParseAddr(raw)
			if err == nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				count++
				break
			}
		}
	}
	return count
}

func parse(address string) (peer.AddrInfo, error) {
	maddr, err := multiaddr.NewMultiaddr(strings.TrimSpace(address))
	if err != nil {
		return peer.AddrInfo{}, err
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	return *info, nil
}

// LocalAddresses are signed into this node's peer record and introduced over
// NKN. Reachable peers can then bootstrap the private DHT without a VPS.
func (b *Backend) LocalAddresses() []string {
	addresses := b.host.Addrs()
	if b.opts.InterfaceAddresses != nil {
		if ips, err := b.opts.InterfaceAddresses(); err == nil {
			for _, listen := range b.host.Network().ListenAddresses() {
				port, err := listen.ValueForProtocol(multiaddr.P_TCP)
				if err != nil {
					continue
				}
				for _, entry := range ips {
					raw := strings.Split(entry.String(), "/")[0]
					ip, err := netip.ParseAddr(raw)
					if err != nil || !ip.IsGlobalUnicast() {
						continue
					}
					family := "ip6"
					if ip.Is4() {
						family = "ip4"
					}
					if _, err := listen.ValueForProtocol(map[string]int{"ip4": multiaddr.P_IP4, "ip6": multiaddr.P_IP6}[family]); err != nil {
						continue
					}
					if address, err := multiaddr.NewMultiaddr("/" + family + "/" + ip.String() + "/tcp/" + port); err == nil {
						addresses = append(addresses, address)
					}
				}
			}
		}
	}
	unique := make([]multiaddr.Multiaddr, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		if !seen[address.String()] {
			unique = append(unique, address)
			seen[address.String()] = true
		}
	}
	addresses = unique
	// Public addresses must not be crowded out by Docker or VPN interfaces.
	sort.SliceStable(addresses, func(i, j int) bool { return addressRank(addresses[i]) < addressRank(addresses[j]) })
	if len(addresses) > 8 {
		addresses = addresses[:8]
	}
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, address.Encapsulate(multiaddr.StringCast("/p2p/"+b.host.ID().String())).String())
	}
	return out
}

// ConnectPeer dials a signed peer's libp2p addresses. It is bounded and best
// effort: DHT reachability cannot be guaranteed behind restrictive NATs.
func (b *Backend) ConnectPeer(ctx context.Context, addresses []string) {
	if len(addresses) > 8 {
		addresses = addresses[:8]
	}
	var target peer.AddrInfo
	for _, address := range addresses {
		info, err := parse(address)
		if err != nil || info.ID == b.host.ID() {
			continue
		}
		if target.ID == "" {
			target.ID = info.ID
		}
		if info.ID == target.ID {
			target.Addrs = append(target.Addrs, info.Addrs...)
		}
	}
	if target.ID == "" || b.host.Network().Connectedness(target.ID) == network.Connected {
		return
	}
	b.mu.Lock()
	if b.dialing[target.ID] {
		b.mu.Unlock()
		return
	}
	b.dialing[target.ID] = true
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.dialing, target.ID); b.mu.Unlock() }()
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	_ = b.host.Connect(dialCtx, target)
}

func addressRank(address multiaddr.Multiaddr) int {
	raw, err := address.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		raw, _ = address.ValueForProtocol(multiaddr.P_IP6)
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return 2
	}
	if ip.IsGlobalUnicast() && !ip.IsPrivate() {
		return 0
	}
	return 1
}

func loadOrCreateIdentity(path string) (crypto.PrivKey, error) {
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		return crypto.UnmarshalPrivateKey(raw)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, encoded, 0o600)
}

// prune removes any registered protocol not on the allowlist. A dependency
// bump can register a new service without anyone editing this file; reading
// the mux back is the only way to know what is really offered.
func prune(h host.Host, logger *slog.Logger) {
	allowed := map[string]bool{}
	for _, name := range allowedProtocols {
		allowed[name] = true
	}
	for _, id := range h.Mux().Protocols() {
		if !allowed[string(id)] {
			h.RemoveStreamHandler(id)
			logger.Warn("removed libp2p protocol this node does not offer", "component", "dht", "protocol", string(id))
		}
	}
}

func (b *Backend) serveRecord(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	b.mu.RLock()
	own := b.own
	b.mu.RUnlock()
	if len(own) > 0 {
		_, _ = stream.Write(own)
	}
}

// Publish stores our record for the record protocol and (re)announces us as
// a provider of the network's rendezvous key.
func (b *Backend) Publish(ctx context.Context, record discovery.PeerRecord) error {
	raw, err := record.Marshal()
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.own = raw
	b.mu.Unlock()
	return b.kad.Provide(ctx, b.key, true)
}

// MaxLookupPeers bounds one lookup's fan-out.
const MaxLookupPeers = 64

// Lookup finds providers and fetches each one's record.
func (b *Backend) Lookup(ctx context.Context, _ string) ([]discovery.PeerRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out []discovery.PeerRecord
	seen := make(map[peer.ID]bool)
	// A directly connected NAS need not wait for provider propagation.
	for _, id := range b.host.Network().Peers() {
		if len(out) >= MaxLookupPeers {
			break
		}
		seen[id] = true
		if record, err := b.fetch(ctx, peer.AddrInfo{ID: id}); err == nil {
			out = append(out, record)
		}
	}
	for info := range b.kad.FindProvidersAsync(ctx, b.key, MaxLookupPeers) {
		if info.ID == b.host.ID() || seen[info.ID] || len(out) >= MaxLookupPeers {
			continue
		}
		if record, err := b.fetch(ctx, info); err == nil {
			out = append(out, record)
		}
	}
	return out, nil
}

func (b *Backend) fetch(ctx context.Context, info peer.AddrInfo) (discovery.PeerRecord, error) {
	if len(info.Addrs) > 0 {
		b.host.Peerstore().AddAddrs(info.ID, info.Addrs, 10*time.Minute)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := b.host.NewStream(fetchCtx, info.ID, RecordProtocol)
	if err != nil {
		return discovery.PeerRecord{}, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(stream, discovery.MaxRecordBytes+1))
	if err != nil {
		return discovery.PeerRecord{}, err
	}
	return discovery.UnmarshalRecord(raw)
}

// Watch is not supported by a DHT; the controller falls back to polling.
func (b *Backend) Watch(context.Context, string) (<-chan discovery.PeerRecord, error) {
	return nil, errors.ErrUnsupported
}

// Close shuts the host down.
func (b *Backend) Close() error {
	b.cancel()
	if b.mdns != nil {
		// Closed without waiting: the library's Close can block forever on a
		// host with no multicast interface (seen in NasSimHub's containers).
		closer := b.mdns
		go func() { _ = closer.Close() }()
	}
	_ = b.kad.Close()
	return b.host.Close()
}

type notifee struct {
	backend *Backend
	ctx     context.Context
}

func (n *notifee) HandlePeerFound(info peer.AddrInfo) {
	if info.ID == "" || info.ID == n.backend.host.ID() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
		defer cancel()
		_ = n.backend.host.Connect(ctx, info)
	}()
}
