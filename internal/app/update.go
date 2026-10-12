package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
)

// registerUpdates shares the dashboard's authentication and same-origin guard.
// Downloads run in the background; installation still requires an explicit owner action.
func (d *Daemon) registerUpdates(mux *http.ServeMux, contexts ...context.Context) {
	var mu sync.Mutex
	var checking, installing bool
	var installStarted time.Time
	var result *releaseupdate.Result
	kind := updateKind()
	serviceCtx := context.Background()
	if len(contexts) > 0 {
		serviceCtx = contexts[0]
	}
	prefetch := newUpdatePrefetch(d, &mu, kind)
	prefetch.busy = func() bool { return installing || checking }
	prefetch.checked = func(checked releaseupdate.Result) { result = &checked }
	if len(contexts) > 0 && updateSupported(d.Config) {
		prefetch.restore()
		go prefetch.run(serviceCtx)
	}
	mux.HandleFunc("POST /api/updates/preferences", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		var req struct {
			Enabled *bool `json:"auto_download"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&req) != nil || req.Enabled == nil {
			http.Error(w, "invalid preferences", 400)
			return
		}
		if err := prefetch.setAuto(*req.Enabled); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"auto_download": *req.Enabled})
	})
	mux.HandleFunc("POST /api/updates/download", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		if !updateSupported(d.Config) {
			http.Error(w, "当前安装方式不支持面板更新", 400)
			return
		}
		if !prefetch.start(serviceCtx, nil) {
			http.Error(w, "update in progress", 409)
			return
		}
		w.WriteHeader(202)
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/updates/apply", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		if !updateSupported(d.Config) {
			http.Error(w, "当前安装方式不支持面板更新", 400)
			return
		}
		mu.Lock()
		if installing || checking || prefetch.active || prefetch.download.State != "ready" || prefetch.readyDir == "" {
			mu.Unlock()
			http.Error(w, "更新尚未准备好或任务正在进行", 409)
			return
		}
		dir := prefetch.readyDir
		installing = true
		installStarted = time.Now()
		mu.Unlock()
		next, err := prefetch.validate(dir)
		if err == nil {
			err = launchUpdate(d.Config, dir)
		}
		if err != nil {
			mu.Lock()
			installing = false
			mu.Unlock()
			http.Error(w, "无法更新："+err.Error(), 400)
			return
		}
		_ = os.Remove(filepath.Join(d.Config.Paths.StateDir, "updates", "ready.json"))
		mu.Lock()
		prefetch.readyDir = ""
		prefetch.download = updateDownload{State: "installing", Version: next, Message: "更新已开始，服务将短暂重启…"}
		mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "version": next, "message": "更新已开始，请稍后刷新；配置和配对会保留。"})
	})
	mux.HandleFunc("GET /api/updates", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var state map[string]any
		if raw, err := os.ReadFile(filepath.Join(d.Config.Paths.StateDir, "update-result.json")); err == nil && len(raw) < 4096 {
			_ = json.Unmarshal(raw, &state)
		}
		if state != nil && installing {
			stamp, _ := state["time"].(string)
			finished, _ := time.Parse(time.RFC3339Nano, stamp)
			if finished.After(installStarted) && (state["state"] == "failed" || state["stu�������k�w��o/ Rendezvous is membership.Key.Rendezvous(): the providers key. Derived
	// from the join secret, so a network id alone does not enumerate members.
	Rendezvous    string
	RecordAllowed func(discovery.PeerRecord) bool
	Logger        *slog.Logger
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

	mu          sync.RWMutex
	own         []byte
	bindings    map[string]peer.ID
	publicPeers map[peer.ID]bool
	publicHints map[peer.ID]bootstrapHint
	dialing     map[peer.ID]bool
	inbound     chan signaling.Inbound
	slots       chan struct{}
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
		bindings: make(map[string]peer.ID), publicPeers: make(map[peer.ID]bool), publicHints: make(map[peer.ID]bootstrapHint), dialing: make(map[peer.ID]bool), inbound: make(chan signaling.Inbound, 128), slots: make(chan struct{}, 16)}
	created.SetStreamHandler(RecordProtocol, backend.serveRecord)
	created.SetStreamHandler(PrivateRecordProtocol, backend.servePrivateRecord)
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
	go backend.restoreBootstrapHints(runCtx)
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
	select {
	case b.slots <- struct{}{}:
	default:
		_ = stream.Reset()
		return
	}
	defer func() { <-b.slots }()
	defer stream.Close()
	if b.opts.RecordAllowed != nil {
		b.mu.RLock()
		allowed := false
		for _, id := range b.bindings {
			if id == stream.Conn().RemotePeer() {
				allowed = true
				break
			}
		}
		b.mu.RUnlock()
		if !allowed {
			_ = stream.Reset()
			return
		}
	}
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
	if err := b.StoreRecord(record); err != nil {
		return err
	}
	return b.kad.Provide(ctx, b.key, true)
}

// StoreRecord refreshes the standby record in memory without DHT traffic.
func (b *Backend) StoreRecord(record discovery.PeerRecord) error {
	raw, err := record.Marshal()
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.own = raw
	b.mu.Unlock()
	return nil
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
	stream, err := b.host.NewStream(fetchCtx, info.ID, PrivateRecordProtocol)
	private := err == nil
	if err != nil {
		stream, err = b.host.NewStream(fetchCtx, info.ID, RecordProtocol)
	}
	if err != nil {
		return discovery.PeerRecord{}, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	if private {
		b.mu.RLock()
		own := append([]byte(nil), b.own...)
		b.mu.RUnlock()
		if len(own) == 0 {
			return discovery.PeerRecord{}, errors.New("no local discovery record")
		}
		own, err = b.sealPrivate(own, b.host.ID(), info.ID, "request")
		if err != nil {
			return discovery.PeerRecord{}, err
		}
		if _, err = stream.Write(own); err != nil {
			return discovery.PeerRecord{}, err
		}
		if err = stream.CloseWrite(); err != nil {
			return discovery.PeerRecord{}, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(stream, discovery.MaxRecordBytes+65))
	if err != nil {
		return discovery.PeerRecord{}, err
	}
	if private {
		raw, err = b.openPrivate(raw, info.ID, b.host.ID(), "response")
		if err != nil {
			return discovery.PeerRecord{}, err
		}
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
