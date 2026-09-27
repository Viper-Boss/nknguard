package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/acl"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// CandidateSource produces this node's own candidates. The production source
// is nat.WireGuardGatherer; tests use a static list.
type CandidateSource interface {
	Gather(ctx context.Context) ([]nat.EndpointCandidate, nat.PortMapping, error)
}

// PeerConnector exchanges private-DHT bootstrap addresses in signed records.
type PeerConnector interface {
	LocalAddresses() []string
	ConnectPeer(context.Context, []string)
}

// StaticCandidates is a CandidateSource that returns a fixed list. It is also
// what a node with a known public endpoint and no need for STUN uses.
type StaticCandidates []nat.EndpointCandidate

// Gather returns the list.
func (s StaticCandidates) Gather(context.Context) ([]nat.EndpointCandidate, nat.PortMapping, error) {
	return append([]nat.EndpointCandidate(nil), s...), nat.PortMapping{Behaviour: nat.BehaviourOpen, PortPreserving: true}, nil
}

// Controller wires the planes together. It owns the peer table, republishes
// this node's record, and reconciles the data plane towards the table.
//
// Every goroutine it starts is tied to the context passed to Run and counted
// in one WaitGroup, and Run does not return until that count is zero:
// `nknguard down` must leave nothing running.
type Controller struct {
	Config     Config
	Device     *identity.DeviceIdentity
	Membership *membership.Key
	Discovery  discovery.Discovery
	Signaling  signaling.Transport
	WireGuard  wireguard.Manager
	Relay      relay.Relay
	Direct     DirectStrategy
	Candidates CandidateSource
	// Rendezvous supplies transport addresses that might be members. Each
	// gets a signed PEER_INFO introduction; see pkg/rendezvous.
	Rendezvous rendezvous.Source
	Policy     acl.Policy
	// PairRequest handles an untrusted, signed enrollment request. It must
	// validate a short-lived invitation before exposing it for local approval.
	PairRequest func(context.Context, protocol.Envelope) error
	Logger      *slog.Logger
	// Nudge asks WireGuard to handshake now. See UDPNudge.
	Nudge func(ctx context.Context, virtualIP netip.Addr)

	mu        sync.RWMutex
	peers     map[string]*Peer
	admitted  map[string]struct{}
	bridges   map[string]*relay.Bridge
	sequence  uint64
	selfCands []nat.EndpointCandidate
	mapping   nat.PortMapping
	virtualIP netip.Addr
	metrics   Metrics
	// introduced remembers when each rendezvous address was last sent our
	// record, so a static list or a topic listing does not turn into a
	// message per address per tick.
	introduced map[string]time.Time

	wg sync.WaitGroup
}

// Config is the controller's tunable surface.
type Config struct {
	NetworkID   string
	DeviceName  string
	DeviceTags  []string
	OverlayCIDR netip.Prefix
	Keepalive   int
	RecordTTL   time.Duration
	// Members is an explicit allow-list on top of membership proofs. It lets
	// an operator pin a device that predates the join secret, and it is empty
	// in a normal deployment.
	Members         []string
	RequireApproval bool
	OwnerDevice     bool
	ClientDevice    bool
	Timing          Timing
}

// Timing holds every interval the controller runs on. They are one struct so
// the test suite can compress the whole schedule without touching logic.
type Timing struct {
	// RepublishInterval must be well under RecordTTL, or peers see this node
	// expire between publications.
	RepublishInterval time.Duration
	// ReconcileInterval is how often the data plane is compared with intent.
	ReconcileInterval time.Duration
	// PollInterval is how often discovery is polled as a backstop to Watch.
	PollInterval time.Duration
	// PunchLead is how far ahead the rendezvous is set. It has to cover one
	// signalling round trip over NKN, which is hundreds of milliseconds.
	PunchLead time.Duration
	// RelayAfter is how long a peer may sit without any path before the
	// initiator opens the relay even though a direct attempt is pending.
	RelayAfter time.Duration
	Selector   Selector
}

// DefaultConfig returns the shipped defaults.
func DefaultConfig() Config {
	return Config{
		OverlayCIDR: netip.MustParsePrefix("10.88.0.0/16"),
		Keepalive:   25,
		RecordTTL:   discovery.DefaultRecordTTL,
		Timing: Timing{
			RepublishInterval: 30 * time.Second,
			ReconcileInterval: 2 * time.Second,
			PollInterval:      15 * time.Second,
			PunchLead:         1500 * time.Millisecond,
			RelayAfter:        20 * time.Second,
			Selector:          *DefaultSelector(),
		},
	}
}

// Metrics are the counters `nknguard status` reports.
type Metrics struct {
	PeersTotal        int `json:"peers_total"`
	PeersDirect       int `json:"peers_direct"`
	PeersRelay        int `json:"peers_relay"`
	PunchSuccess      int `json:"punch_success"`
	PunchFailure      int `json:"punch_failure"`
	RelayFallbacks    int `json:"relay_fallback_count"`
	PathSwitches      int `json:"path_switch_count"`
	RecordsRejected   int `json:"records_rejected"`
	EnvelopesRejected int `json:"envelopes_rejected"`
}

// New returns a controller with an empty peer table and a deny-all policy.
func New() *Controller {
	return &Controller{
		Config:     DefaultConfig(),
		peers:      make(map[string]*Peer),
		admitted:   make(map[string]struct{}),
		bridges:    make(map[string]*relay.Bridge),
		introduced: make(map[string]time.Time),
		Policy:     acl.DefaultPolicy(),
	}
}

func (c *Controller) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// MaxPeers caps the peer table. A household mesh is tens of devices; the cap
// exists so that a flood of valid-looking records cannot grow memory without
// end (spec §28).
const MaxPeers = 512

// maxIntroduced caps the rendezvous bookkeeping for the same reason: a public
// NKN topic can list any number of addresses.
const maxIntroduced = 4096

// ErrNotJoined means the controller has no network to operate in.
var ErrNotJoined = errors.New("mesh: no network configured — run `nknguard join` first")

// Run drives the controller until ctx is cancelled and returns only after
// every goroutine it started has finished.
func (c *Controller) Run(ctx context.Context) error {
	switch {
	case c.Config.NetworkID == "":
		return ErrNotJoined
	case c.Device == nil:
		return errors.New("mesh: controller has no device identity")
	case c.Membership == nil && len(c.Config.Members) == 0:
		return errors.New("mesh: no membership key and no explicit members — nobody could ever be admitted")
	case c.Signaling == nil:
		return errors.New("mesh: signalling is required")
	case c.Discovery == nil && c.Rendezvous == nil:
		return errors.New("mesh: no discovery backend and no rendezvous source — peers could never be found")
	}

	// Our own candidates must exist before anything that carries our record
	// goes out, or the first introduction advertises no way to reach us.
	c.gatherCandidates(ctx)

	dispatcher := c.newDispatcher()
	c.spawn(func() { _ = dispatcher.Run(ctx, c.Signaling) })
	c.spawn(func() { c.publishLoop(ctx) })
	if c.Discovery != nil {
		c.spawn(func() { c.discoverLoop(ctx) })
	}
	if c.Rendezvous != nil {
		c.spawn(func() { c.rendezvousLoop(ctx) })
	}
	c.spawn(func() { c.reconcileLoop(ctx) })
	if acceptor, ok := c.Relay.(relay.Acceptor); ok {
		c.spawn(func() { c.relayAcceptLoop(ctx, acceptor) })
	}

	<-ctx.Done()
	c.closeBridges()
	c.wg.Wait()
	return ctx.Err()
}

// spawn starts a goroutine counted by the controller's WaitGroup. It is the
// only way this package starts one.
func (c *Controller) spawn(work func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		work()
	}()
}

// ---- membership ----------------------------------------------------------

// Authorized reports whether a device is a member of this network. It fails
// closed: a device is admitted only by a verified membership proof or an
// explicit allow-list entry, never by having sent a correctly signed message.
func (c *Controller) Authorized(deviceID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authorizedLocked(deviceID)
}

func (c *Controller) authorizedLocked(deviceID string) bool {
	if _, ok := c.admitted[deviceID]; ok {
		return true
	}
	for _, member := range c.Config.Members {
		if member == deviceID {
			return true
		}
	}
	return false
}

func (c *Controller) admit(record discovery.PeerRecord) bool {
	if c.Membership != nil {
		if err := c.Membership.Verify(record.DeviceID, record.RootPublicKey, record.MembershipProof); err == nil {
			c.mu.Lock()
			if c.Config.RequireApproval {
				listed := false
				for _, member := range c.Config.Members {
					if member == record.DeviceID {
						listed = true
						break
					}
				}
				if !listed {
					c.mu.Unlock()
					return false
				}
			}
			c.admitted[record.DeviceID] = struct{}{}
			c.mu.Unlock()
			return true
		}
	}
	return c.Authorized(record.DeviceID)
}

// permits applies the ACL between this node and a peer. Membership decides
// whether we talk; the ACL decides whether we build a tunnel.
func (c *Controller) permits(record discovery.PeerRecord) bool {
	if c.Config.RequireApproval && c.Authorized(record.DeviceID) {
		return true
	}
	self := acl.Subject{DeviceID: c.Device.DeviceID(), Name: c.Config.DeviceName, Tags: c.Config.DeviceTags}
	peer := acl.Subject{DeviceID: record.DeviceID, Name: record.Name}
	for _, capability := range record.Capabilities {
		if tag, ok := cutTag(capability); ok {
			peer.Tags = append(peer.Tags, tag)
		}
	}
	// A tunnel is bidirectional, so either direction being allowed is enough
	// to build it; per-direction filtering is a v0.2 firewall concern.
	return c.Policy.Permits(self, peer) || c.Policy.Permits(peer, self)
}

// ApproveDevice admits one identity after a local owner action. It is safe to
// call while the controller runs; the caller persists the returned member list.
func (c *Controller) ApproveDevice(deviceID string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, member := range c.Config.Members {
		if member == deviceID {
			return append([]string(nil), c.Config.Members...)
		}
	}
	c.Config.Members = append(c.Config.Members, deviceID)
	return append([]string(nil), c.Config.Members...)
}

// RevokeDevice drops authorization, the peer, and its WireGuard key.
func (c *Controller) RevokeDevice(ctx context.Context, deviceID string) []string {
	c.mu.Lock()
	filtered := c.Config.Members[:0]
	for _, member := range c.Config.Members {
		if member != deviceID {
			filtered = append(filtered, member)
		}
	}
	c.Config.Members = filtered
	delete(c.admitted, deviceID)
	peer := c.peers[deviceID]
	if peer != nil {
		peer.Revoke()
	}
	delete(c.peers, deviceID)
	members := append([]string(nil), filtered...)
	c.mu.Unlock()
	c.closeBridge(deviceID)
	if peer != nil && c.WireGuard != nil {
		if key := peer.Record().WireGuardPublicKey; key != "" {
			_ = c.WireGuard.RemovePeer(ctx, key)
		}
	}
	return members
}

func cutTag(capability string) (string, bool) {
	const prefix = "tag:"
	if len(capability) > len(prefix) && capability[:len(prefix)] == prefix {
		return capability[len(prefix):], true
	}
	return "", false
}

// ---- accessors used by the daemon ---------------------------------------

func (c *Controller) peerFor(deviceID string) *Peer {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.peers[deviceID]; ok {
		return existing
	}
	selector := c.Config.Timing.Selector
	created := NewPeerWithSelector(deviceID, &selector)
	c.peers[deviceID] = created
	return created
}

func (c *Controller) lookupPeer(deviceID string) (*Peer, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	peer, ok := c.peers[deviceID]
	return peer, ok
}

// Peers returns a snapshot of the peer table.
func (c *Controller) Peers() []Snapshot {
	c.mu.RLock()
	peers := make([]*Peer, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	c.mu.RUnlock()
	out := make([]Snapshot, 0, len(peers))
	for _, peer := range peers {
		out = append(out, peer.Snapshot())
	}
	return out
}

// Metrics returns the current counters.
func (c *Controller) Metrics() Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	metrics := c.metrics
	metrics.PeersTotal = len(c.peers)
	return metrics
}

// VirtualIP is this node's overlay address.
func (c *Controller) VirtualIP() netip.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.virtualIP
}

// SetVirtualIP installs a persisted overlay address.
func (c *Controller) SetVirtualIP(addr netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.virtualIP = addr
}

// PortMapping is the last NAT measurement, for the doctor command.
func (c *Controller) PortMapping() nat.PortMapping {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mapping.Behaviour == "" {
		return nat.PortMapping{Behaviour: nat.BehaviourUnknown}
	}
	return c.mapping
}

// SetSequence seeds the record counter from persisted state.
func (c *Controller) SetSequence(sequence uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sequence > c.sequence {
		c.sequence = sequence
	}
}

// Sequence is the current record counter, for persistence.
func (c *Controller) Sequence() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sequence
}

// Records returns the latest verified record for every peer, for the on-disk
// cache that lets a restart survive a discovery outage.
func (c *Controller) Records() []discovery.PeerRecord {
	c.mu.RLock()
	peers := make([]*Peer, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	c.mu.RUnlock()
	out := make([]discovery.PeerRecord, 0, len(peers))
	for _, peer := range peers {
		if record := peer.Record(); record.DeviceID != "" {
			out = append(out, record)
		}
	}
	return out
}

// Ingest feeds a record in as if discovery had produced it. The daemon uses it
// to replay the peer cache at boot.
func (c *Controller) Ingest(ctx context.Context, record discovery.PeerRecord) {
	c.ingestRecord(ctx, record)
}

// IngestCached restores a previously verified record for a short fast-path
// probe. The signature is still checked; live discovery will replace it.
func (c *Controller) IngestCached(ctx context.Context, record discovery.PeerRecord) {
	if record.ExpiresAt < time.Now().Add(-7*24*time.Hour).Unix() || record.IssuedAt <= 0 {
		return
	}
	c.ingestRecordAt(ctx, record, time.Unix(record.IssuedAt+1, 0))
}

// RestoreLinkHint prioritizes a recent observed endpoint for one bounded
// probe. It cannot authorize a peer or claim success without a new handshake.
func (c *Controller) RestoreLinkHint(deviceID, publicKey, endpoint string, seenAt time.Time) bool {
	if time.Since(seenAt) < 0 || time.Since(seenAt) > 7*24*time.Hour {
		return false
	}
	peer, ok := c.lookupPeer(deviceID)
	if !ok || peer.Record().WireGuardPublicKey != publicKey {
		return false
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || address.Addr().IsLoopback() {
		return false
	}
	kind := nat.CandidateReflexive
	if address.Addr().IsPrivate() {
		kind = nat.CandidateHost
	}
	hint := nat.NewCandidate(kind, address, 20*time.Second, time.Now())
	hint.Priority = 2000
	if !hint.Usable() {
		return false
	}
	peer.MergeCandidates(append([]nat.EndpointCandidate{hint}, peer.Candidates()...), time.Now())
	return true
}

// Reconnect forces an immediate direct attempt for one peer.
func (c *Controller) Reconnect(deviceID string) bool {
	peer, ok := c.lookupPeer(deviceID)
	if !ok {
		return false
	}
	peer.mu.Lock()
	peer.selector.lastDirectTry = time.Time{}
	peer.selector.failures = 0
	peer.mu.Unlock()
	return true
}

// AssignVirtualIP derives this node's overlay address, avoiding addresses
// already claimed in verified records.
func (c *Controller) AssignVirtualIP() (netip.Addr, error) {
	taken := make(map[netip.Addr]string)
	for _, record := range c.Records() {
		for _, address := range record.VirtualIPs {
			if addr, err := netip.ParseAddr(address); err == nil {
				taken[addr] = record.DeviceID
			}
		}
	}
	addr, err := AllocateVirtualIP(c.Config.OverlayCIDR, c.Config.NetworkID, c.Device.DeviceID(), taken)
	if err != nil {
		return netip.Addr{}, err
	}
	c.SetVirtualIP(addr)
	return addr, nil
}

// ---- publish and discover -----------------------------------------------

func (c *Controller) gatherCandidates(ctx context.Context) {
	if c.Candidates == nil {
		return
	}
	candidates, mapping, err := c.Candidates.Gather(ctx)
	if err != nil {
		c.logger().Warn("candidate gathering failed", "component", "nat", "error", err)
		return
	}
	c.mu.Lock()
	c.selfCands = candidates
	c.mapping = mapping
	c.mu.Unlock()
}

func (c *Controller) ownCandidates() []nat.EndpointCandidate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]nat.EndpointCandidate(nil), c.selfCands...)
}

func (c *Controller) buildRecord(ctx context.Context) (discovery.PeerRecord, error) {
	c.mu.Lock()
	c.sequence++
	sequence := c.sequence
	virtual := c.virtualIP
	c.mu.Unlock()

	capabilities := protocol.DefaultCapabilities()
	for _, tag := range c.Config.DeviceTags {
		capabilities = append(capabilities, "tag:"+tag)
	}
	record := discovery.PeerRecord{
		NetworkID:    c.Config.NetworkID,
		Name:         c.Config.DeviceName,
		NKNAddress:   c.Signaling.LocalAddress(),
		Candidates:   c.ownCandidates(),
		Capabilities: capabilities,
	}
	if connector, ok := c.Discovery.(PeerConnector); ok {
		record.DHTAddresses = connector.LocalAddresses()
	}
	if c.Membership != nil {
		record.MembershipProof = c.Membership.Proof(c.Device.DeviceID(), c.Device.PublicKey())
	}
	if virtual.IsValid() {
		record.VirtualIPs = []string{virtual.String()}
	}
	if c.WireGuard != nil {
		if key, err := c.WireGuard.PublicKey(ctx); err == nil {
			record.WireGuardPublicKey = key
		}
	}
	ttl := c.Config.RecordTTL
	if ttl <= 0 {
		ttl = discovery.DefaultRecordTTL
	}
	return discovery.Sign(c.Device, record, sequence, ttl, time.Now())
}

func (c *Controller) publishLoop(ctx context.Context) {
	ticker := time.NewTicker(orDefault(c.Config.Timing.RepublishInterval, 30*time.Second))
	defer ticker.Stop()
	first := true
	for {
		if !first {
			c.gatherCandidates(ctx)
		}
		first = false
		record, err := c.buildRecord(ctx)
		if err != nil {
			c.logger().Error("building peer record failed", "component", "discovery", "error", err)
		} else {
			if c.Discovery != nil {
				if err := c.Discovery.Publish(ctx, record); err != nil && ctx.Err() == nil {
					// Publishing failing is survivable: established tunnels do
					// not depend on it (spec §59), and the next tick retries.
					c.logger().Warn("publishing peer record failed", "component", "discovery", "error", err)
				}
			}
			c.pushRecord(ctx, record)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// maxRecordPushes bounds the per-tick fan-out of our own record.
const maxRecordPushes = 64

// pushRecord sends our fresh record straight to every known peer over
// signalling. Discovery would get it there eventually; this gets it there now,
// which is what makes roaming fast (a new public address reaches peers within
// one republish interval) and what keeps a deployment with no discovery
// backend at all from letting records expire.
func (c *Controller) pushRecord(ctx context.Context, record discovery.PeerRecord) {
	raw, err := record.Marshal()
	if err != nil {
		return
	}
	pushed := 0
	for _, peer := range c.Records() {
		if pushed == maxRecordPushes {
			return
		}
		pushed++
		_ = c.send(ctx, peer.DeviceID, protocol.TypePeerInfo, protocol.PeerInfo{Record: raw})
	}
}

func (c *Controller) discoverLoop(ctx context.Context) {
	updates, err := c.Discovery.Watch(ctx, c.Config.NetworkID)
	if err != nil {
		c.logger().Warn("discovery watch unavailable, polling only", "component", "discovery", "error", err)
	}
	ticker := time.NewTicker(orDefault(c.Config.Timing.PollInterval, 15*time.Second))
	defer ticker.Stop()
	c.pollDiscovery(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case record, open := <-updates:
			if !open {
				updates = nil
				continue
			}
			c.ingestRecord(ctx, record)
		case <-ticker.C:
			c.pollDiscovery(ctx)
		}
	}
}

// rendezvousLoop introduces this node to every address a rendezvous source
// names. The introduction is our signed record; an address that belongs to a
// member answers with theirs, and ingestRecord takes it from there.
func (c *Controller) rendezvousLoop(ctx context.Context) {
	ticker := time.NewTicker(orDefault(c.Config.Timing.PollInterval, 15*time.Second))
	defer ticker.Stop()
	for {
		if err := c.Rendezvous.Announce(ctx); err != nil && ctx.Err() == nil {
			c.logger().Warn("rendezvous announce failed", "component", "rendezvous", "error", err)
		}
		if addresses, err := c.Rendezvous.Addresses(ctx); err == nil {
			c.introduce(ctx, addresses)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reintroduceAfter is how often an address that has not become a peer is
// re-sent our record. Long enough that a topic full of strangers costs little,
// short enough that a member who was offline is picked up within minutes.
const reintroduceAfter = 5 * time.Minute

func (c *Controller) introduce(ctx context.Context, addresses []string) {
	self := c.Signaling.LocalAddress()
	known := make(map[string]struct{})
	for _, record := range c.Records() {
		known[record.NKNAddress] = struct{}{}
	}
	var record []byte
	now := time.Now()
	for _, address := range addresses {
		if address == "" || address == self {
			continue
		}
		if _, isPeer := known[address]; isPeer {
			continue
		}
		c.mu.Lock()
		last, sent := c.introduced[address]
		if sent && now.Sub(last) < reintroduceAfter {
			c.mu.Unlock()
			continue
		}
		if len(c.introduced) >= maxIntroduced {
			for stale, at := range c.introduced {
				if now.Sub(at) >= reintroduceAfter {
					delete(c.introduced, stale)
				}
			}
			if len(c.introduced) >= maxIntroduced {
				c.mu.Unlock()
				return
			}
		}
		c.introduced[address] = now
		c.mu.Unlock()
		if record == nil {
			built, err := c.buildRecord(ctx)
			if err != nil {
				return
			}
			if record, err = built.Marshal(); err != nil {
				return
			}
		}
		envelope, err := protocol.Seal(c.Device, c.Config.NetworkID, "", protocol.TypePeerInfo, protocol.PeerInfo{Record: record, WantReply: true})
		if err != nil {
			return
		}
		_ = c.Signaling.SendAddress(ctx, address, envelope)
	}
}

// onPeerInfo accepts an introduction. It is an open message type, so the
// sender may be a stranger: the record inside must be signed by the same key
// that signed the envelope, and ingestRecord then applies the full chain —
// signature, freshness, membership proof, ACL — exactly as for a DHT record.
func (c *Controller) onPeerInfo(ctx context.Context, envelope protocol.Envelope) error {
	var info protocol.PeerInfo
	if err := envelope.DecodePayload(&info); err != nil {
		return err
	}
	record, err := discovery.UnmarshalRecord(info.Record)
	if err != nil {
		return err
	}
	if record.DeviceID != envelope.FromDeviceID {
		return errors.New("mesh: PEER_INFO carries someone else's record")
	}
	c.ingestRecord(ctx, record)
	if !c.Authorized(record.DeviceID) || !info.WantReply {
		return nil
	}
	own, err := c.buildRecord(ctx)
	if err != nil {
		return err
	}
	raw, err := own.Marshal()
	if err != nil {
		return err
	}
	return c.send(ctx, record.DeviceID, protocol.TypePeerInfo, protocol.PeerInfo{Record: raw})
}

func (c *Controller) pollDiscovery(ctx context.Context) {
	records, err := c.Discovery.Lookup(ctx, c.Config.NetworkID)
	if err != nil {
		return
	}
	for _, record := range records {
		c.ingestRecord(ctx, record)
	}
}

// ingestRecord is where an untrusted record becomes a peer: signature and
// freshness first, then membership, then policy. A failure at any step is
// counted and dropped — the store is untrusted, so bad input is expected.
func (c *Controller) ingestRecord(ctx context.Context, record discovery.PeerRecord) {
	c.ingestRecordAt(ctx, record, time.Now())
}

func (c *Controller) ingestRecordAt(ctx context.Context, record discovery.PeerRecord, verifyAt time.Time) {
	if record.DeviceID == c.Device.DeviceID() {
		return
	}
	reject := func(reason string, err error) {
		c.mu.Lock()
		c.metrics.RecordsRejected++
		c.mu.Unlock()
		c.logger().Debug("peer record rejected", "component", "discovery", "peer", record.DeviceID, "reason", reason, "error", err)
	}
	if err := record.Verify(c.Config.NetworkID, verifyAt); err != nil {
		reject("verify", err)
		return
	}
	if !c.admit(record) {
		reject("membership", nil)
		return
	}
	if !c.permits(record) {
		reject("acl", nil)
		return
	}
	if _, known := c.lookupPeer(record.DeviceID); !known {
		c.mu.RLock()
		full := len(c.peers) >= MaxPeers
		c.mu.RUnlock()
		if full {
			reject("peer table full", nil)
			return
		}
	}
	peer := c.peerFor(record.DeviceID)
	previous := peer.Record()
	if !peer.SetRecord(record) {
		return
	}
	if connector, ok := c.Discovery.(PeerConnector); ok && len(record.DHTAddresses) > 0 {
		addresses := append([]string(nil), record.DHTAddresses...)
		c.spawn(func() { connector.ConnectPeer(ctx, addresses) })
	}
	if previous.DeviceID != "" && !sameCandidates(previous.Candidates, record.Candidates) && peer.Path() != PathDirectWG {
		// The peer moved. Whatever backoff its old address earned says
		// nothing about the new one, so try the new one now.
		c.Reconnect(record.DeviceID)
	}
	if record.NKNAddress != "" {
		c.Signaling.SetPeerAddress(record.DeviceID, record.NKNAddress)
	}
	state := peer.State()
	if state == StateUnknown || state == StateOffline || state == StateDegraded {
		_, _ = peer.Apply(EventRecordSeen, time.Now())
		c.logger().Info("peer discovered", "component", "mesh", "peer", record.DeviceID, "name", record.Name)
		c.sendHello(ctx, peer)
	}
}

// ---- signalling ----------------------------------------------------------

func (c *Controller) newDispatcher() *signaling.Dispatcher {
	dispatcher := &signaling.Dispatcher{
		Acceptor: &protocol.Acceptor{
			NetworkID:     c.Config.NetworkID,
			LocalDeviceID: c.Device.DeviceID(),
			Replay:        protocol.NewReplayCache(0, 0),
		},
		Authorized: c.Authorized,
		Open:       map[protocol.MessageType]bool{protocol.TypePeerInfo: true, protocol.TypePairRequest: true},
		OpenLimit:  signaling.NewRateLimiter(10, 30),
		OnRejected: func(inbound signaling.Inbound, err error) {
			c.mu.Lock()
			c.metrics.EnvelopesRejected++
			c.mu.Unlock()
			c.logger().Debug("control message rejected", "component", "signaling", "from", inbound.Envelope.FromDeviceID, "type", inbound.Envelope.Type, "error", err)
		},
	}
	dispatcher.Handle(protocol.TypePeerInfo, c.onPeerInfo)
	if c.PairRequest != nil {
		dispatcher.Handle(protocol.TypePairRequest, c.PairRequest)
	}
	dispatcher.Handle(protocol.TypeHello, c.onHello)
	dispatcher.Handle(protocol.TypeCandidate, c.onCandidate)
	dispatcher.Handle(protocol.TypePunchRequest, c.onPunchRequest)
	dispatcher.Handle(protocol.TypePunchAck, c.onPunchAck)
	dispatcher.Handle(protocol.TypeWGReady, c.onWGReady)
	dispatcher.Handle(protocol.TypeKeepalive, func(context.Context, protocol.Envelope) error { return nil })
	dispatcher.Handle(protocol.TypeDisconnect, c.onDisconnect)
	dispatcher.Handle(protocol.TypeError, c.onError)
	return dispatcher
}

func (c *Controller) send(ctx context.Context, deviceID string, messageType protocol.MessageType, payload any) error {
	envelope, err := protocol.Seal(c.Device, c.Config.NetworkID, deviceID, messageType, payload)
	if err != nil {
		return err
	}
	return c.Signaling.Send(ctx, deviceID, envelope)
}

func (c *Controller) sendHello(ctx context.Context, peer *Peer) {
	hello := protocol.Hello{
		Versions:     protocol.LocalVersionRange(),
		Capabilities: protocol.DefaultCapabilities(),
		DeviceName:   c.Config.DeviceName,
	}
	if err := c.send(ctx, peer.DeviceID(), protocol.TypeHello, hello); err != nil {
		peer.NoteError("hello: " + err.Error())
		return
	}
	_, _ = peer.Apply(EventHelloSent, time.Now())
	// Candidates go out with the HELLO rather than waiting for the reply. The
	// peer may not know us yet and drop the HELLO; sending both means whichever
	// side discovers the other second still ends up with both candidate sets.
	c.sendCandidates(ctx, peer)
}

func (c *Controller) sendCandidates(ctx context.Context, peer *Peer) {
	encoded, err := json.Marshal(c.ownCandidates())
	if err != nil {
		return
	}
	set := protocol.CandidateSet{Candidates: encoded}
	if c.WireGuard != nil {
		if key, err := c.WireGuard.PublicKey(ctx); err == nil {
			set.WireGuardPublicKey = key
		}
	}
	if virtual := c.VirtualIP(); virtual.IsValid() {
		set.VirtualIPs = []string{virtual.String()}
	}
	if err := c.send(ctx, peer.DeviceID(), protocol.TypeCandidate, set); err != nil {
		peer.NoteError("candidates: " + err.Error())
	}
}

func decodeCandidates(raw []byte) ([]nat.EndpointCandidate, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var candidates []nat.EndpointCandidate
	if err := json.Unmarshal(raw, &candidates); err != nil {
		return nil, err
	}
	if len(candidates) > nat.MaxCandidates {
		candidates = candidates[:nat.MaxCandidates]
	}
	return candidates, nil
}

func (c *Controller) onHello(ctx context.Context, envelope protocol.Envelope) error {
	var hello protocol.Hello
	if err := envelope.DecodePayload(&hello); err != nil {
		return err
	}
	if _, ok := protocol.Negotiate(protocol.LocalVersionRange(), hello.Versions); !ok {
		return c.send(ctx, envelope.FromDeviceID, protocol.TypeError, protocol.Error{
			Code:    protocol.ErrorVersionUnsupported,
			Message: fmt.Sprintf("this node speaks %d..%d", protocol.MinVersion, protocol.Version),
		})
	}
	peer, ok := c.lookupPeer(envelope.FromDeviceID)
	if !ok {
		// Authorized but no record yet: discovery will create the peer. We
		// do not create peers from signalling alone, because a peer without a
		// verified record has no pinned WireGuard key.
		return nil
	}
	_, _ = peer.Apply(EventHelloReceived, time.Now())
	c.sendCandidates(ctx, peer)
	return nil
}

func (c *Controller) onCandidate(_ context.Context, envelope protocol.Envelope) error {
	var set protocol.CandidateSet
	if err := envelope.DecodePayload(&set); err != nil {
		return err
	}
	peer, ok := c.lookupPeer(envelope.FromDeviceID)
	if !ok {
		return nil
	}
	// The key in a CANDIDATE message must match the one in the signed record.
	// A mismatch is either a rotation we have not seen the record for yet or
	// an attack; either way, the record is what we trust.
	if set.WireGuardPublicKey != "" && set.WireGuardPublicKey != peer.Record().WireGuardPublicKey {
		return errors.New("mesh: candidate set carries a key that does not match the signed record")
	}
	candidates, err := decodeCandidates(set.Candidates)
	if err != nil {
		return err
	}
	peer.MergeCandidates(candidates, time.Now())
	_, _ = peer.Apply(EventCandidatesGot, time.Now())
	return nil
}

func (c *Controller) onPunchRequest(ctx context.Context, envelope protocol.Envelope) error {
	var request protocol.PunchRequest
	if err := envelope.DecodePayload(&request); err != nil {
		return err
	}
	peer, ok := c.lookupPeer(envelope.FromDeviceID)
	if !ok {
		return nil
	}
	candidates, err := decodeCandidates(request.Candidates)
	if err != nil {
		return err
	}
	if len(candidates) > 0 {
		peer.MergeCandidates(candidates, time.Now())
	}
	startAt := time.UnixMilli(request.StartAtUnixMilli)
	// A rendezvous far in the future is either a clock problem or an attempt
	// to park our goroutine; refuse it rather than wait.
	if time.Until(startAt) > 10*time.Second {
		return c.send(ctx, envelope.FromDeviceID, protocol.TypePunchAck, protocol.PunchAck{Round: request.Round, Reason: "rendezvous too far ahead"})
	}
	if !peer.BeginAttempt() {
		return c.send(ctx, envelope.FromDeviceID, protocol.TypePunchAck, protocol.PunchAck{Round: request.Round, Reason: "attempt in progress"})
	}
	if err := c.send(ctx, envelope.FromDeviceID, protocol.TypePunchAck, protocol.PunchAck{Round: request.Round, Accepted: true}); err != nil {
		peer.EndAttempt(false)
		return err
	}
	var token nat.SessionToken
	copy(token[:], request.Token)
	c.ensureWireGuardPeer(ctx, peer)
	c.spawn(func() { c.runAttempt(ctx, peer, startAt, token, false) })
	return nil
}

func (c *Controller) onPunchAck(_ context.Context, envelope protocol.Envelope) error {
	var ack protocol.PunchAck
	if err := envelope.DecodePayload(&ack); err != nil {
		return err
	}
	if !ack.Accepted {
		if peer, ok := c.lookupPeer(envelope.FromDeviceID); ok {
			peer.NoteError("peer declined direct attempt: " + ack.Reason)
		}
	}
	return nil
}

func (c *Controller) onWGReady(_ context.Context, envelope protocol.Envelope) error {
	c.logger().Info("peer reports wireguard ready", "component", "mesh", "peer", envelope.FromDeviceID)
	return nil
}

func (c *Controller) onDisconnect(_ context.Context, envelope protocol.Envelope) error {
	if peer, ok := c.lookupPeer(envelope.FromDeviceID); ok {
		peer.NoteError("peer disconnected")
	}
	return nil
}

func (c *Controller) onError(_ context.Context, envelope protocol.Envelope) error {
	var report protocol.Error
	if err := envelope.DecodePayload(&report); err != nil {
		return err
	}
	c.logger().Warn("peer reported an error", "component", "signaling", "peer", envelope.FromDeviceID, "code", report.Code, "message", report.Message)
	return nil
}

func sameCandidates(a, b []nat.EndpointCandidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IP != b[i].IP || a[i].Port != b[i].Port || a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}
