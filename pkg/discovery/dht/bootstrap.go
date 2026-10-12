//go:build libp2pdht

package dht

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Public bootstrap reveals only the libp2p identity and reachable addresses.
// Neither membership proofs nor WireGuard/device records are in this protocol.
type bootstrapProof struct {
	Source    string   `json:"source"`
	Nonce     string   `json:"nonce"`
	Expires   int64    `json:"expires"`
	Peer      string   `json:"peer"`
	Key       []byte   `json:"key"`
	Addresses []string `json:"addresses"`
	Signature []byte   `json:"signature,omitempty"`
}

func publicBootstrapAddress(address string, id peer.ID) bool {
	info, err := parse(address)
	if err != nil || info.ID != id || len(info.Addrs) != 1 {
		return false
	}
	m := info.Addrs[0]
	raw, err := m.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		raw, err = m.ValueForProtocol(multiaddr.P_IP6)
	}
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return false
	}
	port, err := m.ValueForProtocol(multiaddr.P_TCP)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 {
		return false
	}
	// Only literal IP + TCP. No DNS, proxy, circuit, or unexpected protocols.
	expected := "/ip6/" + ip.String() + "/tcp/" + port
	if ip.Is4() {
		expected = "/ip4/" + ip.String() + "/tcp/" + port
	}
	return m.String() == expected
}

func (b *Backend) BootstrapServer() bool { return !b.opts.ClientMode }

func (b *Backend) BootstrapNeighborCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id := range b.publicPeers {
		if b.host.Network().Connectedness(id) != network.Connected {
			delete(b.publicPeers, id)
		}
	}
	return len(b.publicPeers)
}

func (b *Backend) BootstrapProof(source, nonce string) ([]byte, error) {
	key := b.host.Peerstore().PrivKey(b.host.ID())
	pub, err := crypto.MarshalPublicKey(key.GetPublic())
	if err != nil {
		return nil, err
	}
	p := bootstrapProof{Source: source, Nonce: nonce, Expires: time.Now().Add(45 * time.Second).Unix(), Peer: b.host.ID().String(), Key: pub}
	for _, address := range b.LocalAddresses() {
		if publicBootstrapAddress(address, b.host.ID()) {
			p.Addresses = append(p.Addresses, address)
		}
	}
	if len(p.Addresses) == 0 {
		return nil, errors.New("DHT has no public reachable candidate")
	}
	raw, _ := json.Marshal(p)
	p.Signature, err = key.Sign(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func verifyBootstrapProof(raw []byte, source, nonce string, now time.Time) (bootstrapProof, error) {
	var p bootstrapProof
	if len(raw) > 8192 || json.Unmarshal(raw, &p) != nil || p.Source != source || p.Nonce != nonce || p.Expires < now.Unix() || p.Expires > now.Add(time.Minute).Unix() || len(p.Addresses) == 0 || len(p.Addresses) > 8 {
		return p, errors.New("invalid or expired bootstrap proof")
	}
	key, err := crypto.UnmarshalPublicKey(p.Key)
	if err != nil {
		return p, err
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil || id.String() != p.Peer {
		return p, errors.New("bootstrap identity mismatch")
	}
	signature := p.Signature
	p.Signature = nil
	body, _ := json.Marshal(p)
	valid, err := key.Verify(body, signature)
	if err != nil || !valid {
		return p, errors.New("bootstrap signature invalid")
	}
	for _, address := range p.Addresses {
		if !publicBootstrapAddress(address, id) {
			return p, errors.New("unsafe bootstrap address")
		}
	}
	return p, nil
}

func (b *Backend) ConnectBootstrap(ctx context.Context, raw []byte, source, nonce string) error {
	p, err := verifyBootstrapProof(raw, source, nonce, time.Now())
	if err != nil {
		return err
	}
	connected := b.BootstrapNeighborCount()
	if connected >= 8 {
		return nil
	}
	b.ConnectPeer(ctx, p.Addresses)
	id, _ := peer.Decode(p.Peer)
	if b.host.Network().Connectedness(id) != network.Connected {
		return errors.New("DHT public candidate could not be reached over TCP")
	}
	b.mu.Lock()
	b.publicPeers[id] = true
	b.mu.Unlock()
	b.rememberBootstrap(id, p.Addresses)
	b.opts.Logger.Info("public DHT neighbor connected", "component", "dht-bootstrap", "neighbors", b.BootstrapNeighborCount())
	// This adds a routing neighbor only. It never calls RegisterPeer, sets
	// a WireGuard endpoint, or bypasses the mesh admission/signature checks.
	return nil
}
