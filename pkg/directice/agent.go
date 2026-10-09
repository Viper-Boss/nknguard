// Package directice establishes an authenticated UDP path independently of
// WireGuard's current endpoint. Only encrypted WireGuard datagrams use it.
package directice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
)

const MaxCandidates = 32

// Description travels only in signed, encrypted peer-to-peer signalling.
// Credentials are ephemeral and must never enter public discovery or logs.
type Description struct {
	ID         string   `json:"id"`
	Ufrag      string   `json:"ufrag"`
	Password   string   `json:"password"`
	Candidates []string `json:"candidates"`
}

type Config struct {
	STUNServers []string
	// Interfaces supplies Android's actual underlying addresses without using
	// restricted netlink enumeration. Ordinary socket operations remain native.
	Interfaces func() ([]net.Addr, error)
	// IncludeLoopback is for isolated transport tests only.
	IncludeLoopback bool
}

type Session struct {
	agent           *ice.Agent
	once            sync.Once
	includeLoopback bool
}

func (s *Session) Close() { s.once.Do(func() { _ = s.agent.Close() }) }

func (cfg Config) Prepare(ctx context.Context, id string) (*Session, Description, error) {
	var urls []*stun.URI
	for _, raw := range cfg.STUNServers {
		if !strings.HasPrefix(raw, "stun:") {
			raw = "stun:" + raw
		}
		if uri, err := stun.ParseURI(raw); err == nil && uri.Scheme == stun.SchemeTypeSTUN {
			urls = append(urls, uri)
		}
		if len(urls) == 3 {
			break
		}
	}
	stunTimeout, disconnected, failed, keepalive := 2*time.Second, 10*time.Second, 20*time.Second, 3*time.Second
	config := &ice.AgentConfig{
		Urls: urls, NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		MulticastDNSMode: ice.MulticastDNSModeDisabled, IncludeLoopback: cfg.IncludeLoopback,
		STUNGatherTimeout: &stunTimeout, DisconnectedTimeout: &disconnected, FailedTimeout: &failed, KeepaliveInterval: &keepalive,
		InterfaceFilter: func(name string) bool {
			for _, prefix := range []string{"wg", "nkg", "tun", "tailscale", "docker", "veth", "br-", "virbr"} {
				if strings.HasPrefix(name, prefix) {
					return false
				}
			}
			return true
		},
		IPFilter: func(ip net.IP) bool {
			addr, ok := netip.AddrFromSlice(ip)
			return ok && !netip.MustParsePrefix("10.88.0.0/16").Contains(addr.Unmap()) &&
				((cfg.IncludeLoopback && addr.IsLoopback()) || (addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast()))
		},
	}
	if cfg.Interfaces != nil {
		// Do not call NewNet: it eagerly enumerates interfaces, which Android
		// may reject before our supplied address list can be used.
		config.Net = &addressNet{Net: &stdnet.Net{}, addresses: cfg.Interfaces}
	}
	agent, err := ice.NewAgent(config)
	if err != nil {
		return nil, Description{}, err
	}
	s := &Session{agent: agent, includeLoopback: cfg.IncludeLoopback}
	var mu sync.Mutex
	desc := Description{ID: id}
	desc.Ufrag, desc.Password, err = agent.GetLocalUserCredentials()
	if err != nil {
		s.Close()
		return nil, Description{}, err
	}
	done := make(chan struct{})
	err = agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			close(done)
			return
		}
		mu.Lock()
		if len(desc.Candidates) < MaxCandidates {
			desc.Candidates = append(desc.Candidates, candidate.Marshal())
		}
		mu.Unlock()
	})
	if err == nil {
		err = agent.GatherCandidates()
	}
	if err != nil {
		s.Close()
		return nil, Description{}, err
	}
	select {
	case <-ctx.Done():
		s.Close()
		return nil, Description{}, ctx.Err()
	case <-done:
	}
	mu.Lock()
	out := desc
	out.Candidates = append([]string(nil), desc.Candidates...)
	mu.Unlock()
	if len(out.Candidates) == 0 {
		s.Close()
		return nil, Description{}, errors.New("ice: no usable local candidates")
	}
	return s, out, nil
}

func Validate(desc Description) error {
	if len(desc.ID) != 32 || len(desc.Ufrag) < 4 || len(desc.Ufrag) > 256 || len(desc.Password) < 22 || len(desc.Password) > 256 ||
		len(desc.Candidates) == 0 || len(desc.Candidates) > MaxCandidates {
		return errors.New("ice: invalid description")
	}
	for _, raw := range desc.Candidates {
		if len(raw) > 1024 {
			return errors.New("ice: oversized candidate")
		}
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			return errors.New("ice: malformed candidate")
		}
		addr, err := netip.ParseAddr(candidate.Address())
		if err != nil || candidate.Component() != 1 || candidate.Port() <= 0 || !candidate.NetworkType().IsUDP() ||
			addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || netip.MustParsePrefix("10.88.0.0/16").Contains(addr.Unmap()) {
			return errors.New("ice: unusable candidate")
		}
	}
	return nil
}

func (s *Session) Connect(ctx context.Context, remote Description, controlling bool) (net.Conn, error) {
	if err := Validate(remote); err != nil {
		return nil, err
	}
	for _, raw := range remote.Candidates {
		candidate, _ := ice.UnmarshalCandidate(raw)
		addr, _ := netip.ParseAddr(candidate.Address())
		if addr.IsLoopback() && !s.includeLoopback {
			return nil, errors.New("ice: remote loopback candidate rejected")
		}
		if err := s.agent.AddRemoteCandidate(candidate); err != nil {
			return nil, err
		}
	}
	var conn *ice.Conn
	var err error
	if controlling {
		conn, err = s.agent.Dial(ctx, remote.Ufrag, remote.Password)
	} else {
		conn, err = s.agent.Accept(ctx, remote.Ufrag, remote.Password)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type addressNet struct {
	transport.Net
	addresses func() ([]net.Addr, error)
}

func (n *addressNet) Interfaces() ([]*transport.Interface, error) {
	addresses, err := n.addresses()
	if err != nil {
		return nil, err
	}
	iface := transport.NewInterface(net.Interface{Index: 1, Name: "underlying", MTU: 1500, Flags: net.FlagUp})
	for _, addr := range addresses {
		iface.AddAddress(addr)
	}
	return []*transport.Interface{iface}, nil
}
