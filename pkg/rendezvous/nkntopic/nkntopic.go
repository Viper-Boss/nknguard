//go:build nknsdk

// Package nkntopic uses an NKN pub/sub topic as a rendezvous point.
//
// Every node of a network subscribes its NKN address to the same topic, and
// listing the topic's subscribers yields the addresses to introduce ourselves
// to. The topic name is derived from the join secret (membership.Key
// .Rendezvous), so the subscriber list is not an index of a network anyone
// can look up by its id.
//
// What this costs and exposes, stated plainly: a subscription is an on-chain
// NKN transaction (zero fee, rate-limited by the chain), and the subscriber
// list is public — anyone who knows the topic name can see which NKN addresses
// are in it. Addresses are not device identities and reveal no IP, but they
// are linkable over time. Deployments that care use a static peer list instead.
package nkntopic

import (
	"context"
	"sync"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
)

// Subscription pacing. A subscription lasts DurationBlocks (~24h at the NKN
// chain's ~20s block time) and is renewed at half-life, so a node that goes
// down disappears from the list within a day and a running node never lapses.
const (
	DurationBlocks = 4320
	RenewEvery     = 12 * time.Hour
	RetryEvery     = 5 * time.Minute
	// ListEvery caps subscriber queries, which are RPC calls to NKN nodes.
	ListEvery = time.Minute
)

// Source implements rendezvous.Source.
type Source struct {
	client  *nkn.MultiClient
	topic   string
	seedRPC []string

	mu          sync.Mutex
	lastSub     time.Time
	lastAttempt time.Time
	lastList    time.Time
	cached      []string
}

// New returns a topic rendezvous.
func New(client *nkn.MultiClient, topic string, seedRPC []string) *Source {
	return &Source{client: client, topic: topic, seedRPC: seedRPC}
}

// Announce subscribes (or renews) when due.
func (s *Source) Announce(context.Context) error {
	s.mu.Lock()
	now := time.Now()
	due := s.lastSub.IsZero() || now.Sub(s.lastSub) >= RenewEvery
	retrying := !s.lastAttempt.IsZero() && now.Sub(s.lastAttempt) < RetryEvery && s.lastSub.Before(s.lastAttempt)
	if !due || retrying {
		s.mu.Unlock()
		return nil
	}
	s.lastAttempt = now
	s.mu.Unlock()

	// Fee nil = zero fee; the subscription costs nothing beyond the on-chain
	// record itself, as in NasSimHub's nknpeer tool.
	if _, err := s.client.Subscribe(nknclient.Identifier, s.topic, DurationBlocks, "", nil); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastSub = time.Now()
	s.mu.Unlock()
	return nil
}

// Addresses lists the topic's subscribers, cached for ListEvery.
func (s *Source) Addresses(context.Context) ([]string, error) {
	s.mu.Lock()
	if !s.lastList.IsZero() && time.Since(s.lastList) < ListEvery {
		out := append([]string(nil), s.cached...)
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()

	config := &nkn.RPCConfig{RPCTimeout: 10000, RPCConcurrency: 2}
	if len(s.seedRPC) > 0 {
		config.SeedRPCServerAddr = nkn.NewStringArray(s.seedRPC...)
	}
	// txPool=true includes subscriptions not yet in a block, so a node that
	// just subscribed is visible within seconds instead of a block later.
	result, err := nkn.GetSubscribers(s.topic, 0, 0, false, true, nil, config)
	if err != nil {
		return nil, err
	}
	var addresses []string
	if result != nil && result.Subscribers != nil {
		for address := range result.Subscribers.Map() {
			addresses = append(addresses, address)
		}
	}
	if result != nil && result.SubscribersInTxPool != nil {
		for address := range result.SubscribersInTxPool.Map() {
			addresses = append(addresses, address)
		}
	}
	s.mu.Lock()
	s.cached = addresses
	s.lastList = time.Now()
	s.mu.Unlock()
	return addresses, nil
}

// Close unsubscribes best-effort. A failure is harmless: the subscription
// expires on its own.
func (s *Source) Close() error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.client.Unsubscribe(nknclient.Identifier, s.topic, nil)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return nil
}
