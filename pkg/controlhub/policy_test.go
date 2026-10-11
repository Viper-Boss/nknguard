package controlhub

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/relay"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

type observedTransport struct {
	signaling.Transport
	health nknclient.ConnectionStatus
	sends  int
	err    error
}

func (t *observedTransport) Receive() <-chan signaling.Inbound            { return nil }
func (t *observedTransport) ConnectionStatus() nknclient.ConnectionStatus { return t.health }
func (t *observedTransport) Send(context.Context, string, protocol.Envelope) error {
	t.sends++
	return t.err
}
func (t *observedTransport) SetPeerAddress(string, string) {}

func TestNKNPrimarySustainedFailoverAndStableRecovery(t *testing.T) {
	ctx := context.Background()
	primary := &observedTransport{health: nknclient.ConnectionStatus{State: "connected"}}
	secondary := &observedTransport{}
	h := New(ctx, secondary, nil)
	defer h.Close()
	now := time.Now()
	h.now = func() time.Time { return now }
	h.unavailableSince = now
	if err := h.Attach(primary, nil, nil); err != nil {
		t.Fatal(err)
	}
	send := func() {
		t.Helper()
		if err := h.Send(ctx, "peer", protocol.Envelope{}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	if primary.sends != 1 || secondary.sends != 0 {
		t.Fatal("healthy NKN was not preferred")
	}
	primary.health.State = "reconnecting"
	primary.err = errors.New("offline")
	if h.DiscoveryFallbackActive() {
		t.Fatal("fallback activated immediately")
	}
	now = now.Add(59 * time.Second)
	if h.DiscoveryFallbackActive() {
		t.Fatal("fallback activated before outage threshold")
	}
	now = now.Add(time.Second)
	if !h.DiscoveryFallbackActive() {
		t.Fatal("sustained outage did not activate DHT")
	}
	send()
	if secondary.sends != 1 {
		t.Fatal("DHT did not carry backup control")
	}
	if _, err := h.Open(ctx, relay.Peer{}); err != relay.ErrNoRelay {
		t.Fatal("DHT became a data relay")
	}
	primary.health.State = "connected"
	primary.err = nil
	if !h.DiscoveryFallbackActive() {
		t.Fatal("recovery skipped stability grace")
	}
	now = now.Add(14 * time.Second)
	if !h.DiscoveryFallbackActive() {
		t.Fatal("switched back too early")
	}
	now = now.Add(time.Second)
	if h.DiscoveryFallbackActive() {
		t.Fatal("stable NKN did not recover")
	}
	send()
	if primary.sends != 2 || secondary.sends != 1 {
		t.Fatal("did not restore NKN priority")
	}
}

func TestNoNKNWaitsBeforeDHTAndInterruptedRecoveryResetsGrace(t *testing.T) {
	h := New(context.Background(), &observedTransport{}, nil)
	defer h.Close()
	now := time.Now()
	h.now = func() time.Time { return now }
	h.unavailableSince = now
	if h.DiscoveryFallbackActive() {
		t.Fatal("startup bypassed NKN grace")
	}
	now = now.Add(time.Minute)
	if !h.DiscoveryFallbackActive() {
		t.Fatal("startup outage never enabled fallback")
	}
	p := &observedTransport{health: nknclient.ConnectionStatus{State: "connected"}}
	if err := h.Attach(p, nil, nil); err != nil {
		t.Fatal(err)
	}
	h.DiscoveryFallbackActive()
	now = now.Add(10 * time.Second)
	p.health.State = "reconnecting"
	h.DiscoveryFallbackActive()
	p.health.State = "connected"
	now = now.Add(10 * time.Second)
	if !h.DiscoveryFallbackActive() {
		t.Fatal("interrupted recovery was counted as stable")
	}
}
