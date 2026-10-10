package controlhub

import (
	"context"
	"errors"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"sync"
	"testing"
	"time"
)

type failingTransport struct{ signaling.Transport }

func (f failingTransport) Receive() <-chan signaling.Inbound { return nil }
func (f failingTransport) Send(context.Context, string, protocol.Envelope) error {
	return errors.New("unreachable")
}

func TestSecondaryWorksBeforeNKNAndFallbackRemainsAvailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wire := signaling.NewSwitch()
	a, b := wire.Attach("a"), wire.Attach("b")
	h := New(ctx, a, nil)
	defer h.Close()
	if err := h.Send(ctx, "b", protocol.Envelope{FromDeviceID: "a"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Receive():
	case <-time.After(time.Second):
		t.Fatal("secondary depended on NKN")
	}
	nkn := signaling.NewSwitch().Attach("nkn")
	h.SetPeerAddress("b", "b-address")
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.LocalAddress(); h.SetPeerAddress("b", "b-address") }()
	}
	if err := h.Attach(nkn, nil, nil); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if address, _ := nkn.PeerAddress("b"); address != "b-address" {
		t.Fatal("attachment lost known peers")
	}
	if h.Attach(nkn, nil, nil) == nil {
		t.Fatal("repeated attachment accepted")
	}
	other := New(ctx, failingTransport{}, nil)
	defer other.Close()
	if err := other.Attach(a, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := other.Send(ctx, "b", protocol.Envelope{}); err != nil {
		t.Fatal("failed to fall back:", err)
	}
}
