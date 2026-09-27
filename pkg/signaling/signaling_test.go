package signaling

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

func TestDispatcherGatesByMembershipExceptOpenTypes(t *testing.T) {
	alice, _ := identity.Generate()
	bob, _ := identity.Generate()
	handled := map[protocol.MessageType]int{}
	dispatcher := &Dispatcher{
		Acceptor:   &protocol.Acceptor{NetworkID: "n", LocalDeviceID: bob.DeviceID(), Replay: protocol.NewReplayCache(0, 0)},
		Authorized: func(string) bool { return false },
		Open:       map[protocol.MessageType]bool{protocol.TypePeerInfo: true},
		OpenLimit:  NewRateLimiter(1, 2),
	}
	for _, kind := range []protocol.MessageType{protocol.TypeHello, protocol.TypePeerInfo} {
		kind := kind
		dispatcher.Handle(kind, func(context.Context, protocol.Envelope) error { handled[kind]++; return nil })
	}
	send := func(kind protocol.MessageType) error {
		envelope, _ := protocol.Seal(alice, "n", bob.DeviceID(), kind, nil)
		return dispatcher.Dispatch(context.Background(), Inbound{Envelope: envelope})
	}
	if err := send(protocol.TypeHello); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("non-member HELLO: %v", err)
	}
	if err := send(protocol.TypePeerInfo); err != nil {
		t.Fatalf("non-member PEER_INFO: %v", err)
	}
	_ = send(protocol.TypePeerInfo)
	if err := send(protocol.TypePeerInfo); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("burst beyond limit: %v", err)
	}
	if handled[protocol.TypeHello] != 0 || handled[protocol.TypePeerInfo] != 2 {
		t.Fatalf("handled: %v", handled)
	}
}

func TestRateLimiterRefills(t *testing.T) {
	clock := time.Now()
	limiter := NewRateLimiter(10, 1)
	limiter.now = func() time.Time { return clock }
	if !limiter.Allow() || limiter.Allow() {
		t.Fatal("burst of 1 not enforced")
	}
	clock = clock.Add(150 * time.Millisecond)
	if !limiter.Allow() {
		t.Fatal("bucket did not refill")
	}
}

func TestLoopbackRoundTripsTheWireFormat(t *testing.T) {
	alice, _ := identity.Generate()
	fabric := NewSwitch()
	a, b := fabric.Attach("a"), fabric.Attach("b")
	envelope, _ := protocol.Seal(alice, "n", "", protocol.TypeKeepalive, nil)
	if err := a.Send(context.Background(), "b", envelope); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.Receive():
		if got.Envelope.MessageID != envelope.MessageID || got.Source != "a" {
			t.Fatalf("got %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing delivered")
	}
	a.SetDrop(true)
	_ = a.Send(context.Background(), "b", envelope)
	select {
	case <-b.Receive():
		t.Fatal("dropped port still delivered")
	case <-time.After(50 * time.Millisecond):
	}
}
