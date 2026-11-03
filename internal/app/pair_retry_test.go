//go:build nknsdk

package app

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"io"
	"sync"
	"testing"
	"time"
)

type lossyPairTransport struct {
	signaling.Transport
	mu           sync.Mutex
	drops, calls int
	ids          map[string]bool
	duplicate    bool
	alwaysFail   bool
}

func (t *lossyPairTransport) SendAddress(ctx context.Context, address string, e protocol.Envelope) error {
	t.mu.Lock()
	t.calls++
	if t.ids == nil {
		t.ids = map[string]bool{}
	}
	if t.ids[e.MessageID] {
		t.duplicate = true
	}
	t.ids[e.MessageID] = true
	drop := t.drops > 0
	if drop {
		t.drops--
	}
	fail := t.alwaysFail
	t.mu.Unlock()
	if fail {
		return errors.New("temporary send failure")
	}
	if drop {
		return nil
	}
	return t.Transport.SendAddress(ctx, address, e)
}
func TestPairRetryRecoversDroppedRequestAndApproval(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	nas, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	network, _, err := nas.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	clientCfg := config.Default()
	clientCfg.Paths.StateDir = t.TempDir()
	client, err := OpenNode(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	sw := signaling.NewSwitch()
	nw := sw.Attach(nas.Device.DeviceID())
	cw := sw.Attach(client.Device.DeviceID())
	nwire := &lossyPairTransport{Transport: nw, drops: 1}
	cwire := &lossyPairTransport{Transport: cw, drops: 1}
	controller := mesh.New()
	controller.Config.NetworkID = network
	controller.Config.RequireApproval = true
	p := NewPairing(nas, controller, nwire)
	invite, err := p.NewInvite()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	dispatch := &signaling.Dispatcher{Acceptor: &protocol.Acceptor{NetworkID: network, LocalDeviceID: nas.Device.DeviceID(), Replay: protocol.NewReplayCache(0, 0)}, Open: map[protocol.MessageType]bool{protocol.TypePairRequest: true}}
	dispatch.Handle(protocol.TypePairRequest, p.HandleRequest)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case in := <-nw.Receive():
				if dispatch.Dispatch(ctx, in) == nil && len(p.Pending()) > 0 {
					_ = p.Approve(ctx, client.Device.DeviceID())
				}
			}
		}
	}()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	result, err := pairExchange(ctx, client, invite, "windows", key, cwire, io.Discard, 50*time.Millisecond)
	cancel()
	<-done
	if err != nil || result.NASID != nas.Device.DeviceID() {
		t.Fatalf("retry failed: %+v %v", result, err)
	}
	cwire.mu.Lock()
	if cwire.calls < 3 || cwire.duplicate {
		t.Error("requests not retried with fresh message IDs")
	}
	cwire.mu.Unlock()
	nwire.mu.Lock()
	if nwire.calls < 2 {
		t.Error("lost approval not resent")
	}
	nwire.mu.Unlock()
	stored, err := client.State.LoadMembership()
	if err != nil || stored.MemberAddresses[invite.NASID] != invite.NASAddress {
		t.Fatal("NAS identity/address not persisted")
	}
	// An approved-but-revoked device must never recover its old credential.
	if err = p.Revoke(context.Background(), client.Device.DeviceID()); err != nil {
		t.Fatal(err)
	}
	if len(p.recent) != 0 {
		t.Fatal("revoked approval cached")
	}
}
func TestPairRetryBoundAndCancellation(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sw := signaling.NewSwitch()
	wire := &lossyPairTransport{Transport: sw.Attach(node.Device.DeviceID()), alwaysFail: true}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = pairExchange(ctx, node, PairInvite{NetworkID: "test", NASID: "nas", NASAddress: "nas", Token: "test", ExpiresAt: time.Now().Add(time.Minute)}, "test", "key", wire, io.Discard, time.Millisecond)
	if err == nil {
		t.Fatal("expired request succeeded")
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	if wire.calls > 60 || wire.calls < 2 {
		t.Fatalf("unbounded/no retries: %d", wire.calls)
	}
}
