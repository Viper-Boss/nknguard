package mesh

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/controlhub"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

// No shared DHT or owner rendezvous: the phone must obtain the NAS record
// itself, even when its controller starts before the NKN transport opens.
func TestNKNColdStartIntroducesAfterTransportAttaches(t *testing.T) {
	e := newEnv(t)
	nas := e.startWith(t, "nas", "203.0.113.1:51820", e.key, func(c *Controller) {
		c.Discovery, c.Rendezvous = nil, rendezvous.Static{}
		c.Config.OwnerDevice = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := controlhub.New(ctx, nil, nil)
	defer hub.Close()
	phone := e.startWith(t, "phone", "203.0.113.2:51820", e.key, func(c *Controller) {
		c.Discovery = nil
		c.Rendezvous = rendezvous.Static{nas.ctrl.Device.DeviceID()}
		c.Config.ClientDevice = true
		c.Signaling = hub
	})
	time.Sleep(600 * time.Millisecond)
	if err := hub.Attach(phone.sig, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitPath(t, 5*time.Second, phone, nas, PathDirectWG, StateDirect)
}

type loseFirstIntroduction struct {
	signaling.Transport
	lost atomic.Bool
}

func (s *loseFirstIntroduction) SendAddress(ctx context.Context, address string, envelope protocol.Envelope) error {
	if envelope.Type == protocol.TypePeerInfo && s.lost.CompareAndSwap(false, true) {
		return nil // Accepted by the transport, but no reply reaches the phone.
	}
	return s.Transport.SendAddress(ctx, address, envelope)
}

func TestClientRetriesUnansweredNASIntroduction(t *testing.T) {
	e := newEnv(t)
	nas := e.startWith(t, "nas", "203.0.113.1:51820", e.key, func(c *Controller) {
		c.Discovery, c.Rendezvous = nil, rendezvous.Static{}
		c.Config.OwnerDevice = true
	})
	phone := e.startWith(t, "phone", "203.0.113.2:51820", e.key, func(c *Controller) {
		c.Discovery = nil
		c.Rendezvous = rendezvous.Static{nas.ctrl.Device.DeviceID()}
		c.Config.ClientDevice = true
		c.Signaling = &loseFirstIntroduction{Transport: c.Signaling}
	})
	waitPath(t, 5*time.Second, phone, nas, PathDirectWG, StateDirect)
}

func TestNASStaysQuietWithoutClientConnectionRequest(t *testing.T) {
	e := newEnv(t)
	phone := e.startWith(t, "phone", "203.0.113.2:51820", e.key, func(c *Controller) {
		c.Discovery, c.Rendezvous = nil, rendezvous.Static{}
		c.Config.ClientDevice = true
	})
	nas := e.startWith(t, "nas", "203.0.113.1:51820", e.key, func(c *Controller) {
		c.Discovery, c.Rendezvous = nil, rendezvous.Static{}
		c.Config.OwnerDevice, c.Config.RequireApproval = true, true
		// An unknown identity cannot add a bootstrap hint.
		c.RememberApprovedAddress("stranger", "untrusted-address")
		if len(c.bootstrapAddresses) != 0 {
			t.Fatal("unapproved transport hint accepted")
		}
		c.ApproveDevice(phone.ctrl.Device.DeviceID())
		c.RememberApprovedAddress(phone.ctrl.Device.DeviceID(), phone.sig.LocalAddress())
		if len(c.Peers()) != 0 {
			t.Fatal("transport hint bypassed signed record authentication")
		}
	})
	time.Sleep(700 * time.Millisecond)
	if len(nas.ctrl.Peers()) != 0 || len(phone.ctrl.Peers()) != 0 {
		t.Fatal("NAS contacted an idle client without its connection request")
	}
	if _, err := nas.ctrl.RevokeDevice(context.Background(), phone.ctrl.Device.DeviceID()); err != nil {
		t.Fatal(err)
	}
	nas.ctrl.mu.RLock()
	defer nas.ctrl.mu.RUnlock()
	if len(nas.ctrl.bootstrapAddresses) != 0 {
		t.Fatal("revoked address retained")
	}
}
