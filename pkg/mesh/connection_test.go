package mesh

import (
	"context"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous"
	"testing"
	"time"
)

func TestSignedDisconnectClosesDirectAndRelayAndRetainsApproval(t *testing.T) {
	for _, path := range []PathType{PathDirectWG, PathNKNRelay} {
		t.Run(string(path), func(t *testing.T) {
			e := newEnv(t)
			e.fake.setBlocked(path == PathNKNRelay)
			nas := e.startWith(t, "nas", "203.0.113.1:51820", e.key, func(c *Controller) {
				c.Config.OwnerDevice = true
				c.Discovery = nil
				c.Rendezvous = rendezvous.Static{}
			})
			phone := e.startWith(t, "phone", "203.0.113.2:51820", e.key, func(c *Controller) {
				c.Config.ClientDevice = true
				c.Discovery = nil
				c.Rendezvous = rendezvous.Static{nas.ctrl.Device.DeviceID()}
			})
			state := StateDirect
			if path == PathNKNRelay {
				state = StateRelay
			}
			waitPath(t, 10*time.Second, phone, nas, path, state)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			phone.ctrl.NotifyDisconnect(ctx)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				phase, _ := nas.ctrl.ConnectionStatus(phone.ctrl.Device.DeviceID())
				if phase == "disconnected" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			phase, _ := nas.ctrl.ConnectionStatus(phone.ctrl.Device.DeviceID())
			if phase != "disconnected" || nas.ctrl.bridgeFor(phone.ctrl.Device.DeviceID()) != nil || nas.ctrl.icePathFor(phone.ctrl.Device.DeviceID()) != nil {
				t.Fatal("disconnect left a connection alive")
			}
			if !nas.ctrl.Authorized(phone.ctrl.Device.DeviceID()) {
				t.Fatal("disconnect removed pairing")
			}
			stats, _ := nas.wg.Stats(ctx)
			if len(stats) != 0 {
				t.Fatal("WireGuard peer survived disconnect")
			}
		})
	}
}

func TestConnectionLeaseDoesNotExtendOnRetry(t *testing.T) {
	c := New()
	c.Config.OwnerDevice = true
	now := time.Now()
	req := protocol.PeerInfo{ConnectionID: "first", ConnectUntil: now.Add(40 * time.Second).Unix()}
	if !c.acceptConnectionRequest("phone", req, now.Unix()) {
		t.Fatal("fresh request refused")
	}
	before := c.connections["phone"].until
	req.ConnectUntil = now.Add(80 * time.Second).Unix()
	if !c.acceptConnectionRequest("phone", req, now.Unix()+1) || !c.connections["phone"].until.Equal(before) {
		t.Fatal("a retry extended the lease")
	}
	c.stopOwnerConnection("phone", "first", "disconnect")
	if c.acceptConnectionRequest("phone", req, now.Unix()+2) || c.ownerConnectionActive("phone", now) {
		t.Fatal("delayed retry revived a disconnected session")
	}
	req.ConnectionID = "second"
	if !c.acceptConnectionRequest("phone", req, now.Unix()+3) {
		t.Fatal("new connection refused")
	}
	c.stopOwnerConnection("phone", "first", "stale disconnect")
	if !c.ownerConnectionActive("phone", now) {
		t.Fatal("old disconnect closed the new connection")
	}
}

func TestRecoveryCountdownDoesNotSlideAndClosesBothPaths(t *testing.T) {
	c := New()
	c.Config.OwnerDevice = true
	now := time.Now()
	c.connections["phone"] = connectionWindow{id: "x", online: true}
	if !c.updateConnection("phone", false, now) {
		t.Fatal("recovery refused")
	}
	until := c.connections["phone"].until
	c.updateConnection("phone", false, now.Add(60*time.Second))
	if !c.connections["phone"].until.Equal(until) {
		t.Fatal("recovery deadline moved")
	}
	phase, remaining := c.ConnectionStatus("phone")
	if phase != "reconnecting" || remaining < 89 || remaining > 91 {
		t.Fatalf("bad countdown %s %d", phase, remaining)
	}
	if c.updateConnection("phone", false, until.Add(time.Second)) {
		t.Fatal("retry continued after timeout")
	}
	phase, remaining = c.ConnectionStatus("phone")
	if phase != "disconnected" || remaining != 0 || c.ownerConnectionActive("phone", now) {
		t.Fatal("timeout did not stop connection")
	}
}

func TestEitherDataPathRecoveryClearsCountdown(t *testing.T) {
	for _, path := range []PathType{PathDirectWG, PathNKNRelay} {
		t.Run(string(path), func(t *testing.T) {
			c := New()
			c.Config.ClientDevice = true
			now := time.Now()
			c.connections["nas"] = connectionWindow{online: true}
			c.updateConnection("nas", false, now)
			c.updateConnection("nas", true, now.Add(5*time.Second))
			phase, remaining := c.ConnectionStatus("nas")
			if phase != "connected" || remaining != 0 {
				t.Fatal("healthy path left recovery active")
			}
		})
	}
}
