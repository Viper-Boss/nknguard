package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

type recordPublication struct {
	content  string
	at       time.Time
	attempts uint32
}

type recordKeepalive struct {
	RetryDirect   bool               `json:"retry_direct,omitempty"`
	RecordRequest bool               `json:"record_request,omitempty"`
	Renewal       *discovery.Renewal `json:"record_renewal,omitempty"`
}

// Renew at one third of the signed lifetime, leaving room for a lost refresh.
// Discovery always receives a full signed record; only capable peers get deltas.
func renewalInterval(record discovery.PeerRecord) time.Duration {
	interval := time.Duration(record.ExpiresAt-record.IssuedAt) * time.Second / 3
	if interval < time.Second {
		return time.Second
	}
	return interval
}

func offlineInterval(base time.Duration, attempts uint32) time.Duration {
	if base <= 0 {
		base = 15 * time.Second
	}
	for i := uint32(1); i < attempts && base < 5*time.Minute; i++ {
		base *= 2
	}
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	return base
}

func (c *Controller) discoveryPublicationDue(record discovery.PeerRecord, now time.Time) bool {
	c.mu.RLock()
	previous := c.publications[""]
	c.mu.RUnlock()
	return previous.content != discovery.ContentID(record) || now.Sub(previous.at) >= renewalInterval(record)
}

func (c *Controller) notePublication(id string, record discovery.PeerRecord, now time.Time, offline bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	previous := c.publications[id]
	previous.content, previous.at = discovery.ContentID(record), now
	if offline {
		previous.attempts++
	} else {
		previous.attempts = 0
	}
	c.publications[id] = previous
}

func (c *Controller) publishToPeer(ctx context.Context, id string, record discovery.PeerRecord, force bool) error {
	peer, ok := c.lookupPeer(id)
	if !ok || peer.Revoked() || !c.Authorized(id) {
		return nil
	}
	c.mu.RLock()
	previous := c.publications[id]
	c.mu.RUnlock()
	now := time.Now()
	if c.Config.OwnerDevice && !c.ownerConnectionActive(id, now) {
		return nil
	}
	content := discovery.ContentID(record)
	offline := peer.Path() == PathNone
	interval := renewalInterval(record)
	if offline {
		interval = offlineInterval(c.Config.Timing.PollInterval, previous.attempts)
	}
	if !force && previous.content == content && now.Sub(previous.at) < interval {
		return nil
	}
	var err error
	if !force && !offline && previous.content == content && protocol.HasCapability(peer.Record().Capabilities, protocol.CapRecordRenewalV1) {
		renewal := discovery.NewRenewal(record)
		err = c.send(ctx, id, protocol.TypeKeepalive, recordKeepalive{Renewal: &renewal})
	} else {
		var raw []byte
		raw, err = record.Marshal()
		if err == nil {
			err = c.send(ctx, id, protocol.TypePeerInfo, protocol.PeerInfo{Record: raw})
		}
	}
	if err == nil {
		c.notePublication(id, record, now, offline)
	}
	return err
}

func (c *Controller) requestFullRecord(ctx context.Context, id string) error {
	if !c.Authorized(id) {
		return nil
	}
	if c.Config.OwnerDevice && !c.ownerConnectionActive(id, time.Now()) {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	if last, ok := c.recordRequests[id]; ok && now.Sub(last) < 30*time.Second {
		c.mu.Unlock()
		return nil
	}
	c.recordRequests[id] = now
	c.mu.Unlock()
	return c.send(ctx, id, protocol.TypeKeepalive, recordKeepalive{RecordRequest: true})
}

func (c *Controller) onRecordKeepalive(ctx context.Context, envelope protocol.Envelope) error {
	if len(envelope.Payload) == 0 {
		return nil
	}
	var request recordKeepalive
	if err := json.Unmarshal(envelope.Payload, &request); err != nil {
		return err
	}
	id := envelope.FromDeviceID
	if !c.Authorized(id) {
		return nil
	}
	if request.RetryDirect {
		c.Reconnect(id)
	}
	if request.Renewal != nil {
		peer, ok := c.lookupPeer(id)
		if !ok {
			return c.requestFullRecord(ctx, id)
		}
		record, err := request.Renewal.Apply(peer.Record(), c.Config.NetworkID, time.Now())
		if errors.Is(err, discovery.ErrRenewalBase) {
			return c.requestFullRecord(ctx, id)
		}
		if errors.Is(err, discovery.ErrRecordSuperseded) {
			return nil
		}
		if err != nil {
			return err
		}
		c.ingestRecord(ctx, record)
	}
	if request.RecordRequest {
		// A burst of missing-base requests must not cause full-record fanout.
		now := time.Now()
		c.mu.Lock()
		key := "reply:" + id
		if last, ok := c.recordRequests[key]; ok && now.Sub(last) < 5*time.Second {
			c.mu.Unlock()
			return nil
		}
		c.recordRequests[key] = now
		c.mu.Unlock()
		record, err := c.buildRecord(ctx)
		if err != nil {
			return err
		}
		return c.publishToPeer(ctx, id, record, true)
	}
	return nil
}
