package protocol

import (
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// DefaultReplayWindow is how long a message id is remembered. It must exceed
// MaxClockSkewPast, or a message could age out of the cache while still being
// inside the accepted clock window — which is exactly the gap a replay would
// aim for.
const DefaultReplayWindow = MaxClockSkewPast + time.Minute

// DefaultReplayCapacity bounds the cache. Without a cap, a peer that can make
// us accept messages can also make us allocate without limit.
const DefaultReplayCapacity = 16384

func newMessageID(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

type replayEntry struct {
	id      string
	expires time.Time
}

// ReplayCache remembers recently accepted message ids. It is bounded in both
// time and count: entries expire, and the oldest is evicted when the cache is
// full, so memory is flat no matter what arrives.
type ReplayCache struct {
	mu       sync.Mutex
	window   time.Duration
	capacity int
	order    *list.List
	index    map[string]*list.Element
}

// NewReplayCache returns a cache with the given window and capacity. Zero
// values select the defaults.
func NewReplayCache(window time.Duration, capacity int) *ReplayCache {
	if window <= 0 {
		window = DefaultReplayWindow
	}
	if capacity <= 0 {
		capacity = DefaultReplayCapacity
	}
	return &ReplayCache{
		window:   window,
		capacity: capacity,
		order:    list.New(),
		index:    make(map[string]*list.Element, capacity),
	}
}

// Admit records id and reports whether it is new. A false result means the
// message has been seen inside the window and must be dropped.
func (c *ReplayCache) Admit(id string, now time.Time) bool {
	if id == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	if _, seen := c.index[id]; seen {
		return false
	}
	for c.order.Len() >= c.capacity {
		c.evictOldestLocked()
	}
	c.index[id] = c.order.PushBack(replayEntry{id: id, expires: now.Add(c.window)})
	return true
}

// Len is the number of live entries, for tests and metrics.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *ReplayCache) expireLocked(now time.Time) {
	for {
		front := c.order.Front()
		if front == nil {
			return
		}
		if front.Value.(replayEntry).expires.After(now) {
			return
		}
		c.removeLocked(front)
	}
}

func (c *ReplayCache) evictOldestLocked() {
	if front := c.order.Front(); front != nil {
		c.removeLocked(front)
	}
}

func (c *ReplayCache) removeLocked(element *list.Element) {
	delete(c.index, element.Value.(replayEntry).id)
	c.order.Remove(element)
}
