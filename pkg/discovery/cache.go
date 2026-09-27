package discovery

import (
	"sort"
	"sync"
	"time"
)

// Cache holds the best verified record seen per device.
//
// It is what lets a node keep working when the DHT goes away: discovery is how
// peers are found the first time, not a per-packet dependency, so a cached
// record plus an established tunnel survives a control-plane outage intact.
type Cache struct {
	mu      sync.RWMutex
	records map[string]PeerRecord
	limit   int
}

// DefaultCacheLimit bounds how many peers one network may hold. A mesh of a
// household's devices is tens; the cap exists so a flooded DHT cannot grow
// this map without end.
const DefaultCacheLimit = 512

// NewCache returns an empty cache. A limit of zero selects the default.
func NewCache(limit int) *Cache {
	if limit <= 0 {
		limit = DefaultCacheLimit
	}
	return &Cache{records: make(map[string]PeerRecord), limit: limit}
}

// Put stores record if it is newer than what is held. It reports whether the
// cache changed, which is what drives "peer updated" events: republishing an
// identical record every thirty seconds must not look like news.
func (c *Cache) Put(record PeerRecord) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	previous, held := c.records[record.DeviceID]
	if held && !record.Supersedes(previous) {
		return false
	}
	if !held && len(c.records) >= c.limit {
		return false
	}
	c.records[record.DeviceID] = record
	return true
}

// PutVerified accepts only fresh, network-matching records. Cache is often
// restored from disk before the controller sees it, so callers must not need
// to remember a second verification pass before reading a peer entry.
func (c *Cache) PutVerified(record PeerRecord, networkID string, now time.Time) error {
	if err := record.Verify(networkID, now); err != nil {
		return err
	}
	c.Put(record)
	return nil
}

// Get returns the record held for a device.
func (c *Cache) Get(deviceID string) (PeerRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	record, ok := c.records[deviceID]
	return record, ok
}

// List returns every record that has not expired, ordered by device id so the
// output of `nknguard peers` is stable between runs.
func (c *Cache) List(now time.Time) []PeerRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]PeerRecord, 0, len(c.records))
	for _, record := range c.records {
		if now.Unix() > record.ExpiresAt {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Prune drops expired records and returns how many were removed.
func (c *Cache) Prune(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for id, record := range c.records {
		if now.Unix() > record.ExpiresAt {
			delete(c.records, id)
			removed++
		}
	}
	return removed
}

// Len is the number of records held, expired or not.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.records)
}
