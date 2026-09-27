package discovery

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-process Discovery. It exists for two reasons that are both
// load-bearing: the integration tests need a discovery plane that does not
// touch the network, and a single-host deployment that already knows its peers
// needs somewhere to put them.
//
// Records are verified on the way in exactly as a real backend's are, so a
// test that passes against Memory is testing the same acceptance rules.
type Memory struct {
	mu        sync.Mutex
	networkID string
	records   map[string]PeerRecord
	watchers  []chan PeerRecord
	closed    bool
	// Now is injectable for tests. Nil means time.Now.
	Now func() time.Time
}

// NewMemory returns an empty in-process discovery for one network.
func NewMemory(networkID string) *Memory {
	return &Memory{networkID: networkID, records: make(map[string]PeerRecord)}
}

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Publish verifies and stores a record, then fans it out to watchers.
func (m *Memory) Publish(ctx context.Context, record PeerRecord) error {
	if err := record.Verify(m.networkID, m.now()); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return context.Canceled
	}
	previous, held := m.records[record.DeviceID]
	if held && !record.Supersedes(previous) {
		m.mu.Unlock()
		return ErrRecordSuperseded
	}
	m.records[record.DeviceID] = record
	// Fan out under the lock: removeWatcher closes channels under the same
	// lock, so a send can never race a close. The sends are non-blocking, so
	// holding the lock costs nothing — a watcher that has stopped reading
	// cannot stall the publisher and picks the record up on its next Lookup.
	for _, watcher := range m.watchers {
		select {
		case watcher <- record:
		default:
		}
	}
	m.mu.Unlock()
	return nil
}

// Lookup returns the unexpired records for a network.
func (m *Memory) Lookup(ctx context.Context, networkID string) ([]PeerRecord, error) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PeerRecord, 0, len(m.records))
	for _, record := range m.records {
		if record.NetworkID != networkID || now.Unix() > record.ExpiresAt {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

// Watch returns a channel of records published after the call. The channel is
// closed when ctx is done or the backend is closed, so a ranging consumer
// terminates without a separate signal.
func (m *Memory) Watch(ctx context.Context, networkID string) (<-chan PeerRecord, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, context.Canceled
	}
	channel := make(chan PeerRecord, 16)
	m.watchers = append(m.watchers, channel)
	m.mu.Unlock()

	go func() {
		<-ctx.Done()
		m.removeWatcher(channel)
	}()
	return channel, nil
}

func (m *Memory) removeWatcher(channel chan PeerRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for index, existing := range m.watchers {
		if existing == channel {
			m.watchers = append(m.watchers[:index], m.watchers[index+1:]...)
			close(channel)
			return
		}
	}
}

// Close releases every watcher.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for _, watcher := range m.watchers {
		close(watcher)
	}
	m.watchers = nil
	return nil
}
