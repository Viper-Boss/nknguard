// Package state persists what a node must remember across restarts.
//
// The test this package is written against: kill the daemon, start it again,
// and every peer that was reachable is reachable, with the same device id and
// the same overlay address, without anyone re-running `join`. A node that has
// to be re-enrolled after a power cut is not something anyone will run on a
// NAS.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/discovery"
)

// FileMode is the permission for state files. They hold no secrets — those are
// in the keystore — but they do hold the membership list, and there is no
// reason for them to be world-readable.
const FileMode fs.FileMode = 0o640

// DirMode is the permission for the state directory.
const DirMode fs.FileMode = 0o750

// Membership is what `nknguard join` produces and the daemon reads on start.
// The join secret is NOT here: it is a secret, it goes in the keystore, and
// keeping it out of this file is what lets the file be readable for debugging.
type Membership struct {
	NetworkID string    `json:"network_id"`
	DeviceID  string    `json:"device_id"`
	JoinedAt  time.Time `json:"joined_at"`
	IsOwner   bool      `json:"is_owner,omitempty"`
	// Members is every device id admitted to the network. In the MVP it grows
	// as peers present a valid join proof; signed invitations replace it in
	// v0.2, which is why it is a list rather than a boolean.
	Members []string `json:"members"`
	// Addresses verified during pairing allow the NAS to request signed peer
	// records after a restart. They are hints, never membership credentials.
	MemberAddresses map[string]string `json:"member_addresses,omitempty"`
	// PendingRemovals survives a crash between revocation and kernel cleanup.
	PendingRemovals []string `json:"pending_wireguard_removals,omitempty"`
}

// Shutdown is written before the control socket closes. A missing completion
// after a crash must not be presented as a successful tunnel cleanup.
type Shutdown struct {
	Completed bool   `json:"completed"`
	Error     string `json:"error,omitempty"`
}

func (s *Store) SaveShutdown(result Shutdown) error { return s.writeJSON("shutdown.json", result) }
func (s *Store) LoadShutdown() (Shutdown, error) {
	var result Shutdown
	err := s.readJSON("shutdown.json", &result)
	return result, err
}

// Runtime is the bookkeeping that must survive a restart but is not a
// membership decision.
type Runtime struct {
	// Sequence is the peer-record counter. It must never go backwards, or
	// peers will reject our records as replays of ones they already hold, so
	// it is persisted before it is used and bumped by a margin on load.
	Sequence uint64 `json:"sequence"`
	// VirtualIP is the overlay address this node settled on. Re-deriving it is
	// deterministic, but a collision resolved by salting is not, so the answer
	// is remembered.
	VirtualIP string `json:"virtual_ip,omitempty"`
	// ProtocolVersion records what this node last spoke, so a downgrade after
	// an upgrade is visible rather than mysterious.
	ProtocolVersion uint32    `json:"protocol_version"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// LinkHint is a previously observed direct endpoint. It is only a probe hint;
// a new WireGuard handshake must confirm it before the UI calls it connected.
type LinkHint struct {
	DeviceID  string    `json:"device_id"`
	PublicKey string    `json:"public_key"`
	Endpoint  string    `json:"endpoint"`
	SeenAt    time.Time `json:"seen_at"`
}

func (s *Store) LoadLinkHints() ([]LinkHint, error) {
	var hints []LinkHint
	err := s.readJSON("links.json", &hints)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return hints, err
}

func (s *Store) SaveLinkHints(hints []LinkHint) error { return s.writeJSON("links.json", hints) }

// SequenceLoadMargin is added to the stored counter on load. A crash between
// bumping the counter and writing it would otherwise reuse a sequence number
// that peers have already seen; skipping ahead costs nothing and closes that
// window.
const SequenceLoadMargin = 16

// Store is the state directory.
type Store struct {
	dir              string
	mu               sync.Mutex
	sequenceMu       sync.Mutex
	reservedSequence uint64
}

// New returns a store rooted at dir.
func New(dir string) *Store { return &Store{dir: dir} }

// Dir is the state directory path.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// LoadMembership reads the membership file. A missing file is not an error: it
// is a node that has not joined anything yet, and the caller says so in
// language an operator can act on.
func (s *Store) LoadMembership() (Membership, error) {
	var membership Membership
	err := s.readJSON("membership.json", &membership)
	if errors.Is(err, fs.ErrNotExist) {
		return Membership{}, nil
	}
	return membership, err
}

// SaveMembership writes the membership file.
func (s *Store) SaveMembership(membership Membership) error {
	return s.writeJSON("membership.json", membership)
}

// LoadRuntime reads the runtime bookkeeping, advancing the sequence counter
// past anything that might already be in flight.
func (s *Store) LoadRuntime() (Runtime, error) {
	var runtime Runtime
	err := s.readJSON("runtime.json", &runtime)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Runtime{}, err
	}
	if err == nil {
		runtime.Sequence += SequenceLoadMargin
	}
	var reservation struct {
		Until uint64 `json:"until"`
	}
	if err := s.readJSON("sequence.json", &reservation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Runtime{}, err
	}
	if reservation.Until > runtime.Sequence {
		runtime.Sequence = reservation.Until
	}
	return runtime, nil
}

// ReserveSequence writes once per 512 signed publications rather than once
// per publication. A restart skips unused numbers; it never reuses them.
func (s *Store) ReserveSequence(next uint64) error {
	s.sequenceMu.Lock()
	defer s.sequenceMu.Unlock()
	if next <= s.reservedSequence {
		return nil
	}
	if next > ^uint64(0)-512 {
		return errors.New("state: sequence exhausted")
	}
	until := next + 512
	if err := s.writeJSON("sequence.json", struct {
		Until uint64 `json:"until"`
	}{until}); err != nil {
		return err
	}
	s.reservedSequence = until
	return nil
}

// SaveRuntime writes the runtime bookkeeping.
func (s *Store) SaveRuntime(runtime Runtime) error {
	runtime.UpdatedAt = time.Now()
	return s.writeJSON("runtime.json", runtime)
}

// LoadPeerCache reads the last known peer records.
//
// This is what makes a control-plane outage survivable: a node that restarts
// while the DHT is unreachable still knows who its peers are and what keys
// they had, so it can bring the interface up and wait for traffic instead of
// sitting isolated until discovery comes back.
func (s *Store) LoadPeerCache() ([]discovery.PeerRecord, error) {
	var records []discovery.PeerRecord
	err := s.readJSON("peers.json", &records)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return records, err
}

// SavePeerCache retains only recently verified records for a bounded
// startup probe. A live message still needs current freshness checks.
func (s *Store) SavePeerCache(records []discovery.PeerRecord) error {
	now := time.Now().Unix()
	live := make([]discovery.PeerRecord, 0, len(records))
	for _, record := range records {
		if record.ExpiresAt > now-int64((7*24*time.Hour).Seconds()) {
			live = append(live, record)
		}
	}
	return s.writeJSON("peers.json", live)
}

func (s *Store) readJSON(name string, target any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("state: decode %s: %w", name, err)
	}
	return nil
}

// writeJSON persists atomically: a crash mid-write leaves the previous file
// intact rather than a truncated one that fails to parse on the next boot.
func (s *Store) writeJSON(name string, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, DirMode); err != nil {
		return fmt.Errorf("state: create %s: %w", s.dir, err)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encode %s: %w", name, err)
	}
	if previous, err := os.ReadFile(s.path(name)); err == nil && string(previous) == string(raw) {
		return nil
	}
	temporary, err := os.CreateTemp(s.dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("state: create temp %s: %w", name, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("state: write %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("state: sync %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("state: close %s: %w", name, err)
	}
	if err := os.Chmod(temporaryName, FileMode); err != nil {
		return fmt.Errorf("state: chmod %s: %w", name, err)
	}
	if err := replaceStateFile(temporaryName, s.path(name)); err != nil {
		return fmt.Errorf("state: install %s: %w", name, err)
	}
	return nil
}
