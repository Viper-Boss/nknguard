// Package discovery publishes and finds signed peer records.
//
// The store a record travels through — a Kademlia DHT, an NKN topic, a file on
// a USB stick — is untrusted by construction. Everything that matters is in
// the record's signature, so a poisoned DHT can waste our time but cannot
// redirect a tunnel.
package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/nat"
)

// RecordVersion is the peer record schema version.
const RecordVersion uint32 = 1

// TTL bounds. A record that never expires is a permanent instruction to dial
// an address that stopped being ours months ago.
const (
	MinRecordTTL     = 30 * time.Second
	MaxRecordTTL     = 5 * time.Minute
	DefaultRecordTTL = 2 * time.Minute
)

// MaxRecordBytes caps a record so a lookup cannot be used to hand us an
// arbitrarily large allocation.
const MaxRecordBytes = 16 * 1024

// Errors a record can fail with.
var (
	ErrRecordTooLarge    = errors.New("discovery: record exceeds size limit")
	ErrBadSignature      = errors.New("discovery: record signature does not verify")
	ErrWrongNetwork      = errors.New("discovery: record is for another network")
	ErrRecordExpired     = errors.New("discovery: record has expired")
	ErrRecordSuperseded  = errors.New("discovery: record is older than the one held")
	ErrDeviceMismatch    = errors.New("discovery: device id does not match root key")
	ErrUnsupported       = errors.New("discovery: unsupported record version")
	ErrInvalidRecordTime = errors.New("discovery: invalid issue or expiry time")
)

// PeerRecord is what a device publishes about itself. It is self-authenticating:
// the root public key is in the record, the device id is derived from that key,
// and the signature covers everything else.
type PeerRecord struct {
	Version uint32 `json:"version"`

	NetworkID string `json:"network_id"`
	DeviceID  string `json:"device_id"`
	Name      string `json:"name,omitempty"`

	RootPublicKey []byte   `json:"root_public_key"`
	NKNPublicKey  []byte   `json:"nkn_public_key,omitempty"`
	NKNAddress    string   `json:"nkn_address,omitempty"`
	DHTAddresses  []string `json:"dht_addresses,omitempty"`

	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	VirtualIPs         []string `json:"virtual_ips,omitempty"`

	Candidates []nat.EndpointCandidate `json:"candidates,omitempty"`

	Capabilities []string `json:"capabilities,omitempty"`

	// MembershipProof is an HMAC over (network, device, root key) under a key
	// derived from the join secret. It is inside the signed region, so it
	// cannot be moved onto another device's record.
	MembershipProof []byte `json:"membership_proof,omitempty"`

	Sequence  uint64 `json:"sequence"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`

	Signature []byte `json:"signature,omitempty"`
}

func (r PeerRecord) signingBytes() ([]byte, error) {
	unsigned := r
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

// Sign fills in the derived fields and signs the record with the root key.
// Sequence must increase across the life of a device; the state store keeps it
// and bumps it on every republish.
func Sign(device *identity.DeviceIdentity, record PeerRecord, sequence uint64, ttl time.Duration, now time.Time) (PeerRecord, error) {
	if ttl < MinRecordTTL {
		ttl = MinRecordTTL
	}
	if ttl > MaxRecordTTL {
		ttl = MaxRecordTTL
	}
	record.Version = RecordVersion
	record.DeviceID = device.DeviceID()
	record.RootPublicKey = device.PublicKey()
	record.Sequence = sequence
	record.IssuedAt = now.Unix()
	record.ExpiresAt = now.Add(ttl).Unix()
	record.Signature = nil

	payload, err := record.signingBytes()
	if err != nil {
		return PeerRecord{}, fmt.Errorf("discovery: encode record: %w", err)
	}
	record.Signature = device.Sign(payload)
	return record, nil
}

// Verify checks a record against the network we are in and the clock. It does
// not check membership: finding a peer is not the same as being allowed to
// build a tunnel with it, and the two checks live in different packages so
// that the distinction cannot quietly erode.
func (r PeerRecord) Verify(networkID string, now time.Time) error {
	if r.Version != RecordVersion {
		return ErrUnsupported
	}
	if networkID != "" && r.NetworkID != networkID {
		return ErrWrongNetwork
	}
	if len(r.RootPublicKey) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if r.DeviceID != identity.DeviceIDFromKey(r.RootPublicKey) {
		return ErrDeviceMismatch
	}
	if r.IssuedAt == 0 || r.ExpiresAt <= r.IssuedAt || now.Unix() > r.ExpiresAt {
		return ErrRecordExpired
	}
	// Reject timestamps too far in either direction, including records whose
	// claimed TTL is longer than the signed-record policy allows.
	if r.IssuedAt > now.Add(30*time.Second).Unix() || r.IssuedAt < now.Add(-MaxRecordTTL).Unix() ||
		time.Unix(r.ExpiresAt, 0).Sub(time.Unix(r.IssuedAt, 0)) > MaxRecordTTL {
		return ErrInvalidRecordTime
	}
	payload, err := r.signingBytes()
	if err != nil {
		return fmt.Errorf("discovery: encode record: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(r.RootPublicKey), payload, r.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Marshal encodes a record and enforces the size cap.
func (r PeerRecord) Marshal() ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("discovery: marshal record: %w", err)
	}
	if len(raw) > MaxRecordBytes {
		return nil, ErrRecordTooLarge
	}
	return raw, nil
}

// UnmarshalRecord decodes a record without verifying it.
func UnmarshalRecord(raw []byte) (PeerRecord, error) {
	if len(raw) > MaxRecordBytes {
		return PeerRecord{}, ErrRecordTooLarge
	}
	var record PeerRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return PeerRecord{}, fmt.Errorf("discovery: decode record: %w", err)
	}
	return record, nil
}

// Supersedes reports whether r is newer than previous for the same device.
func (r PeerRecord) Supersedes(previous PeerRecord) bool {
	if previous.DeviceID == "" {
		return true
	}
	if previous.DeviceID != r.DeviceID {
		return false
	}
	if r.Sequence != previous.Sequence {
		return r.Sequence > previous.Sequence
	}
	// Equal sequence with a later issue time happens when a device restarts
	// and reloads its counter; taking the later one keeps a restarted node
	// reachable without letting an old record win.
	return r.IssuedAt > previous.IssuedAt
}

// Refresh returns a newly signed version of an otherwise identical record
// with a bounded lifetime. It prevents a long-running node from publishing
// an expired or effectively immortal entry by accident.
func Refresh(device *identity.DeviceIdentity, record PeerRecord, sequence uint64, ttl time.Duration, now time.Time) (PeerRecord, error) {
	return Sign(device, record, sequence, ttl, now)
}

// Discovery is the peer-location plane. Implementations are free to be as
// decentralised or as dumb as the deployment needs; the contract is only that
// records go in and come out unmodified, because anything that modified one
// would break its signature and be dropped.
type Discovery interface {
	Publish(ctx context.Context, record PeerRecord) error
	Lookup(ctx context.Context, networkID string) ([]PeerRecord, error)
	Watch(ctx context.Context, networkID string) (<-chan PeerRecord, error)
	Close() error
}
