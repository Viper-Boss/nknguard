// Package identity holds the three keys a NKNGuard node owns and the signed
// statements that bind them together.
//
// The rule this package exists to enforce: a WireGuard key is not a device
// identity, and neither is an NKN address. Both rotate; the device does not.
// A long-lived Ed25519 root key is the device, and it signs short-lived
// bindings that say "this NKN key and this WireGuard key are currently mine".
// Everything a peer receives over the wire is checked back to that root key.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeviceIDPrefix marks a NKNGuard device identifier so it is recognisable in a
// log line that contains a dozen other opaque strings.
const DeviceIDPrefix = "nkg"

var deviceIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Errors returned by this package. They are values so callers can branch on
// them instead of matching strings.
var (
	ErrNoRootKey       = errors.New("identity: no root key")
	ErrBadSignature    = errors.New("identity: signature does not verify")
	ErrBindingExpired  = errors.New("identity: key binding expired")
	ErrBindingMismatch = errors.New("identity: key binding is for another device")
	ErrStaleSequence   = errors.New("identity: sequence went backwards")
)

// DeviceIdentity is the root of a node. The private half never leaves the
// machine that generated it and is never placed in a struct that gets
// marshalled to the wire — Public() is what travels.
type DeviceIdentity struct {
	deviceID string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
}

// Generate creates a fresh root identity.
func Generate() (*DeviceIdentity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate root key: %w", err)
	}
	return FromSeed(priv.Seed())
}

// FromSeed rebuilds an identity from its 32-byte Ed25519 seed, which is what
// the keystore stores on disk.
func FromSeed(seed []byte) (*DeviceIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("identity: unexpected public key type")
	}
	return &DeviceIdentity{deviceID: DeviceIDFromKey(pub), pub: pub, priv: priv}, nil
}

// Seed returns the 32 bytes the keystore persists. Callers must treat the
// result as secret; it is not returned by any accessor that feeds a log or an
// API response.
func (d *DeviceIdentity) Seed() []byte {
	out := make([]byte, ed25519.SeedSize)
	copy(out, d.priv.Seed())
	return out
}

// DeviceID is the stable public name of this device.
func (d *DeviceIdentity) DeviceID() string { return d.deviceID }

// PublicKey is the root verification key peers pin.
func (d *DeviceIdentity) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(d.pub))
	copy(out, d.pub)
	return out
}

// Sign produces a detached signature over message with the root key.
func (d *DeviceIdentity) Sign(message []byte) []byte {
	return ed25519.Sign(d.priv, message)
}

// DeviceIDFromKey derives the device identifier from a root public key. It is
// deterministic, so two nodes independently shown the same key agree on the
// name, and truncated to keep it readable — 80 bits of a SHA-256 is far more
// than enough to name the handful of devices one person owns, and the full key
// is still what authenticates.
func DeviceIDFromKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return DeviceIDPrefix + "_" + deviceIDEncoding.EncodeToString(sum[:10])
}

// ValidDeviceID reports whether text has the shape DeviceIDFromKey produces.
// It says nothing about whether such a device exists or is authorised.
func ValidDeviceID(text string) bool {
	rest, ok := strings.CutPrefix(text, DeviceIDPrefix+"_")
	if !ok || len(rest) != 16 {
		return false
	}
	_, err := deviceIDEncoding.DecodeString(rest)
	return err == nil
}

// KeyBinding is the device's signed claim over a subordinate key. One binding
// covers the NKN identity and the WireGuard identity together because they are
// rotated as a pair in practice and a peer that accepts one without the other
// has half a picture.
type KeyBinding struct {
	DeviceID           string `json:"device_id"`
	RootPublicKey      []byte `json:"root_public_key"`
	NKNPublicKey       []byte `json:"nkn_public_key,omitempty"`
	NKNAddress         string `json:"nkn_address,omitempty"`
	WireGuardPublicKey string `json:"wireguard_public_key,omitempty"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"`
	Sequence           uint64 `json:"sequence"`
	Signature          []byte `json:"signature,omitempty"`
}

// signingBytes is the canonical encoding that the signature covers. It is
// deliberately the JSON of the struct with the signature field cleared: one
// encoder, no second format to keep in sync, and a field added later is
// covered by the signature the day it is added rather than silently ignored.
func (b KeyBinding) signingBytes() ([]byte, error) {
	unsigned := b
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

// NewKeyBinding issues a binding signed by the root identity.
func (d *DeviceIdentity) NewKeyBinding(sequence uint64, lifetime time.Duration, nknPub []byte, nknAddress, wgPublicKey string) (KeyBinding, error) {
	now := time.Now()
	binding := KeyBinding{
		DeviceID:           d.deviceID,
		RootPublicKey:      d.PublicKey(),
		NKNPublicKey:       nknPub,
		NKNAddress:         nknAddress,
		WireGuardPublicKey: wgPublicKey,
		IssuedAt:           now.Unix(),
		ExpiresAt:          now.Add(lifetime).Unix(),
		Sequence:           sequence,
	}
	payload, err := binding.signingBytes()
	if err != nil {
		return KeyBinding{}, fmt.Errorf("identity: encode binding: %w", err)
	}
	binding.Signature = d.Sign(payload)
	return binding, nil
}

// Verify checks a binding standing alone: the signature must verify under the
// root key it carries, the device id must be that key's id, and it must not
// have expired. It does NOT decide whether the device is allowed into a
// network — that is membership, and it lives elsewhere on purpose.
func (b KeyBinding) Verify(now time.Time) error {
	if len(b.RootPublicKey) != ed25519.PublicKeySize {
		return ErrNoRootKey
	}
	if b.DeviceID != DeviceIDFromKey(b.RootPublicKey) {
		return ErrBindingMismatch
	}
	if b.ExpiresAt != 0 && now.Unix() > b.ExpiresAt {
		return ErrBindingExpired
	}
	payload, err := b.signingBytes()
	if err != nil {
		return fmt.Errorf("identity: encode binding: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(b.RootPublicKey), payload, b.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Supersedes reports whether b is a newer statement than previous about the
// same device. A binding that goes backwards in sequence is a replay of a key
// the device has already rotated away from, and accepting it would hand an
// attacker a downgrade.
func (b KeyBinding) Supersedes(previous KeyBinding) bool {
	if previous.DeviceID == "" {
		return true
	}
	if previous.DeviceID != b.DeviceID {
		return false
	}
	return b.Sequence > previous.Sequence
}
