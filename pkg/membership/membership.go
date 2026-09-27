// Package membership decides who belongs to a network.
//
// The MVP model is a network id plus a join secret. Knowing the secret is
// what makes a device a member; the secret itself never leaves the keystore,
// and what travels is an HMAC proof bound to the device's root key. So a proof
// copied out of the DHT is useless to anyone else: it names one device id, and
// only the holder of that device's root key can sign a record carrying it.
//
// Signed invitations and revocation (spec §25) replace this in v0.2. The
// interface below is shaped so that swap touches this package and nothing
// else.
package membership

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
)

// NetworkIDPrefix marks a network identifier.
const NetworkIDPrefix = "nkgnet"

// Sizes. The network id is public-ish (it appears in records and envelopes),
// so its entropy only has to make it unguessable; the join secret is the
// actual credential and gets a full 256 bits.
const (
	networkIDBytes  = 16
	joinSecretBytes = 32
)

var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Errors.
var (
	ErrBadNetworkID  = errors.New("membership: malformed network id")
	ErrBadJoinSecret = errors.New("membership: malformed join secret")
	ErrNoProof       = errors.New("membership: record carries no membership proof")
	ErrBadProof      = errors.New("membership: membership proof does not verify")
)

// NewNetworkID returns a fresh high-entropy network id. It is random rather
// than derived from anything about the creator — not a username, not a MAC,
// not an address — so it identifies the network and nothing else.
func NewNetworkID() (string, error) {
	raw := make([]byte, networkIDBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("membership: network id: %w", err)
	}
	return NetworkIDPrefix + "_" + encoding.EncodeToString(raw), nil
}

// ValidNetworkID checks the shape of a network id.
func ValidNetworkID(id string) bool {
	rest, ok := strings.CutPrefix(id, NetworkIDPrefix+"_")
	if !ok {
		return false
	}
	raw, err := encoding.DecodeString(rest)
	return err == nil && len(raw) == networkIDBytes
}

// NewJoinSecret returns a fresh join secret.
func NewJoinSecret() (string, error) {
	raw := make([]byte, joinSecretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("membership: join secret: %w", err)
	}
	return encoding.EncodeToString(raw), nil
}

// ValidJoinSecret checks the shape of a join secret.
func ValidJoinSecret(secret string) bool {
	raw, err := encoding.DecodeString(strings.TrimSpace(secret))
	return err == nil && len(raw) == joinSecretBytes
}

// Key is the derived membership key. It is secret; it is held in memory by
// the daemon and never logged, marshalled or returned by the local API.
type Key struct {
	networkID string
	proof     []byte
	rendez    []byte
}

// Derive computes the membership key for a network. Two independent
// sub-keys come out of it — one for proofs, one for the discovery rendezvous
// — so that knowing where a network publishes tells you nothing about how to
// forge a proof for it.
func Derive(networkID, joinSecret string) (*Key, error) {
	if !ValidNetworkID(networkID) {
		return nil, ErrBadNetworkID
	}
	secret, err := encoding.DecodeString(strings.TrimSpace(joinSecret))
	if err != nil || len(secret) != joinSecretBytes {
		return nil, ErrBadJoinSecret
	}
	return &Key{
		networkID: networkID,
		proof:     expand(secret, networkID, "nknguard/v1/membership-proof"),
		rendez:    expand(secret, networkID, "nknguard/v1/rendezvous"),
	}, nil
}

// expand is HKDF-Expand for a single 32-byte block (RFC 5869 with the secret
// used directly as the PRK, which is sound because it is already a uniformly
// random 256-bit value).
func expand(secret []byte, networkID, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	mac.Write([]byte{0})
	mac.Write([]byte(networkID))
	mac.Write([]byte{1})
	return mac.Sum(nil)
}

// NetworkID is the network this key belongs to.
func (k *Key) NetworkID() string { return k.networkID }

// Proof produces the membership proof for one device.
func (k *Key) Proof(deviceID string, rootPublicKey []byte) []byte {
	mac := hmac.New(sha256.New, k.proof)
	mac.Write([]byte(k.networkID))
	mac.Write([]byte{0})
	mac.Write([]byte(deviceID))
	mac.Write([]byte{0})
	mac.Write(rootPublicKey)
	return mac.Sum(nil)
}

// Verify checks a device's proof in constant time.
func (k *Key) Verify(deviceID string, rootPublicKey, proof []byte) error {
	if len(proof) == 0 {
		return ErrNoProof
	}
	if !hmac.Equal(k.Proof(deviceID, rootPublicKey), proof) {
		return ErrBadProof
	}
	return nil
}

// Rendezvous is the discovery key a network publishes under. It is derived
// from the secret, not the network id alone, so an observer of the DHT who
// has learned a network id from a log line still cannot enumerate its
// members.
func (k *Key) Rendezvous() string {
	sum := sha256.Sum256(k.rendez)
	return "nknguard-rv-" + encoding.EncodeToString(sum[:20])
}
