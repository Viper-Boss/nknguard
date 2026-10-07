// Package mobile is the protocol core of the NKNGuard Android client.
//
// It runs as a child process of the Android app and speaks newline-delimited
// JSON on its standard input and output (see Serve). Everything that is part
// of the v1 wire protocol — identities, signatures, pairing, peer records, the
// mesh controller, the relay framing and WireGuard itself — is the same Go
// code the NAS and the Windows client run, so the phone cannot drift from them.
// The app supplies what only Android can: the VpnService TUN device, the
// encrypted storage of key material, DNS servers and local addresses.
package mobile

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

// Names of the secrets the app stores for this process. The app treats the
// set as opaque; the names only have to agree with this package.
const (
	SecretRoot       = "root.seed"
	SecretWireGuard  = "wireguard.key"
	SecretNKN        = "nkn.seed"
	SecretJoinSecret = "join.secret"
)

// SecretStore keeps key material in memory only. The Android app holds the one
// persistent copy, encrypted with a non-exportable Android Keystore key; it
// passes the secrets in when this process starts and receives every change
// back through OnChange. Nothing here writes a secret to disk or to a log.
type SecretStore struct {
	mu       sync.Mutex
	writeMu  sync.Mutex
	values   map[string][]byte
	onChange func(map[string][]byte) error
}

// NewSecretStore returns an empty store.
func NewSecretStore() *SecretStore { return &SecretStore{values: make(map[string][]byte)} }

// Load replaces the contents without reporting a change: it is how the app's
// stored copy comes back in.
func (s *SecretStore) Load(encoded map[string]string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	values := make(map[string][]byte, len(encoded))
	for name, value := range encoded {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return fmt.Errorf("mobile: secret %q is not base64", name)
		}
		values[name] = raw
	}
	s.mu.Lock()
	s.values = values
	s.mu.Unlock()
	return nil
}

// SetOnChange registers the function that receives a full copy of the store
// after every write or delete.
func (s *SecretStore) SetOnChange(fn func(map[string][]byte) error) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// ReadSecret implements wireguard.Keystore.
func (s *SecretStore) ReadSecret(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

// WriteSecret implements wireguard.Keystore.
func (s *SecretStore) WriteSecret(name string, data []byte) error {
	return s.change(func(values map[string][]byte) { values[name] = append([]byte(nil), data...) })
}

// Has implements wireguard.Keystore.
func (s *SecretStore) Has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.values[name]
	return ok
}

// Delete removes one secret.
func (s *SecretStore) Delete(name string) error {
	return s.change(func(values map[string][]byte) { delete(values, name) })
}

// Names lists what is stored, for diagnostics. Values are never listed.
func (s *SecretStore) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.values))
	for name := range s.values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// change publishes only after the persistent copy has acknowledged success.
// A failed save leaves the prior in-memory identity intact.
func (s *SecretStore) change(update func(map[string][]byte)) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	fn := s.onChange
	snapshot := make(map[string][]byte, len(s.values))
	for name, value := range s.values {
		snapshot[name] = append([]byte(nil), value...)
	}
	s.mu.Unlock()
	update(snapshot)
	if fn != nil {
		if err := fn(snapshot); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.values = snapshot
	s.mu.Unlock()
	return nil
}

// Encode renders secrets for the app. Only the secrets event uses it.
func Encode(values map[string][]byte) map[string]string {
	out := make(map[string]string, len(values))
	for name, value := range values {
		out[name] = base64.StdEncoding.EncodeToString(value)
	}
	return out
}
