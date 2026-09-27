package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"strings"
)

// EnsureKeyPair creates a standard WireGuard X25519 key pair without needing
// wg tools. Enrollment can therefore run before the tunnel is installed.
func EnsureKeyPair(store Keystore) (public string, err error) {
	raw, err := store.ReadSecret(PrivateKeyName)
	if errors.Is(err, fs.ErrNotExist) {
		private := make([]byte, 32)
		if _, err = rand.Read(private); err != nil {
			return "", err
		}
		private[0] &= 248
		private[31] &= 127
		private[31] |= 64
		raw = []byte(base64.StdEncoding.EncodeToString(private) + "\n")
		if err = store.WriteSecret(PrivateKeyName, raw); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(private) != 32 {
		return "", ErrNoPrivateKey
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
