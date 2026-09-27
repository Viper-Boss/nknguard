package identity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// KeystoreFileMode is the only mode a secret file is ever written with. It is
// checked on read as well: a key that became world-readable at some point in
// its life is a key that should be rotated, and silently using it hides that.
const KeystoreFileMode fs.FileMode = 0o600

// KeystoreDirMode keeps the directory itself owner-only.
const KeystoreDirMode fs.FileMode = 0o700

// Keystore is a directory of secrets on the local disk. It holds the root
// seed and any subordinate private material; nothing here is ever sent
// anywhere, logged, or placed in a diagnostics bundle.
type Keystore struct {
	dir string
}

// NewKeystore returns a keystore rooted at dir. The directory is created on
// first write, not here, so constructing one is side-effect free.
func NewKeystore(dir string) *Keystore { return &Keystore{dir: dir} }

// Dir is where this keystore lives.
func (k *Keystore) Dir() string { return k.dir }

func (k *Keystore) path(name string) string { return filepath.Join(k.dir, name) }

// LoadOrCreateRoot returns the device's root identity, generating and
// persisting one the first time it is called. A node that generated a new root
// key on every start would lose every peer that had pinned it, so this is the
// one operation in the codebase that must be idempotent across restarts.
func (k *Keystore) LoadOrCreateRoot() (*DeviceIdentity, error) {
	seed, err := k.readSecret("root.key")
	switch {
	case err == nil:
		return FromSeed(seed)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	created, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := k.WriteSecret("root.key", created.Seed()); err != nil {
		return nil, err
	}
	return created, nil
}

// WriteSecret stores raw bytes under name with owner-only permissions. The
// write goes to a temporary file in the same directory and is renamed into
// place, so a crash mid-write cannot leave a truncated key behind.
func (k *Keystore) WriteSecret(name string, data []byte) error {
	if err := os.MkdirAll(k.dir, KeystoreDirMode); err != nil {
		return fmt.Errorf("identity: create keystore dir: %w", err)
	}
	temporary, err := os.CreateTemp(k.dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("identity: create temp secret: %w", err)
	}
	name2 := temporary.Name()
	defer func() { _ = os.Remove(name2) }()
	if err := temporary.Chmod(KeystoreFileMode); err != nil && runtime.GOOS != "windows" {
		_ = temporary.Close()
		return fmt.Errorf("identity: chmod temp secret: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("identity: write temp secret: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("identity: sync temp secret: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("identity: close temp secret: %w", err)
	}
	if err := os.Rename(name2, k.path(name)); err != nil {
		return fmt.Errorf("identity: install secret: %w", err)
	}
	return nil
}

// ReadSecret returns a stored secret. It is exported for subordinate keys
// (WireGuard, NKN seed); the root seed goes through LoadOrCreateRoot.
func (k *Keystore) ReadSecret(name string) ([]byte, error) { return k.readSecret(name) }

func (k *Keystore) readSecret(name string) ([]byte, error) {
	path := k.path(name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity: %s is mode %04o, expected %04o — rotate this key", path, info.Mode().Perm(), KeystoreFileMode)
	}
	return os.ReadFile(path)
}

// Has reports whether a secret of that name is present.
func (k *Keystore) Has(name string) bool {
	_, err := os.Stat(k.path(name))
	return err == nil
}
