package app

import (
	"fmt"
	"os"
	"path/filepath"
)

// The file is never unlinked: replacing a locked inode would let a third
// process acquire a different lock. Closing the handle releases it on crash.
func acquireInstanceLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockInstanceFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another NKNGuard instance owns %s: %w", path, err)
	}
	return f, nil
}
