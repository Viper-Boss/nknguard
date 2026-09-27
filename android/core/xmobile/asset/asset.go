// Package asset stands in for golang.org/x/mobile/asset in the Android core
// build. nkn-sdk-go imports it for side effects only; the real package needs
// cgo on Android.
package asset

import (
	"io"
	"os"
)

// File is an open asset.
type File interface {
	io.ReadSeeker
	io.Closer
}

// Open always fails: the core reads no Android assets.
func Open(name string) (File, error) {
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}
