//go:build !windows

package main

import (
	"errors"
	"io"
)

func cmdClient(_ globals, _ io.Writer) error {
	return errors.New("the desktop client is available on Windows")
}
