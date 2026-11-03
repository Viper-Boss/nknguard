//go:build !windows

package main

import "errors"

func installWireGuardDependency() error {
	return errors.New("WireGuard dependency installer is Windows-only")
}
