//go:build !windows

package wireguard

// NewHostManager returns the native WireGuard control path for this host.
func NewHostManager(store Keystore, interfaceName, _ string) Manager {
	return NewLinuxManager(store, interfaceName)
}
