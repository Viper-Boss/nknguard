package mesh

// DiscoveryFallbackActive leaves standalone discovery backends unchanged;
// production's hub delays DHT until the primary NKN transport is unavailable.
func (c *Controller) DiscoveryFallbackActive() bool {
	if policy, ok := c.Signaling.(interface{ DiscoveryFallbackActive() bool }); ok {
		return policy.DiscoveryFallbackActive()
	}
	return true
}
