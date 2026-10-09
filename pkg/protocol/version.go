// Package protocol defines the wire format of every NKNGuard control message
// and the rules for accepting one.
//
// Versioning is here from the first commit rather than retrofitted later,
// because the cost of adding it to a deployed mesh is a flag day and the cost
// of having it from the start is thirty lines.
package protocol

// Version is the protocol version this build speaks natively.
const Version uint32 = 1

// MinVersion is the oldest version this build still understands. It exists so
// that a future build can drop support deliberately and say so, rather than
// failing to parse and reporting a mysterious decode error.
const MinVersion uint32 = 1

// Capabilities are optional behaviours a node advertises in its HELLO. A peer
// that does not recognise a capability ignores it; a peer that needs one that
// is absent degrades rather than failing.
const (
	CapWireGuardDirect = "wireguard-direct"
	CapNKNRelay        = "nkn-relay"
	CapUDPPunchV1      = "udp-punch-v1"
	CapDHTRecordV1     = "dht-record-v1"
	CapACLV1           = "acl-v1"
	CapICEUDPV1        = "ice-udp-v1"
)

// DefaultCapabilities is the baseline v1 capability set. Optional transports
// are advertised by the controller only when they are configured.
func DefaultCapabilities() []string {
	return []string{CapWireGuardDirect, CapNKNRelay, CapUDPPunchV1, CapDHTRecordV1, CapACLV1}
}

// VersionRange is exchanged in the handshake.
type VersionRange struct {
	Min uint32 `json:"min_version"`
	Max uint32 `json:"max_version"`
}

// LocalVersionRange is what this build offers.
func LocalVersionRange() VersionRange { return VersionRange{Min: MinVersion, Max: Version} }

// Negotiate picks the highest version both ends speak. ok is false when the
// ranges do not overlap, which the caller answers with ErrorVersionUnsupported
// instead of trying to guess.
func Negotiate(local, remote VersionRange) (version uint32, ok bool) {
	high := local.Max
	if remote.Max < high {
		high = remote.Max
	}
	low := local.Min
	if remote.Min > low {
		low = remote.Min
	}
	if high < low {
		return 0, false
	}
	return high, true
}

// HasCapability reports whether list advertises name.
func HasCapability(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}
