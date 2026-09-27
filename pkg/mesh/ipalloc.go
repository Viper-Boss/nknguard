package mesh

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// MaxIPAllocationAttempts bounds the salted retry. Past this the pool is
// either too small or something is very wrong, and looping forever would hang
// the join instead of saying so.
const MaxIPAllocationAttempts = 64

// AllocateVirtualIP derives a stable overlay address for a device.
//
// There is no address server, because there is no server at all — that is the
// premise of the project. So the address is a hash of (network, device),
// which gives every node the same answer without anybody coordinating, and
// gives the same node the same address after a reinstall.
//
// Hashing collides. The caller passes taken, the set of addresses it has seen
// in verified peer records, and a collision re-hashes with an incremented
// salt. The salt is part of the derivation, so the peer that observes the
// collision from the other side reaches the same conclusion. It is not a
// consensus algorithm and does not pretend to be: two nodes that collide while
// unable to see each other will both keep their address until discovery
// introduces them, and the one with the lower device id keeps it.
func AllocateVirtualIP(cidr netip.Prefix, networkID, deviceID string, taken map[netip.Addr]string) (netip.Addr, error) {
	if !cidr.IsValid() {
		return netip.Addr{}, fmt.Errorf("mesh: invalid overlay prefix")
	}
	if !cidr.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("mesh: overlay prefix %s must be IPv4 in this version", cidr)
	}
	hostBits := 32 - cidr.Bits()
	if hostBits < 2 {
		return netip.Addr{}, fmt.Errorf("mesh: overlay prefix %s is too small", cidr)
	}
	// Reserve .0 (network) and the all-ones host address; a pool of 2^n minus
	// two is what is actually assignable.
	span := uint64(1) << hostBits
	usable := span - 2

	base := cidr.Masked().Addr().As4()
	baseValue := uint64(binary.BigEndian.Uint32(base[:]))

	for salt := uint32(0); salt < MaxIPAllocationAttempts; salt++ {
		offset := hashOffset(networkID, deviceID, salt, usable)
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], uint32(baseValue+1+offset))
		candidate := netip.AddrFrom4(raw)
		if owner, clash := taken[candidate]; !clash || owner == deviceID {
			return candidate, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("mesh: could not find a free address in %s after %d attempts", cidr, MaxIPAllocationAttempts)
}

func hashOffset(networkID, deviceID string, salt uint32, usable uint64) uint64 {
	hasher := sha256.New()
	hasher.Write([]byte(networkID))
	hasher.Write([]byte{0})
	hasher.Write([]byte(deviceID))
	hasher.Write([]byte{0})
	var saltBytes [4]byte
	binary.BigEndian.PutUint32(saltBytes[:], salt)
	hasher.Write(saltBytes[:])
	sum := hasher.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8]) % usable
}

// ResolveCollision decides which of two devices claiming the same address
// keeps it. Lower device id wins — an arbitrary rule, but a deterministic one,
// which is the only property that matters: both sides must reach the same
// answer without talking about it.
func ResolveCollision(localDeviceID, remoteDeviceID string) (localKeeps bool) {
	return localDeviceID < remoteDeviceID
}
