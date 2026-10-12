//go:build libp2pdht

package mobile

import (
	"context"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/discovery/dht"
	"path/filepath"
	"time"
)

func init() {
	mobileDiscovery = func(ctx context.Context, s *session) (discovery.Discovery, error) {
		key, err := s.agent.membershipKey(s.profile)
		if err != nil {
			return nil, err
		}
		return dht.Open(ctx, dht.Options{StateDir: filepath.Join(s.agent.StateDir, "dht"),
			PrivateRecordKey: key.DiscoveryEncryptionKey(),
			Rendezvous:       key.Rendezvous(), LANDiscovery: true, Logger: s.agent.Logger, ClientMode: true, InterfaceAddresses: s.agent.interfaceAddrs,
			RecordAllowed: func(r discovery.PeerRecord) bool {
				return r.DeviceID == s.profile.NASID && r.Verify(key.NetworkID(), time.Now()) == nil && key.Verify(r.DeviceID, r.RootPublicKey, r.MembershipProof) == nil
			}})
	}
}
