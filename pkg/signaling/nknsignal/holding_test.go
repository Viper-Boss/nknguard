//go:build nknsdk

package nknsignal

import (
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"testing"
)

func TestConnectionMessagesAreNeverHeldForOfflineClients(t *testing.T) {
	for _, kind := range []protocol.MessageType{protocol.TypePeerInfo, protocol.TypeKeepalive, protocol.TypeDisconnect, protocol.TypeICEOffer, protocol.TypeICEAnswer} {
		if holdingSeconds(kind) != 0 {
			t.Fatalf("%s has offline holding", kind)
		}
	}
	if holdingSeconds(protocol.TypePairRequest) != 30 || holdingSeconds(protocol.TypePairApproval) != 30 {
		t.Fatal("pairing delivery window lost")
	}
}
