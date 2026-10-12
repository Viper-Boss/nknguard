//go:build libp2pdht

package dht

import (
	"crypto/rand"
	"encoding/json"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"strings"
	"testing"
	"time"
)

func TestBootstrapIdentityFreshnessAndAddressSafety(t *testing.T) {
	key, _, _ := crypto.GenerateEd25519Key(rand.Reader)
	id, _ := peer.IDFromPrivateKey(key)
	pub, _ := crypto.MarshalPublicKey(key.GetPublic())
	now := time.Now()
	for _, test := range []string{"valid", "tampered", "source", "nonce", "expired", "future", "private", "cgnat", "loopback", "peer"} {
		t.Run(test, func(t *testing.T) {
			p := bootstrapProof{Source: "nknguard.source", Nonce: strings.Repeat("a", 32), Expires: now.Add(45 * time.Second).Unix(), Peer: id.String(), Key: pub, Addresses: []string{"/ip4/1.1.1.1/tcp/45000/p2p/" + id.String()}}
			switch test {
			case "expired":
				p.Expires = now.Add(-time.Second).Unix()
			case "future":
				p.Expires = now.Add(time.Hour).Unix()
			case "private":
				p.Addresses[0] = "/ip4/192.168.1.2/tcp/45000/p2p/" + id.String()
			case "cgnat":
				p.Addresses[0] = "/ip4/100.64.1.2/tcp/45000/p2p/" + id.String()
			case "loopback":
				p.Addresses[0] = "/ip4/127.0.0.1/tcp/45000/p2p/" + id.String()
			case "peer":
				p.Peer = "wrong"
			}
			body, _ := json.Marshal(p)
			p.Signature, _ = key.Sign(body)
			if test == "tampered" {
				p.Addresses[0] = "/ip4/8.8.8.8/tcp/45000/p2p/" + id.String()
			}
			raw, _ := json.Marshal(p)
			source, nonce := p.Source, p.Nonce
			if test == "source" {
				source = "other"
			}
			if test == "nonce" {
				nonce = "other"
			}
			_, err := verifyBootstrapProof(raw, source, nonce, now)
			if (err == nil) != (test == "valid") {
				t.Fatalf("%s: %v", test, err)
			}
		})
	}
}
