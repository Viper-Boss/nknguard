package config

import (
	"strings"
	"testing"

	"github.com/Viper-Boss/nknguard/pkg/acl"
)

const specExample = `version: 1

device:
  name: nas-home

network:
  id: nkgnet_example
  cidr: 10.88.0.0/16

nkn:
  enabled: true
  multiclient: true

discovery:
  dht: true

nat:
  stun:
    enabled: true
    servers:
      - stun.cloudflare.com:3478
      - stun.l.google.com:19302

wireguard:
  interface: nkg0
  listen_port: 0
  persistent_keepalive: 25

relay:
  nkn:
    enabled: true

acl:
  default: deny
  rules:
    - src: laptop
      dst: nas-home
      action: allow

logging:
  level: info
`

func TestParseSpecExample(t *testing.T) {
	config, err := Parse(specExample)
	if err != nil {
		t.Fatal(err)
	}
	if config.Device.Name != "nas-home" || config.Network.ID != "nkgnet_example" || config.WireGuard.Interface != "nkg0" {
		t.Fatalf("scalars: %+v", config)
	}
	if len(config.NAT.STUNServers) != 2 || config.NAT.STUNServers[0] != "stun.cloudflare.com:3478" {
		t.Fatalf("stun servers: %v", config.NAT.STUNServers)
	}
	if config.ACL.Default != acl.Deny || len(config.ACL.Rules) != 1 || config.ACL.Rules[0].Destination != "nas-home" {
		t.Fatalf("acl: %+v", config.ACL)
	}
}

func TestRenderRoundTrips(t *testing.T) {
	original := Default()
	original.Device.Name = "laptop"
	original.Network.ID = "nkgnet_x"
	original.Device.Tags = []string{"admin"}
	original.Discovery.StaticPeers = []string{"nknguard.abc123", "nknguard.def456"}
	original.NKN.SeedRPC = []string{"http://127.0.0.1:30003"}
	original.ACL.Rules = []acl.Rule{{Source: "laptop", Destination: "*", Action: acl.Allow}}
	parsed, err := Parse(original.Render())
	if err != nil {
		t.Fatalf("rendered config does not parse: %v\n%s", err, original.Render())
	}
	if parsed.Render() != original.Render() {
		t.Fatalf("round trip changed the file:\n%s\n---\n%s", original.Render(), parsed.Render())
	}
}

func TestInvalidConfigsAreRefused(t *testing.T) {
	cases := map[string]string{
		"bad version":  "version: 9\n",
		"bad cidr":     "version: 1\nnetwork:\n  cidr: nope\n",
		"ipv6 overlay": "version: 1\nnetwork:\n  cidr: fd00::/64\n",
		"tiny overlay": "version: 1\nnetwork:\n  cidr: 10.0.0.0/31\n",
		"bad acl":      "version: 1\nacl:\n  default: maybe\n",
		"tab indent":   "version: 1\ndevice:\n\tname: x\n",
		"bad port":     "version: 1\nwireguard:\n  listen_port: 70000\n",
	}
	for name, source := range cases {
		if _, err := Parse(source); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfigHoldsNoSecrets(t *testing.T) {
	rendered := strings.ToLower(Default().Render())
	for _, word := range []string{"secret", "private", "seed", "password"} {
		if strings.Contains(rendered, word) {
			t.Fatalf("config file mentions %q — secrets belong in the keystore", word)
		}
	}
}

func TestColonsInScalars(t *testing.T) {
	config, err := Parse("version: 1\nnkn:\n  seed_rpc:\n    - http://10.0.0.1:30003\n    - \"http://x:1\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.NKN.SeedRPC) != 2 || config.NKN.SeedRPC[0] != "http://10.0.0.1:30003" || config.NKN.SeedRPC[1] != "http://x:1" {
		t.Fatalf("seed_rpc: %q", config.NKN.SeedRPC)
	}
}
