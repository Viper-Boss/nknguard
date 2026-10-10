// Package config loads and validates the daemon's configuration file.
//
// Two rules the file format enforces rather than documents: no secret is ever
// stored here, and an invalid file is refused rather than partially applied.
// Private keys and the join secret live in the keystore at 0600; this file is
// safe to put in a repository, paste into an issue, and include in a
// diagnostics bundle.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/acl"
	"github.com/Viper-Boss/nknguard/pkg/nat"
)

// Version is the configuration schema version.
const Version = 1

// DefaultPath is where the daemon looks when no path is given.
const DefaultPath = "/etc/nknguard/config.yaml"

// DefaultStateDir holds identity, keystore and cached records.
const DefaultStateDir = "/var/lib/nknguard"

// DefaultSocketPath is the local control API. It is a Unix socket, not a TCP
// port, so "listening on 0.0.0.0 by accident" is not a thing that can happen.
const DefaultSocketPath = "/run/nknguard/nknguard.sock"

// DefaultConfigPath follows the user's profile on Windows, so an elevated
// client and its interactive controls use the same per-user configuration.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "config.yaml")
	}
	return DefaultPath
}

// Config is the whole file.
type Config struct {
	Version int `json:"version"`

	Device struct {
		Name string   `json:"name"`
		Tags []string `json:"tags,omitempty"`
	} `json:"device"`

	Network struct {
		ID   string `json:"id"`
		CIDR string `json:"cidr"`
	} `json:"network"`

	NKN struct {
		Enabled     bool     `json:"enabled"`
		MultiClient bool     `json:"multiclient"`
		SeedRPC     []string `json:"seed_rpc,omitempty"`
	} `json:"nkn"`

	Discovery struct {
		DHT            bool     `json:"dht"`
		BootstrapPeers []string `json:"bootstrap_peers,omitempty"`
		LANDiscovery   bool     `json:"lan_discovery"`
		// NKNTopic makes the node findable through an NKN pub/sub topic
		// derived from the join secret. It is on by default because it is
		// the only zero-configuration way for two nodes on different networks
		// to meet; see pkg/rendezvous/nkntopic for what it exposes.
		NKNTopic bool `json:"nkn_topic"`
		// StaticPeers are NKN addresses introduced to directly. Two nodes
		// that list each other need no DHT and no topic at all.
		StaticPeers []string `json:"static_peers,omitempty"`
	} `json:"discovery"`

	NAT struct {
		PortMapping bool     `json:"port_mapping"`
		STUNEnabled bool     `json:"stun_enabled"`
		STUNServers []string `json:"stun_servers"`
	} `json:"nat"`

	WireGuard struct {
		Interface           string `json:"interface"`
		ListenPort          int    `json:"listen_port"`
		MTU                 int    `json:"mtu,omitempty"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
	} `json:"wireguard"`

	Relay struct {
		NKNEnabled bool `json:"nkn_enabled"`
	} `json:"relay"`

	ACL acl.Policy `json:"acl"`

	Logging struct {
		Level string `json:"level"`
	} `json:"logging"`
	Dashboard struct {
		Listen string `json:"listen"`
	} `json:"dashboard"`
	Pairing struct {
		ApprovalRequired bool `json:"approval_required"`
	} `json:"pairing"`
	// UsageStats is the default for the anonymous active-installation count
	// (see pkg/usagestats). The dashboard switch, once used, overrides it.
	UsageStats struct {
		// Deprecated: retained for reading older configurations. Applications always enable statistics.
		Enabled bool `json:"enabled"`
	} `json:"usage_stats"`

	Paths struct {
		StateDir string `json:"state_dir"`
		Socket   string `json:"socket"`
		// LegacySetupNote is the first-run.txt that older installers wrote
		// next to the configuration file with a generated dashboard password.
		// It is derived from the configuration path, never read from the
		// file, and removed once the owner sets a new dashboard password.
		LegacySetupNote string `json:"-"`
	} `json:"paths"`
}

// Default returns a configuration that is safe to run with: ACL denies, the
// overlay is in a range unlikely to collide with a LAN or a Docker bridge, and
// the WireGuard listen port is zero so the kernel picks one that is free.
func Default() Config {
	var config Config
	config.Version = Version
	config.Device.Name = hostnameOr("nknguard-node")
	config.Network.CIDR = "10.88.0.0/16"
	config.NKN.Enabled = true
	config.NKN.MultiClient = true
	config.Discovery.DHT = true
	config.Discovery.LANDiscovery = true
	config.Discovery.NKNTopic = true
	config.NAT.STUNEnabled = true
	config.NAT.PortMapping = true
	config.NAT.STUNServers = nat.DefaultSTUNServers()
	config.WireGuard.Interface = "nkg0"
	config.WireGuard.ListenPort = 0
	config.WireGuard.PersistentKeepalive = 25
	config.Relay.NKNEnabled = true
	config.ACL = acl.DefaultPolicy()
	config.Logging.Level = "info"
	config.Dashboard.Listen = "127.0.0.1:7878"
	config.Pairing.ApprovalRequired = true
	config.UsageStats.Enabled = true
	config.Paths.StateDir = DefaultStateDir
	config.Paths.Socket = DefaultSocketPath
	if runtime.GOOS == "windows" {
		base := filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard")
		config.Paths.StateDir = filepath.Join(base, "state")
		config.Paths.Socket = filepath.Join(base, "run", "nknguard.sock")
		config.WireGuard.Interface = "nknguard"
	}
	return config
}

func hostnameOr(fallback string) string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

// Load reads a configuration file, filling anything absent from Default.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(string(raw))
}

// Parse decodes configuration text.
func Parse(source string) (Config, error) {
	root, err := parseYAML(source)
	if err != nil {
		return Config{}, err
	}
	config := Default()
	config.Version = root.intOr(Version, "version")

	config.Device.Name = root.stringOr(config.Device.Name, "device", "name")
	if tags := root.strings("device", "tags"); len(tags) > 0 {
		config.Device.Tags = tags
	}

	config.Network.ID = root.stringOr(config.Network.ID, "network", "id")
	config.Network.CIDR = root.stringOr(config.Network.CIDR, "network", "cidr")

	config.NKN.Enabled = root.boolOr(config.NKN.Enabled, "nkn", "enabled")
	config.NKN.MultiClient = root.boolOr(config.NKN.MultiClient, "nkn", "multiclient")
	if seeds := root.strings("nkn", "seed_rpc"); len(seeds) > 0 {
		config.NKN.SeedRPC = seeds
	}

	config.Discovery.DHT = root.boolOr(config.Discovery.DHT, "discovery", "dht")
	config.Discovery.LANDiscovery = root.boolOr(config.Discovery.LANDiscovery, "discovery", "lan_discovery")
	config.Discovery.NKNTopic = root.boolOr(config.Discovery.NKNTopic, "discovery", "nkn_topic")
	if peers := root.strings("discovery", "static_peers"); len(peers) > 0 {
		config.Discovery.StaticPeers = peers
	}
	if peers := root.strings("discovery", "bootstrap_peers"); len(peers) > 0 {
		config.Discovery.BootstrapPeers = peers
	}

	config.NAT.STUNEnabled = root.boolOr(config.NAT.STUNEnabled, "nat", "stun", "enabled")
	config.NAT.PortMapping = root.boolOr(config.NAT.PortMapping, "nat", "port_mapping")
	if servers := root.strings("nat", "stun", "servers"); len(servers) > 0 {
		config.NAT.STUNServers = servers
	}

	config.WireGuard.Interface = root.stringOr(config.WireGuard.Interface, "wireguard", "interface")
	config.WireGuard.ListenPort = root.intOr(config.WireGuard.ListenPort, "wireguard", "listen_port")
	config.WireGuard.MTU = root.intOr(config.WireGuard.MTU, "wireguard", "mtu")
	config.WireGuard.PersistentKeepalive = root.intOr(config.WireGuard.PersistentKeepalive, "wireguard", "persistent_keepalive")

	config.Relay.NKNEnabled = root.boolOr(config.Relay.NKNEnabled, "relay", "nkn", "enabled")

	config.Logging.Level = root.stringOr(config.Logging.Level, "logging", "level")
	config.Dashboard.Listen = root.stringOr(config.Dashboard.Listen, "dashboard", "listen")
	config.Pairing.ApprovalRequired = root.boolOr(config.Pairing.ApprovalRequired, "pairing", "approval_required")
	config.UsageStats.Enabled = root.boolOr(config.UsageStats.Enabled, "usage_stats", "enabled")
	config.Paths.StateDir = root.stringOr(config.Paths.StateDir, "paths", "state_dir")
	config.Paths.Socket = root.stringOr(config.Paths.Socket, "paths", "socket")

	config.ACL = parseACL(root, config.ACL)

	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func parseACL(root *yamlNode, fallback acl.Policy) acl.Policy {
	node := root.child("acl")
	if node == nil {
		return fallback
	}
	policy := acl.Policy{Default: acl.Action(root.stringOr(string(fallback.Default), "acl", "default"))}
	if rules := node.child("rules"); rules != nil {
		for _, entry := range rules.sequence {
			if entry.mapping == nil {
				continue
			}
			rule := acl.Rule{
				Source:      entry.stringOr("", "src"),
				Destination: entry.stringOr("", "dst"),
				Action:      acl.Action(entry.stringOr(string(acl.Deny), "action")),
			}
			policy.Rules = append(policy.Rules, rule)
		}
	}
	return policy
}

// Validate refuses a configuration the daemon cannot honour. It is called by
// Parse, so an invalid file never reaches the controller half-applied.
func (c Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("config: version %d is not supported (this build reads version %d)", c.Version, Version)
	}
	if strings.TrimSpace(c.Device.Name) == "" {
		return fmt.Errorf("config: device.name must not be empty")
	}
	prefix, err := netip.ParsePrefix(c.Network.CIDR)
	if err != nil {
		return fmt.Errorf("config: network.cidr %q: %w", c.Network.CIDR, err)
	}
	if !prefix.Addr().Is4() {
		return fmt.Errorf("config: network.cidr must be IPv4 in this version, got %s", c.Network.CIDR)
	}
	last := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		last[bit/8] |= 1 << (7 - uint(bit%8))
	}
	if !prefix.Masked().Addr().IsPrivate() || !netip.AddrFrom4(last).IsPrivate() {
		return fmt.Errorf("config: network.cidr must stay within a private IPv4 range; internet exit routes are not supported")
	}
	if prefix.Bits() > 30 {
		return fmt.Errorf("config: network.cidr %s leaves no room for peers", c.Network.CIDR)
	}
	if c.WireGuard.ListenPort < 0 || c.WireGuard.ListenPort > 65535 {
		return fmt.Errorf("config: wireguard.listen_port %d is out of range", c.WireGuard.ListenPort)
	}
	if c.WireGuard.PersistentKeepalive < 0 || c.WireGuard.PersistentKeepalive > 3600 {
		return fmt.Errorf("config: wireguard.persistent_keepalive %d is out of range", c.WireGuard.PersistentKeepalive)
	}
	if strings.TrimSpace(c.WireGuard.Interface) == "" {
		return fmt.Errorf("config: wireguard.interface must not be empty")
	}
	address, err := netip.ParseAddrPort(c.Dashboard.Listen)
	if err != nil || !address.Addr().IsLoopback() {
		return fmt.Errorf("config: dashboard.listen must be a loopback IP and port, got %q", c.Dashboard.Listen)
	}
	if err := c.ACL.Validate(); err != nil {
		return err
	}
	return nil
}

// OverlayPrefix is the parsed CIDR.
func (c Config) OverlayPrefix() netip.Prefix {
	prefix, err := netip.ParsePrefix(c.Network.CIDR)
	if err != nil {
		return netip.MustParsePrefix("10.88.0.0/16")
	}
	return prefix
}

// KeystoreDir is where secrets live.
func (c Config) KeystoreDir() string { return filepath.Join(c.Paths.StateDir, "keystore") }

// RecordTTL is how long this node's published record stays valid.
func (c Config) RecordTTL() time.Duration { return 2 * time.Minute }

// Render writes the configuration back out in the documented format. It is
// what `nknguard init` produces, so the shipped example and the code that
// reads it can never drift apart.
func (c Config) Render() string {
	var out strings.Builder
	fmt.Fprintf(&out, "version: %d\n\n", c.Version)
	fmt.Fprintf(&out, "device:\n  name: %s\n", c.Device.Name)
	if len(c.Device.Tags) > 0 {
		out.WriteString("  tags:\n")
		for _, tag := range c.Device.Tags {
			fmt.Fprintf(&out, "    - %s\n", tag)
		}
	}
	networkID := c.Network.ID
	if networkID == "" {
		networkID = `""`
	}
	fmt.Fprintf(&out, "\nnetwork:\n  id: %s\n  cidr: %s\n", networkID, c.Network.CIDR)
	fmt.Fprintf(&out, "\nnkn:\n  enabled: %t\n  multiclient: %t\n", c.NKN.Enabled, c.NKN.MultiClient)
	writeList(&out, "  seed_rpc:\n", "    - ", c.NKN.SeedRPC)
	fmt.Fprintf(&out, "\ndiscovery:\n  dht: %t\n  lan_discovery: %t\n  nkn_topic: %t\n", c.Discovery.DHT, c.Discovery.LANDiscovery, c.Discovery.NKNTopic)
	writeList(&out, "  bootstrap_peers:\n", "    - ", c.Discovery.BootstrapPeers)
	writeList(&out, "  static_peers:\n", "    - ", c.Discovery.StaticPeers)
	out.WriteString("\nnat:\n  stun:\n")
	fmt.Fprintf(&out, "    enabled: %t\n    servers:\n", c.NAT.STUNEnabled)
	for _, server := range c.NAT.STUNServers {
		fmt.Fprintf(&out, "      - %s\n", server)
	}
	fmt.Fprintf(&out, "  port_mapping: %t\n", c.NAT.PortMapping)
	fmt.Fprintf(&out, "\nwireguard:\n  interface: %s\n  listen_port: %d\n  persistent_keepalive: %d\n",
		c.WireGuard.Interface, c.WireGuard.ListenPort, c.WireGuard.PersistentKeepalive)
	fmt.Fprintf(&out, "\nrelay:\n  nkn:\n    enabled: %t\n", c.Relay.NKNEnabled)
	fmt.Fprintf(&out, "\nacl:\n  default: %s\n", c.ACL.Default)
	if len(c.ACL.Rules) > 0 {
		out.WriteString("  rules:\n")
		for _, rule := range c.ACL.Rules {
			fmt.Fprintf(&out, "    - src: %s\n      dst: %s\n      action: %s\n", rule.Source, rule.Destination, rule.Action)
		}
	}
	fmt.Fprintf(&out, "\nlogging:\n  level: %s\n", c.Logging.Level)
	fmt.Fprintf(&out, "\ndashboard:\n  listen: %s\n", c.Dashboard.Listen)
	fmt.Fprintf(&out, "\npairing:\n  approval_required: %t\n", c.Pairing.ApprovalRequired)
	fmt.Fprintf(&out, "\nusage_stats:\n  enabled: %t\n", c.UsageStats.Enabled)
	fmt.Fprintf(&out, "\npaths:\n  state_dir: %s\n  socket: %s\n", c.Paths.StateDir, c.Paths.Socket)
	return out.String()
}

func writeList(out *strings.Builder, header, prefix string, values []string) {
	if len(values) == 0 {
		return
	}
	out.WriteString(header)
	for _, value := range values {
		out.WriteString(prefix + value + "\n")
	}
}
