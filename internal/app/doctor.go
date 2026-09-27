package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// Doctor checks everything that can be checked from this machine and says
// what to do about each failure. It runs without the daemon, so it answers
// "why won't it start" as well as "why is it slow".
func Doctor(ctx context.Context, cfg config.Config) diagnostics.Report {
	report := diagnostics.Report{GeneratedAt: time.Now()}

	if err := cfg.Validate(); err != nil {
		report.Add("configuration", diagnostics.LevelFail, err.Error())
	} else {
		report.Add("configuration", diagnostics.LevelOK, "")
	}

	nknBuilt, dhtBuilt := BuildFeatures()
	if nknBuilt {
		report.Add("NKN support compiled in", diagnostics.LevelOK, "")
	} else {
		report.Add("NKN support compiled in", diagnostics.LevelFail, ErrNoNKN.Error())
	}
	switch {
	case !cfg.Discovery.DHT:
		report.Add("DHT discovery", diagnostics.LevelOK, "disabled in config")
	case dhtBuilt:
		report.Add("DHT discovery", diagnostics.LevelOK, "")
	default:
		report.Add("DHT discovery", diagnostics.LevelWarn, "enabled in config but not compiled in (build tag libp2pdht); NKN topic and static peers still work")
	}

	keystore := identity.NewKeystore(cfg.KeystoreDir())
	if keystore.Has("root.key") {
		if _, err := keystore.LoadOrCreateRoot(); err != nil {
			report.Add("device identity", diagnostics.LevelFail, err.Error())
		} else {
			report.Add("device identity", diagnostics.LevelOK, "")
		}
	} else {
		report.Add("device identity", diagnostics.LevelWarn, "not created yet — `nknguard init` or `join` creates it")
	}

	if node, err := OpenNode(cfg); err == nil {
		if _, current, err := node.MembershipKey(); err != nil {
			report.Add("network membership", diagnostics.LevelFail, err.Error())
		} else {
			report.Add("network membership", diagnostics.LevelOK, current.NetworkID)
		}
	}

	manager := wireguard.NewHostManager(wireguard.FromIdentityKeystore(keystore), cfg.WireGuard.Interface, cfg.Paths.StateDir)
	switch state, reason := manager.Supported(ctx); state {
	case wireguard.StateUnsupported, wireguard.StateToolsMissing:
		report.Add("WireGuard available", diagnostics.LevelFail, reason+" — install wireguard-tools (and wireguard-go if the kernel lacks the module)")
	default:
		report.Add("WireGuard available", diagnostics.LevelOK, "")
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			report.Add("TUN support", diagnostics.LevelWarn, "/dev/net/tun missing — only matters for wireguard-go")
		} else {
			report.Add("TUN support", diagnostics.LevelOK, "")
		}
	}

	socket, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		report.Add("UDP socket", diagnostics.LevelFail, err.Error())
	} else {
		report.Add("UDP socket", diagnostics.LevelOK, "")
		checkSTUN(ctx, &report, cfg, socket)
		_ = socket.Close()
	}

	client := NewClient(cfg.Paths.Socket)
	status, err := client.Status()
	if err != nil {
		report.Add("daemon", diagnostics.LevelWarn, err.Error())
		return report
	}
	report.Add("daemon", diagnostics.LevelOK, "running "+status.Uptime)
	if status.WireGuard.State == wireguard.StateUp {
		report.Add("interface "+status.WireGuard.Interface, diagnostics.LevelOK, status.VirtualIP)
	} else {
		report.Add("interface "+status.WireGuard.Interface, diagnostics.LevelFail, string(status.WireGuard.State)+" "+status.WireGuard.Error)
	}
	if status.NKNAddress != "" {
		report.Add("NKN connectivity", diagnostics.LevelOK, status.NKNAddress)
	}
	for _, peer := range status.Peers {
		name := peer.Name
		if name == "" {
			name = peer.DeviceID
		}
		switch peer.Path {
		case mesh.PathDirectWG:
			report.Add("peer "+name, diagnostics.LevelOK, "direct "+peer.Endpoint)
		case mesh.PathNKNRelay:
			report.Add("peer "+name, diagnostics.LevelWarn, "relayed through NKN — works, but slower; a direct path is retried automatically")
		default:
			report.Add("peer "+name, diagnostics.LevelWarn, string(peer.State)+" "+peer.LastError)
		}
	}
	return report
}

func checkSTUN(ctx context.Context, report *diagnostics.Report, cfg config.Config, socket net.PacketConn) {
	if !cfg.NAT.STUNEnabled || len(cfg.NAT.STUNServers) == 0 {
		report.Add("STUN", diagnostics.LevelWarn, "disabled — only LAN and static candidates will be advertised")
		return
	}
	gatherer := nat.Gatherer{STUNServers: cfg.NAT.STUNServers, STUNTimeout: 3 * time.Second}
	candidates, behaviour, err := gatherer.Gather(ctx, socket)
	if err != nil {
		report.Add("STUN", diagnostics.LevelWarn, err.Error())
		return
	}
	var public []string
	for _, candidate := range candidates {
		if candidate.Type == nat.CandidateReflexive {
			public = append(public, candidate.IP)
		}
	}
	if len(public) == 0 {
		report.Add("STUN", diagnostics.LevelWarn, "no STUN server answered — UDP/3478 may be blocked; peers will likely use the relay")
		return
	}
	report.Add("STUN", diagnostics.LevelOK, "public address "+strings.Join(dedupe(public), ", "))
	switch behaviour {
	case nat.BehaviourAddressDependent:
		report.Add("NAT type", diagnostics.LevelWarn, "symmetric NAT suspected — direct paths are unlikely to peers also behind NAT; the NKN relay will carry them")
	case nat.BehaviourUnknown:
		report.Add("NAT type", diagnostics.LevelWarn, "could not classify (need two STUN answers)")
	default:
		report.Add("NAT type", diagnostics.LevelOK, fmt.Sprint(behaviour))
	}
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
