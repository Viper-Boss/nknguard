package mobile

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// Status is the payload of status events and of the status command. Every
// field is observed: Phase is "direct" or "relay" only while WireGuard has a
// fresh handshake with the NAS on that path.
type Status struct {
	Phase            string    `json:"phase"`
	Connected        bool      `json:"connected"`
	Paired           bool      `json:"paired"`
	Revoked          bool      `json:"revoked"`
	NASID            string    `json:"nas_id,omitempty"`
	NASName          string    `json:"nas_name,omitempty"`
	NASAddress       string    `json:"nas_address,omitempty"`
	NASVirtualIP     string    `json:"nas_virtual_ip,omitempty"`
	VirtualIP        string    `json:"virtual_ip,omitempty"`
	NKNAddress       string    `json:"nkn_address,omitempty"`
	NKNConnected     bool      `json:"nkn_connected"`
	Path             string    `json:"path"`
	PeerState        string    `json:"peer_state,omitempty"`
	Endpoint         string    `json:"endpoint,omitempty"`
	LastHandshake    int64     `json:"last_handshake_unix,omitempty"`
	HandshakeOK      bool      `json:"handshake_fresh"`
	RxBytes          int64     `json:"rx_bytes"`
	TxBytes          int64     `json:"tx_bytes"`
	RelayFallback    int       `json:"relay_fallbacks"`
	LastError        string    `json:"last_error,omitempty"`
	Since            int64     `json:"since_unix,omitempty"`
	RouteCIDR        string    `json:"route_cidr,omitempty"`
	AllowedCIDR      string    `json:"allowed_cidr,omitempty"`
	DirectAttempting bool      `json:"direct_attempting"`
	NextDirectRetry  time.Time `json:"next_direct_retry,omitempty"`
	DHTEnabled       bool      `json:"dht_enabled"`
	DHTPeers         int       `json:"dht_peers"`
	RelayReady       bool      `json:"relay_ready"`
	RelayStandby     bool      `json:"relay_standby"`
}

func (a *Agent) status() Status {
	status := Status{Phase: PhaseIdle, Path: string(mesh.PathNone)}
	profile, paired, _ := loadProfile(a.StateDir)
	if paired {
		status.Paired = a.Secrets.Has(SecretJoinSecret)
		status.Revoked = profile.RevokedAt != nil
		status.NASID = profile.NASID
		status.NASAddress = profile.NASAddress
		status.NASVirtualIP = profile.NASVirtualIP
	}
	switch {
	case !status.Paired:
		status.Phase = PhaseNotPaired
	case status.Revoked:
		status.Phase = PhaseRevoked
		status.LastError = errRevoked.Error()
	}
	a.mu.Lock()
	current := a.session
	a.mu.Unlock()
	if current == nil {
		return status
	}
	current.mu.Lock()
	controller := current.controller
	status.Phase = current.phase
	status.LastError = current.lastError
	status.NKNAddress = current.nknAddress
	status.NKNConnected = current.nknAddress != ""
	status.VirtualIP = current.virtual.String()
	status.Since = current.started.Unix()
	status.RouteCIDR = nasRoute(current.profile.NASVirtualIP)
	revoked := current.revoked
	current.mu.Unlock()
	status.Connected = true
	if revoked {
		status.Revoked = true
		return status
	}
	if controller == nil {
		return status
	}
	status.RelayFallback = controller.Metrics().RelayFallbacks
	var nas mesh.Snapshot
	for _, peer := range controller.Peers() {
		if peer.DeviceID == current.profile.NASID {
			nas = peer
		}
	}
	status.PeerState = string(nas.State)
	status.NASName = nas.Name
	status.NASVirtualIP = nas.VirtualIP
	status.DirectAttempting = nas.DirectAttempting
	if nas.Relay != nil {
		status.RelayReady, status.RelayStandby = nas.Relay.Open, nas.Relay.Standby
	}
	status.NextDirectRetry = nas.NextDirectRetry
	status.DHTEnabled, status.DHTPeers, _ = controller.DiscoveryStatus()
	if nas.VirtualIP != "" {
		status.AllowedCIDR = nas.VirtualIP + "/32"
	}
	if nas.LastError != "" && status.LastError == "" {
		status.LastError = nas.LastError
	}
	var stat wireguard.PeerStats
	if nas.WireGuardPublicKey != "" && current.wg != nil {
		stats, _ := current.wg.Stats(context.Background())
		for _, candidate := range stats {
			if candidate.PublicKey == nas.WireGuardPublicKey {
				stat = candidate
			}
		}
	}
	status.Endpoint = stat.Endpoint
	status.LastHandshake = stat.LastHandshake
	status.HandshakeOK = stat.Current
	status.RxBytes = stat.TransferRxBytes
	status.TxBytes = stat.TransferTxBytes
	status.Path = string(mesh.PathNone)
	switch {
	case stat.Current && nas.Path == mesh.PathDirectWG:
		status.Phase, status.Path = PhaseDirect, string(mesh.PathDirectWG)
	case stat.Current && nas.Path == mesh.PathNKNRelay:
		status.Phase, status.Path = PhaseRelay, string(mesh.PathNKNRelay)
	case status.Phase == PhaseDirect || status.Phase == PhaseRelay:
		status.Phase = PhaseWaiting
	}
	return status
}

var (
	longHex    = regexp.MustCompile(`[0-9a-fA-F]{24,}`)
	longBase64 = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)
)

// redact shortens anything that looks like a key or an address, so a
// diagnostics report can be pasted into an issue. Nothing secret is ever put
// into a log line; this also keeps public identifiers from being tracked.
func redact(text string) string {
	shorten := func(match string) string {
		if len(match) <= 12 {
			return match
		}
		return match[:6] + "…" + match[len(match)-4:]
	}
	text = longHex.ReplaceAllStringFunc(text, shorten)
	return longBase64.ReplaceAllStringFunc(text, shorten)
}

func (a *Agent) diagnostics() string {
	var out strings.Builder
	status := a.status()
	fmt.Fprintf(&out, "NKNGuard Android core %s\n", app.Version)
	fmt.Fprintf(&out, "generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	if device, _, err := a.identity(); err == nil {
		fmt.Fprintf(&out, "device: %s\n", device.DeviceID())
	}
	fmt.Fprintf(&out, "phase: %s  path: %s  paired: %t  revoked: %t\n", status.Phase, status.Path, status.Paired, status.Revoked)
	fmt.Fprintf(&out, "nas: %s  nas_address: %s\n", status.NASID, redact(status.NASAddress))
	fmt.Fprintf(&out, "virtual_ip: %s  nas_virtual_ip: %s  mtu: %d\n", status.VirtualIP, status.NASVirtualIP, TunnelMTU)
	fmt.Fprintf(&out, "nkn: connected=%t address=%s\n", status.NKNConnected, redact(status.NKNAddress))
	fmt.Fprintf(&out, "wireguard: peer_state=%s endpoint=%s last_handshake=%d fresh=%t rx=%d tx=%d relay_fallbacks=%d\n",
		status.PeerState, status.Endpoint, status.LastHandshake, status.HandshakeOK, status.RxBytes, status.TxBytes, status.RelayFallback)
	if status.LastError != "" {
		fmt.Fprintf(&out, "last_error: %s\n", redact(status.LastError))
	}
	fmt.Fprintf(&out, "stored secrets: %s\n", strings.Join(a.Secrets.Names(), ", "))
	if a.Logs != nil {
		out.WriteString("\nrecent log:\n")
		for _, line := range a.Logs.Lines() {
			out.WriteString(redact(line))
			if !strings.HasSuffix(line, "\n") {
				out.WriteByte('\n')
			}
		}
	}
	return out.String()
}
