// Package diagnostics renders what the node is doing and packages it for a bug
// report.
//
// The constraint that shapes this package: a diagnostics bundle is something a
// user will paste into a public issue tracker. So redaction is not a feature
// applied at export time, it is the only way values enter these structures at
// all — there is no field here that could hold a private key, a join secret or
// a wallet seed, and the redactor is a second line of defence rather than the
// first.
package diagnostics

import (
	"time"

	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// Status is the whole node, as `nknguard status` prints it and the local API
// returns it.
type Status struct {
	Version     string    `json:"version"`
	DeviceID    string    `json:"device_id"`
	Device      string    `json:"device_name"`
	NetworkID   string    `json:"network_id"`
	VirtualIP   string    `json:"virtual_ip,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	Uptime      string    `json:"uptime"`
	OverlayCIDR string    `json:"overlay_cidr"`
	DHTEnabled  bool      `json:"dht_enabled"`
	DHTPeers    int       `json:"dht_peers"`
	DHTRoutes   int       `json:"dht_routes"`
	DHTLANPeers *int      `json:"dht_lan_peers,omitempty"`

	NKNAddress    string                     `json:"nkn_address,omitempty"`
	NKNConnected  bool                       `json:"nkn_connected"`
	NKNConnection nknclient.ConnectionStatus `json:"nkn_connection"`
	NAT           nat.Behaviour              `json:"nat_behaviour"`

	WireGuard wireguard.Status `json:"wireguard"`
	Peers     []mesh.Snapshot  `json:"peers"`
	Metrics   mesh.Metrics     `json:"metrics"`
}

// Check is one line of `nknguard doctor`.
type Check struct {
	Name   string `json:"name"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
}

// Level is a check's outcome.
type Level string

const (
	// LevelOK means the thing works.
	LevelOK Level = "OK"
	// LevelWarn means it works but something will bite later — a symmetric
	// NAT, a missing STUN server, a peer stuck on the relay.
	LevelWarn Level = "WARN"
	// LevelFail means this node cannot do its job until it is fixed.
	LevelFail Level = "FAIL"
)

// Report is the doctor's output.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Checks      []Check   `json:"checks"`
}

// Worst returns the most severe level in the report, which is what the command
// turns into an exit status.
func (r Report) Worst() Level {
	worst := LevelOK
	for _, check := range r.Checks {
		switch check.Level {
		case LevelFail:
			return LevelFail
		case LevelWarn:
			worst = LevelWarn
		}
	}
	return worst
}

// Add appends a check.
func (r *Report) Add(name string, level Level, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Level: level, Detail: detail})
}
