package wireguard

import (
	"strconv"
	"strings"
	"time"
)

// parseDump turns the output of `wg show <iface> dump` into a status.
//
// The format is tab-separated and stable: the first line is the interface
// (private key, public key, listen port, fwmark) and every later line is a
// peer (public key, preshared key, endpoint, allowed ips, last handshake,
// rx, tx, keepalive). The private key in field one is read past and never
// stored anywhere, which is why this parser exists instead of a regex over the
// human-readable output.
func parseDump(output string, now time.Time) Status {
	status := Status{State: StateUp, UpdatedAt: now}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index, line := range lines {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if index == 0 {
			if len(fields) >= 3 {
				status.PublicKey = fields[1]
				status.ListenPort, _ = strconv.Atoi(fields[2])
			}
			continue
		}
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		received, _ := strconv.ParseInt(fields[5], 10, 64)
		sent, _ := strconv.ParseInt(fields[6], 10, 64)
		endpoint := fields[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		status.Peers = append(status.Peers, PeerStats{
			PublicKey:       fields[0],
			Endpoint:        endpoint,
			LastHandshake:   handshake,
			TransferRxBytes: received,
			TransferTxBytes: sent,
			Current:         handshake > 0 && now.Sub(time.Unix(handshake, 0)) < HandshakeFreshness,
		})
	}
	return status
}
