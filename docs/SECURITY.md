# Security model

## Trust boundary

| Trusted | Untrusted |
|---|---|
| local private keys in the keystore | the internet and every network path |
| records and envelopes whose signatures verify | NKN nodes (relay and routing) |
| membership proofs under our join secret | the DHT and anything stored in it |
| WireGuard's cryptographic peer identity | NKN topic subscriber lists |
| | STUN servers |
| | the endpoint a packet appears to come from |
| | the device id a peer claims |

## Keys

| Key | Purpose | Storage | Rotates |
|---|---|---|---|
| device root (Ed25519) | signs records, envelopes, bindings; *is* the device | `keystore/root.key` 0600 | never (reinstall = new device) |
| WireGuard | data plane | `keystore/wireguard.key` 0600 | independently (v0.2) |
| NKN seed | NKN address | `keystore/nkn.seed` 0600 | independently |
| join secret | membership | `keystore/join.secret` 0600 | with the network |
| dashboard password | local administration | `keystore/dashboard.key` 0600 | manually after compromise |

The keystore refuses to read a secret whose mode allows group or other access.
The WireGuard private key reaches `wg` on stdin only, never on a command line
(`ps` could read it) and never in a temporary file. No key, seed or secret is
logged, returned by the local API, or included in a diagnostics bundle; the
bundle is additionally passed through a redactor.

## Threats

**Discovery poisoning.** A DHT participant or topic subscriber can serve stale,
forged or someone else's records. Forged or altered records fail the signature;
stale ones fail TTL and sequence; another network's records fail the network
id; a genuine record from a non-member fails the membership proof. The worst a
poisoner can do is withhold records (denial of discovery), which static peers
work around.

**Impersonation.** The device id is a hash of the root key, and every envelope
and record is signed by that key. A `CANDIDATE` carrying a WireGuard key that
differs from the signed record is refused.

**Replay.** Envelopes: clock window (−2 min/+30 s) plus a bounded message-id
cache covering it. Records: TTL and strictly increasing sequence (persisted and
advanced on restart, so a crash cannot reuse a number).

**Route hijack.** A member could advertise a LAN range or `0.0.0.0/0` as its
virtual IP. AllowedIPs are installed only as /32s inside the overlay CIDR.

**Relay trust.** Relayed traffic is WireGuard ciphertext end to end. NKN nodes
see sizes, timing and the two NKN addresses; they cannot read or forge
traffic. The bridge accepts local datagrams only from WireGuard's own port.

**Denial of service.** Size caps (64 KiB envelope, 16 KiB record, 16
candidates, 512 peers, 4096 pending introductions), a token bucket on the one message type strangers
may send (checked before signature verification), bounded replay cache and
transition history, one attempt per peer at a time, bounded retries with
jittered backoff, and a refusal to park on a rendezvous more than 10 s ahead.

**Compromised member.** The NAS verifies the device's signed identity and its
local approved-device list. The owner can revoke that identity and remove its
WireGuard peer. The former client still has the shared network secret, so a
compromise of that secret calls for recreating the network and pairing all
legitimate clients again. There is no automatic key rotation. Approval-mode
tunnels are permitted once the device is approved; fine-grained traffic ACLs
are not enforced by a firewall in this release.

**Local privilege.** The daemon runs as root to manage the interface. The
local control API is a Unix socket, mode 0660. The dashboard listens only on
loopback and requires a separate administrator password. Its Basic credentials
travel over HTTP on loopback; remote access should use an SSH tunnel. Commands
are always argument vectors; nothing is ever passed to a shell.

## Metadata exposure

- **NKN topic rendezvous** publishes this node's NKN address under a
  secret-derived topic. The list is public to anyone who knows the topic;
  NKN addresses are stable and therefore linkable. Use `static_peers` and
  `nkn_topic: false` to avoid it.
- **STUN** servers learn your public IP and that you use STUN.
- **Peers** learn your public IP (it is how WireGuard works).
- **NKN** nodes learn which NKN addresses talk to each other and when.
- Nothing here provides anonymity.

## Updates

NKNGuard has no self-update and no network message can trigger code download
or execution. Releases publish SHA-256 sums; signed releases are planned.

## Reporting

See the repository's [SECURITY.md](../SECURITY.md).
