# NAT traversal

What NKNGuard does to get a direct WireGuard path, why it works when it does,
and where it cannot.

## Candidates

For WireGuard's listen port `P`, a node advertises:

| Type | How | Priority |
|---|---|---|
| host | each non-loopback interface address, port `P` | 1000 (private/link-local), 900 (public) |
| srflx | public IP from STUN, port `P` | 500, halved if the NAT remaps ports |

**The port-inference problem.** Kernel WireGuard owns its UDP socket, so
NKNGuard cannot send STUN from it. Instead it opens a probe socket, asks STUN
servers what they see, and checks whether the NAT kept the probe's source
port. If it did (most home routers, Linux MASQUERADE when the port is free),
WireGuard's port is very likely preserved too, and `public_ip:P` is a real
candidate. If it did not, the candidate is still offered at lower priority —
trying costs a few packets — and the relay is the likely outcome.

STUN servers are only asked "what address do you see"; they are told nothing
about the network. They are configurable (`nat.stun.servers`).

## Punching with WireGuard's own handshake

1. The initiator (lower device id) sends `PUNCH_REQUEST` with a rendezvous
   1.5 s ahead.
2. At the rendezvous, both sides set the other's best candidate as the peer
   endpoint (`wg set … endpoint`) and send one UDP byte to the peer's overlay
   address, which makes WireGuard send a handshake initiation *now*.
3. Each side's initiation opens its own NAT mapping toward the other; the other
   side's initiation then arrives at a mapping that exists.
4. Success is a handshake newer than the attempt's start over a non-loopback
   endpoint, read from `wg show dump`. It is observed, not inferred.
5. Otherwise the next candidate gets a 3 s window (up to 4). Both sides order
   candidates identically.

On failure the initiator opens the relay; if a relay is already up, the
WireGuard endpoint is pointed back at it, so a failed attempt costs seconds of
relay traffic, not the relay.

## Expected outcomes

| A | B | Expected |
|---|---|---|
| public IP | public IP | direct |
| public IP | NAT | direct |
| cone NAT | cone NAT | direct (punch) |
| same LAN | same LAN | direct (host candidates) |
| symmetric NAT | cone NAT | sometimes direct, often relay |
| symmetric NAT | symmetric NAT | relay |
| UDP blocked | any | relay |
| CGNAT (carrier) | anything behind NAT | usually relay |

**Symmetric NAT is not claimed to work.** `nknguard doctor` reports
"symmetric NAT suspected" when two STUN servers see different ports.

## Roaming

When a laptop moves from Wi-Fi to a hotspot, WireGuard itself roams: an
authenticated packet from a new address updates the endpoint without NKNGuard.
When the *laptop's own* public address changes and the other side cannot reach
it, the next republish (≤ 30 s) pushes the new record straight to peers over
NKN; a changed candidate set resets the direct-retry backoff so the next
reconcile tries the new address immediately. Device id and virtual IP do not
change.

### Noticing a dead path

A WireGuard handshake stays "fresh" for three minutes, far too long to notice
that a path died. Both sides send a keepalive every 25 s, so a live path
delivers a packet at least that often. The controller watches each peer's
received-byte counter: when it has not moved for two keepalive intervals plus
five seconds (55 s, so one lost keepalive is tolerated) the path counts as
dead, and after a further 10 s of grace the peer falls back to the relay and a
new punch starts. A relayed stream that goes silent the same way is dropped
and reopened. `Timing.ReceiveTimeout` overrides the interval; a negative value
turns the check off.

Three events short-cut the wait:

- **Local address change.** The daemon polls its interface addresses every
  5 s (`Controller.WatchNetwork`); the Android app reports changes from the
  system. On a change the node sends a packet to every peer at once (so the
  other side's WireGuard roams without waiting for a keepalive), gathers
  candidates, pushes its record and clears the direct-retry backoff. A path
  that still works is not touched.
- **Resume from suspend.** A reconcile tick arriving more than 10 s late means
  the host slept. The silence clocks restart and every peer gets a packet, so
  a path that survived the sleep is not mistaken for a dead one.
- **The peer's candidates changed** (above).

## Relay fallback

After 20 s without any path the initiator opens an NKN session to the peer.
Both sides bridge it to WireGuard on `127.0.0.1`. Direct retries continue
(30 s, doubling to 10 min); when a direct handshake appears the selector waits
5 s of stability, then closes the bridge.

## Validation status and test matrix

Covered in-process (`pkg/mesh/mesh_test.go`, with `-race`): discovery → direct;
relay fallback with direct blocked, real datagrams through real bridges;
recovery to direct when unblocked; signalling outage with a live tunnel;
introductions without any DHT; non-member rejection; goroutine-clean shutdown.

**Not yet run on real networks.** Before calling v0.1 done:

| Scenario | Check |
|---|---|
| VPS ↔ VPS | `ping`, `iperf3` ≈ bare WireGuard |
| home NAT ↔ VPS | direct within 30 s |
| home NAT ↔ home NAT | direct or relay, never stuck |
| phone hotspot ↔ home NAT | ditto; record NAT type from doctor |
| `iptables -A OUTPUT -p udp --dport <peer port> -j DROP` | relay within ~25 s, ping works |
| remove the rule | back to direct |
| Wi-Fi → hotspot on a laptop | same virtual IP, recovers without restart |
| stop NKN (block outbound to NKN nodes) with direct up | tunnel unaffected |
| `kill -9` the daemon | tunnel keeps working; restart resumes |
| 24 h soak, 2 nodes | flat RSS and goroutine count |
