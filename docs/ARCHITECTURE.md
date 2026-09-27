# Architecture

NKNGuard is a control plane for WireGuard. It decides who is in the network,
where each peer can be reached, and which path carries its traffic — and then
tells WireGuard. It never encrypts, forwards or inspects a packet itself; the
relay bridge copies WireGuard ciphertext and nothing else.

## Planes

```text
 ┌──────────────── control plane ────────────────┐   ┌──── data plane ────┐
 │                                               │   │                    │
 │ identity ─ membership ─ acl                   │   │  WireGuard (kernel │
 │     │           │        │                    │   │  or wireguard-go)  │
 │     ▼           ▼        ▼                    │   │         ▲          │
 │  discovery ──▶ mesh controller ──▶ wireguard ─┼──▶│ peers, endpoints   │
 │  rendezvous ─▶   │  ▲    │      manager       │   │         │          │
 │  signalling ◀──▶ │  │    └──▶ relay bridge ───┼──▶│ 127.0.0.1 endpoint │
 │                  ▼  │                         │   │  when relayed      │
 │               nat (candidates, strategy)      │   │                    │
 └───────────────────────────────────────────────┘   └────────────────────┘
```

| Plane | Package | Responsibility |
|---|---|---|
| Identity | `pkg/identity` | Ed25519 device root key, device id, key bindings, 0600 keystore |
| Membership | `pkg/membership` | network id + join secret → membership proof and rendezvous key |
| Discovery | `pkg/discovery` (+ `/dht`) | signed peer records; verify, cache, publish, look up |
| Rendezvous | `pkg/rendezvous` (+ `/nkntopic`) | bare transport addresses to introduce ourselves to |
| Signalling | `pkg/signaling` (+ `/nknsignal`) | signed envelopes; one dispatcher that decides what is trusted |
| Protocol | `pkg/protocol` | envelope format, versions, capabilities, replay cache |
| NAT | `pkg/nat` | STUN client, candidate gathering, port inference, punch primitives |
| WireGuard | `pkg/wireguard` | interface, peers, endpoints, handshake stats via `wg`/`ip` |
| Relay | `pkg/relay` (+ `/nknrelay`) | UDP↔stream bridge over an NKN session |
| Mesh | `pkg/mesh` | peer state machine, path selector, reconcile loop, IP allocation |
| Policy | `pkg/acl` | first-match allow/deny between devices and tags |
| Observability | `pkg/diagnostics`, `internal/app` | status, doctor, redacted bundle, local API |

Everything that talks to NKN or libp2p is in a build-tagged sub-package. The
rest is standard library only, which is what lets the whole state machine be
tested offline.

## Trust flows one way

A record or message becomes trusted in exactly one place each:

1. **Record** (`mesh.Controller.ingestRecord`): signature and freshness
   (`PeerRecord.Verify`) → membership proof (`membership.Key.Verify`) → ACL.
   Only then does a peer exist.
2. **Envelope** (`signaling.Dispatcher.Dispatch`): version, signature,
   device-id binding, network, addressing, clock window, replay → membership.
   `PEER_INFO` is the one type accepted from non-members, rate-limited before
   signature verification, and its payload must itself pass step 1.

Nothing is trusted for arriving over NKN, from the DHT, or from a LAN address.

## The reconcile loop

The controller does not react to events to decide whether a tunnel works. Every
`ReconcileInterval` it reads `wg show dump` and, per peer:

- a fresh handshake over a non-loopback endpoint → **direct**;
- a fresh handshake over the loopback bridge → **relay**;
- otherwise the path selector decides whether to start a direct attempt, open
  the relay, or wait.

Because the data plane is the source of truth, a lost message, a daemon
restart or an NKN outage cannot make the controller believe a working tunnel
is broken (Principle 4). The state machine's `EventHandshakeOK` is legal from
every live state for the same reason.

## Direct path

Only one side — the one with the lower device id — initiates, so two attempts
never move the same WireGuard endpoint in opposite directions. The initiator
sends `PUNCH_REQUEST` with a wall-clock rendezvous; at that instant both sides
set each other's best candidate as the WireGuard endpoint and nudge a
handshake. WireGuard's handshake packets are the punch. See
[NAT_TRAVERSAL.md](NAT_TRAVERSAL.md).

## Relay path

The initiator opens an NKN session to the peer, and each side binds a loopback
UDP socket (the *bridge*) and points the peer's WireGuard endpoint at it.
WireGuard does not know it is relayed. When a direct handshake later arrives,
WireGuard roams to it on its own; the next reconcile sees a non-loopback
endpoint, the selector switches to direct after `DirectRecoveryHold`, and the
bridge is closed.

## Path selector

Hysteresis in both directions (`pkg/mesh/selector.go`):

- leave direct only after it has been stale for `DirectLossGrace` (20 s);
- return to direct only after it has been healthy for `DirectRecoveryHold` (5 s);
- direct retries back off from 30 s to 10 min, reset by any success or by the
  peer advertising new candidates.

## Goroutines and shutdown

`Controller.spawn` is the only way the controller starts a goroutine, and
`Run` waits for all of them. `TestShutdownLeavesNoGoroutines` holds this.
Shutdown order (spec §62): cancel → controller (discovery, signalling,
attempts, relay bridges) → persist state → close NKN → remove the interface.

## State on disk

```text
/etc/nknguard/config.yaml            no secrets; safe to share
/var/lib/nknguard/keystore/  0700    root.key, wireguard.key, nkn.seed, join.secret (0600)
/var/lib/nknguard/membership.json    network id, device id, joined-at
/var/lib/nknguard/runtime.json       record sequence (+16 on load), virtual IP
/var/lib/nknguard/peers.json         unexpired verified peer records
/var/lib/nknguard/dht/libp2p.key     DHT host identity (tag libp2pdht)
/run/nknguard/nknguard.sock  0660    local API
```

## Relationship to NasSimHub

NKNGuard was extracted from NasSimHub's networking code; see
[EXISTING_CODE_AUDIT.md](EXISTING_CODE_AUDIT.md) and
[MIGRATION_PLAN.md](MIGRATION_PLAN.md). The intended end state is NasSimHub
consuming NKNGuard (Go module or the local API), not maintaining a second copy.
