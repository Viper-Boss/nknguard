# Protocol (version 1)

All control messages are **envelopes**, carried as NKN messages (end-to-end
encrypted by NKN; unencrypted messages are dropped). The envelope's own
signature is what is trusted, not the transport.

## Identifiers

| Name | Format |
|---|---|
| Device id | `nkg_` + base32(lowercase, no padding) of `SHA-256(root_public_key)[:10]` — 16 chars |
| Network id | `nkgnet_` + base32 of 16 random bytes |
| Join secret | base32 of 32 random bytes; sent only in an encrypted NKN approval message after local approval |
| NKN address | `nknguard.<hex public key>` (sub-client prefix `__N__.` stripped) |

Root keys are Ed25519. The device id is derived, so a message claiming a
device id it cannot sign for fails verification.

## Signing rule

Envelopes, peer records and key bindings are signed the same way: Ed25519 over
the JSON encoding of the object with `signature` absent (Go `encoding/json`,
fields in declared order, `[]byte` as standard base64, `omitempty` as
declared, no insignificant whitespace, and Go's escaping of `<`, `>`, `&`,
U+2028 and U+2029 as `\u003c`-style sequences). A future non-Go implementation
must reproduce these bytes exactly; v2 may move to a canonical binary
encoding, negotiated by version.

Fixed test vectors for every signed or derived value — device id, pairing
code, QR URI, envelope signing bytes and signature, membership proof,
rendezvous topic, peer record, relay frame and virtual IP — are in
[`internal/vectors/testdata/v1.json`](../internal/vectors/testdata/v1.json).
The test in that package fails on any byte change, so the wire format cannot
change without a deliberate regeneration.

## Envelope

```json
{
  "protocol_version": 1,
  "message_id": "base64url(SHA-256(nonce)[:12])",
  "network_id": "nkgnet_...",
  "from_device_id": "nkg_...",
  "from_public_key": "<base64 32 bytes>",
  "to_device_id": "nkg_... or empty",
  "type": "HELLO",
  "timestamp_unix_milli": 1790000000000,
  "nonce": "<base64 16 bytes>",
  "payload": { },
  "signature": "<base64 64 bytes>"
}
```

A receiver drops the envelope, with no reply, unless **all** hold:

1. `MinVersion ≤ protocol_version ≤ Version`
2. `from_device_id == DeviceID(from_public_key)` and the signature verifies
3. `network_id` is ours; `to_device_id` is empty or ours
4. timestamp within **−2 min / +30 s** of local time
5. `message_id` not seen in the last 3 min (bounded cache, 16 384 ids)
6. sender is an admitted member — except for rate-limited `PEER_INFO` and a valid short-lived `PAIR_REQUEST`
7. encoded size ≤ **64 KiB**

## Message types

| Type | Payload | Purpose |
|---|---|---|
| `PEER_INFO` | `{record, want_reply}` | introduction: carries the sender's signed peer record. Open to non-members, rate-limited (10/s, burst 30) before signature checks. `record.device_id` must equal the envelope sender. |
| `HELLO` | `{versions:{min_version,max_version}, capabilities, device_name}` | version negotiation |
| `CANDIDATE` | `{wireguard_public_key, candidates, virtual_ips}` | current endpoints; the key must match the signed record |
| `PUNCH_REQUEST` | `{round, candidates, start_at_unix_milli, token}` | direct attempt at a rendezvous ≤ 10 s ahead |
| `PUNCH_ACK` | `{round, accepted, reason}` | accept or decline |
| `WG_READY` | `{wireguard_public_key, endpoint, virtual_ip}` | informational: direct path observed |
| `KEEPALIVE` | — | reserved |
| `REKEY`, `ROUTE_UPDATE`, `RELAY_REQUEST`, `RELAY_READY` | — | reserved for v0.2 |
| `DISCONNECT` | `{reason}` | courtesy |
| `PAIR_REQUEST` | `{token,name,nkn_address,wireguard_public_key}` | signed request using a short-lived QR invitation; requires local NAS approval |
| `PAIR_APPROVAL` | `{join_secret,nas_id,nas_address,invite_token}` | encrypted NKN reply from the pinned NAS identity |
| `ERROR` | `{code, message}` | e.g. `VERSION_UNSUPPORTED`; `NOT_AUTHORIZED` from an owner to a revoked device (below) |

Unknown types from a newer peer are dropped quietly.

## Versions and capabilities

`HELLO` carries `{min_version, max_version}`; the highest common version is
used, and no overlap is answered with `ERROR VERSION_UNSUPPORTED`.
Capabilities (v1): `wireguard-direct`, `nkn-relay`, `udp-punch-v1`,
`dht-record-v1`, `acl-v1`, plus `tag:<name>` for ACL tags. Unknown capabilities
are ignored.

## Pairing

The six-digit code both sides show is
`SHA-256(JSON({"Token":token,"DeviceID":device_id,"WGKey":wireguard_public_key}))`,
first four bytes big-endian, modulo 1 000 000, zero-padded to six digits. The
JSON keys are capitalised (a Go anonymous struct). The client accepts a
`PAIR_APPROVAL` only if it verifies, comes from the NAS device id and root
key pinned in the QR code, and echoes the invitation token, NAS id and NAS
address. The owner persists the approval before sending it and rolls it back
if the message cannot be sent.

## Revocation notice

An owner that requires approval answers a `PEER_INFO` whose record is
correctly signed, fresh, carries a valid membership proof and arrived from the
NKN address the record names, but whose device is not on the approval list,
with a signed `ERROR {code: NOT_AUTHORIZED}` addressed to that device — at most
once a minute per device. A client that receives it from the NAS it pinned at
pairing treats its pairing as revoked. A sender without a valid membership
proof gets no reply. Older clients log the error and otherwise ignore it.

## Peer record

```json
{
  "version": 1,
  "network_id": "nkgnet_...", "device_id": "nkg_...", "name": "nas-home",
  "root_public_key": "...", "nkn_public_key": "...", "nkn_address": "nknguard.<hex>",
  "dht_addresses": ["/ip4/..."],
  "wireguard_public_key": "...", "virtual_ips": ["10.88.41.7"],
  "candidates": [{"type":"srflx","ip":"203.0.113.5","port":51820,"priority":500,
                  "protocol":"udp","observed_at":0,"expires_at":0}],
  "capabilities": ["wireguard-direct", "tag:admin"],
  "membership_proof": "...",
  "sequence": 42, "issued_at": 0, "expires_at": 0,
  "signature": "..."
}
```

- TTL clamped to **30 s – 5 min** (default 2 min); republished every 30 s.
- `sequence` strictly increases per device (persisted, +16 on restart).
- ≤ 16 KiB; ≤ 16 candidates are used; loopback/unspecified/multicast dropped.
- A peer's `virtual_ips` are installed as WireGuard AllowedIPs **only if inside
  the local overlay CIDR**, as /32s.

## Membership

```text
proof_key   = HMAC-SHA256(join_secret, "nknguard/v1/membership-proof" ‖ 0x00 ‖ network_id ‖ 0x01)
proof       = HMAC-SHA256(proof_key,  network_id ‖ 0x00 ‖ device_id ‖ 0x00 ‖ root_public_key)
rv_key      = HMAC-SHA256(join_secret, "nknguard/v1/rendezvous" ‖ 0x00 ‖ network_id ‖ 0x01)
topic       = "nknguard-rv-" + base32(SHA-256(rv_key)[:20])
```

The proof is inside the signed record, so it cannot be moved to another device
or root key. The rendezvous topic depends on the secret, so a leaked network
id does not reveal where members publish.

## Relay framing

Over an NKN session (ncp): `uint16 big-endian length ‖ WireGuard datagram`,
repeated. Zero length is an error. The bridge accepts local datagrams only from
WireGuard's own listen address.

## Userspace punch packet (reserved)

`"NKGP" ‖ kind(1=probe, 2=reply) ‖ token[8]` — 13 bytes. Used by `nat.Punch`
for a future userspace data plane that shares one socket with WireGuard; the
kernel-WireGuard daemon punches with WireGuard handshakes instead.

## Timing constants

| | |
|---|---|
| republish | 30 s |
| reconcile | 2 s |
| punch lead | 1.5 s |
| per-candidate window | 3 s, up to 4 candidates |
| relay after no path for | 20 s |
| direct retry | 30 s → 10 min (×2) |
| handshake freshness | 3 min |
