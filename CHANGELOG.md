# Changelog

## Unreleased

- Windows client rewritten as a native Win32 app (walk): painted banner and buttons, white cards, tray icon (closing the window keeps the tunnel), single instance, no Microsoft Edge needed. Built with a go-winres manifest and icon.
- NAS dashboard shows the pairing link (`nknguard://pair/v1?...`) as text next to the QR code, with a copy button that falls back to selecting the text.
- Anonymous active-installation counts (24 h / 30 d / 90 d) from zero-fee NKN subscriptions to `nknguard.usage.*`, shown in the NAS dashboard, Windows client and Android app, on by default with a switch (`pkg/usagestats`, docs/USAGE_STATS.md).
- Built-in China NKN seed tried before the official seeds; dashboard wrong-password back-off; web password change removes the legacy `first-run.txt`.
- Android client (`android/`): QR/paste/link pairing with six-digit code, VpnService routing only the overlay, WireGuard (wireguard-go) direct path with NKN relay fallback, Keystore-wrapped keys, revocation display. The protocol core is the shared Go code (`internal/mobile`).
- Owners answer revoked devices with a signed `ERROR NOT_AUTHORIZED` so clients can show that their approval is gone.
- Pairing approval is persisted before the join secret is sent and rolled back if it cannot be delivered.
- Userspace WireGuard data plane (`pkg/wireguard/userspace`) and v1 wire-format test vectors (`internal/vectors`).

- Re-license NKNGuard contributions from this revision onward under AGPL-3.0-only, preserving the original Apache-2.0 attribution and license text for incorporated material.

## v0.1.0-dev (unreleased)

First extraction from NasSimHub's networking code.

- Device root identity (Ed25519) separate from WireGuard and NKN keys; 0600 keystore.
- Versioned, signed control envelopes with replay protection and size/rate limits.
- Signed peer records with TTL, sequence, and a join-secret membership proof.
- Discovery: private Kademlia DHT (`libp2pdht`), NKN topic rendezvous and static peers (`nknsdk`), `PEER_INFO` introductions.
- NAT: STUN client, candidate gathering, WireGuard-port inference, handshake-based hole punching.
- NKN relay fallback via a UDP↔session bridge, with automatic return to direct.
- Path selector with hysteresis; per-peer state machine; deterministic overlay IP allocation.
- ACL (default deny, first match, tags).
- CLI: init, join, invite, leave, up/daemon, down, status, peers, reconnect, doctor, diagnostics export.
- Local Unix-socket API; systemd unit; CI for amd64/arm64.

Not yet validated on real networks.
