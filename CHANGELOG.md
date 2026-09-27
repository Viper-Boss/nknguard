# Changelog

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
