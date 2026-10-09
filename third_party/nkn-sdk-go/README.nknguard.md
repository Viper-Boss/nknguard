# NKNGuard compatibility patch

This directory contains nkn-sdk-go v1.4.8 from github.com/nknorg/nkn-sdk-go,
with its Apache-2.0 LICENSE retained. The root project and Android core both
use this copy through a local Go module replacement.

`ClientConfig.RemoteSubClients` is opt-in (NKNGuard sets it to 4). With zero,
upstream behaviour is unchanged. With a positive value:

- Messages target up to four remote subclient IDs, retaining the same message
  ID for upstream deduplication and the existing end-to-end encryption.
- NCP **handshake** packets target those IDs, so a sender with only ID 3 can
  bootstrap a receiver with only IDs 0..2. Data and acknowledgements continue
  to use the remote client IDs negotiated by NCP, without extra fanout.
- Closed clients are excluded from a newly created session.

This changes routing availability only. Signed NKNGuard membership checks,
device approval and WireGuard encryption remain authoritative.

Regression tests: `go test -race github.com/nknorg/nkn-sdk-go` from the root.
Tests include an in-memory NCP session with disjoint local client IDs and
checks that ordinary data is never broadcast.
