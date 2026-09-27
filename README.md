# NKNGuard

**Serverless WireGuard mesh over NKN.**

NKNGuard connects your machines into a private WireGuard network without a
coordination server. Nodes find each other and exchange keys over the
[NKN](https://nkn.org) network, punch through NAT with WireGuard's own
handshake, and fall back to a relayed path over NKN when a direct path is not
possible.

```text
Tailscale:  node ── coordination server ── node      (+ DERP relay)
NKNGuard:   node ── NKN signalling / DHT ── node     (+ NKN relay)
                         │
                         └─ data: WireGuard, direct whenever the NAT allows
```

- **WireGuard is the data plane.** Kernel WireGuard (or wireguard-go). NKNGuard
  never touches packet cryptography.
- **NKN is the control plane.** Signed, versioned control messages travel as
  end-to-end-encrypted NKN messages. No server of ours is in the loop.
- **Discovery is untrusted by design.** Peers are found through an NKN topic, a
  private Kademlia DHT, or a static list. Every record is signed by the
  device's root key and carries a membership proof; nothing is trusted because
  of where it came from.
- **Direct first, relay second.** The relay exists so peers are *connected at
  all*. While a peer is relayed, NKNGuard keeps retrying the direct path and
  moves back as soon as it works.
- **The tunnel outlives the control plane.** If NKN or the DHT goes away, an
  established WireGuard tunnel keeps running, and if the daemon crashes the
  interface and its peers stay up until it is restarted.

> **Status: development preview.** The NAS/Linux daemon, local dashboard, QR approval, Windows one-click client, and NKN/WireGuard paths have automated tests. Real fnOS, Windows tunnel, and cross-NAT tests remain outstanding. The Android client has automated interop tests; on-device testing is outstanding (see [Android](docs/ANDROID.md)).

## Quick start

Requirements: Linux (amd64 or arm64), `wireguard-tools` (`wg`, `ip`), kernel
WireGuard or `wireguard-go`, root, and a roughly correct clock (±2 min).

```bash
make deps && make build          # needs Go ≥ 1.25.7 and module access once
sudo ./scripts/install.sh
```

First device:

```bash
sudo nknguard init --name nas-home
# Network ID: nkgnet_...
```

Start the NAS and open its local dashboard:

```bash
sudo systemctl enable --now nknguard
# NAS browser: http://127.0.0.1:7878/
# Or: ssh -L 7878:127.0.0.1:7878 user@nas
```

The browser requests administrator user `admin` and the password chosen during installation. An NAS administrator can reset it locally with `sudo nknguard dashboard-password set`. The dashboard displays the NAS's full NKN address for visual comparison. The first visit displays a five-minute QR invitation. On another Linux device, use `sudo nknguard pair '<QR content>' --name laptop`; on Windows, paste the QR content into the [client](docs/WINDOWS.md). Compare the six-digit code and approve on the NAS. The QR has the NAS public identity and a one-time request token, never the shared membership secret. See [pairing](docs/PAIRING.md).

Legacy `join --secret` and `invite` commands work only with `pairing.approval_required: false`. The dashboard binds only to `127.0.0.1:7878`; do not publish its admin port directly.

In legacy enrollment mode the ACL defaults to **deny**. Allow what you want in
`/etc/nknguard/config.yaml`:

```yaml
acl:
  default: deny
  rules:
    - src: laptop
      dst: nas-home
      action: allow
```

Then on each device:

```bash
sudo systemctl enable --now nknguard      # or: sudo nknguard up (foreground)
nknguard status
```

```text
PEER      IP           PATH        STATE   ENDPOINT             LAST HANDSHAKE
laptop    10.88.41.7   direct-wg   DIRECT  203.0.113.5:51820    12s ago
vps-eu    10.88.3.200  nkn-relay   RELAY   127.0.0.1:41822      4s ago
```

## Commands

| Command | |
|---|---|
| `nknguard init` | create a network and join it |
| `nknguard pair <QR-content>` | request owner-approved enrollment (Linux CLI) |
| `nknguard dashboard-password set` | privately set or reset the NAS dashboard password |
| `nknguard join <id> --secret <s>` | legacy enrollment, only with approval disabled |
| `nknguard invite` | legacy join command, only with approval disabled |
| `nknguard leave` | forget the network (device identity is kept) |
| `sudo nknguard up` / `daemon` | run the node |
| `sudo nknguard down` | stop the node and remove the interface |
| `nknguard status` / `peers` | what is connected, how, and what happened |
| `nknguard reconnect <device-id>` | retry a direct path now |
| `nknguard doctor` | check the host, NAT and running node |
| `nknguard diagnostics export` | redacted bundle for a bug report |

## How peers find each other

Pick any combination in `discovery:`:

| Source | Setup | Trade-off |
|---|---|---|
| **NKN topic** (`nkn_topic: true`, default) | none | Topic name is derived from the join secret. The subscriber list is public: anyone who knows the topic sees which NKN addresses are in it. |
| **Private DHT** (`dht: true`, build tag `libp2pdht`) | bootstrap peers, or mDNS on a LAN | Project-private Kademlia (never the public IPFS DHT). |
| **Static peers** (`static_peers:`) | list each other's NKN address | Nothing public at all. |

Whatever the source, a peer is admitted only if its signed record verifies and
its membership proof matches the join secret — and a tunnel is built only if
the ACL allows it.

## Build

The default build also uses go-qrcode. NKN and libp2p support are behind build tags:

```bash
go test ./...                               # core
make deps                                   # fetch nkn-sdk-go, libp2p
go build -tags "nknsdk libp2pdht" ./cmd/nknguard
```

A binary built without `nknsdk` can `init`, `join` and `doctor`, and refuses
`up` with an explanation. See [docs/BUILD.md](docs/BUILD.md).

## Limitations

Stated plainly, because networking software that over-promises is worse than
useless:

- **Not every NAT can be traversed.** Two peers both behind symmetric NAT will
  almost always end up on the relay. `nknguard doctor` tells you which case you
  are in.
- **The relay is slow.** It rides NKN sessions; expect far lower throughput and
  higher latency than a direct path. It is a fallback, not a data plane.
- **Kernel WireGuard owns its UDP port**, so the public port is inferred from a
  probe socket assuming port-preserving NAT. This is right for most home
  routers and wrong for some; see [docs/NAT_TRAVERSAL.md](docs/NAT_TRAVERSAL.md).
- **Membership proofs still use a shared secret.** The NAS enforces an approved device identity list and can revoke one device. Rotate or recreate network credentials if the shared secret or a device identity key is compromised; automated rotation is not implemented.
- **Windows is a preview client.** It requires official WireGuard for Windows and Microsoft Edge; see [Windows setup](docs/WINDOWS.md). The Android client is a preview; see [Android client](docs/ANDROID.md). IPv4 overlay and one network per node.
- **Not anonymous.** WireGuard endpoints reveal IP addresses to your peers, NKN
  addresses are linkable over time, and STUN servers see your public address.
- **Real-network validation is outstanding.** The two-node, cross-NAT test
  matrix in [docs/NAT_TRAVERSAL.md](docs/NAT_TRAVERSAL.md) has not been run yet.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol](docs/PROTOCOL.md)
- [NAT traversal](docs/NAT_TRAVERSAL.md)
- [Security model](docs/SECURITY.md) · [Reporting vulnerabilities](SECURITY.md)
- [Build](docs/BUILD.md) · [Contributing](CONTRIBUTING.md)
- [Windows client](docs/WINDOWS.md)
- [Android client](docs/ANDROID.md)
- [中文说明](README.zh-CN.md)

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Earlier published
preview binaries and commits remain under their original Apache-2.0 terms;
this change applies to this revision and subsequent releases.
