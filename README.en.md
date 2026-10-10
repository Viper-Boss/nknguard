<div align="center">

# NKNGuard

**Reach your NAS from anywhere — no public IP, no relay server of ours.**

A private NAS connection: NKN pairs devices, ICE finds a direct WireGuard path, and an encrypted NKN relay stays ready as fallback. Paired devices can also exchange signed connection information over a private DHT.

[![Release](https://img.shields.io/github/v/release/Viper-Boss/nknguard?include_prereleases&label=release&color=2f80ed)](https://github.com/Viper-Boss/nknguard/releases)
[![CI](https://github.com/Viper-Boss/nknguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Viper-Boss/nknguard/actions/workflows/ci.yml)
[![Android](https://github.com/Viper-Boss/nknguard/actions/workflows/android.yml/badge.svg)](https://github.com/Viper-Boss/nknguard/actions/workflows/android.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-1f9e8f)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20fnOS%20%C2%B7%20Windows%20%C2%B7%20Android-4b5563)

[简体中文](README.md) · **English** · **[❤ Support the author](#-support-the-author)**

<img src="docs/images/nas-dashboard-overview.jpg" alt="NAS dashboard: overview" width="860">

</div>

> [!WARNING]
> **Development preview.** The protocol, NAS daemon, Windows and Android clients have automated tests, with successful Android-to-NAS tests on LAN and cellular networks; coverage of routers, carriers and long-running sessions is still limited. Try it on non-critical devices first and do not rely on it as your only way in.

## Download

Everything is on the **[Releases page](https://github.com/Viper-Boss/nknguard/releases)**.

| Platform | File | Notes |
| --- | --- | --- |
| 🗄️ **NAS / Linux** (ARM64, incl. ARM fnOS) | `nknguard-linux-arm64` | Needs root and `wireguard-tools`; see [Install the NAS](#1-install-the-nas) |
| 🗄️ **NAS / Linux** (x86_64) | `nknguard-linux-amd64` | Same as above |
| 🪟 **Windows 10/11** | `NKNGuard-Windows-preview.zip` | Native desktop app with a tray icon; install [WireGuard for Windows](https://www.wireguard.com/install/) first |
| 🤖 **Android 8.0+** | `NKNGuard-Android-preview.apk` | Preview; maintainer-signed builds with the same certificate upgrade in place and preserve pairing |

Each release ships a `SHA256SUMS` file: `sha256sum -c SHA256SUMS`. Windows preview binaries are unsigned. Maintainer-delivered Android APKs use a persistent signing certificate; raw CI debug artifacts use a temporary certificate.

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/images/nas-dashboard-pairing.png" alt="NAS dashboard: pairing"><br><sub><b>NAS dashboard · Pairing</b> — one-time QR plus the same pairing link as text, compare a six-digit code, approve; revoke single devices later</sub></td>
    <td width="50%"><img src="docs/images/nas-dashboard-usage.png" alt="NAS dashboard: usage counts"><br><sub><b>NAS dashboard · Overview</b> — device paths and NKNGuard users in the last 24 h / 30 d / 90 d</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/images/windows-client-connected.png" alt="Windows client: connected"><br><sub><b>Windows client</b> — native window, one-click connect, keeps the tunnel in the tray</sub></td>
    <td width="50%"><img src="docs/images/windows-client-pairing.png" alt="Windows client: first pairing"><br><sub><b>Windows client · First pairing</b> — paste the pairing link, confirm the same code on the NAS</sub></td>
  </tr>
</table>

<sub>Rendered from the real UI code with demo data (the Windows client under Wine). The UI is currently in Chinese. Android screenshots below come from the actual app in an emulator with clearly labeled demo NAS profiles.</sub>


## Android interface

<img src="docs/images/android-home.jpg" alt="Android NAS list" width="320">

Native Android UI with separate pairing information for each saved NAS. Name, switch or remove a profile independently.

## ❤ Support the author

If NKNGuard is useful to you, you can support its maintenance. Donations are optional and do not affect features or device authorization.

Scan a QR code below, or click an image to view the original.

<table>
  <tr><th align="center">WeChat</th><th align="center">Alipay</th></tr>
  <tr>
    <td align="center"><a href="internal/app/dashboard/wechat.png"><img src="internal/app/dashboard/wechat.png" alt="WeChat收款码" width="240"></a></td>
    <td align="center"><a href="internal/app/dashboard/alipay.png"><img src="internal/app/dashboard/alipay.png" alt="Alipay收款码" width="240"></a></td>
  </tr>
</table>

<table>
  <tr><th align="center">USDT · TRC20（Tron）</th><th align="center">BTC · Bitcoin</th></tr>
  <tr>
    <td align="center"><a href="docs/images/support-usdt.png"><img src="docs/images/support-usdt.png" alt="USDT TRC20 收款地址二维码" width="180"></a></td>
    <td align="center"><a href="docs/images/support-btc.png"><img src="docs/images/support-btc.png" alt="BTC 收款地址二维码" width="180"></a></td>
  </tr>
  <tr><th align="center">ETH · Ethereum</th><th align="center">SOL · Solana</th></tr>
  <tr>
    <td align="center"><a href="docs/images/support-eth.png"><img src="docs/images/support-eth.png" alt="ETH 收款地址二维码" width="180"></a></td>
    <td align="center"><a href="docs/images/support-sol.png"><img src="docs/images/support-sol.png" alt="SOL 收款地址二维码" width="180"></a></td>
  </tr>
</table>

<details>
<summary>Copy cryptocurrency receiving addresses</summary>

**USDT · TRC20（Tron）**

```text
TEwbANy1Mo3DFdT6CMphgjU511LzbCoQsm
```

**BTC · Bitcoin**

```text
bc1q8m5fp9jgmve8sjva2cfdwhs3pc65723nezrc3v
```

**ETH · Ethereum**

```text
0x9d955292BD72904fB5D5D9A147250A625f80c6E5
```

**SOL · Solana**

```text
24BL4HqrJUdDzg6fu3yk4Qi5oh6utRUWEQitpCa5HgwS
```

</details>

## Highlights

- 🔐 **WireGuard is the data plane.** All traffic is WireGuard-encrypted; NKNGuard never touches packet cryptography.
- 🛰️ **NKN is the control plane — no server of ours.** Devices find each other and exchange signed records over NKN; control messages are end-to-end encrypted.
- 🔗 **ICE direct paths with NKN standby.** Upgraded NAS and clients check IPv4/IPv6 UDP candidates independently of an active relay, then authenticate the selected path with WireGuard. See [ICE + NKN](docs/ICE-NKN.md) (Chinese).
- ⚡ **Direct first, relay second.** NAT is punched with WireGuard's own handshake. If that fails, **WireGuard ciphertext** rides an NKN session while the direct path keeps being retried, and traffic moves back as soon as it works.
- 📱 **Scan to pair, owner approves.** The QR holds only the NAS public key and a one-time request token — never the network secret. Every new device needs the six-digit code confirmed and approved on the NAS. Single devices can be revoked; a revoked phone gets a signed notice and disconnects at once.
- 🇨🇳 **Built-in China seed.** A mainland-China community NKN seed is tried before the overseas official seeds; add your own node in the config.
- 🧱 **The tunnel outlives the control plane.** If NKN drops, established WireGuard tunnels keep running.
- 📊 **Anonymous user counts.** The dashboard and clients show how many devices ran NKNGuard in the last 24 hours / 30 days / 90 days, read from zero-fee NKN on-chain subscriptions with no server involved. Automatically enabled without an off switch; see [usage statistics](docs/USAGE_STATS.md) (Chinese).
- 🧭 **NAS access only.** Clients install a route to the selected NAS virtual IP (`/32`); Linux NAS forwarding rules block client-to-client and internet forwarding without changing Docker rules.
- 🗂️ **Multiple saved NAS profiles on Android.** Each NAS has separate credentials and cached connection information. Name, switch or delete one without losing the others; one active VPN at a time.
- 🌐 **Private DHT signaling and dynamic router mapping.** IPv4/IPv6 DHT discovery starts alongside NKN, using cached signed peer addresses. UPnP/NAT-PMP map the current random port when a router supports it; ICE and NKN remain fallback. See [DHT + NKN](docs/DHT-NKN.md).

## How it works

```text
Tailscale:  device ── coordination server ── device    (+ DERP relay)
NKNGuard:   device ── NKN signalling / DHT ── device   (+ NKN relay)
                            │
                            └─ data: WireGuard, direct whenever the NAT allows
```

| Path | When | Speed |
| --- | --- | --- |
| **WireGuard direct** | At least one side's NAT can be traversed (most home broadband) | Close to line rate |
| **NKN encrypted relay** | Both sides behind symmetric / carrier-grade NAT, or UDP blocked | Slow — a fallback so you are connected at all |

## Quick start

### 1. Install the NAS

**fnOS:** follow [docs/FNOS_DISK_DEPLOY.md](docs/FNOS_DISK_DEPLOY.md) to keep the binary, config and identity on a data disk.

**Other Linux:** amd64 or arm64, `wireguard-tools` (`wg`, `ip`), `iptables` and `ip6tables`, kernel WireGuard or `wireguard-go`, root, and a clock within ±2 minutes.

```bash
git clone https://github.com/Viper-Boss/nknguard && cd nknguard
mkdir -p bin && install -m 0755 ~/Downloads/nknguard-linux-arm64 bin/nknguard   # or build: make deps && make build
sudo ./scripts/install.sh
sudo nknguard init --name nas-home      # creates the network and asks for a dashboard password
sudo systemctl enable --now nknguard
```

### 2. Open the dashboard

The dashboard listens only on the NAS's `127.0.0.1:7878`. **Do not** publish it to the internet. From a computer on the LAN:

```bash
ssh -L 7878:127.0.0.1:7878 user@nas
# then open http://127.0.0.1:7878/ — user admin, the password set during init
```

Forgot it? Run `sudo nknguard dashboard-password set` on the NAS. Five wrong passwords in a row trigger a temporary back-off.

### 3. Pair a device

1. In **配对与授权 (Pairing)**, generate a QR code (valid 5 minutes); the same **pairing link** `nknguard://pair/v1?...` is shown under it with a copy button.
2. Request access from the device:
   - **Android** — open the app and tap “扫码配对” (scan to pair);
   - **Windows** — paste the pairing link into the client, enter a name, click “请求 NAS 配对”;
   - **Linux** — `sudo nknguard pair '<QR content>' --name laptop`.
3. Check that the **six-digit code** matches on both screens, then click **核对后批准** (approve) on the NAS.
4. Tap **Connect** on the device and reach the NAS on its virtual IP (shown in the client, e.g. `10.88.0.1`).

More: [Pairing](docs/PAIRING.md) · [Windows client](docs/WINDOWS.md) · [Android client](docs/ANDROID.md)

## Commands

| Command | |
| --- | --- |
| `nknguard init` | create a network and set the dashboard password |
| `nknguard pair <pairing-link>` | request owner-approved enrollment (Linux) |
| `nknguard dashboard-password set` | set or reset the dashboard password on the NAS |
| `sudo nknguard up` / `daemon` | run the node |
| `sudo nknguard down` | stop the node and remove the interface |
| `nknguard status` / `peers` | what is connected, how, and what happened |
| `nknguard reconnect <device-id>` | retry a direct path now |
| `nknguard doctor` | check the host, NAT and running node |
| `nknguard diagnostics export` | redacted bundle for a bug report |

```text
PEER      IP           PATH        STATE   ENDPOINT             LAST HANDSHAKE
laptop    10.88.41.7   direct-wg   DIRECT  203.0.113.5:51820    12s ago
vps-eu    10.88.3.200  nkn-relay   RELAY   127.0.0.1:41822      4s ago
```

## How peers find each other

| Source | Setup | Trade-off |
| --- | --- | --- |
| **NKN topic** (`nkn_topic: true`, default) | none | The topic name derives from the join secret; its subscriber list is public to anyone who knows it |
| **Private DHT** (`dht: true`, build tag `libp2pdht`) | bootstrap peers, or mDNS on a LAN | Project-private Kademlia, never the public IPFS DHT |
| **Static peers** (`static_peers:`) | list each other's NKN address | Nothing public at all |

Whatever the source, a tunnel is built only for a device whose signed record verifies, whose membership proof matches and which the NAS has approved.

**NKN seeds** are tried in order: `nkn.seed_rpc` from the config → the built-in China seed → the official seeds. To add a self-hosted node:

```yaml
nkn:
  seed_rpc:
    - http://192.168.1.10:30003
```

## Limitations

Stated plainly, because networking software that over-promises is worse than useless:

- **Not every NAT can be traversed.** Two peers both behind symmetric NAT will almost always be relayed. `nknguard doctor` tells you which case you are in.
- **The relay is slow.** It rides NKN sessions — a fallback, not a data plane.
- **UPnP cannot bypass upstream CGNAT.** Unsupported routers or blocked UDP still need ICE or relay. See [ICE + NKN](docs/ICE-NKN.md).
- **Membership proofs still use a shared secret.** The NAS enforces an approved-device list and can revoke single devices; recreate network credentials if the secret or a device key leaks. Automated rotation is not implemented.
- **Preview clients.** IPv4 virtual addresses over IPv4/IPv6 transport. Android saves multiple NAS profiles but connects to one at a time; no automatic boot connection yet.
- **Usage statistics are public.** Each running device automatically publishes an anonymous key on three public NKN topics once a day; the NKN node it talks to sees its IP address. Anyone can subscribe to the topics, so the counts are indicative.
- **Not anonymous.** WireGuard endpoints reveal IP addresses to peers, NKN addresses are linkable over time, and STUN servers see your public address.
- **The China seed is community-run** and may move; the official seeds remain as fallback.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Protocol](docs/PROTOCOL.md) · [NAT traversal](docs/NAT_TRAVERSAL.md) · [Pairing](docs/PAIRING.md) · [Security model](docs/SECURITY.md) · [Build](docs/BUILD.md) · [Windows](docs/WINDOWS.md) · [Android](docs/ANDROID.md) · [fnOS deployment](docs/FNOS_DISK_DEPLOY.md) · [Usage statistics](docs/USAGE_STATS.md) · [Contributing](CONTRIBUTING.md) · [Reporting vulnerabilities](SECURITY.md)

## Build from source

```bash
go test ./...                                     # core, standard library only
make deps                                         # fetch nkn-sdk-go, libp2p
go build -tags "nknsdk libp2pdht" ./cmd/nknguard  # full binary
cd android && ./gradlew assembleDebug             # Android (JDK 17 + Android SDK, no NDK)
```

Requires Go ≥ 1.25.7. A binary built without `nknsdk` can `init`, `join` and `doctor`, and refuses `up` with an explanation. See [docs/BUILD.md](docs/BUILD.md).

## Contributors

- **[Viper-Boss](https://github.com/Viper-Boss)** — project creator and maintainer.
- **Claude** — initial prototype and Android development assistance.
- **Codex (OpenAI)** — networking, security, NAS/Android implementation, UI and verification assistance. AI-assisted changes remain under the maintainer's review.

The [NAT dial](docs/NAT-GAUGE.md) shows measured mapping conditions, with a grey pointer when unknown. Four traditional NAT categories are explained separately; mapping-only observations do not identify inbound filtering.

## License

NKNGuard is licensed under **AGPL-3.0-only**; see [LICENSE](LICENSE). Notices for third-party modules are in [NOTICE](NOTICE).
