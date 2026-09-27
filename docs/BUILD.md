# Build

## Two builds, on purpose

| | Command | Needs | Can |
|---|---|---|---|
| core | `go build ./cmd/nknguard` | Go ≥ 1.25.7 and pinned modules | local identity/config/tests; NKN commands require the full build |
| full | `go build -tags "nknsdk libp2pdht" ./cmd/nknguard` | the modules below | everything |

The Windows GUI uses the full build and the official WireGuard for Windows installation.
The Android app and its Go core are built from `android/`; see [ANDROID.md](ANDROID.md).

The core build omits the NKN and DHT adapters but still resolves the modules
in `go.mod` on a fresh machine. Once dependencies are cached, tests can run
offline.
`nknguard version` prints which planes a binary contains.

## Full build

```bash
make deps     # download the pinned go.mod dependency graph
make build    # bin/nknguard
make release  # dist/nknguard-linux-{amd64,arm64} + SHA256SUMS
```

Windows GUI from PowerShell (the resource step adds the icon and the
common-controls v6 manifest the native window needs):

```powershell
cd cmd/nknguard
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest gui --icon winres/icon.png --product-name NKNGuard
cd ../..
go build -tags "nknsdk libp2pdht" -trimpath -ldflags "-H=windowsgui -X main.guiBuild=1" -o NKNGuard-Windows.exe ./cmd/nknguard
```

Run `NKNGuard-Windows.exe` to open the native desktop client (walk, no browser). A console build uses the
same source without the `-ldflags` setting. See [WINDOWS.md](WINDOWS.md).

Pinned versions (the ones NasSimHub already builds against):

| Module | Version | Tag |
|---|---|---|
| github.com/nknorg/nkn-sdk-go | v1.4.8 | nknsdk |
| github.com/libp2p/go-libp2p | v0.49.0 | libp2pdht |
| github.com/libp2p/go-libp2p-kad-dht | v0.42.2 | libp2pdht |
| github.com/multiformats/go-multiaddr | v0.16.1 | libp2pdht |
| github.com/multiformats/go-multihash | v0.2.3 | libp2pdht |
| github.com/ipfs/go-cid | v0.6.2 | libp2pdht |

`nknsdk` alone is a working node (NKN topic + static peers). `libp2pdht` adds
the private DHT and LAN mDNS.

### Behind a restrictive network

If `proxy.golang.org` is unreachable, set a mirror (for example
`GOPROXY=https://goproxy.cn,direct`), or build on a machine whose module cache
already has these versions — a machine that builds NasSimHub does.

## Runtime requirements

- Linux amd64/arm64, root (or `CAP_NET_ADMIN`)
- `wireguard-tools` (`wg`, `ip` from iproute2)
- kernel WireGuard (5.6+ or the backport module), or `wireguard-go` on `PATH`
- clock within ±2 minutes (NTP)

## Development notes

- The NKN and libp2p adapters now compile and pass automated tests with the
  pinned real SDK modules. Live NKN and real NAT integration remain to be run.
- The libp2p adapter follows NasSimHub's `agent/internal/dht` closely, but its
  provider/record-fetch layer is new and untested against a live DHT.
