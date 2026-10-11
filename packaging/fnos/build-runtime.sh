#!/bin/sh
# Build self-contained runtime tools; never install dependencies on the NAS.
set -eu
output=${1:?usage: build-runtime.sh OUTPUT_DIR}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
version=1.0.20260223
source="$work/wireguard-tools-$version.tar.xz"
curl -fL --retry 3 "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-$version.tar.xz" -o "$source"
printf '%s  %s\n' af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf "$source" | sha256sum -c -
tar -xJf "$source" -C "$work"
wg_source="$work/wireguard-tools-$version"
cd "$root"
go_source=$(go list -m -f '{{.Dir}}' golang.zx2c4.com/wireguard)
for arch in amd64 arm64; do
  case "$arch" in amd64) cc=gcc;; arm64) cc=aarch64-linux-gnu-gcc;; esac
  target="$output/$arch"
  mkdir -p "$target/bin" "$target/share/licenses" "$target/share/sources"
  make -C "$wg_source/src" clean
  make -C "$wg_source/src" -j2 wg CC="$cc" LDFLAGS=-static WIREGUARD_TOOLS_VERSION="$version"
  install -m 0755 "$wg_source/src/wg" "$target/bin/wg"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags '-s -w' -o "$target/bin/wireguard-go" golang.zx2c4.com/wireguard
  cp "$wg_source/COPYING" "$target/share/licenses/wireguard-tools.txt"
  cp "$go_source/LICENSE" "$target/share/licenses/wireguard-go.txt"
  cp "$source" "$target/share/sources/"
  cp "$root/packaging/fnos/build-runtime.sh" "$target/share/sources/"
  # Actual native/emulated execution catches unsupported runtime dependencies.
  case "$arch" in amd64) emulator=;; arm64) emulator=qemu-aarch64;; esac
  $emulator "$target/bin/wg" --version
  private=$($emulator "$target/bin/wg" genkey)
  public=$(printf '%s\n' "$private" | $emulator "$target/bin/wg" pubkey)
  [ "${#private}" -eq 44 ] && [ "${#public}" -eq 44 ]
  $emulator "$target/bin/wireguard-go" --version
done
