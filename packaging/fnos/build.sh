#!/bin/sh
# The same source produces two architecture-specific packages, never platform=all.
set -eu
arch=${1:?usage: build.sh amd64|arm64 VERSION BINARY [OUTPUT_DIR]}
version=${2:?}
binary=${3:?}
output=${4:-dist}
case "$arch" in amd64) platform=x86;; arm64) platform=arm;; *) exit 2;; esac
magic=$(od -An -tx1 -N6 "$binary" | tr -d ' \n')
machine=$(od -An -tx1 -j18 -N2 "$binary" | tr -d ' \n')
case "$arch:$magic:$machine" in
  amd64:7f454c460201:3e00|arm64:7f454c460201:b700) ;;
  *) printf '%s\n' 'Binary is not a matching 64-bit Linux ELF' >&2; exit 2;;
esac
case "$version" in *[!0-9A-Za-z.+-]*|'') exit 2;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT INT TERM
cp -R "$root/packaging/fnos/." "$stage/"
rm -f "$stage/build.sh" "$stage/README.md"
mkdir -p "$stage/app/bin"
cp "$root/LICENSE" "$root/NOTICE" "$stage/app/"
cp "$binary" "$stage/app/bin/nknguard"
chmod 755 "$stage/app/bin/nknguard" "$stage"/cmd/*
sed -i "s/^platform[[:space:]]*=.*/platform = $platform/;s/^version[[:space:]]*=.*/version = ${version#v}/" "$stage/manifest"
# A valid ELF alone is insufficient: fnOS dispatches installation by manifest.
grep -qx "platform = $platform" "$stage/manifest"
grep -qx "version = ${version#v}" "$stage/manifest"
# fnpack writes appname.fpk in the current working directory.
(cd "$output" && "${FNPACK:-fnpack}" build --directory "$stage")
mv "$output/nknguard.fpk" "$output/NKNGuard-fnOS-$arch-${version#v}.fpk"
