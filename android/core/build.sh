#!/bin/sh
# Builds the NKNGuard Android core for each ABI the app ships and places it
# where the Android Gradle plugin packages native libraries:
#
#   app/src/main/jniLibs/<abi>/libnkgcore.so
#
# The file is an executable, not a JNI library. Naming it lib*.so makes the
# package manager extract it into the app's native library directory, the one
# place an app may execute its own binaries on Android 10 and later.
#
# Requires only Go (see go.mod for the version); no Android NDK. arm64 is a
# native GOOS=android build. Go cannot link android/arm or android/amd64
# without cgo, so the 32-bit ARM and x86_64 (emulator) builds are static
# Linux binaries, which run on the Android kernel; the app sets SSL_CERT_DIR
# for them.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="${1:-$here/../app/src/main/jniLibs}"
abis="${NKG_ABIS:-arm64-v8a armeabi-v7a x86_64}"
version="${NKG_VERSION:-$(git -C "$here" describe --tags --always --dirty 2>/dev/null || echo 0.1.1-android)}"
flags="-s -w -checklinkname=0 -X github.com/Viper-Boss/nknguard/internal/app.Version=$version"

cd "$here"
for abi in $abis; do
  case "$abi" in
    arm64-v8a)   env="GOOS=android GOARCH=arm64" ;;
    armeabi-v7a) env="GOOS=linux GOARCH=arm GOARM=7" ;;
    x86_64)      env="GOOS=linux GOARCH=amd64" ;;
    *) echo "unknown ABI $abi" >&2; exit 1 ;;
  esac
  mkdir -p "$out/$abi"
  echo "building $abi ($env)"
  env CGO_ENABLED=0 $env go build -tags "nknsdk libp2pdht" -trimpath -ldflags "$flags" -o "$out/$abi/libnkgcore.so" .
done
