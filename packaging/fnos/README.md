# NKNGuard fnOS package

This is the fnOS App Center source directory for the ARM64 NAS service. It
requires `wg`, `ip`, an available App Center volume, and permission to run as
root so that it can create the `nkg0` WireGuard interface.

## Build

1. Cross compile the server binary from the repository root:

   ```sh
   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags 'nknsdk libp2pdht' -trimpath -ldflags='-s -w' -o packaging/fnos/app/bin/nknguard ./cmd/nknguard
   ```

2. On an ARM64 fnOS host with `fnpack`, copy this directory to a private
   build directory. Set executable permissions, then build:

   ```sh
   chmod 755 /path/to/fnos/cmd/* /path/to/fnos/app/bin/nknguard
   fnpack build -d /path/to/fnos
   ```

   The result is `nknguard.fpk`. The `chmod` step is needed when the source
   was archived on Windows. Do not copy `setup.txt`, state, or private
   keys into this build directory.

3. Install the package from the App Center, or run
   `sudo appcenter-cli install-fpk /path/to/nknguard.fpk --volume INDEX`, where
   `INDEX` identifies an available App Center volume. The volume must be
   configured in fnOS first; `0` means that no default volume is selected.

The installation wizard asks the owner to enter and confirm a dashboard
password. NKNGuard stores a salted password hash, not the plaintext password.
The dashboard binds to `127.0.0.1:7878`. Use an SSH port forward to access it
from another machine; the dashboard must not be exposed on a public address.
An installed owner can change the password on the dashboard's Security page.

The package's start, stop, and uninstall callbacks manage the NKNGuard daemon
and `nkg0`. fnOS removes the app's target, configuration, and data directories
on uninstall. An interrupted uninstall should be checked for a remaining
`nkg0` interface and NKNGuard process before reinstalling.
