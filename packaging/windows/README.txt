NKNGuard Windows preview

Install for the current Windows user. Install the official WireGuard for
Windows from https://www.wireguard.com/install/ before connecting.
NKNGuard requests administrator approval only to control its tunnel.
Do not approve using a different Windows account: that account has a separate
configuration and identity. Sign in using an account that can approve UAC.

Pairing: open your NAS dashboard, generate a pairing link, paste it into the
client, then compare the six-digit code and approve on the NAS.

Once a direct or relayed path is verified, copy the NAS virtual IP into the
fnOS client. Open NAS uses the default fnOS HTTP port 5666; use the copied IP
and your custom port if you changed it. Disconnect when finished.

Close hides the window to the tray. Choose Exit in the tray menu before
upgrading or uninstalling. If tunnel cleanup fails, retry cleanup first.
The uninstaller removes its application files and shortcuts. Pairing and
identity in %LOCALAPPDATA%\NKNGuard remain for reinstallation. To permanently
remove them, first revoke this device on the NAS, finish tunnel cleanup, then
delete that exact directory. The shared WireGuard installation is retained.

This preview is unsigned. Android CI packages also use debug signing.
Source and AGPL-3.0-only license: https://github.com/Viper-Boss/nknguard
