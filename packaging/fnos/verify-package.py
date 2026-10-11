#!/usr/bin/env python3
"""Validate fnOS packages before release without installing them."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile

def elf(data, cpu, label, static=False):
    assert data[:6] == bytes.fromhex("7f454c460201"), f"Expected 64-bit little-endian ELF: {label}"
    assert struct.unpack_from("<H", data, 18)[0] == cpu, f"Wrong {label} CPU architecture"
    if static:
        assert len(data) >= 64, f"Truncated {label} ELF"
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        assert not count or size >= 56, f"Invalid {label} program headers"
        for i in range(count):
            pos = offset + i * size
            assert pos + size <= len(data), f"Truncated {label} program headers"
            assert struct.unpack_from("<I", data, pos)[0] != 3, f"{label} needs a system dynamic loader"

def verify(path, arch, version):
    platform, cpu = {"amd64": ("x86", 62), "arm64": ("arm", 183)}[arch]
    archive = None
    if path.is_dir():
        read = lambda name: (path / name).read_bytes()
        binaries = {name: read("app/bin/" + name) for name in ("nknguard", "wg", "wireguard-go")}
        licenses = {name: read("app/share/licenses/" + name) for name in ("wireguard-tools.txt", "wireguard-go.txt")}
        ui = {name: read("app/ui/" + name) for name in ("config", "images/icon_64.png", "images/icon_256.png")}
    else:
        archive = tarfile.open(path, "r:*")
        def read(name):
            stream = archive.extractfile(name)
            assert stream is not None, f"Missing {name}"
            return stream.read()
        payload = read("app.tgz")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as app:
            members = {m.name.removeprefix("./"): m for m in app.getmembers()}
            binaries = {}
            for name in ("nknguard", "wg", "wireguard-go"):
                binary = members["bin/" + name]
                assert binary.isfile() and binary.mode & 0o111, f"{name} must be executable"
                binaries[name] = app.extractfile(binary).read()
            licenses = {name: app.extractfile(members["share/licenses/" + name]).read() for name in ("wireguard-tools.txt", "wireguard-go.txt")}
            assert "share/sources/wireguard-tools-1.0.20260223.tar.xz" in members, "Missing bundled wg source"
            ui = {name: app.extractfile(members["ui/" + name]).read() for name in ("config", "images/icon_64.png", "images/icon_256.png")}
        for member in archive.getmembers():
            if member.name.startswith("cmd/") and member.isfile():
                assert member.mode & 0o111, f"Lifecycle script not executable: {member.name}"
    try:
        manifest = dict(line.split("=", 1) for line in read("manifest").decode().splitlines() if "=" in line and not line.lstrip().startswith("#"))
        fields = {k.strip(): v.strip() for k, v in manifest.items()}
        assert fields.get("appname") == "nknguard", "Unexpected appname"
        assert fields.get("platform") == platform, "Wrong manifest platform"
        assert fields.get("version") == version, "Wrong manifest version"
        assert fields.get("desktop_uidir") == "ui", "Missing desktop directory"
        assert fields.get("desktop_applaunchname") == "nknguard.main", "Missing desktop entry"
        assert fields.get("service_port") == "7878", "Wrong dashboard service port"
        entry = json.loads(ui["config"])[".url"]["nknguard.main"]
        assert entry.get("type") == "url" and entry.get("protocol") == "http", "Desktop must open browser"
        assert entry.get("port") == "7878" and entry.get("url") == "/", "Wrong desktop dashboard URL"
        assert entry.get("icon") == "images/icon_{0}.png", "Wrong desktop icon path"
        for size in (64, 256):
            assert ui[f"images/icon_{size}.png"] == read("ICON.PNG" if size == 64 else "ICON_256.PNG"), "Wrong desktop icon"
        assert b"--dashboard-listen auto-lan:7878" in read("cmd/main"), "Missing LAN dashboard listener"
        elf(binaries["nknguard"], cpu, "daemon")
        for name in ("wg", "wireguard-go"):
            elf(binaries[name], cpu, name, static=True)
        assert all(licenses.values()), "Missing bundled tool licenses"
        for name, expected in (("ICON.PNG", 64), ("ICON_256.PNG", 256)):
            png = read(name)
            assert png[:8] == b"\x89PNG\r\n\x1a\n", f"Invalid icon {name}"
            assert struct.unpack_from(">II", png, 16) == (expected, expected), f"Wrong icon size {name}"
        if archive is not None:
            assert fields.get("checksum") == hashlib.md5(payload).hexdigest(), "Wrong app.tgz checksum"
        raw = read("wizard/install")
        assert len(raw) > 10, "Empty install wizard is rejected by fnOS"
        steps = json.loads(raw)
        assert isinstance(steps, list) and steps, "Install wizard needs at least one step"
        for step in steps:
            assert step.get("stepTitle") and isinstance(step.get("items"), list) and step["items"], "Invalid wizard step"
            for item in step["items"]:
                assert item.get("type") == "tips" and item.get("helpText"), "Expected read-only installation instructions"
        for name in ("install_init", "install_callback", "main", "upgrade_init", "upgrade_callback"):
            script = read("cmd/" + name)
            assert script.startswith(b"#!/bin/sh\n") and b"\r" not in script, f"Invalid script line endings: {name}"
        assert b"arm:aarch64|x86:x86_64" in read("cmd/install_init"), "Missing architecture-specific installation check"
        assert b"command -v wg" not in read("cmd/install_init"), "Installation must not depend on a system wg"
        for name in ("main", "install_callback"):
            assert b'PATH="$TRIM_APPDEST/bin:' in read("cmd/" + name), f"Bundled tools are not on PATH in {name}"
    finally:
        if archive is not None:
            archive.close()

if __name__ == "__main__":
    verify(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    print(f"FPK validation passed: {sys.argv[2]} {sys.argv[3]}")
