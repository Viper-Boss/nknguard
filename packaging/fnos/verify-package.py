#!/usr/bin/env python3
"""Validate fnOS packages before release without installing them."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile

def verify(path, arch, version):
    platform, cpu = {"amd64": ("x86", 62), "arm64": ("arm", 183)}[arch]
    archive = None
    if path.is_dir():
        read = lambda name: (path / name).read_bytes()
        header = read("app/bin/nknguard")[:20]
    else:
        archive = tarfile.open(path, "r:*")
        def read(name):
            stream = archive.extractfile(name)
            assert stream is not None, f"Missing {name}"
            return stream.read()
        payload = read("app.tgz")
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as app:
            members = {m.name.removeprefix("./"): m for m in app.getmembers()}
            binary = members["bin/nknguard"]
            assert binary.isfile() and binary.mode & 0o111, "Daemon must be executable"
            header = app.extractfile(binary).read(20)
        for member in archive.getmembers():
            if member.name.startswith("cmd/") and member.isfile():
                assert member.mode & 0o111, f"Lifecycle script not executable: {member.name}"
    try:
        manifest = dict(line.split("=", 1) for line in read("manifest").decode().splitlines() if "=" in line and not line.lstrip().startswith("#"))
        fields = {k.strip(): v.strip() for k, v in manifest.items()}
        assert fields.get("appname") == "nknguard", "Unexpected appname"
        assert fields.get("platform") == platform, "Wrong manifest platform"
        assert fields.get("version") == version, "Wrong manifest version"
        assert header[:6] == bytes.fromhex("7f454c460201"), "Expected 64-bit little-endian ELF"
        assert struct.unpack_from("<H", header, 18)[0] == cpu, "Wrong daemon CPU architecture"
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
    finally:
        if archive is not None:
            archive.close()

if __name__ == "__main__":
    verify(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    print(f"FPK validation passed: {sys.argv[2]} {sys.argv[3]}")
