#!/usr/bin/env python3
"""Exercise real install preflight for both CPUs and reject invalid package inputs."""
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_package", ROOT / "verify-package.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

class PackagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "cmd", self.root / "cmd")
        shutil.copytree(ROOT / "wizard", self.root / "wizard")
        for icon in ("ICON.PNG", "ICON_256.PNG"):
            shutil.copy2(ROOT / icon, self.root / icon)
        (self.root / "app/bin").mkdir(parents=True)
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        for name, script in {
            "id": "printf '0\\n'",
            "uname": 'printf "%s\\n" "$TEST_MACHINE"',
            "ip": "exit 1",
        }.items():
            p = self.stubs / name
            p.write_text("#!/bin/sh\n" + script + "\n")
            p.chmod(0o755)
    def tearDown(self):
        self.temp.cleanup()
    def stage(self, arch):
        platform, machine = {"amd64": ("x86", 62), "arm64": ("arm", 183)}[arch]
        (self.root / "manifest").write_text(f"appname = nknguard\nversion = 0.2.18-preview.3\nplatform = {platform}\n")
        header = bytearray(64)
        header[:6] = bytes.fromhex("7f454c460201")
        struct.pack_into("<H", header, 18, machine)
        for name in ("nknguard", "wg", "wireguard-go"):
            (self.root / "app/bin" / name).write_bytes(header)
        licenses = self.root / "app/share/licenses"
        licenses.mkdir(parents=True, exist_ok=True)
        for name in ("wireguard-tools.txt", "wireguard-go.txt"):
            (licenses / name).write_text("test license")
    def test_both_architectures_and_cross_install_rejection(self):
        for arch, correct, wrong in [("amd64", "x86_64", "aarch64"), ("arm64", "aarch64", "x86_64")]:
            self.stage(arch)
            verifier.verify(self.root, arch, "0.2.18-preview.3")
            for machine, success in [(correct, True), (wrong, False)]:
                with self.subTest(package=arch, device=machine):
                    env = dict(os.environ, PATH=str(self.stubs) + os.pathsep + os.environ["PATH"], TEST_MACHINE=machine)
                    result = subprocess.run(["sh", str(self.root / "cmd/install_init")], env=env, capture_output=True)
                    self.assertEqual(result.returncode == 0, success, result.stderr.decode())
    def test_fnOS_temporary_package_environment(self):
        self.stage("arm64")
        detached = self.stubs / "install_init"
        shutil.copy2(self.root / "cmd/install_init", detached)
        env = dict(os.environ, PATH=str(self.stubs) + os.pathsep + os.environ["PATH"], TEST_MACHINE="aarch64", TRIM_PKGINST_TEMP_DIR=str(self.root))
        result = subprocess.run(["sh", str(detached)], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
    def test_empty_wizard_is_rejected(self):
        self.stage("arm64")
        (self.root / "wizard/install").write_text("[]\n")
        with self.assertRaisesRegex(AssertionError, "Empty install wizard"):
            verifier.verify(self.root, "arm64", "0.2.18-preview.3")
    def test_wrong_binary_is_rejected(self):
        self.stage("arm64")
        (self.root / "manifest").write_text("appname = nknguard\nversion = 0.2.18-preview.3\nplatform = x86\n")
        with self.assertRaisesRegex(AssertionError, "Wrong daemon CPU"):
            verifier.verify(self.root, "amd64", "0.2.18-preview.3")
    def test_bundled_wg_architecture_is_checked(self):
        self.stage("arm64")
        data = bytearray((self.root / "app/bin/wg").read_bytes())
        struct.pack_into("<H", data, 18, 62)
        (self.root / "app/bin/wg").write_bytes(data)
        with self.assertRaisesRegex(AssertionError, "Wrong wg CPU"):
            verifier.verify(self.root, "arm64", "0.2.18-preview.3")
    def test_initialization_uses_bundled_wg(self):
        self.stage("arm64")
        app = self.root / "app"
        # The fake daemon requires wg on PATH, as real init does. No host wg stub.
        for name, body in (("wg", "printf 'bundled-wg\\n'"), ("nknguard", 'wg genkey > "$WG_MARKER"')):
            p = app / "bin" / name
            p.write_text("#!/bin/sh\n" + body + "\n")
            p.chmod(0o755)
        marker = self.root / "wg-called"
        env = dict(os.environ, PATH=str(self.stubs) + os.pathsep + os.environ["PATH"], TRIM_APPDEST=str(app), TRIM_PKGETC=str(self.root / "etc"), TRIM_PKGVAR=str(self.root / "var"), WG_MARKER=str(marker))
        result = subprocess.run(["sh", str(self.root / "cmd/install_callback")], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(marker.read_text().strip(), "bundled-wg")

if __name__ == "__main__":
    unittest.main()
