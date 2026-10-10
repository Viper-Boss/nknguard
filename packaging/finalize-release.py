#!/usr/bin/env python3
"""Finalize a draft using keys that stay on the maintainer's NAS.

Never place private signing keys or GitHub credentials in the repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def run(*args):
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--work", required=True)
    parser.add_argument("--key", default="/mnt/docker-data/nknguard-release-signing/ed25519.pem")
    parser.add_argument("--apk-signer", default="/mnt/docker-data/nknguard-signing/sign-apk.sh")
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args()
    version = args.tag.removeprefix("v")
    if not version or any(c not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+-" for c in version):
        raise SystemExit("Invalid release version")
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    repo = "Viper-Boss/nknguard"
    metadata = json.loads(subprocess.check_output([args.gh, "release", "view", args.tag, "--repo", repo, "--json", "isDraft"]))
    if not metadata["isDraft"]:
        raise SystemExit("Refusing to modify an already published release")
    run(args.gh, "release", "download", args.tag, "--repo", repo, "--dir", str(work), "--clobber")
    unsigned = work / "UNSIGNED-NKNGuard-Android-preview.apk"
    apk = work / f"NKNGuard-Android-{version}.apk"
    run("sh", args.apk_signer, str(unsigned), str(apk))
    records = []
    for name, kind, arch in [
        ("nknguard-linux-amd64", "linux", "amd64"),
        ("nknguard-linux-arm64", "linux", "arm64"),
        (f"NKNGuard-fnOS-amd64-{version}.fpk", "fnos", "amd64"),
        (f"NKNGuard-fnOS-arm64-{version}.fpk", "fnos", "arm64"),
        (f"NKNGuard-Setup-{version}.exe", "windows-installer", "amd64"),
        ("NKNGuard-Windows-x86_64-preview.zip", "windows-portable", "amd64"),
        (apk.name, "android", "all"),
    ]:
        p = work / name
        digest = hashlib.file_digest(p.open("rb"), "sha256").hexdigest()
        records.append(dict(name=name, kind=kind, arch=arch, size=p.stat().st_size, sha256=digest))
    manifest = work / "release.json"
    manifest.write_bytes(json.dumps(dict(version=args.tag, assets=records), separators=(",", ":")).encode())
    signature = work / "release.json.sig"
    run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", args.key, "-in", str(manifest), "-out", str(signature))
    public = subprocess.check_output(["openssl", "pkey", "-in", args.key, "-pubout", "-outform", "DER"])[-32:].hex()
    if public != "f9e46b45a2cd1a249468fda1529fa52d13179c4d9effac54f8b0d0b91a782649":
        raise SystemExit("Catalogue key does not match the updater's public key")
    uploads = [work / a["name"] for a in records] + [manifest, signature]
    for a in records:
        if a["kind"] not in ("linux", "fnos"):
            continue
        bundle = work / f"NKNGuard-NAS-Update-{a['kind']}-{a['arch']}-{version}.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
            for p in (manifest, signature, work / a["name"]):
                z.write(p, p.name)
        uploads.append(bundle)
    checksums = work / "SHA256SUMS"
    checksums.write_text("".join(f"{hashlib.file_digest(p.open('rb'), 'sha256').hexdigest()}  {p.name}\n" for p in uploads))
    run(args.gh, "release", "upload", args.tag, *(str(p) for p in uploads), str(checksums), "--repo", repo, "--clobber")
    run(args.gh, "release", "delete-asset", args.tag, unsigned.name, "--repo", repo, "--yes")
    # Publish only after both persistent APK signing and catalogue signing pass.
    run(args.gh, "release", "edit", args.tag, "--repo", repo, "--draft=false", "--prerelease")
    print(f"Published https://github.com/{repo}/releases/tag/{args.tag}")


if __name__ == "__main__":
    main()
