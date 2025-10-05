from __future__ import annotations

import argparse
import os
from getpass import getpass
from pathlib import Path

from .models import ManifestBuilder
from .storage import ArtifactCollector, parse_add_file, sha256_of_file
from .crypto import Encryptor, Signer, tool_exists
from .ui import run_interactive

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Manifest Wizard for Pentest/IR artifacts.")
    p.add_argument("--non-interactive", action="store_true", help="Use CLI flags instead of the interactive wizard.")
    p.add_argument("--output-dir", type=Path, default=Path("."), help="Base output directory (default: current)")

    # meta
    p.add_argument("--finding-id", required=False, help="Finding/Case ID (e.g., CERT-20251005-01)")
    p.add_argument("--phase", required=False, help="Phase (Reconnaissance|Exploit|Post-Exploitation|Reporting)")
    p.add_argument("--collector", required=False, help="Collector/operator (pseudonym)")
    p.add_argument("--tool", required=False, help="Tool name")
    p.add_argument("--tool-version", default="", help="Tool version")
    p.add_argument("--tool-command", required=False, help="Command used (for provenance)")
    p.add_argument("--target", required=False, help="Target descriptor/URL")
    p.add_argument("--notes", default="", help="Short notes (purpose of collection)")

    # files
    p.add_argument("--add-file", action="append",
                   help="Add evidence file as PATH[:TYPE] (TYPE is request|response|other). Repeatable.")

    # crypto
    p.add_argument("--encrypt", action="store_true", help="Encrypt resulting ZIP with OpenSSL (GCM or CBC fallback)")
    p.add_argument("--passphrase", help="Passphrase for --encrypt (otherwise prompted)")
    p.add_argument("--sign", action="store_true", help="Sign manifest.json with GPG (detached, ASCII)")
    p.add_argument("--gpg-key", help="GPG key id/email for --sign (uses default if omitted)")

    return p

def _require(args: argparse.Namespace, fields: list[str]) -> None:
    missing = [f for f in fields if not getattr(args, f)]
    if missing:
        raise SystemExit(f"--non-interactive requires: {', '.join('--'+m.replace('_','-') for m in missing)}")

def run_non_interactive(args: argparse.Namespace) -> None:
    _require(args, ["finding_id", "phase", "collector", "tool", "tool_command", "target"])

    builder = ManifestBuilder(
        finding_id=args.finding_id,
        phase=args.phase,
        collector=args.collector,
        tool_name=args.tool,
        tool_version=args.tool_version,
        tool_command=args.tool_command,
        target=args.target,
        notes=args.notes,
    )

    collector_io = ArtifactCollector(args.output_dir)
    artifacts_dir = collector_io.create_case_dir(args.finding_id, now=builder.now)

    idx = 1
    for path, ftype in parse_add_file(args.add_file or []):
        if not path.exists():
            raise SystemExit(f"File not found: {path}")
        meta = collector_io.copy_evidence(path, artifacts_dir, ftype, idx)
        builder.add_file(meta)
        idx += 1

    manifest = builder.build()
    manifest_path = artifacts_dir / "manifest.json"
    csv_path = artifacts_dir / "manifest.csv"
    manifest.to_json(manifest_path)
    collector_io.write_csv(manifest, csv_path)

    zip_path = collector_io.zip_case(artifacts_dir, manifest.finding_id, now=builder.now)
    zip_sha, _ = sha256_of_file(zip_path)
    print(f"ZIP created: {zip_path}")
    print(f"SHA256(archive): {zip_sha}")

    # Encrypt
    if args.encrypt:
        if not tool_exists("openssl"):
            raise SystemExit("OpenSSL not found; cannot --encrypt.")
        pwd = args.passphrase or getpass("Encryption password (not shown): ")
        enc_path = zip_path.with_suffix(".zip.enc")
        ok, msg = Encryptor().encrypt(zip_path, enc_path, pwd)
        if ok:
            print(f"Encrypted: {enc_path} — {msg}")
        else:
            raise SystemExit(f"OpenSSL encryption error: {msg}")

    # Sign
    if args.sign:
        if not tool_exists("gpg"):
            raise SystemExit("GPG not found; cannot --sign.")
        signer = Signer()
        if not signer.have_secret_key() and not args.gpg_key:
            raise SystemExit("No GPG secret key found. Create one with 'gpg --full-generate-key' or pass --gpg-key.")
        sig_path = artifacts_dir / "signature-manifest.sig"
        ok, msg = signer.sign(manifest_path, sig_path, key_id=args.gpg_key)
        if ok:
            manifest.signed_by = args.gpg_key or (os.getlogin() if hasattr(os, "getlogin") else "operator")
            manifest.signature = sig_path.as_posix()
            manifest.to_json(manifest_path)
            print(f"Signed: {sig_path}")
        else:
            raise SystemExit(f"GPG signing error: {msg}")

    print("Completed.")
    print(f"Artifacts: {artifacts_dir.resolve()}")
    print(f"Manifest : {manifest_path.resolve()}")
    print(f"ZIP      : {zip_path.resolve()}")

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.non_interactive:
        run_non_interactive(args)
    else:
        run_interactive(args.output_dir)
