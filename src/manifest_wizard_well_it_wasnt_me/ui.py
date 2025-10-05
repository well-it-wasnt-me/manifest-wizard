from __future__ import annotations

import os
from getpass import getpass
from pathlib import Path
from typing import List

from .models import ManifestBuilder, FileMeta
from .storage import ArtifactCollector, sha256_of_file
from .crypto import Encryptor, Signer, tool_exists

# Try Rich for UX, fallback to plain input/print.
try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None

def _prompt(msg: str, default: str | None = None) -> str:
    if RICH:
        return Prompt.ask(msg, default=default) if default is not None else Prompt.ask(msg)
    val = input(f"{msg}{f' [{default}]' if default else ''}: ").strip()
    return val or (default or "")

def _confirm(msg: str, default: bool = False) -> bool:
    if RICH:
        return Confirm.ask(msg, default=default)
    val = input(f"{msg} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return (val == "" and default) or val in ("y", "yes")

def _print_header(title: str) -> None:
    if RICH:
        console.rule(f"[bold cyan]{title}")
    else:
        print(f"\n=== {title} ===")

def _print_table(rows: List[list[str]], title: str) -> None:
    if RICH:
        table = Table(title=title)
        for h in ["#", "Type", "Path", "SHA256", "Bytes"]:
            table.add_column(h)
        for r in rows:
            table.add_row(*r)
        console.print(table)
    else:
        print(title)
        for r in rows:
            print(" | ".join(r))

def run_interactive(base_output: Path) -> None:
    _print_header("Manifest Wizard (Interactive)")

    finding_id = _prompt("Finding ID", "CERT-YYYYMMDD-XX")
    phase = _prompt("Phase (Reconnaissance|Exploit|Post-Exploitation|Reporting)", "Exploit")
    try:
        default_collector = os.getlogin()
    except Exception:
        default_collector = "operator"
    collector = _prompt("Collector / operator (pseudonym)", default_collector)

    tool_name = _prompt("Tool (name)", "curl")
    tool_version = _prompt("Tool version", "")
    tool_cmd = _prompt("Command used (e.g., curl ...)", f"{tool_name} --version")
    target = _prompt("Target (e.g., https://example/api?param=...)", "")
    notes = _prompt("Short notes (purpose of collection)", "")

    builder = ManifestBuilder(
        finding_id=finding_id,
        phase=phase,
        collector=collector,
        tool_name=tool_name,
        tool_version=tool_version,
        tool_command=tool_cmd,
        target=target,
        notes=notes,
    )

    collector_io = ArtifactCollector(base_output)
    artifacts_dir = collector_io.create_case_dir(finding_id, now=builder.now)

    _print_header("Add Evidence Files")
    idx = 1
    rows = []
    while True:
        p = _prompt(f"File path #{idx} (ENTER to finish)", "")
        if not p:
            break
        src = Path(p).expanduser()
        if not src.exists():
            if RICH: console.print(f"[red]File not found:[/red] {src}")
            else: print(f"! File not found: {src}")
            continue
        ftype = _prompt("File type (request/response/other)", "response").lower()
        meta = collector_io.copy_evidence(src, artifacts_dir, ftype, idx)
        builder.add_file(meta)
        rows.append([str(idx), ftype, meta.path, f"{meta.sha256[:12]}…", str(meta.size_bytes)])
        _print_table([rows[-1]], title="Added")
        idx += 1

    # manual paste?
    if _confirm("Paste a manual request/response?", default=False):
        while True:
            kind = _prompt("Type (request/response)", "request").lower()
            if kind not in ("request", "response"):
                if RICH: console.print("[red]Choose 'request' or 'response'[/red]")
                else: print("Choose 'request' or 'response'")
                continue
            if RICH:
                console.print("[dim]Paste your text. End with a line containing ONLY 'EOF'[/dim]")
            else:
                print("Paste your text. End with a line containing ONLY 'EOF'")
            lines: list[str] = []
            while True:
                line = input()
                if line.strip() == "EOF":
                    break
                lines.append(line)
            filename = artifacts_dir / f"{kind}-manual-{idx}.txt"
            filename.write_text("\n".join(lines), encoding="utf-8")
            sha, size = sha256_of_file(filename)
            meta = FileMeta(path=str(filename.as_posix()), type=kind, sha256=sha, size_bytes=size)
            builder.add_file(meta)
            rows.append([str(idx), kind, meta.path, f"{meta.sha256[:12]}…", str(meta.size_bytes)])
            _print_table([rows[-1]], title="Added")
            idx += 1
            if not _confirm("Add another pasted item?", default=False):
                break

    manifest = builder.build()
    manifest_path = artifacts_dir / "manifest.json"
    csv_path = artifacts_dir / "manifest.csv"
    manifest.to_json(manifest_path)
    collector_io.write_csv(manifest, csv_path)

    if RICH:
        console.print(f"[green]Manifest created:[/green] {manifest_path}")
        console.print(f"[green]CSV created:[/green] {csv_path}")
    else:
        print(f"Manifest created: {manifest_path}")
        print(f"CSV created: {csv_path}")

    zip_path = collector_io.zip_case(artifacts_dir, manifest.finding_id, now=builder.now)
    if RICH:
        console.print(f"[green]ZIP created:[/green] {zip_path}")
    else:
        print(f"ZIP created: {zip_path}")

    # Encryption
    if tool_exists("openssl") and _confirm("Encrypt the archive with OpenSSL? (GCM with CBC fallback)", False):
        enc_path = zip_path.with_suffix(".zip.enc")
        pwd = getpass("Encryption password (not shown): ")
        ok, msg = Encryptor().encrypt(zip_path, enc_path, pwd)
        if ok:
            if RICH:
                console.print(f"[green]Encrypted:[/green] {enc_path} — {msg}")
            else:
                print(f"Encrypted: {enc_path} — {msg}")
        else:
            if RICH:
                console.print(f"[red]OpenSSL encryption error:[/red] {msg}")
            else:
                print(f"OpenSSL encryption error: {msg}")
    elif not tool_exists("openssl"):
        if RICH: console.print("[yellow]OpenSSL not found; skipping encryption.[/yellow]")
        else: print("OpenSSL not found; skipping encryption.")

    # Signing
    if tool_exists("gpg") and _confirm("Sign manifest.json with GPG?", False):
        signer = Signer()
        if not signer.have_secret_key():
            if RICH:
                console.print("[yellow]No GPG secret key found. Create one with 'gpg --full-generate-key' or use CLI with --gpg-key.[/yellow]")
            else:
                print("No GPG secret key found. Create one with 'gpg --full-generate-key' or use CLI with --gpg-key.")
        else:
            sig_path = artifacts_dir / "signature-manifest.sig"
            ok, msg = signer.sign(manifest_path, sig_path, key_id=None)
            if ok:
                # update manifest with signature metadata
                try:
                    signed_by = os.getlogin()
                except Exception:
                    signed_by = "operator"
                manifest.signed_by = signed_by
                manifest.signature = sig_path.as_posix()
                manifest.to_json(manifest_path)
                if RICH:
                    console.print(f"[green]Signed:[/green] {sig_path}")
                else:
                    print(f"Signed: {sig_path}")
            else:
                if RICH:
                    console.print(f"[red]GPG signing error:[/red] {msg}")
                else:
                    print(f"GPG signing error: {msg}")
    elif not tool_exists("gpg"):
        if RICH: console.print("[yellow]GPG not found; skipping signing.[/yellow]")
        else: print("GPG not found; skipping signing.")

    _print_header("Completed")
    if RICH:
        console.print(f"[bold]Artifacts:[/bold] {artifacts_dir.resolve()}")
        console.print(f"Manifest: {manifest_path.resolve()}")
        console.print(f"ZIP     : {zip_path.resolve()}")
        console.print("[dim]Share encrypted archives only with authorized recipients.[/dim]")
    else:
        print(f"Artifacts: {artifacts_dir.resolve()}")
        print(f"Manifest : {manifest_path.resolve()}")
        print(f"ZIP      : {zip_path.resolve()}")
        print("Share encrypted archives only with authorized recipients.")
