from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .storage import sha256_of_file

def _run(argv: list[str], input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        input=(input_text.encode("utf-8") if input_text is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


class Encryptor:
    """OpenSSL encryption with AES-256-GCM preferred, CBC fallback."""
    @staticmethod
    def _supports_gcm() -> bool:
        proc = _run(["openssl", "enc", "-ciphers"])
        out = (proc.stdout or b"").decode("utf-8", errors="ignore").lower()
        return "aes-256-gcm" in out

    def encrypt(self, input_zip: Path, output_enc: Path, passphrase: str) -> Tuple[bool, str]:
        prefer_gcm = self._supports_gcm()
        cipher = "-aes-256-gcm" if prefer_gcm else "-aes-256-cbc"
        args = ["openssl", "enc", cipher, "-pbkdf2", "-iter", "100000", "-salt",
                "-in", str(input_zip), "-out", str(output_enc), "-pass", "stdin"]
        proc = _run(args, input_text=passphrase)
        if proc.returncode == 0 and output_enc.exists():
            return True, f"ok ({'GCM' if prefer_gcm else 'CBC'})"
        if prefer_gcm:
            args[2] = "-aes-256-cbc"
            proc2 = _run(args, input_text=passphrase)
            if proc2.returncode == 0 and output_enc.exists():
                return True, "ok (CBC fallback)"
            err = (proc2.stderr or proc.stderr).decode("utf-8", errors="ignore") or "unknown error"
            return False, err
        return False, (proc.stderr or b"").decode("utf-8", errors="ignore") or "unknown error"


class Signer:
    """GPG detached ASCII signature."""
    @staticmethod
    def have_secret_key() -> bool:
        proc = _run(["gpg", "--list-secret-keys", "--keyid-format=long"])
        out = (proc.stdout or b"").decode("utf-8", errors="ignore")
        return "sec" in out

    def sign(self, target: Path, output_sig: Path, key_id: Optional[str] = None) -> Tuple[bool, str]:
        args = ["gpg", "--armor", "--detach-sign", "--output", str(output_sig)]
        if key_id:
            args.extend(["--local-user", key_id])
        args.append(str(target))
        proc = _run(args)
        if proc.returncode == 0 and output_sig.exists():
            return True, "ok"
        return False, (proc.stderr or b"").decode("utf-8", errors="ignore") or "unknown error"
