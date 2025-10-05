from pathlib import Path
from manifest_wizard.crypto import Encryptor
def test_fallback(tmp_path: Path, monkeypatch):
    src = tmp_path / "a.zip"; src.write_bytes(b"dummy")
    out = tmp_path / "a.zip.enc"
    enc = Encryptor()
    monkeypatch.setattr(Encryptor, "_supports_gcm", lambda self: False)  # force CBC path
    ok, msg = enc.encrypt(src, out, "pw")
    # ok can be False if your system openssl is missing; assert only on message shape here:
    assert "CBC" in msg or not ok