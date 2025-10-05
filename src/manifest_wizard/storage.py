from __future__ import annotations

import csv
import hashlib
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Tuple

from .models import CSV_HEADER, Manifest, FileMeta, ARTIFACT_TYPES

def sha256_of_file(path: Path) -> Tuple[str, int]:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size

def normalize_posix(p: Path) -> str:
    return p.as_posix()

def slugify(s: str, repl: str = "-") -> str:
    s = s.strip().lower()
    s = re.sub(r"[^\w\-\.]+", repl, s)
    s = re.sub(rf"{repl}+", repl, s)
    return s.strip(repl) or "untitled"

class ArtifactCollector:
    def __init__(self, base_output: Path) -> None:
        self.base_output = base_output

    def create_case_dir(self, finding_id: str, now: datetime) -> Path:
        case_slug = f"{slugify(finding_id)}_{now.strftime('%Y%m%dT%H%M%S')}"
        out = self.base_output / "artifacts" / case_slug
        out.mkdir(parents=True, exist_ok=True)
        return out

    def copy_evidence(self, src: Path, dest_dir: Path, artifact_type: str, index: int) -> FileMeta:
        if artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"Invalid artifact type: {artifact_type}. Use one of {sorted(ARTIFACT_TYPES)}")
        dest = dest_dir / f"{artifact_type}-{index}{src.suffix}"
        shutil.copy2(src, dest)
        sha, size = sha256_of_file(dest)
        return FileMeta(path=normalize_posix(dest), type=artifact_type, sha256=sha, size_bytes=size)

    def write_csv(self, manifest: Manifest, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            for file in manifest.files:
                w.writerow([
                    manifest.uuid,
                    manifest.finding_id,
                    manifest.phase,
                    manifest.timestamp,
                    manifest.timezone,
                    manifest.collector,
                    manifest.tool["name"],
                    manifest.tool["version"],
                    manifest.tool["command"],
                    manifest.target,
                    file.type,
                    file.path,
                    file.sha256,
                    file.size_bytes,
                    manifest.notes,
                    manifest.signed_by,
                    manifest.signature
                ])

    def zip_case(self, case_dir: Path, finding_id: str, now: datetime) -> Path:
        stem = f"artifacts_{slugify(finding_id)}_{now.strftime('%Y%m%dT%H%M%S')}"
        base = case_dir.parent / stem
        shutil.make_archive(str(base), "zip", case_dir.parent, case_dir.name)
        return base.with_suffix(".zip")


def parse_add_file(values: Iterable[str]) -> List[Tuple[Path, str]]:
    results: List[Tuple[Path, str]] = []
    for v in values:
        if ":" in v:
            path_str, ftype = v.split(":", 1)
            ftype = ftype.strip().lower()
        else:
            path_str, ftype = v, "other"
        p = Path(path_str).expanduser()
        results.append((p, ftype))
    return results
