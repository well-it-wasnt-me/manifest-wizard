from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

try:
    from zoneinfo import ZoneInfo
    DEFAULT_TZ = ZoneInfo("Europe/Rome")
    DEFAULT_TZ_NAME = "Europe/Rome"
except Exception:
    DEFAULT_TZ = timezone.utc
    DEFAULT_TZ_NAME = "UTC"

CSV_HEADER = [
    "uuid", "finding_id", "phase", "timestamp_iso8601", "timezone", "collector",
    "tool", "tool_version", "tool_command", "target",
    "artifact_type", "artifact_path", "sha256", "filesize_bytes",
    "notes", "signed_by", "signature_path"
]

ARTIFACT_TYPES = {"request", "response", "other"}


@dataclass
class FileMeta:
    path: str
    type: str
    sha256: str
    size_bytes: int


@dataclass
class Manifest:
    uuid: str
    finding_id: str
    phase: str
    timestamp: str
    timezone: str
    collector: str
    tool: Dict[str, str]
    target: str
    files: List[FileMeta]
    notes: str
    signed_by: str = ""
    signature: str = ""

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")


class ManifestBuilder:
    """Helper to assemble a manifest consistently."""
    def __init__(
        self,
        finding_id: str,
        phase: str,
        collector: str,
        tool_name: str,
        tool_version: str,
        tool_command: str,
        target: str,
        notes: str = "",
        now: Optional[datetime] = None,
    ) -> None:
        self.now = now or datetime.now(DEFAULT_TZ)
        self.manifest = Manifest(
            uuid=str(uuid.uuid4()),
            finding_id=finding_id,
            phase=phase,
            timestamp=self.now.isoformat(),
            timezone=DEFAULT_TZ_NAME,
            collector=collector,
            tool={"name": tool_name, "version": tool_version, "command": tool_command},
            target=target,
            files=[],
            notes=notes,
        )

    def add_file(self, meta: FileMeta) -> None:
        self.manifest.files.append(meta)

    def build(self) -> Manifest:
        return self.manifest
