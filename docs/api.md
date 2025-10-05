# API Reference

The manifest-wizard package is organized into the following modules:

## manifest_wizard.models
Contains dataclasses and builders used to construct manifests.

- class FileMeta
- class Manifest
- class ManifestBuilder

## manifest_wizard.storage
Provides file system operations:
- Evidence collection and copying
- Hashing (SHA-256)
- CSV export
- ZIP archive creation

## manifest_wizard.crypto
Implements encryption and signing:
- class Encryptor (OpenSSL AES-256-GCM with CBC fallback)
- class Signer (GPG detached ASCII signature)

## manifest_wizard.ui
Handles the interactive Rich-based command-line interface.

## manifest_wizard.cli
Entry point for both interactive and non-interactive workflows.

---

Example usage from Python:

```python
from manifest_wizard.models import ManifestBuilder
from manifest_wizard.storage import ArtifactCollector

builder = ManifestBuilder(
    finding_id="CERT-20251005-01",
    phase="Exploit",
    collector="alice",
    tool_name="curl",
    tool_version="8.9.1",
    tool_command="curl --version",
    target="https://example.com",
    notes="POC",
)

collector = ArtifactCollector(Path("."))
case_dir = collector.create_case_dir(builder.manifest.finding_id, builder.now)
```