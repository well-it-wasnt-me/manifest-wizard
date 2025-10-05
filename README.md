# Manifest Wizard (yes, it actually works)
You drop a bunch of forensic/pentest artifacts in a pile and Manifest Wizard turns them into neat little 
manifests (JSON + CSV), computes hashes, zips everything up, can encrypt it with OpenSSL if you’re paranoid, and sign it 
with GPG if you want to pretend you did it all properly.

It ships a fancy interactive Rich UI for humans and a no-nonsense CLI for CI systems that don’t care about your feelings.

## Install
If you know how to type and have Python, this will be the easiest part of your day:
```bash
$ pip install manifest-wizard
```
## Usage

### Interactive (for people who like pretty things and colorful progress bars)

```bash
$ manifest-wizard
```
Walk away while it makes your life tidy. Or hover over it...I won’t judge.

### Non-interactive (for scripts, cron jobs, and robots)
If you prefer things automated like most of the questionable decisions in IT...here's the full command:
```bash 
$ manifest-wizard \
  --non-interactive \
  --finding-id CASE-20251005-01 \
  --phase Exploit \
  --collector alice \
  --tool curl \
  --tool-version 8.9.1 \
  --tool-command "curl --version" \
  --target "https://api.example.com/endpoint" \
  --notes "POC collection for ticket #123" \
  --add-file ./req.txt:request \
  --add-file ./resp.json:response \
  --encrypt \
  --sign \
  --gpg-key alice@example.com
```

Yes, all those flags. Yes, you probably need most of them. No, there’s no “Make me a sandwich” flag...the moral standards 
of CLI maintainers are low, but not that low.

## What it actually does (short version)

* Scans and records files you tell it about.
* Computes hashes so you can prove you didn’t “accidentally” alter anything.
* Zips the artifacts, because nobody wants twenty loose files floating around.
* Optionally encrypts with OpenSSL (AES-256-GCM preferred, falls back to AES-256-CBC like a polite bouncer).
* Optionally signs with GPG (detached ASCII), because signatures look official and make things feel legal.

## Notes (nerdy but important)

* Encryption prefers **AES-256-GCM** if your OpenSSL is modern and feeling brave; otherwise it falls back to 
**AES-256-CBC** like a sensible adult.
* Password strengthening: PBKDF2 with 100,000 iterations and salted...yes, it takes a moment, but you wanted secure, not instant-gratification.
* Signing uses detached ASCII GPG signatures.
* Pass --gpg-key to select a specific key. If you don’t, it’ll try the default key and hope for the best.

# Tests (they work; don’t make it mad) 
Minimal smoke test to keep CI happy:

```python
from pathlib import Path
from manifest_wizard.models import ManifestBuilder, FileMeta
from manifest_wizard.storage import ArtifactCollector

def test_builder(tmp_path: Path):
    b = ManifestBuilder("CASE-1", "Exploit", "alice", "curl", "8.0", "curl --version", "https://x", "notes")
    ac = ArtifactCollector(tmp_path)
    case = ac.create_case_dir("CASE-1", now=b.now)
    # create a temp file and add
    p = case / "dummy.txt"
    p.write_text("hello")
    meta = ac.copy_evidence(p, case, "other", 1)
    b.add_file(meta)
    m = b.build()
    assert m.files and m.finding_id == "CASE-1"
```
Run the tests. If they fail, blame the CI pipeline and then fix your code.

# Contributing
Open a PR, file an issue, or send a strongly worded email. Contributions welcome. Be kind, or at least be funny about it.

# Final thoughts (advice you didn’t ask for)

If you're handling evidence, treat it like whiskey: respect it, label it, and don’t leave it in a hot car. 
Manifest Wizard helps with the labeling and the zip...the hot car part is still on you.