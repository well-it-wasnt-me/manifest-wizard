# Usage

## Interactive mode

Run the wizard interactively to create a new manifest:

manifest-wizard

You’ll be prompted for:
- Finding ID
- Phase (Reconnaissance, Exploit, Post-Exploitation, or Reporting)
- Collector (operator name or pseudonym)
- Tool information (name, version, command used)
- Target URL or description
- Optional notes
- Evidence file paths or manual request/response entries

When done, the tool produces:
- manifest.json
- manifest.csv
- ZIP archive (containing all artifacts)

Optionally, you can encrypt and/or sign the output.

---

## Non-interactive mode

Run manifest-wizard in non-interactive mode using command-line flags:

```bash
$ manifest-wizard \
  --non-interactive \
  --finding-id CERT-20251005-01 \
  --phase Exploit \
  --collector alice \
  --tool curl \
  --tool-version 8.9.1 \
  --tool-command "curl --version" \
  --target "https://example.com/api" \
  --notes "Demo collection" \
  --add-file ./req.txt:request \
  --add-file ./resp.json:response \
  --encrypt \
  --sign \
  --gpg-key alice@example.com
```

This mode is ideal for automated environments, CI pipelines, or repeatable forensic workflows.

---

## Encryption and signing

- **Encryption** uses OpenSSL AES-256-GCM (if supported) or automatically falls back to AES-256-CBC.
  - Uses PBKDF2 with 100,000 iterations and salt.
  - Passphrase is read securely via stdin.

- **Signing** uses GPG detached ASCII signatures.
  - Provide `--gpg-key` to specify a key ID or email.
  - Without a key, the tool uses the default secret key if available.
