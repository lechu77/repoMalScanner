# repoMalScanner

A bash-based security scanner that clones a GitHub repository and analyzes it for malicious behavior — focused on credential theft, data exfiltration, and supply chain attacks (not CVEs).

## Motivation

With the rise of AI-assisted "vibe coding", malicious actors embed data-stealing code in seemingly innocent repos — similar to the OpenClaw extension attacks. This tool helps you audit a repo before running it.

## What It Checks

| # | Check | Tool | Detects |
|---|---|---|---|
| 1 | Secrets | gitleaks | Tokens, API keys, credentials in code |
| 2 | Security audit | semgrep | Exfiltration patterns, malicious code |
| 3 | Secrets in code | detect-secrets | Hardcoded secrets with high precision |
| 4 | Malware patterns | yara | Credential harvesting, webhooks, RCE, obfuscation |
| 5 | Data exfiltration | grep | Outbound HTTP calls to external endpoints |
| 6 | Sensitive file/env access | grep | `~/.ssh`, `~/.aws`, `document.cookie`, env vars |
| 7 | Remote code execution | grep | `curl \| bash`, `eval(fetch(...))` |
| 8 | Verified secrets | trufflehog | High-entropy secrets with active verification |
| 9 | Suspicious exfil domains | grep | webhook.site, Telegram, ngrok, Pastebin, etc. |
| 10 | Network syscalls in binaries | strings | `.so`, `.dylib`, `.exe` with network calls |

## Requirements

```bash
brew install gitleaks semgrep yara trufflehog
pipx install detect-secrets
```

> Dependencies are checked and installed automatically on each run.

## Usage

```bash
# Interactive
./repo-scanner.sh

# Direct
./repo-scanner.sh --repo https://github.com/user/repo
```

After scanning, the cloned repo is automatically deleted. You will be prompted to save the report as a Markdown file in `out/`.

## Output

- Terminal: ASCII table with color-coded results (`GREEN` / `RED` / `YELLOW`)
- Report: `out/<repo-name>-security-report.md` (optional)

## Project Structure

```
repoMalScanner/
├── repo-scanner.sh     # Main scanner script
├── yara-rules.yar      # YARA rules for malware detection
├── tmp/                # Temporary clone directory (auto-cleaned)
└── out/                # Saved scan reports
```

## Test Repos

Repos designed to trigger security scanners — good for validating the tool:

```bash
./repo-scanner.sh --repo https://github.com/trufflesecurity/test_keys
./repo-scanner.sh --repo https://github.com/gitleaks/gitleaks
./repo-scanner.sh --repo https://github.com/OWASP/wrongsecrets

# Large repo — clone will take a while
./repo-scanner.sh --repo https://github.com/juice-shop/juice-shop
```

### Sample output

```
./repo-scanner.sh --repo https://github.com/gitleaks/gitleaks

╔══════════════════════════════════════════╗
║        REPO SECURITY SCANNER             ║
╚══════════════════════════════════════════╝

  Repo URL: https://github.com/gitleaks/gitleaks

  Cloning...
  Running gitleaks...
  Running semgrep...
  Running detect-secrets...
  Running YARA...
  Checking exfiltration patterns...
  Checking sensitive access patterns...
  Checking remote execution patterns...
  Running trufflehog...
  Checking suspicious domains...
  Checking binaries for network syscalls...

┌──────────────────────────────────────────────────────────────────────┐
│  CHECK                                 RESULT                        │
├──────────────────────────────────────────────────────────────────────┤
│  Secrets (gitleaks)                    CLEAN                         │
│  Security audit (semgrep)              FOUND (34 matches)            │
│    ↳ cmd/diagnostics.go (use-tls)                                    │
│    ↳ cmd/generate/config/rules/aws.go (detected-aws-access-key-id)   │
│  Secrets in code (detect-secrets)      CLEAN                         │
│  Malware patterns (yara)               FOUND (4 matches)             │
│    ↳ RuntimeObfuscation detect/codec/hex.go                          │
│    ↳ DataExfiltration cmd/generate/config/rules/telegram.go          │
│    ↳ DataExfiltration cmd/generate/config/rules/flyio.go             │
│  Data exfiltration                     FOUND (1 files)               │
│    ↳ cmd/generate/config/rules/jwt.go                                │
│  Sensitive file/env access             FOUND (1 files)               │
│    ↳ cmd/generate/config/rules/huggingface.go                        │
│  Remote code execution                 CLEAN                         │
│  Verified secrets (trufflehog)         FOUND (50 secrets)            │
│    ↳ cmd/generate/config/rules/jwt.go (URI)                          │
│    ↳ cmd/generate/config/rules/azure.go (Azure)                      │
│    ↳ cmd/generate/config/rules/jwt.go (JWT)                          │
│  Suspicious exfil domains              FOUND (2 files)               │
│    ↳ cmd/generate/config/rules/telegram.go                           │
│    ↳ cmd/generate/config/rules/flyio.go                              │
│  Network syscalls in binaries          CLEAN                         │
└──────────────────────────────────────────────────────────────────────┘
  Scanned: https://github.com/gitleaks/gitleaks

  Save report as Markdown? [y/N]:
```

## License

MIT
