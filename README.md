# repoMalScanner

A bash-based security scanner that clones a GitHub repository and analyzes it for malicious behavior — focused on credential theft, data exfiltration, and supply chain attacks (not CVEs).

## Motivation

With the rise of AI-assisted "vibe coding", malicious actors embed data-stealing code in seemingly innocent repos — similar to the OpenClaw extension attacks. This tool helps you audit a repo before running it.

## What It Checks

| # | Check | Tool | Detects |
|---|---|---|---|
| 1 | Secrets | gitleaks | Tokens, API keys, credentials in code |
| 2 | Security audit | semgrep | Supply chain patterns, secrets (`p/secrets`, `p/supply-chain`) |
| 3 | Secrets in code | detect-secrets | Hardcoded secrets with high precision |
| 4 | Malware patterns | yara | Credential harvesting, webhooks, RCE, obfuscation |
| 5 | Data exfiltration | grep | Outbound HTTP calls to external endpoints |
| 6 | Sensitive file/env access | grep | `~/.ssh`, `~/.aws`, `document.cookie`, env vars |
| 7 | Remote code execution | grep | `curl \| bash`, `eval(fetch(...))` |
| 8 | Verified secrets | trufflehog | High-entropy secrets with active verification |
| 9 | Suspicious exfil domains | grep | webhook.site, Telegram, ngrok, Pastebin, etc. |
| 10 | Network syscalls in binaries | strings | `.so`, `.dylib`, `.exe` with network calls |
| 11 | Committed .env files | find | `.env`, `.env.production`, `.env.local`, etc. |
| 12 | Lifecycle script abuse | python3 | `postinstall`/`preinstall` with remote execution |
| 13 | Typosquatting | python3 | npm/pip deps with Levenshtein distance ≤1 to popular packages |

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

# CI/CD — exits with code 1 on high-severity findings, no prompts
./repo-scanner.sh --repo https://github.com/user/repo --no-interactive

# Scan full git history (slower, finds secrets in old commits)
./repo-scanner.sh --repo https://github.com/user/repo --full-history
```

After scanning, the cloned repo is automatically deleted. You will be prompted to save the report as a Markdown file in `out/`.

## Output

- Terminal: ASCII table with color-coded results (`GREEN` / `RED` / `YELLOW`)
- Risk score: 0–100 weighted by finding severity
- Report: `out/<repo-name>-security-report.md` (optional)

## Flags

| Flag | Description |
|---|---|
| `--repo <url>` | Repository URL to scan |
| `--no-interactive` | Skip all prompts; exit code 1 if high-severity findings |
| `--full-history` | Clone full git history and run gitleaks on all commits |

## Risk Score

Each check has a weight. The final score is the sum of triggered weights normalized to 0–100.

| Weight | Checks |
|---|---|
| 30 (high) | Remote code execution, lifecycle script abuse, verified secrets, typosquatting |
| 20 (medium) | Secrets (gitleaks), detect-secrets, YARA, data exfiltration, suspicious domains, binaries, .env files |
| 10 (low) | Semgrep, sensitive file access |

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

## License

MIT
