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

## License

MIT
