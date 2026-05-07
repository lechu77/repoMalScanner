# repoMalScanner

A bash-based security scanner that clones a GitHub repository and analyzes it for malicious behavior — focused on credential theft, data exfiltration, and supply chain attacks (not CVEs).

## Motivation

With the rise of AI-assisted "vibe coding", malicious actors embed data-stealing code in seemingly innocent repos — similar to the OpenClaw extension attacks. This tool helps you audit a repo before running it.

## What It Checks

| Check | Tool | Detects |
|---|---|---|
| Secrets | gitleaks | Tokens, API keys, credentials in code |
| Security audit | semgrep | Exfiltration patterns, malicious code |
| Secrets in code | detect-secrets | Hardcoded secrets with high precision |
| Malware patterns | yara | Credential harvesting, webhooks, RCE, obfuscation |
| Data exfiltration | grep | Outbound HTTP calls to external endpoints |
| Sensitive file/env access | grep | `~/.ssh`, `~/.aws`, `document.cookie`, env vars |
| Remote code execution | grep | `curl \| bash`, `eval(fetch(...))` |

## Requirements

```bash
brew install gitleaks semgrep yara
pipx install detect-secrets
```

## Usage

```bash
# Interactive
./repo-scanner.sh

# Direct
./repo-scanner.sh --repo https://github.com/user/repo
```

After scanning, the cloned repo is automatically deleted. You will be prompted to save the report as a Markdown file in `out/`.

## Output

- Terminal: ASCII table with color-coded results (GREEN / RED / YELLOW)
- Report: `out/<repo-name>-security-report.md` (optional)

## Project Structure

```
repoMalScanner/
├── repo-scanner.sh     # Main scanner script
├── yara-rules.yar      # YARA rules for malware detection
├── tmp/                # Temporary clone directory (auto-cleaned)
└── out/                # Saved scan reports
```
