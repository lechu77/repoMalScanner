# repoMalScanner

A bash-based security scanner that clones a GitHub repository and analyzes it for malicious behavior — focused on credential theft, data exfiltration, and supply chain attacks (not CVEs).

## Motivation

With the rise of AI-assisted "vibe coding", malicious actors embed data-stealing code in seemingly innocent repos — similar to the OpenClaw extension attacks. This tool helps you audit a repo before running it.

## What It Checks

| # | Check | Tool | Detects |
|---|---|---|---|
| 1 | Secrets in code | gitleaks | Tokens, API keys, credentials in code & git history |
| 2 | Verified active secrets | trufflehog | High-entropy secrets validated live against providers (`--only-verified`) |
| 3 | Supply chain audit | semgrep | Supply chain patterns and vulnerable package practices (`p/supply-chain`) |
| 4 | Malware patterns | yara | Behavioral heuristics, credential theft, reverse shells, obfuscation |
| 5 | Sensitive files & AI credentials | grep | `~/.claude`, `~/.cursor`, `~/.ssh`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, cookies |
| 6 | Remote code execution | grep | Shell scripts or execution-bound calls (`exec`, `spawn`) with `curl \| bash` |
| 7 | Suspicious exfil endpoints | grep | webhook.site, Telegram bots, Discord webhooks, ngrok, Pastebin, etc. |
| 8 | Network syscalls in binaries | strings | `.so`, `.dylib`, `.exe` compiled with network socket syscalls |
| 9 | Committed .env files | find | `.env`, `.env.production`, `.env.local`, etc. |
| 10 | Lifecycle script abuse | python3 | `postinstall`/`preinstall` with remote execution |
| 11 | Dependency typosquatting | python3 | npm/pip deps with Levenshtein distance ≤1 to popular packages |
| 12 | Insecure MCP & agent tools | python3 | Rogue commands, direct shells, or unpinned `npx -y` in MCP server configs |
| 13 | Python .pth & unsafe serialization | python3 | `.pth` auto-exec startup hooks and dangerous pickle deserialization opcodes |

## Requirements

```bash
brew install gitleaks semgrep yara trufflehog
```

> Dependencies are checked and offered for installation automatically on each run.
> Redundant tools like `detect-secrets` and noisy generic HTTP greps have been eliminated.

## Usage

```bash
# Interactive
./repo-scanner.sh

# Direct URL or local path
./repo-scanner.sh --repo https://github.com/user/repo
./repo-scanner.sh https://github.com/user/repo
./repo-scanner.sh --repo /path/to/local/project
./repo-scanner.sh .

# Auto-save report to out/
./repo-scanner.sh --repo https://github.com/user/repo --save

# CI/CD — exits with code 1 on high-severity findings, no prompts
./repo-scanner.sh --repo https://github.com/user/repo --no-interactive --save

# Scan full git history (slower, finds secrets in old commits)
./repo-scanner.sh --repo https://github.com/user/repo --full-history
```

After scanning a remote repository, the temporary clone is automatically deleted. Local folders are scanned in-place without modification or deletion. You can save the scan report as a Markdown file in `out/`.

## Output

- Terminal: ASCII table with color-coded results (`GREEN` / `RED` / `YELLOW`)
- Risk score: 0–100 weighted by finding severity
- Report: `out/<repo-name>-security-report.md` (optional or via `--save`)

## Flags

| Flag | Description |
|---|---|
| `-r, --repo <url\|path>` | Repository URL or local directory to scan |
| `--save` | Automatically save report to `out/` without interactive prompt |
| `--no-interactive` | Skip all prompts; exit code 1 if high-severity findings |
| `--full-history` | Clone full git history and run gitleaks on all commits |
| `--check-updates` | Check Homebrew for outdated scanner dependencies |
| `-h, --help` | Show usage and options |

## Risk Score

Each check has a weight. The final score is the sum of triggered weights normalized to 0–100.

| Weight | Checks |
|---|---|
| 30 (high) | Remote code execution, lifecycle script abuse, verified secrets, insecure MCP & agent tools, Python .pth & unsafe serialization |
| 20 (medium) | Secrets in code (gitleaks), YARA malware patterns, suspicious exfil endpoints, network syscalls in binaries, committed .env files, dependency typosquatting |
| 10 (low) | Semgrep supply chain patterns, sensitive files & AI credentials |

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
