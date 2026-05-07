# MEMORY

Key decisions and context for this project.

## Design Decisions

- **No CVE scanning** — tools like `osv-scanner`, `pip-audit`, and `codeql` are installed but intentionally excluded. The focus is malicious intent, not vulnerable dependencies.
- **bash 3.2 compatible** — macOS ships with bash 3.2. No `declare -A` (associative arrays). Results stored as prefixed plain variables (`RESULT_X`, `DETAIL_X`).
- **Shallow clone** — `git clone --depth=1` to minimize time and disk usage.
- **Auto-cleanup** — `trap 'rm -rf "$TMPDIR_SCAN"' EXIT` ensures the cloned repo is always deleted, even on error.
- **Tool-agnostic** — each tool check is wrapped in `command -v` guards. Missing tools show `SKIPPED` in yellow instead of failing.
- **YARA rules are local** — `yara-rules.yar` lives in the project root and is focused on behavioral patterns (exfiltration destinations, credential access, obfuscation), not file hashes.

## Tool Stack

| Tool | Purpose |
|---|---|
| gitleaks | Secret detection in files |
| semgrep | Static analysis (`p/security-audit`, `p/secrets`) |
| detect-secrets | High-precision secret scanning |
| yara | Custom malware/behavioral pattern matching |
| grep | Lightweight custom pattern checks |

## Directory Layout

- `tmp/scan-<PID>/` — isolated per-run clone, deleted on exit
- `out/` — persisted Markdown reports
