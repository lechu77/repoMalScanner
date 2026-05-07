# MEMORY

Key decisions and context for this project.

## Design Decisions

- **No CVE scanning** — `osv-scanner`, `pip-audit`, and `codeql` are installed but intentionally excluded. The focus is malicious intent, not vulnerable dependencies.
- **No Bandit** — Bandit is a Python SAST tool for security-by-design issues, not malicious behavior detection. Excluded by design.
- **bash 3.2 compatible** — macOS ships with bash 3.2. No `declare -A` (associative arrays). Results stored as prefixed plain variables (`RESULT_X`, `DETAIL_X`).
- **Shallow clone** — `git clone --depth=1` to minimize time and disk usage.
- **Auto-cleanup** — `trap 'rm -rf "$TMPDIR_SCAN"' EXIT` ensures the cloned repo is always deleted, even on error.
- **Tool-agnostic** — each tool check is wrapped in `command -v` guards. Missing tools show `SKIPPED` in yellow instead of failing.
- **Auto dependency management** — on each run, missing tools are offered for install and outdated ones for update.
- **YARA excludes docs** — `.gitignore`, `.gitattributes`, `README`, and `.md` files are excluded from YARA to avoid false positives (e.g. `.git-credentials` appearing in a `.gitignore`).
- **YARA rules are local** — `yara-rules.yar` lives in the project root, focused on behavioral patterns (exfiltration destinations, credential access, obfuscation), not file hashes.
- **Binary inspection** — `strings` is used to detect network syscalls in compiled binaries (`.so`, `.dylib`, `.exe`), catching threats that source-only scanners miss.

## Tool Stack

| Tool | Purpose |
|---|---|
| gitleaks | Secret detection in files |
| semgrep | Static analysis (`p/security-audit`, `p/secrets`) |
| detect-secrets | High-precision secret scanning |
| trufflehog | High-entropy verified secrets |
| yara | Custom malware/behavioral pattern matching |
| grep | Lightweight custom pattern checks |
| strings | Network syscall detection in binaries |

## Directory Layout

- `tmp/scan-<PID>/` — isolated per-run clone, deleted on exit
- `out/` — persisted Markdown reports
