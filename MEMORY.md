# MEMORY

Key decisions and context for this project.

## Design Decisions

- **No CVE scanning** — `osv-scanner`, `pip-audit`, and `codeql` are installed but intentionally excluded. The focus is malicious intent, not vulnerable dependencies.
- **No Bandit** — Bandit is a Python SAST tool for security-by-design issues, not malicious behavior detection. Excluded by design.
- **bash 3.2 compatible** — macOS ships with bash 3.2. No `declare -A` (associative arrays). Results stored as prefixed plain variables (`RESULT_X`, `DETAIL_X`).
- **Shallow clone by default** — `git clone --depth=1` to minimize time and disk usage. Use `--full-history` to scan full git history with gitleaks.
- **Auto-cleanup** — `trap 'rm -rf "$TMPDIR_SCAN"' EXIT` ensures the cloned repo is always deleted, even on error.
- **Tool-agnostic** — each tool check is wrapped in `command -v` guards. Missing tools show `SKIPPED` in yellow instead of failing.
- **Auto dependency management** — on each run, missing tools are offered for install and outdated ones for update.
- **YARA excludes docs** — `.gitignore`, `.gitattributes`, `README`, `.md`, `.txt`, `.rst`, and `.adoc` files are excluded from YARA to avoid false positives.
- **YARA rules are local** — `yara-rules.yar` lives in the project root, focused on behavioral patterns (exfiltration destinations, credential access, obfuscation), not file hashes.
- **YARA rules require co-occurrence** — `SupplyChainHook` requires lifecycle hook + execution pattern; `RuntimeObfuscation` requires obfuscation + exec indicator. This reduces false positives.
- **Binary inspection** — `strings` is used to detect network syscalls in compiled binaries (`.so`, `.dylib`, `.exe`), catching threats that source-only scanners miss.
- **Test directories excluded** — grep checks exclude `test/`, `tests/`, `__tests__/`, `fixtures/`, `testdata/`, and `spec/` to avoid false positives from test fixtures.
- **`os.environ` assignment excluded** — the sensitive access check (SENS) filters out lines that are env var assignments (`os.environ[...] =`, `process.env.VAR =`). Only reads/accesses are flagged, not writes. This avoids false positives in code that sets tokens for libraries (e.g. `os.environ["HF_TOKEN"] = token`).
- **Semgrep focused on supply chain** — uses `p/secrets` and `p/supply-chain` rulesets, not `p/security-audit` (which includes generic SAST rules outside scope).
- **Risk scoring** — weighted 0-100 score based on finding severity. High-risk checks (RCE, lifecycle abuse, verified secrets, typosquatting) have weight 30; medium 20; low 10.
- **CI/CD mode** — `--no-interactive` flag exits with code 1 on high-severity findings (RCE, lifecycle abuse, verified secrets, typosquatting), enabling pipeline integration.

## Tool Stack

| Tool | Purpose |
|---|---|
| gitleaks | Secret detection in files (supports full history with `--full-history`) |
| semgrep | Static analysis (`p/secrets`, `p/supply-chain`) |
| detect-secrets | High-precision secret scanning |
| trufflehog | High-entropy verified secrets |
| yara | Custom malware/behavioral pattern matching |
| grep | Lightweight custom pattern checks |
| strings | Network syscall detection in binaries |
| python3 | Lifecycle script analysis, typosquatting detection |

## Directory Layout

- `tmp/scan-<PID>/` — isolated per-run clone, deleted on exit
- `out/` — persisted Markdown reports

## New Features (2026-05-12)

- **Committed .env detection** — finds `.env`, `.env.local`, `.env.production`, etc. in the repo
- **Lifecycle script analysis** — detects suspicious `postinstall`/`preinstall` scripts in `package.json` and `setup.py` that contain execution patterns
- **Typosquatting detection** — compares npm/pip dependencies against popular packages using Levenshtein distance ≤1
- **Risk score** — 0-100 weighted score displayed in report
- **`--full-history`** — runs gitleaks on full git history instead of shallow clone
- **`--no-interactive`** — exits with code 1 on high-severity findings, no prompts

## Fixes (2026-05-12)

- **Table right border padding** — corrected padding formula (`-4` instead of `-2`) so the right `│` aligns correctly for all result lengths
- **`os.environ` false positive** — SENS check now filters assignment lines; only reads are flagged (e.g. `os.environ["HF_TOKEN"] = x` is ignored, `token = os.environ["HF_TOKEN"]` is flagged)
