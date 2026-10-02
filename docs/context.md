# Domain Context & Ubiquitous Language

> Canonical domain definitions, entity lifecycles, and anti-synonym rules.
> All agents (Leader, Implementer, Reviewer) must adhere strictly to these terms.
> Deviations cause cascading hallucination and naming drift across agent sessions.

---

## 1. Canonical Entities

| Entity Name | Definition | Key Identifiers / Core Fields |
|-------------|------------|-------------------------------|
| `Target`    | Repository URL (remote) or local directory path being audited | `url_or_path`, `is_local`, `repo_name`, `clone_dir` |
| `Check`     | Isolated static or behavioral analysis inspection routine | `id`, `label`, `weight`, `result`, `detail` |
| `Finding`   | Specific threat indicator detected during inspection | `file_path`, `rule_or_detector`, `detail_line` |
| `RiskScore` | Weighted normalized metric (0–100) representing threat level | `score`, `max_score`, `percentage`, `severity_tier` |
| `Report`    | Markdown audit summary artifact generated in `out/` | `target_name`, `scan_date`, `table`, `findings_detail` |

---

## 2. Check Severity & Exit Protocol

| Severity Tier | Weight | Checks | Non-Interactive CI Exit |
|---|---|---|---|
| **High** | 30 | `RCE`, `LIFECYCLE`, `TRUFFLEHOG`, `MCPCONFIG`, `PTHSERIAL`, `AUTOEXEC` | Exits with code `1` |
| **Medium** | 20 | `GITLEAKS`, `YARA`, `DOMAINS`, `BINSYSC`, `ENVFILES`, `TYPOSQUAT` | Non-fatal (exits `0` unless High present) |
| **Low** | 10 | `SEMGREP`, `SENS` | Non-fatal |

---

## 3. Anti-Synonym & Disambiguation Rules

| Canonical Term (USE THIS) | FORBIDDEN Synonyms (DO NOT USE) | Context / Scope |
|---------------------------|---------------------------------|-----------------|
| `target`                  | `subject`, `repo_to_scan`, `input` | Audit target path or remote git URL |
| `check`                   | `test_case`, `filter`, `detector` | Top-level scanner analysis category |
| `finding`                 | `incident`, `bug`, `alert`      | Specific detected malicious match |
| `report`                  | `log_file`, `doc`, `summary_md` | Markdown file produced in `out/` |

---

## 4. Operational Boundaries

- **Zero-Residual**: Cloned remote repositories in `tmp/` must always be purged via trap handlers upon exit.
- **In-Place Immutability**: Local directory targets must never be cloned, mutated, or deleted.
- **Active Verification Only**: Trufflehog is strictly constrained to `--only-verified` to eliminate RFC dummy test credentials.
