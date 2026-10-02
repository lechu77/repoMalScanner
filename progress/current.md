# Active Session

## Task
- **Slug:** autoexec_on_open
- **Agent:** Leader -> Implementer

## Sprint Contract

### Done means
1. New check `AUTOEXEC` ("Auto-execution on open", weight 30, high severity) in `repo-scanner.sh`
   with `RESULT_/DETAIL_/label_/weight_` entries, sanitized details, included in `CHECKS`.
2. Detects (high = scored, exit 1):
   - `.vscode/tasks.json` / `*.code-workspace` tasks with `runOptions.runOn: folderOpen` whose
     command uses a downloader/interpreter/obfuscation/remote pattern or runs a repo script
     (JSONC: comments + trailing commas parse).
   - `.vscode/settings.json` / workspace `settings`: interpreter/executable overrides to repo-local
     or odd paths, terminal env/shellArgs/automationProfile overrides, `task.allowAutomaticTasks: on`.
   - devcontainer (`.devcontainer.json`, `.devcontainer/devcontainer.json`,
     `.devcontainer/*/devcontainer.json`): `initializeCommand` (host) always; lifecycle commands
     with downloader/interpreter patterns.
   - `.envrc`: remote fetch / eval / source of remote content, or non-direnv commands.
   - Git hooks: `git config core.hooksPath` instructions + hook dirs (`.husky`, `.githooks`,
     hooksPath target) with downloaders; lefthook / pre-commit `repo: local` entries with downloaders.
   - Agent configs: `.claude/settings*.json` hooks (remote/interpreter patterns), broad
     `permissions.allow` (`Bash(*)`, `Bash`, `*`), `enableAllProjectMcpServers: true`;
     `.cursor/hooks.json`, `.gemini/settings.json`, `.codex/config.toml` hooks.
3. Benign auto-exec (folderOpen `npm run watch`, formatter hook `prettier --write`) is reported
   as `INFO` (shown, not scored, not high) so normal repos stay at 0/100.
4. Unparseable config files -> `WARN` (fail-open; other files still analysed).
5. Safety: paths via argv, no eval, symlinks/FIFOs skipped, capped reads, details sanitized.
6. `.vscode/mcp.json` / `.mcp.json` servers keep being covered by MCPCONFIG (confirm, extend if
   VS Code `servers` key is missed).

### Verification
- `bash tests/test_scanner.sh` exits 0 with new Test 24 (per-vector FOUND on dedicated repos,
  CLEAN on benign fixtures, INFO on benign folderOpen, WARN on broken JSONC).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive` -> 0/100, rc 0.

### Files
- `repo-scanner.sh`, `checks/autoexec/*.py` (new analyzer package), `tests/test_scanner.sh`,
  `README.md`, `docs/context.md` (gitignored, local), `docs/architecture.md`,
  `progress/impl_autoexec.md`, `progress/current.md`.

## Log
| Time | Action | Result |
|------|--------|--------|
| 1 | Baseline `bash tests/test_scanner.sh` | exit 0 |
| 2 | Prototype analyzer on scratch fixtures | all 6 vectors HIGH, benign INFO/CLEAN |
| 3 | Split into `checks/autoexec/` package (<=300 lines/file, type hints, no global state); wired section 14 | done |
| 4 | MCP check: VS Code `servers` key + JSONC (reuses `core.strip_jsonc`); `MANIFEST_JSON_RE` extended | done |
| 5 | FP corpus (15 popular repos) | FPs on microsoft/vscode (folderOpen running build script, `cmd.exe /c`) and TypeScript CI `/dev/null` hooksPath -> rules refined, now INFO/none |
| 6 | Tests 24 + 25 added; `bash tests/test_scanner.sh` | exit 0 |
| 7 | `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive` | rc 0, 0/100, AUTOEXEC CLEAN |
| 8 | README/docs updated; temp fixtures and clones removed | done |
| 9 | Round 2: review_autoexec.md B1-B8, W1-W6 | fixed, T26 added |
| 10 | Round 2: security_autoexec.md (CRITICAL `python3 -I`, symlinks, case, test dirs, .envrc, 2x DoS) | fixed, T27 added |
| 11 | FP corpus (12 repos) re-run | INFO only except contracted kubernetes-helm initializeCommand |
| 12 | `bash tests/test_scanner.sh` / omlx | exit 0 / 0/100 |
| 13 | Round 3: review N1 (lenient JSONC fallback), N2 (sourced env files content-only) | fixed, T28 |
| 14 | Round 3: security N1 (git-index symlinks in clone mode), N2 (flushed HIGH, priority order, budget) | fixed, T28 (file:// e2e, padded repo) |
| 15 | `bash tests/test_scanner.sh` / omlx / FP re-check | exit 0 / 0/100 / devenv FP fixed |
| 16 | Round 4: tolerant JSONC re-parse with normal verdicts (`tolerant.py`) | fixed, T29 |
| 17 | Round 4 security: CRITICAL no git on local targets (ls-files, semgrep `--no-git-ignore`, gitleaks history), HIGH cap, symlinked scripts, shipped `.git` config/hooks | fixed, T30 (PWNED test) |
| 18 | `bash tests/test_scanner.sh` / omlx / 15 local checkouts | exit 0 / 0/100 / no HIGH FP |
| 19 | Round 5: tiered priority + per-file slice + re-parse cap (starvation PoC HIGH, exit 1); `.git` config.worktree/commondir/BOM | fixed, T31; suite exit 0, omlx 0/100 |

## Next Step
Round-5 re-review of `autoexec_on_open` (report: `progress/impl_autoexec.md`, Round 5 section). Not committed, not marked [x].
