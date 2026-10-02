# Implementation Report: autoexec_on_open

## Summary
New high-severity check 14 **Auto-execution on open** (`AUTOEXEC`, weight 30, exit 1 in
`--no-interactive`). It flags code that runs just by opening, entering or using the repo in
common tools. The analysis is static only: repo files are parsed, never executed.

## Files
| File | Change |
|---|---|
| `checks/autoexec/__main__.py` (new, 142 lines) | Entry point `python3 -B -E -s checks/autoexec <target>`: walks the target, routes each file to a handler, scans hook dirs, prints `H`/`I`/`E` records |
| `checks/autoexec/core.py` (new, 249) | `Repo` (confined paths, capped reads with `O_NOFOLLOW|O_NONBLOCK` + `S_ISREG`), `Finding`, JSONC parser, danger patterns, script resolution, `npm run X` expansion, `script_verdict` |
| `checks/autoexec/editors.py` (new, 206) | `.vscode/tasks.json`, `.vscode/settings.json`, `*.code-workspace`, devcontainer configs, env-override checks |
| `checks/autoexec/vcs_hooks.py` (new, 139) | `.envrc`, `core.hooksPath`/`core.fsmonitor` instructions, `.husky`/`.githooks` hook dirs, lefthook/pre-commit, package.json husky v4/simple-git-hooks |
| `checks/autoexec/agents.py` (new, 112) | `.claude/settings(.local).json`, `.gemini/settings.json`, `.cursor/hooks.json`, `.codex/config.toml` |
| `repo-scanner.sh` | Section 14 (runs the analyzer, maps records to FOUND/WARN/INFO/CLEAN/SKIPPED); `AUTOEXEC` added to sanitize loop, labels, `CHECKS`, weights, high-severity list; `INFO*` is unscored and yellow; MCP check accepts VS Code `servers` key and JSONC (reuses `core.strip_jsonc`); `MANIFEST_JSON_RE` now also covers `.devcontainer/*/devcontainer.json`, `settings.local.json`, `.cursor/hooks.json` |
| `tests/test_scanner.sh` | Test 2 asserts AUTOEXEC CLEAN on clean-repo; Test 24 (11 dedicated repos via full scanner); Test 25 (analyzer coverage of 16 vectors, VS Code MCP, hostile inputs) |
| `README.md` | Check table row 14, MCP row, risk table, INFO semantics, precision trade-offs, project structure |
| `docs/architecture.md` | 14 checks, AUTOEXEC entry |
| `docs/context.md` | AUTOEXEC added to the High tier. Note: this file is gitignored (`.gitignore: CONTEXT.md` matches it on case-insensitive filesystems), so the change is local only |

## Noise filter (confirmed)
`MANIFEST_JSON_RE` already exempted `.vscode/tasks.json`, `.devcontainer/devcontainer.json` and
`.devcontainer.json`. `*.code-workspace` and `.envrc` are not `*.json`, so they were never data
paths. Nested `.devcontainer/<name>/devcontainer.json`, `.claude/settings.local.json` and
`.cursor/hooks.json` were treated as data and skipped by the generic content checks. They are now
exempt too. The AUTOEXEC analyzer does its own walk and does not depend on the noise filter.

## Severity design (goal: no false positives on normal repos)
- **Danger patterns** (`core.danger`) are downloaders (curl, wget, iwr/irm, certutil, bitsadmin,
  `/dev/tcp`, `fetch(`, urllib/requests), inline interpreters (`node -e`, `python -c`,
  `perl/ruby -e`, `php -r`, powershell/pwsh, osascript -e, mshta/rundll32/regsvr32), and
  obfuscation (base64, atob, fromCharCode, eval, `exec(`, `xxd -r`, `-enc <b64>`, `\x..` runs,
  pipe into sh/python, 40+ space padding). A match is HIGH in every context.
- `sh -c` / `cmd /c` wrappers alone are **not** flagged, but the wrapped text is analysed. Evidence:
  microsoft/vscode `extensions/copilot/.vscode/tasks.json` has a folderOpen task that uses
  `cmd.exe /c if not exist node_modules npm ci`.
- **folderOpen tasks**: HIGH if the command (including per-OS overrides, `options.shell`,
  `dependsOn` closure, and one level of `npm run X` resolution) matches a danger pattern, or if
  it runs a repo file that is disguised (non-script extension such as `.woff2`) or that itself
  downloads or decodes code. All other folderOpen tasks are **INFO**: `npm run watch`, and
  `node scripts/watch.js` too (the same microsoft/vscode task runs `.esbuild.mts`).
- **initializeCommand** (runs on the host): HIGH unless every segment is
  `mkdir|touch|echo|true|test|[|docker network/volume create` (those give INFO). Running a repo
  script on the host is HIGH, as specified.
- **Container lifecycle commands** (onCreate/updateContent/postCreate/postStart/postAttach): HIGH
  only on danger patterns. `npm install` and `pip install -r requirements.txt` stay clean.
- **VS Code settings**: `task.allowAutomaticTasks: on` is HIGH. Executable/interpreter keys
  (`*InterpreterPath`, `pythonPath`, `*executablePath`, `executable`, `*.path`, `binPath`,
  `serverPath`, `nodePath`, `tsdk`, `prettierPath`, `cmakePath`) are HIGH only when they point at a
  file **committed in the repo** or at an odd path (shell metacharacters, URL, /tmp, %TEMP%). The
  common `${workspaceFolder}/.venv/bin/python` stays clean because `.venv` is not committed.
  Terminal env is HIGH for loader variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`,
  `ENV`, `PROMPT_COMMAND`, `ZDOTDIR`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, ...),
  for `NODE_OPTIONS` only with `--require/--import/--loader`, and for `JAVA_TOOL_OPTIONS` only with
  `-javaagent`. A PATH override is INFO. Shell/profile/automationProfile overrides are HIGH when
  they have repo/odd paths or init args (`-c`, `--rcfile`, `-Command`, ...), otherwise INFO.
- **.envrc**: HIGH on danger patterns, `fetchurl`/`source_url`, or `source <(...)`. Tool-init
  `eval "$(pyenv init -)"` (and similar: direnv, nix, conda, mise, asdf, ...) is allowed. Commands
  outside the direnv stdlib are INFO.
- **Git hooks**: a `git config core.hooksPath X` instruction in any README, Makefile, script or
  config is INFO, and X is queued for hook scanning. `/dev/null` is ignored, and so is
  `.github/`, because CI files run on CI runners. `--global`/`--system` hooksPath is HIGH.
  `core.fsmonitor <command>` is HIGH. Hooks in `.husky`, `.githooks`, `.git-hooks`, `githooks` or
  the hooksPath target are HIGH on danger patterns (comment lines ignored). lefthook `run:` and
  pre-commit `entry:` values (including block scalars) are HIGH on danger patterns, parsed line by
  line with no PyYAML dependency. A lefthook remote `git_url` is INFO.
- **Agents**: hook, statusLine, apiKeyHelper/awsAuthRefresh/awsCredentialExport/otelHeadersHelper
  and Gemini tool-discovery commands are HIGH on danger patterns or when the repo script they run
  is disguised or downloading. Otherwise they are INFO (e.g. `prettier --write`).
  `permissions.allow` of `Bash`/`Bash(*)`/`Bash(:*)`/`*` is HIGH. Interpreter or downloader
  prefixes such as `Bash(curl:*)` are INFO. `defaultMode: bypassPermissions` and
  `enableAllProjectMcpServers: true` are HIGH. `env` redirecting `ANTHROPIC_BASE_URL`/
  `OPENAI_BASE_URL`/`HTTPS_PROXY` to a non-local host is HIGH. Codex `notify`/`command` with danger
  patterns and `sandbox_mode = "danger-full-access"` are HIGH. `approval_policy = "never"` is INFO.
- **Result mapping**: any HIGH gives `FOUND (n entries)` (scored, exit 1). Otherwise an unparseable
  config gives `WARN (n configs unparsed)`, because it may hide an auto-run entry. Otherwise any
  INFO gives `INFO (n auto-run entries)`. Otherwise `CLEAN`. A crashed analyzer gives
  `SKIPPED (error)`. WARN, INFO and SKIPPED are not scored.
- MCP servers in `.vscode/mcp.json` / `.mcp.json` stay in the existing MCP check (reused, not
  duplicated). It now reads the VS Code `servers` key and JSONC.

## Safety (same patterns as c03ffd7)
- The target path goes to python via argv. There is no eval and no interpolation of repo data
  into code.
- Python runs with `-B -E -s`: no bytecode is written into the scanner dir, and `PYTHON*` env and
  user site-packages are ignored.
- Every path goes through `Repo.safe_path`: it must be inside the target and `realpath ==
  normpath` (no symlink component). Reads use `O_NOFOLLOW|O_NONBLOCK`, `fstat S_ISREG`, and a
  1 MiB cap, so symlinks, FIFOs and devices are never read.
- Each file is handled in its own try block. A malformed config adds an `E` record (WARN) and the
  walk continues.
- Detail strings are stripped of C0/C1 controls, whitespace-collapsed and truncated (160 chars)
  in python. They then go through the existing `sanitize_text` (terminal) and `md_escape`
  (saved report).
- No external dependencies. `tomllib` is stdlib (Python 3.11+). If it is missing, the Codex config
  is reported as unparsed.

## False-positive validation
The analyzer was run on shallow clones (temp dirs, deleted afterwards):

| Repo | Result |
|---|---|
| microsoft/TypeScript | INFO: a `$hooksPath` mention in a pipeline yml. Before the fix it also showed `/dev/null` hooksPath entries from `.github/workflows` (now ignored) |
| microsoft/vscode | INFO: copilot folderOpen watch task. Before the rule refinement it was HIGH ("runs repo file .esbuild.mts", then "cmd.exe /c"); both rules were fixed |
| astral-sh/ruff | INFO: SessionStart hook running `.claude/hooks/session-start.sh`. The script was inspected and is benign |
| prettier/prettier, fastapi/fastapi, excalidraw/excalidraw, anthropics/claude-code, microsoft/vscode-python, vitejs/vite, denoland/deno, tiangolo/full-stack-fastapi-template, home-assistant/core, withastro/astro, langchain-ai/langchain | No records |

The analyzer took 2.2 s on microsoft/vscode.

`./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive`: rc=0, AUTOEXEC CLEAN,
**Risk score 0/100**.

## Known limitations / follow-ups
- Dockerfile `RUN curl|sh`, devcontainer `features` from arbitrary registries, and `runArgs`/mounts
  of host paths are out of scope.
- JetBrains `.idea` startup tasks, Zed `.zed/tasks.json` and `.gitattributes` filter drivers via
  `include.path` are not covered.
- `npm run X` resolution goes one level deep. Transitive script chains are covered only by the
  danger patterns on the resolved text.
- Nested `test/tests/fixtures/examples` trees are skipped (they are never opened as the workspace
  root). A `.envrc` placed there would be missed.

## Test command and output
`bash tests/test_scanner.sh` (exit 0):

```
── Setting up test fixtures ──
── Test 1: CLI invocation variations ──
✓ All CLI argument variations passed
── Test 2: Clean repo false positive check ──
✓ Clean repo produces zero false positives
── Test 3: Malicious repo detection check ──
✓ Malicious repo detected with exit code 1 (MCP, PTH, pickle, RCE, YARA, SENS, lifecycle, typosquat, .env)
── Test 5: YARA precision rules ──
✓ YARA precision rules detect chains and skip benign code
── Test 6: MCP pinning precision ──
✓ Unpinned npx flagged, pinned npx and rsync args stay clean
── Test 7: Filename command injection must not execute ──
✓ Crafted filenames are reported, never executed
── Test 8: Symlinks to /dev/zero and host files are not followed ──
✓ Symlinks skipped, scan completes
── Test 9: Stealer in minified lifecycle target ──
✓ Minified lifecycle target scanned with no noise filter
── Test 10: Split decode/exec and minified eval(atob) ──
✓ Split decode/exec (low confidence) and minified eval(atob) detected
── Test 11: Pickle evasions (memo, padding, concatenation, zip) ──
✓ Memo indirection, >64 MB padding, concatenated streams, compressed zip and importlib detected
── Test 12: Credential access patterns ──
✓ ~/.ssh enumeration, .netrc, ~/.npmrc, id_rsa/.aws joins, env dumps and fetched authorized_keys detected
── Test 13: Shell and code RCE variants ──
✓ echo-prefixed, sudo, process-substitution, sh -c $(curl), |python, conftest.py, README-named code detected
── Test 14: setup.py install hooks and entry points ──
✓ setup.py launcher/install-hook subprocesses and bin entry points detected
── Test 15: Typosquat parsers and PE network imports ──
✓ Pipfile, install_requires with extras, WinHTTP imports detected
── Test 16: Malformed manifests do not disable entry-point resolution ──
✓ Each manifest fails open; unparseable manifests give WARN, not CLEAN
── Test 17: Pickle bypasses (zip prefix, .pth checkpoint, huge args, DUP, gadgets) ──
✓ Zip prefix, .pth checkpoint, 65 MB args, legacy streams, DUP, timeit, _posixsubprocess, corrupt zip detected; benign pickles clean
── Test 18: Report and terminal output neutralize repo-derived markup ──
✓ Markdown image beacons, HTML and ANSI/OSC sequences neutralized
── Test 19: SIGPIPE-safe matching on large files ──
✓ Large files detected (no grep -q under pipefail)
── Test 20: FIFO, TSV injection and option injection ──
✓ FIFOs skipped, entry records cannot escape the repo, '-' URLs rejected
── Test 21: npm run indirection and local requires from entry points ──
✓ npm run X and one level of local require() resolved
── Test 22: Pickle allowlist (stdlib gadgets, shadowing, no-STOP streams) ──
✓ Per-name allowlist: stdlib/torch gadgets, shadowing and no-STOP streams flagged; torch/numpy clean; unknown classes suspicious
── Test 23: High-precision YARA rules scan tests/ code imported by the package ──
✓ Stealer in tests/ detected by high-precision rules
── Test 24: Auto-execution on open (per-vector repos) ──
✓ folderOpen, devcontainer, .envrc, hooksPath, Claude hooks/permissions detected; benign configs clean/INFO
── Test 25: Auto-execution analyzer coverage and hostile inputs ──
✓ Settings, workspaces, nested devcontainers, lefthook, pre-commit, Cursor, Codex, Gemini, VS Code MCP covered; symlinks/FIFOs skipped
── Test 4: Report generation with --save ──
✓ Report generated successfully with --save
All tests passed successfully!
```

---

# Round 2: fixes for review_autoexec.md and security_autoexec.md

## Package layout (all files ≤300 lines, functions ≤50 lines, lines ≤100 chars)
`__main__.py` (dispatch and output) · `discovery.py` (new: walk, symlinks, case-insensitive
names) · `core.py` (Repo, JSONC, script resolution) · `patterns.py` (new: detection regexes) ·
`vscode_tasks.py` (new: tasks/workspaces) · `editors.py` (settings, devcontainer, env) ·
`vcs_hooks.py` · `agents.py`.

## Code review blockers
| # | Fix | Regression test |
|---|---|---|
| B1 | `clean()` re-encodes with `errors="replace"`, so lone surrogates no longer crash it; stdout uses `errors="replace"`; `safe_path` returns None on `ValueError` (NUL byte); instruction and hook-dir scans are wrapped per file | T26 `r2-surrogate`, `r2-nul` → FOUND, exit 1 |
| B1/W5 | An analyzer crash, timeout or missing package now gives `WARN (analyzer error)` with the stderr tail as detail. It is scored (weight 10, not high) instead of SKIPPED/0 | T26 runs a scanner copy with a crashing `__main__.py` → WARN, detail shown, score ≠ 0/100 |
| B2/W1 | `runOn` is lowercased; `folderopen` and `worktreecreated` are both auto-run values | T26 `FolderOpen`, `worktreeCreated` |
| B3 | Tasks are read from `tasks` and from the top-level `windows/osx/linux.tasks` arrays (also in workspaces) | T26 `osarr` |
| B4 | `check_env` runs on the `options.env` of each task in the dependsOn closure, its per-OS variants and the globals. Top-level and per-OS `command`/`args`/`options.shell` are inherited by `task_commands` | T26 `envtask`, `globalshell` |
| B5 | `SCRIPT_DANGER` now also covers: axios, `got(`, node-fetch, undici, `http(s)/net/tls.request/connect(`, `require('https')`, `from 'https'`, `Buffer.from(..,'base64')`, `os.dup2`, `pty.spawn`, `socket.socket(`, and variable-built command names | T26 `axios`, `b64fn`, Claude hook `s.js` |
| B6 | `.envrc` lines and hook lines resolve `source`/`.`/`source_env`/executed repo files through `script_target`, including `$(…)` contents and segments after `if`/`then`/`!`/`[ … ] ||`, then apply `script_verdict` | T26 `i/.envrc`, `.husky/pre-commit` → `scripts/precommit.sh` |
| B7 | `initializeCommand` is benign only if there is no `$(`, backtick, `<(` or `>`; segments are split on `&& \|\| ; \| & \n`; `cd` was added to the benign heads | T26 `j`-`m` (nc exfil in `$(…)`, backticks, `\n`, `> ~/.bashrc`); T27 `&` with a disguised payload |
| B8 | PowerShell only with `-c/-Command/-e/-enc/-EncodedCommand` or `iex/Invoke-Expression`. `task.allowAutomaticTasks` downgraded to INFO (application-scoped). `enableAllProjectMcpServers` is HIGH only when a project `.mcp.json` exists. Hash-pinned `source_url`/`fetchurl` is INFO | T26 `r2-fp` → INFO, 0/100, exit 0; `r2-mcpjson` → FOUND |

## Code review warnings
| # | Fix | Test |
|---|---|---|
| W2 | `nc host port` / `netcat` added to REMOTE | T26 `apiKeyHelper` |
| W3 | `npx/bunx/pnpx` with `-y/--yes/@latest`, `uvx`, `pnpm/yarn dlx` without a version pin → HIGH in auto-run contexts (tasks, initializeCommand, agent commands). `npx tsc -w` stays INFO | T26 `npx`; `r2-fp` `npx tsc -w` |
| W4 | `.envrc` `$(…)` contents are analysed (danger, script resolution). Other substitutions are INFO | T26 `p/.envrc` |
| W6 | Trailing-comma removal happens in a tokenizer that skips strings; `_next_significant` walks by index (no slicing) | T26 `r2-comma` |

## Security findings
| Severity | Fix | Test |
|---|---|---|
| CRITICAL | Every `python3` in `repo-scanner.sh` (all 13 heredocs/`-c` calls, including pre-c03ffd7 ones) now runs `python3 -I -B`, so cwd and script dir are never on sys.path and nothing is written. The analyzer runs as `python3 -I -B checks/autoexec`, and `__main__.py` pins `sys.path` to the package dir before any local import. Verified the old form imports a cwd `json.py`, and `-I` does not | T27 `r3-hijack`: json/re/os/shlex/typing/dataclasses/sys/tomllib/pathlib `.py` planted, scanned with `cd target && repo-scanner.sh --repo .` → no marker |
| HIGH symlinks | `discovery.py` walks with `os.scandir` (no follow). A symlinked config dir or file (`.vscode`, `.devcontainer`, `.claude`, `.cursor`, `.gemini`, `.codex`, hook dirs, `.envrc`, `*.code-workspace`, hook configs, `.mcp.json`, or anything inside a config dir): an in-repo target is **analysed at the link location** (INFO "symlink to X"); a target outside the repo gives **HIGH** "config path is a symlink leaving the repo" and is never read. Loops are bounded (each target is expanded once, max 64 linked dirs). Symlinked interpreter paths in settings → HIGH "symlinked repo path" | T27 `.vscode -> cfg/editor`, `.devcontainer -> x`, `.vscode -> /etc` → FOUND; T25 escaping `tasks.json` and `.envrc -> /dev/zero` → HIGH, content not read; T27 `pyl` symlink |
| HIGH case | Directory and file names are compared lowercased (`.VSCODE/TASKS.JSON`, `.Devcontainer`, `.ENVRC`, ...) | T27 `r3-case` |
| HIGH test dirs | Config files are analysed everywhere. `test`/`fixtures`/`examples` (and `.github/`) are skipped only for generic hooksPath instruction scanning | T27 `.devcontainer/test/devcontainer.json` |
| HIGH .envrc | Every segment's command word is checked (split on `; && \|\| \| &`, keywords/`[ … ]` stripped, redirection fragments ignored). Executed or sourced repo scripts are INFO, or HIGH when `script_verdict` flags them | T27 `[ -f x ] \|\| ./tools/fmt` (`${c}rl` payload) → HIGH; `echo hi; python3 -m http.server &` → INFO |
| HIGH regex DoS | `${…}` stripping uses `\$\{[^{}$]*\}` (linear); executable-path values over 4096 chars are "odd path"; a 120 s `timeout` around the analyzer gives scored WARN | T27 `r3-dos`: 400 KB of `${` analysed in under 30 s (0.1 s measured) |
| HIGH fan-out DoS | package.json scripts are parsed once per directory (`Repo.scripts` cache). Command lines are memoized per file and deduped per task. dependsOn objects `{"task": …}` resolve | T27 `r3-dos`: 400 tasks × 49 dependsOn × 3 OS overrides plus a 680 KB package.json, under 30 s (0.4 s measured) |
| Follow-ups done | Quote-split normalization (`cu""rl`, `c\url`); variable-built command names (`${c}rl`, `cu$r`); `&`/newline splitting; hooksPath variants (`git -C . config`, `git config set`, `$(pwd)/` prefix); bidi/zero-width stripped in `clean()`; `.gitignore` gets `__pycache__/` and `*.swp` | T27 `e`, `f`, `d`, `h` (bidi) |

Not done (follow-ups): YAML-anchored lint-staged resolution, remote `repo:` pre-commit INFO,
`.idea`/`.zed`, transitive `npm run` chains, scoring WARN for non-autoexec checks.
`.README.md.swp` is the user's vim swap file. It is now ignored rather than deleted.
`tmp/ae` and `tmp/a.sh` were already gone.

## False-positive re-validation (round 2)
Analyzer run on shallow clones (`core.symlinks=false`, same as the scanner). The clones were
deleted afterwards.

| Repo | Result |
|---|---|
| microsoft/vscode (2), microsoft/TypeScript (1), microsoft/vscode-eslint (2), nrwl/nx (2), astral-sh/ruff (1) | INFO only |
| PowerShell/PowerShell, home-assistant/core, anthropics/claude-code, microsoft/vscode-python, vitejs/vite | No records |
| cachix/devenv | INFO only. It was HIGH on `--no-pure-eval` (fixed: `eval` must not be part of a hyphenated word) and on `eval "$(devenv direnvrc)"` (devenv added to the env-manager eval allowlist) |
| devcontainers/templates | One HIGH: `src/kubernetes-helm` `initializeCommand: cd .devcontainer && bash ensure-mount-sources`. This is the contracted behaviour (a repo script on the host is HIGH), and the reviewer accepted it as a NOTE |

`./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive`: rc=0, AUTOEXEC CLEAN,
**Risk score 0/100**.

## Test output (round 2)
`bash tests/test_scanner.sh` (exit 0):

```
── Setting up test fixtures ──
── Test 1: CLI invocation variations ──
✓ All CLI argument variations passed
── Test 2: Clean repo false positive check ──
✓ Clean repo produces zero false positives
── Test 3: Malicious repo detection check ──
✓ Malicious repo detected with exit code 1 (MCP, PTH, pickle, RCE, YARA, SENS, lifecycle, typosquat, .env)
── Test 5: YARA precision rules ──
✓ YARA precision rules detect chains and skip benign code
── Test 6: MCP pinning precision ──
✓ Unpinned npx flagged, pinned npx and rsync args stay clean
── Test 7: Filename command injection must not execute ──
✓ Crafted filenames are reported, never executed
── Test 8: Symlinks to /dev/zero and host files are not followed ──
✓ Symlinks skipped, scan completes
── Test 9: Stealer in minified lifecycle target ──
✓ Minified lifecycle target scanned with no noise filter
── Test 10: Split decode/exec and minified eval(atob) ──
✓ Split decode/exec (low confidence) and minified eval(atob) detected
── Test 11: Pickle evasions (memo, padding, concatenation, zip) ──
✓ Memo indirection, >64 MB padding, concatenated streams, compressed zip and importlib detected
── Test 12: Credential access patterns ──
✓ ~/.ssh enumeration, .netrc, ~/.npmrc, id_rsa/.aws joins, env dumps and fetched authorized_keys detected
── Test 13: Shell and code RCE variants ──
✓ echo-prefixed, sudo, process-substitution, sh -c $(curl), |python, conftest.py, README-named code detected
── Test 14: setup.py install hooks and entry points ──
✓ setup.py launcher/install-hook subprocesses and bin entry points detected
── Test 15: Typosquat parsers and PE network imports ──
✓ Pipfile, install_requires with extras, WinHTTP imports detected
── Test 16: Malformed manifests do not disable entry-point resolution ──
✓ Each manifest fails open; unparseable manifests give WARN, not CLEAN
── Test 17: Pickle bypasses (zip prefix, .pth checkpoint, huge args, DUP, gadgets) ──
✓ Zip prefix, .pth checkpoint, 65 MB args, legacy streams, DUP, timeit, _posixsubprocess, corrupt zip detected; benign pickles clean
── Test 18: Report and terminal output neutralize repo-derived markup ──
✓ Markdown image beacons, HTML and ANSI/OSC sequences neutralized
── Test 19: SIGPIPE-safe matching on large files ──
✓ Large files detected (no grep -q under pipefail)
── Test 20: FIFO, TSV injection and option injection ──
✓ FIFOs skipped, entry records cannot escape the repo, '-' URLs rejected
── Test 21: npm run indirection and local requires from entry points ──
✓ npm run X and one level of local require() resolved
── Test 22: Pickle allowlist (stdlib gadgets, shadowing, no-STOP streams) ──
✓ Per-name allowlist: stdlib/torch gadgets, shadowing and no-STOP streams flagged; torch/numpy clean; unknown classes suspicious
── Test 23: High-precision YARA rules scan tests/ code imported by the package ──
✓ Stealer in tests/ detected by high-precision rules
── Test 24: Auto-execution on open (per-vector repos) ──
✓ folderOpen, devcontainer, .envrc, hooksPath, Claude hooks/permissions detected; benign configs clean/INFO
── Test 25: Auto-execution analyzer coverage and hostile inputs ──
✓ Settings, workspaces, nested devcontainers, lefthook, pre-commit, Cursor, Codex, Gemini, VS Code MCP covered; symlinks/FIFOs skipped
── Test 26: Auto-execution round-2 regressions (crashes, bypasses, FP shapes) ──
✓ Crash-proof analyzer (WARN on crash), runOn case/worktreeCreated, per-OS arrays, task env/global shell, loader shapes, indirection, host allowlist, FP shapes
── Test 27: Auto-execution security round (isolation, symlinks, case, DoS, bypasses) ──
✓ Isolated python (no cwd imports), symlinked/case-variant/test-dir configs, .envrc segments, hooksPath variants, bidi, DoS bounded
── Test 4: Report generation with --save ──
✓ Report generated successfully with --save
All tests passed successfully!
```

---

# Round 3: review N1/N2 and security round-2 findings

## Fixes
| Item | Fix | Regression test (T28) |
|---|---|---|
| Review N1: lenient JSONC downgrade | New `fallback.py`. When a JSON/JSONC config (tasks, settings, workspaces, devcontainer, agent configs; not package.json) fails strict parsing, every string literal of the comment-stripped text is decoded (raw text if the escape is invalid) and checked with `auto_run_danger`. Command-like literals (containing a space) are also resolved to repo files and checked with `script_verdict`. Any hit is HIGH "unparseable config (tools parse it leniently)". WARN applies only when nothing dangerous is found | `r4-comma` (missing-comma devcontainer, host `curl\|sh`) and `r4-garbage` (tasks.json with trailing ` x`) → FOUND, exit 1; T24 `broken` → `WARN (1 analysis warnings)` |
| Review N2: sourced env files | `script_target_kind` reports whether the file is sourced (`source`/`.`/`source_env*`). Sourced files skip the disguised-extension rule and get a content-only verdict (`sourced_verdict`): unpinned `source_url`/`fetchurl`, downloaders, inline interpreters, decoding and pipe-to-shell count; a local `eval "$env"` (direnv libraries such as devenv's `direnvrc`) does not. Benign → INFO "sources repo file X". Also fixed the doubled "runs runs" wording (`disguised non-script file`) | `r4-envfiles` (`.envrc.local`, `.env.defaults`, devenv-style `lib/direnvrc`) → INFO, exit 0; `r4-envbad` (`.envrc.local` with `curl\|sh`) → FOUND |
| Security N1: symlinks in clone mode | After the clone, the scanner lists index symlinks with `git -C "$CLONE_DIR" ls-files -s -z` (mode 120000), writes them NUL-separated to `$TMPDIR_SCAN/autoexec-links.bin`, and passes that file as argv[2]. `discovery.py` treats each listed config path (checked out as a plain file holding the link text) as a link. The text is resolved inside the root, chains are followed up to 8 hops, and reads are capped at 4 KiB. Policy for both modes: a target outside the repo or dangling is **HIGH**; an in-repo target gives **WARN** (E record, scored 10) and is analysed at the link location, so dangerous content is HIGH | `r4-gitlinks` (`.vscode -> cfg/editor` with a folderOpen `curl\|sh`) via `file://` → FOUND; `r4-gitout` (`.devcontainer -> /etc`) → FOUND; `r4-gitin` (`.vscode/settings.json -> ../shared/settings.json`, benign) → WARN |
| Security N2: timeout drops HIGH | (a) `Output` prints and flushes each HIGH record immediately; INFO and E records come at the end. On a hard-timeout kill the scanner keeps the partial stdout, so FOUND wins. (b) Steps run in this order: root-level configs (`.vscode`, `.devcontainer*`, `.envrc`, `.claude`, `.cursor`, `.gemini`, `.codex`, hook configs, `.mcp.json`, `*.code-workspace`), then root hook dirs, then nested configs by depth, then hooksPath instructions, then remaining hook dirs. (c) Internal budget `AUTOEXEC_BUDGET_SECONDS` = timeout − 30 s (default 90 s); when it runs out the analyzer stops and emits E "analysis time budget (Ns) exhausted; rest not analysed" (WARN if there is no HIGH). Per-task command lines are memoized, so the dependsOn fan-out is computed once per task. The hard timeout falls back to `gtimeout` and can be set with `REPO_SCANNER_AUTOEXEC_TIMEOUT` | `r4-pad` (12 padded subdirs, about 3 s, plus a malicious root tasks.json): analyzer killed after 1 s still prints the H record; full scanner with `REPO_SCANNER_AUTOEXEC_TIMEOUT=2` → FOUND, exit 1; `r4-padclean` with a 0.5 s budget → `E analysis time budget ...` |

E records are now free-text messages (unparsed config, symlinked config, budget). The scanner
shows `WARN (n analysis warnings)`, scored 10, never high.

## Not changed (noted)
- Exec-form `initializeCommand: ["mkdir","-p","x;id"]` is still HIGH (security follow-up 4).
  It is a false positive, not a risk.
- The `devcontainers/templates` kubernetes-helm `initializeCommand` (a repo script on the host)
  stays HIGH by contract.
- Running external tools with `env -u PYTHONPATH ...` (security follow-up 1) is left as a
  follow-up: user-env only, not repo-controllable.

## Verification
- `bash tests/test_scanner.sh` exits 0, 28 test groups (output below).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive`: rc=0, AUTOEXEC
  CLEAN, **0/100**.
- FP re-check with git-index links: microsoft/vscode (1 link), TypeScript, nrwl/nx, astral-sh/ruff
  (1 link) and cachix/devenv give no HIGH. devenv was HIGH on its sourced `devenv/direnvrc`
  (`eval "$env"`) and was fixed via the local-eval rule above. devcontainers/templates keeps only
  the contracted kubernetes-helm HIGH.

```
── Setting up test fixtures ──
── Test 1: CLI invocation variations ──
✓ All CLI argument variations passed
── Test 2: Clean repo false positive check ──
✓ Clean repo produces zero false positives
── Test 3: Malicious repo detection check ──
✓ Malicious repo detected with exit code 1 (MCP, PTH, pickle, RCE, YARA, SENS, lifecycle, typosquat, .env)
── Test 5: YARA precision rules ──
✓ YARA precision rules detect chains and skip benign code
── Test 6: MCP pinning precision ──
✓ Unpinned npx flagged, pinned npx and rsync args stay clean
── Test 7: Filename command injection must not execute ──
✓ Crafted filenames are reported, never executed
── Test 8: Symlinks to /dev/zero and host files are not followed ──
✓ Symlinks skipped, scan completes
── Test 9: Stealer in minified lifecycle target ──
✓ Minified lifecycle target scanned with no noise filter
── Test 10: Split decode/exec and minified eval(atob) ──
✓ Split decode/exec (low confidence) and minified eval(atob) detected
── Test 11: Pickle evasions (memo, padding, concatenation, zip) ──
✓ Memo indirection, >64 MB padding, concatenated streams, compressed zip and importlib detected
── Test 12: Credential access patterns ──
✓ ~/.ssh enumeration, .netrc, ~/.npmrc, id_rsa/.aws joins, env dumps and fetched authorized_keys detected
── Test 13: Shell and code RCE variants ──
✓ echo-prefixed, sudo, process-substitution, sh -c $(curl), |python, conftest.py, README-named code detected
── Test 14: setup.py install hooks and entry points ──
✓ setup.py launcher/install-hook subprocesses and bin entry points detected
── Test 15: Typosquat parsers and PE network imports ──
✓ Pipfile, install_requires with extras, WinHTTP imports detected
── Test 16: Malformed manifests do not disable entry-point resolution ──
✓ Each manifest fails open; unparseable manifests give WARN, not CLEAN
── Test 17: Pickle bypasses (zip prefix, .pth checkpoint, huge args, DUP, gadgets) ──
✓ Zip prefix, .pth checkpoint, 65 MB args, legacy streams, DUP, timeit, _posixsubprocess, corrupt zip detected; benign pickles clean
── Test 18: Report and terminal output neutralize repo-derived markup ──
✓ Markdown image beacons, HTML and ANSI/OSC sequences neutralized
── Test 19: SIGPIPE-safe matching on large files ──
✓ Large files detected (no grep -q under pipefail)
── Test 20: FIFO, TSV injection and option injection ──
✓ FIFOs skipped, entry records cannot escape the repo, '-' URLs rejected
── Test 21: npm run indirection and local requires from entry points ──
✓ npm run X and one level of local require() resolved
── Test 22: Pickle allowlist (stdlib gadgets, shadowing, no-STOP streams) ──
✓ Per-name allowlist: stdlib/torch gadgets, shadowing and no-STOP streams flagged; torch/numpy clean; unknown classes suspicious
── Test 23: High-precision YARA rules scan tests/ code imported by the package ──
✓ Stealer in tests/ detected by high-precision rules
── Test 24: Auto-execution on open (per-vector repos) ──
✓ folderOpen, devcontainer, .envrc, hooksPath, Claude hooks/permissions detected; benign configs clean/INFO
── Test 25: Auto-execution analyzer coverage and hostile inputs ──
✓ Settings, workspaces, nested devcontainers, lefthook, pre-commit, Cursor, Codex, Gemini, VS Code MCP covered; symlinks/FIFOs skipped
── Test 26: Auto-execution round-2 regressions (crashes, bypasses, FP shapes) ──
✓ Crash-proof analyzer (WARN on crash), runOn case/worktreeCreated, per-OS arrays, task env/global shell, loader shapes, indirection, host allowlist, FP shapes
── Test 27: Auto-execution security round (isolation, symlinks, case, DoS, bypasses) ──
✓ Isolated python (no cwd imports), symlinked/case-variant/test-dir configs, .envrc segments, hooksPath variants, bidi, DoS bounded
── Test 28: Auto-execution round 3 (lenient JSONC, sourced env files, clone-mode symlinks, timeouts) ──
✓ Lenient JSONC keeps HIGH, sourced env files content-checked, git-index symlinks in clone mode, partial HIGH kept on timeout
── Test 4: Report generation with --save ──
✓ Report generated successfully with --save
All tests passed successfully!
```

## Round 4

### Review: tolerant re-parse of malformed configs
- New `checks/autoexec/tolerant.py`: an error-tolerant JSONC parser that mirrors VS Code / devcontainers `jsonc-parser` recovery (missing commas and colons, stray tokens, raw newlines in strings, leading garbage, trailing content). Nesting is capped at a depth of 200.
- When the strict parse fails, `run_handler` now re-runs the same handler on the tolerant tree, so a broken config gets the normal verdicts. `lenient_scan` still runs as a literal-level backstop. The config also keeps the WARN "config could not be parsed strictly".
- Results: the 4 reviewer fixtures (font payload, host scp, exec-form host command, host repo script) are FOUND with exit 1. Malformed benign configs give `WARN (2 analysis warnings)` with exit 0. Covered by Test 29.

### Security round 3
1. **CRITICAL: git ran on local targets.** I confirmed `git ls-files` and semgrep (which calls `git ls-files` internally) both executed the target's `core.fsmonitor`. Fixes:
   - The git-index symlink listing now runs only for our own URL clone (`IS_LOCAL != true`). It also runs with hardened overrides: `-c core.fsmonitor= core.hooksPath=/dev/null core.pager=cat diff.external= core.sshCommand= protocol.allow=never`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_TERMINAL_PROMPT=0`.
   - Semgrep now runs with `--no-git-ignore`, so it never calls git.
   - For local dirs, gitleaks `--full-history` falls back to `--no-git` and prints a WARN explaining why. The gitleaks detail also states that history was not scanned.
   - Audit of the other tools: trufflehog runs in `filesystem` mode and yara needs no git (both verified not to trigger the hook). `git clone` runs only on URLs.
   - Test 30: a local dir with `core.fsmonitor`, `diff.external` and `core.pager` set to `touch PWNED`, scanned both normally and with `--full-history`. No PWNED file is created.
2. **HIGH: output cap.** `Output.add` has no shared cap any more. Every HIGH is printed (deduplicated) and INFO is capped separately at `MAX_LIST`. Hook directories list git hook names first, with a bound of 500 files instead of the first 50 sorted names. Test 30: 100 benign folderOpen tasks plus a curl task, and 25 benign workspaces plus a hostile one. Both HIGH records are kept and INFO stays ≤ 50.
3. **HIGH: symlinked scripts.**
   - New `Repo` link support in `core.py`: `index_links`, `inside`, `is_link`, `resolve_inside`, `resolve_index_link`, `follow`, `warn`. Discovery reuses it.
   - `script_target_kind` now accepts linked script paths. The exception is linked `node_modules`/venv paths, which come from local installs.
   - `script_verdict` and `sourced_verdict` follow the link. A link leaving the repo, or a dangling one, is HIGH. An in-repo link gives a WARN and the target is analysed, including the disguised-extension check on the target name (`run.js -> p.woff2`).
   - `scan_hook_dir` handles hook files that are themselves symlinks.
   - This works for both real symlinks (local) and git-index links (file:// clone).
   - Test 30 cases: husky hostile target (local and file://), font target, outside target, benign target (WARN) and a symlinked hook file.
4. **HIGH: shipped `.git` metadata.** New `checks/autoexec/gitdir.py`, a static parser only (git is never run).
   - It locates the git dir: `.git` as a directory, an in-repo symlink, or an in-repo `gitdir:` file.
   - It parses `.git/config`, following in-repo `include`/`includeIf` paths. Includes outside the target give a WARN.
   - Command keys are HIGH: `core.fsmonitor` (non-boolean), pager, editor, `sequence.editor`, `sshCommand`, `gitProxy`, `askPass`, `diff.external`, `gpg.program`, `credential.helper` (`!` or path), `filter.*.clean/smudge/process`, `diff.*.textconv/command`, `merge.*.driver`, `remote.*.uploadpack/receivepack`, `!` aliases, and `core.hooksPath` outside the repo. A `core.hooksPath` inside the repo is scanned as a hook dir.
   - Well-known programs are INFO: `less`, `code --wait`, `vim`, `git-lfs`, plain credential helper names.
   - Executable, non-`.sample` hooks with git hook names: hostile content is HIGH, hook-manager stubs (pre-commit, husky, lefthook, git-lfs) are INFO, anything else is WARN.
   - Test 30 cases: config keys (incl. via include), a hostile post-checkout hook, a benign active hook (WARN), and a benign config with sample hooks (INFO).
- **Extra FP fix:** pipe-to-shell no longer matches regex alternations like `(md|sh|json)` or `(py|sh)$`. These were found in a real local pre-commit hook. Test 30 covers this with `r6-regex`.
- **FP check:** 15 local dev checkouts give no HIGH from the new code. Custom active hooks there are WARN by design.

### Verification
- `bash tests/test_scanner.sh` exits 0, with 30 ✓ (Tests 29 and 30 are new this round).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive` exits 0: 0/100, AUTOEXEC CLEAN.
- `checks/autoexec/__pycache__` and `tmp/r5`/`tmp/r6` were removed.

## Round 5 (security round-4 HIGHs)

1. **Budget starvation by malformed root `*.code-workspace` files**
   - Strict tiers in `__main__.priority`:
     - 0: fixed root tool locations (`.vscode/`, `.devcontainer*`, `.envrc`, `.claude/`, `.cursor/`, `.gemini/`, `.codex/`, `.mcp.json`, hook configs)
     - root hook dirs
     - 1: root `*.code-workspace`
     - 2: nested configs
     - 3: nested workspaces
     - then instructions, then remaining hook dirs.
   - `.git/config`, `config.worktree`, commondir and hooks are always analysed first, before discovery.
   - Only files with a handler are queued.
   - Every step runs inside a per-file time slice (`signal.setitimer`, min(10 s, budget/4), at least 1 s). `FileTimeout` is a BaseException, so the handlers' `except Exception` cannot swallow it. A cut-off file gives the WARN "X: not fully analysed (per-file time slice)".
   - Workspaces are capped at 200, root first. The costly tolerant/lenient re-parse runs for at most 20 malformed globbed workspaces. A hard cap of 20 workspace files was rejected because it would turn a HIGH in workspace #21 into a WARN and break the round-4 cap test.
   - Skipped files produce `E N files not analysed (budget)`, inserted **first**, together with "analysis time budget exhausted". A full error list can no longer hide them.
   - PoC (130 malformed 1 MB root workspaces + `.vscode/tasks.json` curl|sh, `file://`): FOUND, exit 1, about 10 s end to end.
2. **`.git` config locations** (`gitdir.py`)
   - A UTF-8 BOM is stripped before parsing.
   - `config.worktree` is parsed: always, which is conservative compared to git, which needs `extensions.worktreeConfig`.
   - `commondir` is followed only inside the target, and its `config`, `config.worktree` and `hooks/` are used. A commondir outside the target, or a non-regular commondir file, is HIGH.
   - In-repo `include`/`includeIf` targets are analysed and produce no false "outside" WARN (security follow-up 4: not reproducible with the current tree; it is now asserted in the test).
3. **Test 31**: starvation PoC, analyzer (`AUTOEXEC_BUDGET_SECONDS=1`, skip WARN first) and end to end (`REPO_SCANNER_AUTOEXEC_TIMEOUT=2`, exit 1); malformed-workspace re-parse cap; per-file slice unit check; config.worktree, in-repo commondir, outside commondir, BOM and includeIf; BOM end to end with exit 1.

### Verification
- `bash tests/test_scanner.sh` exits 0, with 31 ✓.
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive` exits 0: 0/100, AUTOEXEC CLEAN.
- Temp fixtures and `__pycache__` were removed.
- Not done, non-blocking follow-ups: lenient strings across raw newlines (1), per-file memory (2), committed `node_modules` links (3).
