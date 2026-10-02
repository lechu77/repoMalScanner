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
| 5 | Sensitive files & AI credentials | grep + python3 | SSH private keys and `~/.ssh` enumeration, `~/.aws/credentials`, `~/.netrc`/`~/.npmrc`/`~/.pypirc`/`~/.docker/config.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`, `state.vscdb`, env dumps sent to a network sink, `authorized_keys` writes with a hardcoded or downloaded key |
| 6 | Remote code execution | grep | `curl \| (sudo) sh`, `\| python`, `bash <(curl)`, `sh -c "$(curl)"` in shell scripts; decoded/downloaded payload passed straight to `exec`/`eval` |
| 7 | Suspicious exfil endpoints | grep | webhook.site, Telegram bots, Discord webhooks, ngrok, Pastebin, etc. |
| 8 | Network syscalls in binaries | strings | `.so`, `.dylib`, `.exe` compiled with network socket syscalls |
| 9 | Committed .env files | find | `.env`, `.env.production`, `.env.local`, etc. |
| 10 | Lifecycle script abuse | python3 | Inline remote execution in npm hooks, malicious files run by hooks (`node scripts/x.min.js`), setup.py network/exec or install-hook subprocesses |
| 11 | Dependency typosquatting | python3 | npm/pip deps with Levenshtein distance ≤1 to popular packages |
| 12 | Insecure MCP & agent tools | python3 | Rogue commands, direct shells, or `npx`/`uvx` packages without a version pin in MCP server configs (`mcpServers`, and VS Code `.vscode/mcp.json` `servers`; JSONC accepted) |
| 13 | Python .pth & unsafe serialization | python3 | `.pth` auto-exec startup hooks; pickle imports outside a per-name allowlist (`torch.*`, numpy reconstruct/dtype/ndarray, `collections.OrderedDict`, safe builtins, the repo's own classes, ...). Stdlib gadgets and stdlib modules shadowed by repo files are high severity; unknown third-party classes are "suspicious" (weight 10, not high severity), found by a static opcode walk with memo/stack tracking over every concatenated stream and zip member (including `*.pth` checkpoints). It never unpickles. Unparseable `.pkl` files and analysis-budget overruns are reported (fail closed) |
| 14 | Auto-execution on open | python3 (`checks/autoexec/`) | Code that runs just by opening, entering or using the repo: VS Code `runOn: folderOpen`/`worktreeCreated` tasks (case-insensitive; `tasks.json`, per-OS task arrays, `*.code-workspace`, inherited global `command`/`args`/`options.shell`, task `options.env` loaders, `dependsOn`, `npm run X` resolution) that download, inline-eval, obfuscate, fetch unpinned packages (`npx -y`, `uvx`, `dlx`) or run a disguised/downloading repo file (axios/got/https loaders, `Buffer.from(..,'base64')`, reverse shells); `.vscode/settings.json` interpreter/executable paths pointing at committed, symlinked or odd paths, terminal env loaders (`NODE_OPTIONS=--require`, `LD_PRELOAD`, `BASH_ENV`, `GIT_SSH_COMMAND`, ...) and shell/automation profiles with init args; devcontainer `initializeCommand` (runs on the host; only `mkdir`/`touch`/`echo`/`test`/`cd`/`docker network\|volume` without substitution or redirection is INFO) and lifecycle commands with downloaders; `.envrc` remote fetch/eval, unpinned `source_url`/`fetchurl`, hostile sourced/executed repo scripts; `git config core.hooksPath` instructions (incl. `git -C`, `config set`) and `.husky`/`.githooks` hooks with downloaders or hostile referenced scripts, global hooksPath, `core.fsmonitor` commands, lefthook/pre-commit `run:`/`entry:` downloaders; Claude Code / Gemini / Cursor hooks and helper commands, `permissions.allow: Bash(*)`, `bypassPermissions`, `enableAllProjectMcpServers` with a project `.mcp.json`, API base-URL redirects; Codex `notify`/`danger-full-access`; a shipped `.git/config`, `config.worktree` and in-repo `commondir` config (local dirs/archives; UTF-8 BOM skipped like git; in-repo `include`/`includeIf` followed; a `commondir` outside the repo is high) with command keys — `core.fsmonitor`, `core.pager`/`editor`, `core.sshCommand`, `diff.external`, `filter.*.clean/smudge/process`, `diff.*.textconv`, `!` aliases, `!` credential helpers, outside `core.hooksPath` (high; well-known programs such as `less`, `code --wait`, `git-lfs` are INFO) — and executable non-sample `.git/hooks` (hostile content: high; hook-manager stubs: INFO; other: `WARN`); symlinked scripts run by hooks/tasks/agent hooks (escaping or dangling: high; in-repo: `WARN` and the target analysed); symlinked config paths, including symlinks recorded in the git index of a `core.symlinks=false` clone (escaping or dangling: high; in-repo: `WARN` and analysed at the link location). Config names match case-insensitively. Configs that strict JSON rejects but VS Code/devcontainers parse leniently (missing comma, trailing garbage) are scanned literal by literal and stay high when a dangerous command is present. Sourced env files (`source_env .envrc.local`, `. .env.defaults`) are content-checked. Benign auto-run entries are `INFO`; unparseable configs without dangerous literals, in-repo config symlinks, analyzer crashes and exhausted time budgets are `WARN` (scored 10). Fixed root locations (`.vscode/`, `.devcontainer*`, `.envrc`, agent dirs, `.git`) are analysed before globbed `*.code-workspace` files and nested configs. Each file gets a time slice (≤10 s), malformed workspaces get the costly tolerant re-parse only up to 20, and skipped files are reported first as `WARN "N files not analysed (budget)"`. HIGH records are flushed immediately and never capped (INFO is capped at 50 separately), so a padded repo cannot time or crowd a finding out |

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
| `--full-history` | Clone full git history and run gitleaks on all commits (URLs only: ignored with a warning for local directories) |
| `--check-updates` | Check Homebrew for outdated scanner dependencies |
| `-h, --help` | Show usage and options |

## Risk Score

Each check has a weight. The final score is the sum of triggered weights normalized to 0–100.

| Weight | Checks |
|---|---|
| 30 (high) | Remote code execution, lifecycle script abuse, verified secrets, insecure MCP & agent tools, Python .pth & unsafe serialization, auto-execution on open |
| 20 (medium) | Secrets in code (gitleaks), YARA malware patterns, suspicious exfil endpoints, network syscalls in binaries, committed .env files, dependency typosquatting |
| 10 (low) | Semgrep supply chain patterns, sensitive files & AI credentials; YARA when the only hit is the decode-then-exec proximity rule (low confidence); auto-execution `WARN` (unparseable execution config, analyzer crash or 120 s timeout — attacker-reachable, so never 0) |

`WARN` (for example, unparseable manifests that may hide entry points), `INFO` (benign auto-run entries worth knowing about before opening the repo) and `SKIPPED` results are shown in yellow and are not scored, except auto-execution `WARN`, which scores 10.

### Precision trade-offs
- Generic heuristics skip tests, docs/data files and minified bundles. High-precision YARA rules (credential theft, sensitive files, decode-and-exec, lifecycle hooks) still run on tests and minified bundles; they skip only docs/data files. Entry points are always scanned with no filter: package.json `main`/`bin`, lifecycle-script targets (one level of `npm run X`), pyproject scripts, `setup.py`, `conftest.py`, and one level of local `require()`/`import` from JS entry points. Deeper transitive imports into noise paths are only covered by the high-precision rules.
- Decode-then-exec is detected within a single expression or within 400 bytes. Splits further apart are missed.
- Auto-execution on open: only patterns that download, inline-evaluate, obfuscate or fetch unpinned packages (or run a disguised or downloading repo file) are high; `sh -c`/`cmd /c` wrappers alone are not (VS Code's own repo uses them in folderOpen tasks) — the wrapped command is analysed, after undoing trivial quote splits (`cu""rl`) and flagging variable-built command names (`${c}rl`). PowerShell is flagged only with `-Command`/`-EncodedCommand`/`iex`, not as a bare word (PowerShell's own devcontainers). `task.allowAutomaticTasks` is INFO because VS Code ignores it at workspace scope; a hash-pinned `source_url` (nix-direnv) is INFO. Config files are analysed everywhere (including `.devcontainer/test/`); nested `test`/`fixtures`/`examples` trees and `.github/` are skipped only for generic `git config core.hooksPath` instruction scanning. YAML hook configs are parsed line by line (no PyYAML dependency). Remote targets are cloned with `core.symlinks=false`; symlinks are then taken from the git index (`git ls-files -s`, mode 120000) and resolved textually inside the clone. No git command ever runs against a local target (its `.git/config` could run `core.fsmonitor`, pagers or diff drivers): local symlinks are read with `lstat`, gitleaks uses `--no-git` there, semgrep runs with `--no-git-ignore`, and the index listing of our own clone runs with hardened `-c` overrides and no system/global config. The analyzer has an internal time budget (timeout − 30 s) inside a hard `timeout`/`gtimeout` of 120 s (`REPO_SCANNER_AUTOEXEC_TIMEOUT`).
- Every `python3` call runs isolated (`-I -B`): a `json.py`/`re.py` committed in a target scanned in place (`cd target && repo-scanner.sh .`) is never imported.
- Repo-derived strings are stripped of control characters and Markdown-escaped before they reach the terminal or the saved report.

## Project Structure

```
repoMalScanner/
├── repo-scanner.sh     # Main scanner script
├── yara-rules.yar      # YARA rules for malware detection
├── checks/autoexec/    # Auto-execution-on-open analyzer (python3 package)
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
