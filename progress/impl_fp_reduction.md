# Implementer Report — fp_reduction_and_precision_tuning

## Sprint contract
- Done = `bash tests/test_scanner.sh` exits 0 with new FP regression + detection fixtures, and
  `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive --save` scores 0/100.
- Files: `yara-rules.yar`, `repo-scanner.sh`, `tests/test_scanner.sh`, `README.md`.

## Root causes found on jundot/omlx (31/100 → 0/100)
| Check | FP trigger | Fix |
|---|---|---|
| YARA RuntimeObfuscation | `base64.b64decode` + unrelated `subprocess` anywhere in file | Rule now requires decode→exec in one expression (`exec(...b64decode`) |
| YARA CredentialHarvesting | `localStorage.getItem('…token')`, `SecItemCopyMatching` (app's own storage) | Dropped; added stealer indicators (Chrome Safe Storage, Login Data, key4.db, dump-keychain, keytar.findCredentials, cookie+network sink) |
| YARA SupplyChainHook | `"prepare"` + `exec(` anywhere in highlight.min.js | Exec pattern must be inside the lifecycle script JSON value |
| YARA (all) | `.txt` corpora, `.jsonl` eval data, `*.min.js`/`*.umd.js` | Shared `is_noise_path` filter (DataExfiltration still scanned everywhere) |
| SENS | `~/.ssh/omlx_cluster`, `~/.codex/config.toml`, `os.environ["HF_…"]`, `OMLX_*_TOKEN` | Only credential material: private keys, credential/token stores, bulk env dumps; `.pub` ignored; new hardcoded-key `authorized_keys` backdoor detection |
| RCE | `exec(` / `eval(` with `.*` greedy match in katex.min.js and calibration JSON | Payload must be the call argument; code extensions only; noise filter; comment/echo lines ignored in `.sh` |
| Lifecycle | setup.py `cmdclass` + `sys.executable` (matched `exec`) | Flag only install-time network/dynamic exec (urlopen, requests, socket, curl, os.system, word-bounded exec/eval, b64decode) |

## Other precision fixes (same FP class, not hit by omlx)
- Binary syscalls: exact symbol lines only (no `send`/`recv` substrings).
- Typosquatting: real dependency parsing (requirements.txt, pyproject via tomllib, setup.py install_requires); skip <5 chars and scoped npm; small legit-neighbor allowlist (preact, color, scapy…); OSA distance so transpositions (`lodahs`) are caught.
- MCP: npx/uvx flagged only without a version pin; `\bnc\b` (no `rsync` match).
- Pickle: static `pickletools.genops` walk of GLOBAL/STACK_GLOBAL/INST, incl. `*.pkl` inside torch zip checkpoints; never unpickles.
- `t.me/` must not be preceded by a hostname char (YARA + grep).
- Grep excludes `node_modules`, `.git`, `.venv`, `venv`, `site-packages`.
- Security: package.json path now passed to python via argv (was interpolated into code → injection with crafted filenames).

## Verification
- `bash tests/test_scanner.sh` → "All tests passed successfully!" (Tests 1–6; new Test 5 YARA precision, Test 6 MCP pinning).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive --save` → all 13 checks CLEAN, Risk score 0/100 (`out/omlx-security-report.md`).
- grep in use by bash: BSD grep 2.6.0-FreeBSD; `\b`/`\s` verified working.

## Trade-offs (for Reviewer)
- Noise filter skips minified bundles, data JSON and test dirs for heuristic checks — malware hidden there is only caught by exfil-domain, gitleaks, trufflehog and semgrep checks.
- `authorized_keys` writes without a hardcoded key (legit cluster pairing, as in omlx) are no longer flagged.
- Pre-existing untracked scratch files `tmp/test-*.yar` left untouched (not created by this task).

---

## Round 2: Security Reviewer and Code Reviewer findings

Sources: `progress/security_fp_reduction.md` (ISSUES_FOUND) and `progress/review_fp_reduction.md` (CHANGES_REQUESTED, items 1-8 and 10, plus the cheap parts of item 9).

### Security fixes
| Finding | Fix |
|---|---|
| CRITICAL `eval` of repo filenames in `run_grep` | `printf -v` assignments. Report reads use `${!var}`, so the script has no `eval` left. The clone prefix is stripped with bash parameter expansion (`strip_clone_prefix`) instead of `sed "s\|$CLONE_DIR\|"`. |
| HIGH symlinks / unbounded reads | `git clone -c core.symlinks=false`, `yara -N`, and `find -type f` for package.json and setup.py. Every `os.walk` loop skips `islink` and non-`isfile` entries. Every read is capped (1-2 MB for text, 64 MB for pickle prefixes). BSD `grep -r` was verified not to follow symlinks. |
| MEDIUM pickle | Always analyses the first 64 MB instead of skipping large files. Simulated stack plus memo (PUT/BINPUT/LONG_BINPUT/MEMOIZE to GET) resolves STACK_GLOBAL. Loops over up to 16 concatenated pickles. Wider denylist: importlib, marshal, ctypes, shutil, webbrowser, runpy, sys, multiprocessing, urllib/requests/http; `pickle.loads`, `types.FunctionType/CodeType`, `operator.attrgetter/methodcaller`, `functools.reduce`, builtins `getattr/open/...`. |
| MEDIUM zip | At most 256 pickle members and 256 MB decompressed per archive. Members with a compression ratio above 100x are read only up to a 1 MB prefix, so padding cannot hide a payload and bombs stay bounded. |
| MEDIUM noise evasion | The README match is now anchored to a basename `/README$`; doc extensions already cover README.md. Filtering is split into data paths (docs/data/non-manifest JSON/vendored trees), which every check skips, and generic noise (tests, `*.min.js`), which only the generic heuristics skip. The high-precision YARA rules (CredentialHarvesting, SensitiveFileAccess, SupplyChainHook, RuntimeObfuscation) now run on minified files. **Entry-point resolver**: package.json `main`/`bin`, lifecycle targets (`node X`, `python X`, `sh X`, `./X`), pyproject `[project.scripts]`/gui-scripts/poetry scripts, setup.py and conftest.py are never treated as noise and are also grepped directly. Lifecycle targets are checked against YARA plus the RCE/SENS patterns. |
| MEDIUM split decode/exec | New `RuntimeObfuscationSplit` YARA rule: a decoder call followed by `exec/eval/Function(` within 400 bytes. It is generic, so noise-filtered. If it is the only YARA hit, the result is "low confidence" and the check scores weight 10 instead of 20. On omlx (`b64decode` plus `subprocess`) it does not fire. |
| LOW coverage | Re-added `.netrc` (SENS and YARA) and `keytar.getPassword`; neither matches on omlx. Added `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json` (tilde/`$HOME` form and `homedir()/Path.home()` form) and the `".aws", "credentials"` split join. An `authorized_keys` write with a network fetch within 400 bytes is flagged (omlx's fetches are more than 400 bytes away). |
| LOW argv | gitleaks, semgrep and trufflehog parsers now receive paths through argv or a quoted heredoc. |

### Code Reviewer items
1. Split decode/exec via the proximity rule above. Added the decoders `fromhex`, `b32decode`, `b85decode` and `a85decode` (YARA and RCE). The RCE payload class now allows digits, so `exec(base64.b64decode(...))` matches. That case was a silent miss before.
2. `~/.ssh` enumeration (listdir/glob/iterdir/readdir within 80 chars of `.ssh`), `.netrc` and the credential files listed above.
3. setup.py now uses an AST/regex check. It flags network access or dynamic exec (`__import__`, `powershell`, `os.popen` added). It flags subprocess calls whose arguments launch an interpreter or downloader (powershell, pwsh, cmd, sh/bash, `-c`, iwr, certutil, mshta, curl, wget). It flags subprocess calls inside install/develop/egg_info command classes unless they run cmake, ninja, pip, make or meson.
4. Pickle memo handling, padding and denylist (see above).
5. The shell RCE check now ignores only comment lines and lines that are exactly `echo`/`printf` plus one quoted string. `echo ...; curl | sh` is flagged.
6. Minified files are covered by the high-precision rules. `.vscode/tasks.json`, `.devcontainer/devcontainer.json` and `.devcontainer.json` are exempt from the JSON noise rule. `*.code-workspace` was never noise. The autoexec check itself is left to task `autoexec_on_open`.
7. Added dedicated fixture repos with per-check FOUND assertions and exact counts (Tests 7-15). Test 5 now filters out only `.jsonl`, so minified and JSON fixtures are proven clean against the raw rules.
8. Env dumps: `...process.env`, `Object.entries/keys/values(process.env)`, `JSON.stringify(...process.env`, `dict/str(os.environ)`, `os.environ.copy()` and `environ.items()` count only within 400 bytes of a network sink. Spawning a child with `{...process.env}` stays clean, and a clean fixture checks this.
9. Added `curl|sudo bash`, `| python` reading stdin (`| python3 -m json.tool` stays clean), `bash <(curl)`, `sh -c "$(curl)"`, conftest.py as an entry point, Pipfile parsing, and the `WinHttpOpen/WinHttpConnect`, `InternetOpen[AW]`, `HttpSendRequest*` symbols. Go static binaries are skipped, as instructed.
10. No bare `except:` remains; handlers catch specific exceptions and log to stderr. `add_sens_hit` deduplicates with newline-delimited entries. The `install_requires` regex tolerates extras (`requests[socks]`).

Also fixed: YARA `$sh_dl1/2` matched `curl ... | bash` inside comments or echo hints after a shebang (a clean fixture exposed this). The download must now start a command line.

Bug found during the work: under `set -e`, a no-match `grep | filter_noise | head` inside `<( { ...; ...; } )` aborted the process substitution before the entry-point grep ran. Fixed with `|| true`.

### Skipped (documented)
- `.kube/config`: kubeconfig loading is normal behaviour for any Kubernetes client, so it would be a high-FP signal. Not added.
- `~/.cursor/` credential files: Cursor tokens live in `state.vscdb`, which is already covered.
- Reporting noise-path hits as weight-0 INFO (security option 4): not done. Entry-point resolution plus high-precision rules on minified files close the concrete evasion.
- gitleaks, semgrep and trufflehog on local symlinked dirs: these are external tools. With `/dev/zero` symlinks each finished in 3 s or less (measured), and remote clones are made with `core.symlinks=false`.
- `docs/conventions.md` 300-line limit: `repo-scanner.sh` was already about 900 lines and the embedded-heredoc pattern was kept. Extracting the Python helpers to `lib/` is a candidate refactor task.

### Files modified (round 2)
`repo-scanner.sh`, `yara-rules.yar`, `tests/test_scanner.sh`, `README.md`.

### Verification
- `bash tests/test_scanner.sh` exits 0 with "All tests passed successfully!" (15 checkmarks; Tests 1-15).
  - Test 7: `x$(touch PWNED).js` and `` y`touch PWNED2`.js `` are not executed and are reported as exfil hits (2 files). As a control, the HEAD scanner on the same fixture did create `PWNED`.
  - Test 8: 7 `/dev/zero` symlinks plus a symlink to a host `.pth`. Run under `timeout 300`, the scan completes and PTH stays CLEAN.
  - Test 9: postinstall runs `node scripts/setup.min.js` (Chrome Safe Storage stealer). Lifecycle and YARA are both FOUND.
  - Test 10: two-step `b64decode` then `exec` gives YARA FOUND (low confidence). `dist/index.min.js` with `eval(atob())` gives YARA FOUND.
  - Test 11: memo-indirection, 70 MB padded, concatenated legacy, compressed zip and importlib pickles give FOUND (5 payloads); a benign pickle stays clean.
  - Tests 12-15: credential access (8 files), RCE variants (7 files), setup.py hooks (2 files) plus a bin entry point in `test/`, typosquats in Pipfile and in extras-style requirements (2), and WinHTTP imports.
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive --save`: all 13 checks CLEAN, **Risk score 0/100** (`out/omlx-security-report.md`). Raw `yara -N -r` on the omlx clone returns no matches at all.
- Temp files cleaned (`/tmp/omlx-ref`, fixtures). Pre-existing untracked `tmp/test-*.yar` and an editor swap file `.README.md.swp` were not created by this task and were left alone.

---

## Round 3: Security Reviewer (round 2 audit) and Code Reviewer (round 2 review)

### Security findings
| Finding | Fix |
|---|---|
| HIGH F1: a malformed pyproject.toml aborts entry-point resolution | **Fail-open per source.** Each manifest is parsed inside its own `except Exception` handler, which logs the error and continues. Every TOML/JSON access is guarded with `as_dict`/`isinstance`. Unparseable manifests emit `error` records. If Lifecycle would otherwise be CLEAN, it becomes `WARN (N manifests unparsed)`, which is yellow and unscored. |
| HIGH F2: pickle bypasses | (a/c/d) Prefix reads are gone. `genops` streams from a `SkippingReader` that seeks over opcode arguments larger than 1 MB (`Skipped` bytes stand-in), bounds lines to 1 MB, and counts decompressed bytes against a 256 MB per-archive budget. There is a 5M-opcode cap. (b) Order is zip, then pickle magic (`\x80` plus protocol 2-5, or a protocol-0 opcode in a pickle-named file), then `.pth` text hook. (e) DUP is modelled explicitly. An unresolvable STACK_GLOBAL is a finding. (f) Switched to an **allowlist**: torch, numpy, collections, `_codecs`, copyreg, sklearn, scipy, pandas, transformers, omegaconf, mlx and others, plus the repo's own top-level packages. Safe builtins (set, slice, ...) are allowed. A deny-prefix list applies inside allowed roots: `torch.hub/load/jit`, `numpy.testing/load`, `pandas.eval/read_`, `functools.reduce`, `operator.attrgetter`, and so on. Any module path containing `subprocess` is denied. Every other import is flagged ("dangerous" for known gadget roots such as timeit, cProfile, pydoc, `_io`, os and importlib; otherwise "non-allowlisted"). **Fail closed:** truncated or unparseable `.pkl` files, and magic-prefixed pickle-named files, are reported, and so are budget overruns. Trailing raw bytes after a complete stream (legacy torch storages) are ignored. Imports in a stream after the first, or in an unmagicked file, count only once that stream reaches STOP, so random binary data does not produce false hits. |
| HIGH F3: Markdown image beacon in the saved report | `md_escape` turns `&`, `<` and `>` into entities and backslash-escapes ``[]()!|`*_~#{}\``. It is applied to table cells, REPO_NAME/URL and the detail sections. Detail sections are now 4-space indented code blocks of escaped text, so a fence cannot be closed. |
| MEDIUM F4: ANSI/OSC injection | `sanitize_text` (`LC_ALL=C tr -d` for C0 controls except `\n` and `\t`, plus DEL, and `sed` for UTF-8 C1 `\xc2[\x80-\x9f]`) is applied to every DETAIL before console or report output. |
| MEDIUM F5: scan abort | TYPO, MCP and PTH substitutions use `|| X_ERR=true`, which yields `SKIPPED (error)`. Each per-file handler uses `except Exception`. A non-dict `dependencies` field is guarded. A corrupt deflate stream is reported as unanalysed. |
| MEDIUM F6: FIFO hang | `-D skip` on every grep (the GREP_EXCLUDES base and `grep_entry_points`). |
| MEDIUM F7: noise trade-off | One level of local `require()`/`import()`/`from "./x"` is resolved from JS entry points (`.js/.cjs/.mjs/.ts`, `index.js`), and so is `npm/pnpm/yarn run X`. Deeper chains are documented in the README "Precision trade-offs". |
| LOW: TSV injection | Records are NUL-separated, and targets or rels containing `\t\n\r\0` or a leading `..` are rejected. In bash, `realpath` must fall under `pwd -P` of the clone, and the target must be a regular file that is not a symlink. |
| LOW: option injection | URLs starting with `-` are rejected, and `git clone ... -- "$REPO_URL"` is used. |
| LOW: .gitignore | Added `*.db` and `*.sqlite*`. |

### Code Reviewer items
- **B1:** the setup.py exec/eval check now ignores a local-read argument: `exec(open(..).read())`, `exec(fp.read(), about)`, `.read_text()` and `compile(open(..`. `b64decode` alone is no longer flagged. Network access (urlopen/requests/curl/socket/powershell/`__import__`) is still flagged. The clean fixture now has both version idioms.
- **B2:** no `| grep -q` remains. SENS uses `count_matches_excluding` (`grep -c`), the RCE hint filter uses `grep -cvE`, the binary check uses `strings | grep -cE`, and the YARA low-confidence and brew checks use `grep -c`. A stress fixture is added (3000-line `curl|sh`, 20000-line `id_rsa`, `connect` followed by 20000 strings).
- **W1:** `_posixsubprocess` is caught (any `subprocess` in the module path, plus the allowlist).
- **W2:** high-precision YARA rules skip test dirs unless the file is an entry point. `is_precision_skip` sits between `is_data_path` and `is_noise_path`. The clean fixture `tests/test_client.py` holds `.ssh/id_rsa` test data.
- **N1:** the 400-byte window is documented in the README.
- **N2:** `$sh_dl1/2` accept `;` and `&&` before curl/wget.
- **N3:** `npm run X` is resolved one level.
- **N4:** the path predicates compute rel inline and no longer fork `$(rel_path)`.

### Tests added (16-21) and changed
- 16: malformed pyproject, truncated package.json and `"dependencies": 5` next to a postinstall `setup.min.js`. Lifecycle and RCE are FOUND and Typosquat completes. A repo with only a broken package.json gives `WARN (1 manifests unparsed)`.
- 17: 9 payloads: zip with a 2 MB BINBYTES8 prefix, `model.pth` torch zip, 65 MB BINBYTES8, legacy with a 65 MB second stream, DUP/POP, timeit, `_posixsubprocess`, corrupt deflate, `.pth` hook. The benign repo (OrderedDict, own-package class, legacy plus raw storage bytes) is CLEAN.
- 18: MCP name `![b](https://attacker..)` with `<img>` and a backtick, and a filename with `\e[2K\e[1A..\e[8m`. The console contains no injected escapes, and the saved report has no `![`, `](http`, `<img` or ESC.
- 19: SIGPIPE stress for RCE, SENS and BINSYSC.
- 20: FIFO under `timeout 120`, TSV record injection, and a `--repo "--upload-pack=..."` rejection.
- 21: `npm run setup` to `lib/s.min.js` stealer gives Lifecycle FOUND. `main` requiring `vendor/jquery.min.js` with `execSync(curl|sh)` gives RCE FOUND.
- Clean-repo changes: setup.py version-exec idioms and `tests/test_client.py`. Test 5's raw-rule clean filter now also excludes `/tests/`.

### Verification
- `bash tests/test_scanner.sh` exits 0 with "All tests passed successfully!" (Tests 1-21).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive --save`: all 13 CLEAN, **Risk score 0/100**, about 16 s.
- Temp fixtures cleaned. Pre-existing `tmp/test-*.yar` and `.README.md.swp` were left untouched.

### Residual notes
- Non-allowlisted pickle imports score at full PTHSERIAL weight (30). ML repos that ship pickles of third-party classes outside the allowlist will be flagged; extend `SAFE_ROOTS` as needed.
- External tools (gitleaks, semgrep, trufflehog) on local dirs with FIFOs or `/dev/zero` symlinks: measured, no hang.

---

## Round 4: Security re-audit (round 3) and Leader decision

### HIGH 1: pickle allowlist bypasses (uuid, pathlib.write_text, pkgutil shadowing, no-STOP streams)
- **Switched to a per-name allowlist, as the Leader decided (picklescan/fickling style).** `torch.*` is trusted as a whole, except the `DENY_PREFIXES` (hub, load, jit, cpp_extension, package, ops, datapipes). Everything else must appear in `SAFE_GLOBALS` by exact `module.name`:
  - numpy: `_reconstruct`, `scalar`, `dtype`, `ndarray`, `_frombuffer`, random ctors, plus scalar types via regex.
  - stdlib: `collections.OrderedDict`/`defaultdict`/`deque`/`Counter`, `_codecs.encode`, `copyreg._reconstructor`, datetime constructors, `uuid.UUID`, `pathlib.*Path` (class only), `argparse.Namespace`, `functools.partial`, `types.SimpleNamespace`, `array`, `re._compile`.
  - builtins: `set`, `frozenset`, `slice`, `complex`, `bytearray`, and the like.
  - Qualified names such as `PosixPath.write_text` are therefore not allowlisted.
- Severity:
  - **dangerous** (high): known gadget roots, any `subprocess` module, non-allowlisted builtins, any other **stdlib** name (`sys.stdlib_module_names`, which covers uuid, pkgutil, pathlib methods, timeit and so on), `__main__`, and any stdlib or gadget module shadowed by a repo top-level file.
  - **suspicious**: unknown third-party names. When every hit is suspicious, the result is `FOUND (n payloads, suspicious only)` with weight 10 and no high severity.
- `LOCAL_ROOTS` (the repo's own classes) excludes stdlib names, gadget roots, torch and numpy. Private (`_x`) and risky names in local modules are not allowed.
- **Streams with no STOP:** a dangerous import is reported the moment it is yielded, in any stream and with or without trust, because load runs REDUCE before the later parse error. Suspicious and unresolved STACK_GLOBAL findings are deferred to stream completion, except in a trusted first stream (keeps random-bytes FPs down).

### HIGH 2: round-3 regression where high-precision YARA rules skipped tests/
- `is_precision_skip` is now `is_data_path` only, so high-precision rules run on tests/ and on minified bundles again. Only the generic heuristics skip tests/ (`is_noise_path`).
- The paramiko-style FP is now handled by the rule instead of a path skip. `SensitiveFileAccess $a` requires a home or read context within 80 chars of `.ssh/id_*` (open/readFile/read_text/expanduser/homedir()/Path.home()/`$HOME`/`~`/`cat`). The clean fixture `tests/test_client.py` (`"tests/configs/.ssh/id_rsa"`) stays clean against the raw rules, and Test 5 no longer excludes `/tests/`.
- README trade-off sentence corrected.

### Tests
- **Test 22:** five payloads detected (uuid `_get_command_stdout`, `pathlib.PosixPath.write_text`, repo `pkgutil.py` plus `pkgutil.resolve_name`, a protocol-0 `.joblib` with no STOP, a legacy `.pt` whose second stream has no STOP). A sklearn class gives `FOUND (1 payloads, suspicious only)` and the scanner still exits 0. Benign torch `_rebuild_tensor_v2`/`FloatStorage`, numpy `_reconstruct`/`ndarray`/`dtype` and `OrderedDict` stay CLEAN.
- **Test 23:** a Chrome Safe Storage stealer in `tests/util.py`, imported by `pkg/__init__.py`, gives YARA FOUND.

### Verification
- `bash tests/test_scanner.sh` exits 0 with "All tests passed successfully!" (Tests 1-23).
- `./repo-scanner.sh --repo https://github.com/jundot/omlx --no-interactive --save` gives **Risk score 0/100**, all CLEAN.

### Not done (non-blocking follow-ups from the audit)
- Python transitive-import resolution, bidi-override stripping, and wrapping report values in inline code were not done. The high-precision rules on tests/ cover the concrete PoC.
- The Code Reviewer's round-3 verdict had not been received when this round was finished.
