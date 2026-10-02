# Security Audit Report (Round 4, re-test 3): fp_reduction_and_precision_tuning

## Verdict: SECURE

## Re-test 3 (after the dotted-name fix in `classify()`)
Method: static unit test of the extracted `classify()` (no unpickling) plus `bash tests/test_scanner.sh` (exit 0, 23 checks, Test 22 now expects 8 payloads including fixtures g and h).

| Probe | Result |
|---|---|
| The 4 dotted `...subprocess.Popen` chains from `torch.nn.modules.module` (`cuda._memory_viz`, `_strobelight.cli_function_profiler`, `_strobelight.compile_time_profiler`, `utils.collect_env`) | dangerous |
| Local `mypkg` + `os.system` | dangerous |
| GLOBAL/INST protocol-0 forms with a dotted func | Covered. `classify()` does not depend on the opcode, so a dotted func is dangerous for every opcode |
| Unicode lookalike (`Ｆoo.Bar`, fullwidth F) and whitespace (`"torch.nn.modules.module "`, `"Lin ear"`) | dangerous |
| `collect_env.run`, `multiprocessing.spawn`, `serialization.save` | dangerous (unchanged) |

No CRITICAL/HIGH issue remains. All earlier PoCs (1)-(7) were re-verified in re-test 1 (below) and are unaffected by this change.

### Follow-ups (non-blocking)
- LOW: `TORCH_SAFE.match` with `$` accepts a trailing newline (`"Linear\n"` is allowlisted). It cannot be exploited, because `getattr` fails at load, but use `re.fullmatch` or `\Z`.
- LOW: the nn.modules branch allows any CapWords attribute of a `torch.nn.modules.*` module, including names re-exported from other modules (e.g. `module.Callable`), not only `nn.Module` subclasses. It would be safer to list the real module classes, or to check them against `torch.nn.modules.__all__`.
- MEDIUM (design): the local-package trust allows CapWords names and nested CapWords chains (`mypkg.Runner`, `mypkg.Foo.Popen`). If the repo aliases a gadget (`from subprocess import Popen as Runner`), the pickle is allowlisted. Impact is limited because unpickling already imports, and so executes, the attacker's package code. Still, consider resolving local names against the repo AST (only classes defined in the repo).
- Carried over: Python transitive-import resolution, bidi stripping, inline-code wrapping of report values, semgrep/trufflehog egress whitelist entries, typosquat dependency parsing.

---

## Re-test 2 (history)

- Fixed: `torch.utils.collect_env.run` (.pth), `torch.multiprocessing.spawn`, `torch.serialization.save`, `torch.<x>Storage`-named dotted tricks, `_rebuild_x.os.system`: all now `dangerous`.
- **NEW HIGH (blocker): dotted-qualname bypass of `TORCH_SAFE`.** The nn.modules branch `^torch\.nn\.modules\.[a-z_.]+\.[A-Z][A-Za-z0-9]*$` lets `[a-z_.]+` span dots, and the regex is matched against `mod + "." + func`. Pickle protocol 4 resolves dotted names in STACK_GLOBAL via attribute traversal (harmless check: `pathlib` + `os.getcwd` resolved and called on load). So `STACK_GLOBAL("torch.nn.modules.module", "torch.cuda._memory_viz.subprocess.Popen")` classifies as allowlisted and a static scan of that `model.pth` reports **CLEAN**. Introspection on torch 2.6 (attribute walk only, no unpickling) shows 4 reachable chains after plain `import torch`: `..._strobelight.cli_function_profiler.subprocess.Popen`, `..._strobelight.compile_time_profiler.subprocess.Popen`, `...cuda._memory_viz.subprocess.Popen`, `...utils.collect_env.subprocess.Popen`. `"subprocess" in mod` only inspects `mod`, not the dotted `func`.
- Remediation: reject any `func` containing `.` for torch (and ideally for every root: `classify` should treat a dotted `func` as dangerous unless the exact qualname is allowlisted); restrict the nn.modules branch to `torch\.nn\.modules\.[a-z_]+(\.[a-z_]+)?` with `mod` and `func` matched separately; apply the `subprocess` check to `full`. Add the dotted-Popen fixture to Test 22.
- Also check `LOCAL_ROOTS`: a dotted `func` on a repo package (e.g. `pkg` + `os.system`) passes the `RISKY_NAMES` check because `"os.system" != "system"`. Lower impact (the repo's own code is already imported), but it falls under the same fix.

---

## Earlier re-test (pre-fix, kept for history)

One HIGH, trivially-exploitable allowlist bypass blocks. Every other round-3/round-4
PoC was re-run against the current code and is correctly detected. PoCs were run in
`tmp/audit_r4` (deleted). Dangerous-pickle fixtures were only ever walked statically by
the scanner's `pickletools.genops` path (never unpickled); `pickle.load` was used only on
a harmless `os.system("touch ...")` payload in a throwaway subprocess to confirm the
REDUCE mechanism.

## BLOCKER

| Severity | Category | Location | Finding | Remediation |
|---|---|---|---|---|
| HIGH | Dynamic execution (H.pickle) / allowlist bypass | `repo-scanner.sh` check 13, `TRUSTED_ROOTS = {"torch"}` + `classify()` (lines ~1132, 1259-1272) | torch is trusted as a whole root (deny only `DENY_PREFIXES`). `classify("torch.utils.collect_env","run")` returns `None` (allowlisted). That function is a real shell-exec gadget: `subprocess.Popen(command, shell=True)` (torch/utils/collect_env.py `run()`). A `model.pth`/`.pkl` that REDUCEs `torch.utils.collect_env.run("<cmd>")` is reported **CLEAN**. Also allowlisted: `torch.multiprocessing.spawn`, `torch.serialization.save`, and any other `torch.*` callable not in the 7 deny prefixes. | Put torch on a per-name allowlist like every other package: permit only the `torch._utils._rebuild_*` family, `*Storage` classes, `torch.Size/device/dtype`, `OrderedDict`, etc.; flag every other `torch.*` import as dangerous/suspicious. This is the previous auditor's documented MEDIUM concern, now confirmed exploitable. |

### PoC (static scanner verdict + mechanism, no weaponized load)
- Crafted `model.pth` = pickle REDUCE of `torch.utils.collect_env.run("id")`. Scanner check 13 (static genops walk, never loads) → **no finding (CLEAN)**.
- Unit test of the extracted `classify()`: `torch.utils.collect_env.run -> None`, `torch.multiprocessing.spawn -> None`, `torch.serialization.save -> None`; contrast `torch.load/jit.load/hub.* / cpp_extension.load -> dangerous`.
- `collect_env.run` body confirmed to be `subprocess.Popen(command, shell=True)` in an installed torch 2.6.0.
- REDUCE-executes-on-load proven separately with a harmless `os.system("touch PICKLE_EXEC_PROOF")` pickle loaded in a subprocess (file was created). The torch gadget is the same mechanism, only allowlisted.

## Re-verified as FIXED (PoCs re-run this round)
| PoC | Result |
|---|---|
| (1) Filenames `x$(touch FN_PWNED).js`, `` y`touch FN_PWNED2`.js ``, `z$(id).js` across checks | Not executed; no `FN_PWNED*` created anywhere. Reported as exfil hits. |
| (2) Symlinks to `/dev/zero`, `/etc/passwd`, `~/.ssh/id_rsa`; FIFOs `pipe.js`/`pipe.pkl` | Scan completes in <120s, exit 0, no hang, no unbounded read, Risk 0. |
| (3) Zip with 5000 pickle members | Bounded by `MAX_ZIP_MEMBERS=256`; completes, CLEAN, no DoS. |
| (4) Pickle bypasses: `uuid._get_command_stdout`, `pathlib.PosixPath.write_text`, memo-indirection STACK_GLOBAL (`os.system`), no-STOP stream, 2 KB zip prefix member, local `pkgutil.py` shadow → `pkgutil.resolve_name` | All reported `dangerous pickle import`. Only the torch gadget slips (see BLOCKER). |
| (5) Stealer in `tests/util.py` imported by `pkg/__init__.py` | YARA FOUND (high-precision rules run on tests/). |
| (6) Malformed `pyproject.toml` + `postinstall: node scripts/setup.min.js` stealer | Scan does not crash; Lifecycle FOUND + YARA FOUND. |
| (7) Markdown/HTML/ANSI injection (`![pwn](...)`, `<img onerror>`, backticks, ESC in filename) into `--save` report | Neutralized: `\!\[`, `&lt;img&gt;`, escaped backticks, zero ESC bytes, no unescaped `](http`. |

## Follow-ups (non-blocking)
- Carried from prior rounds: Python transitive-import resolution; strip Unicode bidi overrides in `sanitize_text`; wrap report values in inline code; semgrep/trufflehog egress not on `docs/security.md` whitelist (predates task); typosquat real-dependency parsing; pickle `pickletools` static walk already in place.
- After torch is moved to per-name allowlisting, re-check `torch.multiprocessing.spawn`/`torch.serialization.*` do not remain reachable.

## Verification
- `bash tests/test_scanner.sh` → exit 0, "All tests passed successfully!" (Tests 1-23 era suite).
- All `tmp/audit_r4` fixtures deleted. Pre-existing `tmp/test-*.yar` scratch files left untouched (not this task's).

## Required to close
Move torch from whole-root trust (`TRUSTED_ROOTS`) to a per-name allowlist, or otherwise
deny `torch.utils.collect_env.run`, `torch.multiprocessing.spawn` and the rest of the
executable `torch.*` surface. Then re-run PoC (4)'s torch case to confirm it is FOUND.
