# Review (Round 4 tree): fp_reduction_and_precision_tuning

**Verdict: APPROVED**

I reviewed the current working tree (`repo-scanner.sh`/`yara-rules.yar` mtime 17:41:33, `tests/test_scanner.sh` mtime 17:42:04). The tree was stable for more than 3 minutes before and during verification. Both round-2 blockers are fixed. There are no detection regressions vs HEAD across 41 fixtures, and the precision goal holds (omlx 0/100). The remaining items are non-blocking follow-ups.

## Verification performed
- **Test suite:** `bash tests/test_scanner.sh` exits 0, "All tests passed successfully!" (23 checkmarks, Tests 1-23, 105 s).
- **No `| grep -q` remains:** `grep -nE '\| *grep -q' repo-scanner.sh` returns nothing.
- **Differential fixtures:** 41 in total, run on the new tree and compared against HEAD (`git show HEAD:`). All were created under `tmp/rev3/` and deleted afterwards.
  - 18 from round 1.
  - 14 adversarial/precision fixtures from round 2.
  - 4 stress fixtures.
  - 5 new: setup.py data-file exec, joblib/ctypeslib pickles, test-dir stealer, test-dir path data.
- **Precision and performance on real repos:**

| Repo | HEAD | New | Time HEAD / New |
|---|---|---|---|
| jundot/omlx | 31/100 | **0/100**, all CLEAN | 9 s / 10 s |
| paramiko | 3/100 | 6/100 (see F1) | 78 s / 78 s |
| psf/requests | 10/100 | 10/100 (`.netrc`, legitimate) | 5 s / 6 s |

No slowdown worth noting.

## Round-2 blockers
| # | Status | Evidence |
|---|---|---|
| B1 setup.py `exec(open(..).read())` FP | **FIXED** | `LOCAL_READ_ARG` / `dynamic_exec()` in the setup.py heredoc. The version-idiom fixture is CLEAN. `exec(urlopen(..).read())` and `exec(open(x).read() + __import__('base64')...)` are still FOUND. The cmake `build_ext` fixture stays CLEAN. A clean fixture was added to the suite. |
| B2 pipefail + `grep -q` SIGPIPE | **FIXED** | `count_matches_excluding` and `grep -c`/`-cvE` everywhere. All three stress fixtures are now FOUND, and all three were CLEAN in round 2: 3000-line `curl\|sh` (RCE), 20000-line `id_rsa` (SENS, which HEAD also missed), and `connect` followed by 20000 strings in a `.so` (BINSYSC, which HEAD also missed). Test 19 covers them. |

## Round-2 warnings and notes
- **W1 `_posixsubprocess` pickle:** FIXED. Any module path containing `subprocess` is flagged as dangerous.
- **W2 high-precision YARA on tests/:** the Leader's decision re-enabled scanning tests/ and narrowed `SensitiveFileAccess $a` to read/home context instead. A test-dir stealer (`tests/helper.py` reading `~/.ssh/id_rsa`) is FOUND. Plain path data (`"tests/configs/.ssh/id_rsa"`) is CLEAN. paramiko still scores 6/100 (see F1). This is an accepted trade-off, not a blocker.
- **N1 400-byte window:** documented in the README.
- **N2 `echo ..; curl\|sh` in YARA:** FIXED (YARA and RCE both FOUND).
- **N3 `npm run X`:** FIXED (Lifecycle FOUND on the `npm run setup` → `lib/s.min.js` fixture).
- **N4 path-predicate forks:** FIXED (rel computed inline).

## Differential summary (current tree vs HEAD)
- **Everything HEAD detected is still detected,** except the `dist/index.min.js` RCE line. That one is a documented trade-off, and YARA still flags the file.
- **Newly detected (HEAD missed):** typosquats (pyproject, Pipfile), conftest.py, `curl|sudo bash`, postinstall target stealer, `dict(os.environ)` exfil, `exec(bytes.fromhex)`, 70 MB padded pickle, `tests/x.js` and `test/index.js` reached via postinstall/main, `Path.home()/".ssh"` enumeration, all 3 stress fixtures.
- **Precision:**
  - The setup.py version idiom and the cmake `build_ext` are CLEAN, where HEAD flagged them.
  - `{...process.env}` spawn and comment/echo-only install hints are CLEAN, where HEAD flagged them.
  - Benign pickles stay CLEAN: OrderedDict, datetime/decimal/set, random bytes in `.bin`.
- Round-3/4 additions are exercised by Tests 16-23 and pass: fail-open manifests, Markdown/ANSI escaping in the report, FIFO skip, `-`-prefixed URL rejection, NUL-separated entry records.

## Blockers
None.

## Follow-ups (non-blocking, suggested for a later task)
1. **F1, NOTE: `SensitiveFileAccess $a` context includes a bare `~`** (`yara-rules.yar:32`).
   - `~/.ssh/id_rsa` is the most common way to write the path, so the context requirement barely narrows anything.
   - paramiko's tests, config fixture and comments still trigger YARA (weight 20, not high severity).
   - Consider requiring a read verb (open/readFile/expanduser/cat) and dropping bare `~` and `$HOME`.
2. **F2, NOTE: pickle gadgets inside third-party roots are rated only "suspicious"** (weight 10, not high severity).
   - `joblib.load` (a nested-pickle load; HEAD also missed it) and `numpy.ctypeslib.load_library` (native library load) both come out as `FOUND (1 payloads, suspicious only)`.
   - Suggestion: treat names matching `load|load_library|read_pickle|loads|open|system|exec|eval` in any non-torch module as dangerous, or add explicit deny entries.
3. **F3, NOTE: setup.py `exec(open("data/strings.txt").read())` is a full bypass** (`LOCAL_READ_ARG`).
   - The executed payload sits in a `.txt` file, which is a data path and is skipped by every check. HEAD also missed it, so this is not a regression.
   - Suggestion: allow the local-read exemption only when the opened path ends in `.py` or matches `version|__about__|_version`.
4. **F4, NOTE: the decode/exec split window is 400 bytes.** Padding beyond it evades `RuntimeObfuscationSplit`. This is an accepted, documented trade-off.
5. **F5, NOTE: housekeeping.**
   - `repo-scanner.sh` is about 1600 lines with embedded Python heredocs, well past the `docs/conventions.md` 300-line guideline. A `lib/` extraction refactor is worth a dedicated task.
   - `.README.md.swp` is untracked in the repo root.

## Checkpoints
| C | Result | Notes |
|---|---|---|
| C1 Harness integrity | PASS | |
| C2 State coherence | PASS | One active `[/]` task (`TASKS.md:25`). |
| C3 Architecture | PASS | No bare `except:`, no bash `eval`, no new dependencies. File size is a follow-up (F5). |
| C4 Tests | PASS | 23 tests, with per-check FOUND assertions, clean fixtures and stress fixtures. |
| C5 Security | PASS | SIGPIPE evasion closed. Report output escaped. Symlink, FIFO and option-injection guards are tested. |
| C6 Clean closure | PENDING (Leader) | Review fixtures deleted. `tmp/audit_r4`, `tmp/scan-*` and `tmp/test-fixture-*` belong to other agents or runs and were left untouched. |
