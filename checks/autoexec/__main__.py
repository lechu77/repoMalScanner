"""Auto-execution-on-open check: `python3 checks/autoexec <target_dir>`.

Prints one record per line: `P<TAB>detail` (pass-1 raw-text HIGH candidate,
flushed first; scored unless a later `X<TAB>same detail` retracts it after a full
strict verdict of that file), `H<TAB>detail` (high, scored, every one kept),
`I<TAB>detail` (benign auto-run, shown only, capped), `E<TAB>text` (analysis
warning: unparsed config, symlinked config/script, shipped git hook, budget).
"""
from __future__ import annotations

import os
import sys

# Explicit import root: only this package directory (the scanner runs python3 -I,
# so neither the cwd nor a repo directory is ever on sys.path)
sys.path[:] = [os.path.dirname(os.path.abspath(__file__))] + [
    p for p in sys.path if p not in ("", ".", os.getcwd())]

import signal  # noqa: E402
import time  # noqa: E402
from typing import Any, Callable, Iterable  # noqa: E402

from agents import handle_agent_settings, handle_codex  # noqa: E402
from core import HIGH, INFO, MAX_LIST, Finding, Repo, clean  # noqa: E402
from discovery import CONFIG_DIRS, CONFIG_FILES, Entry, discover  # noqa: E402
from editors import handle_devcontainer, handle_settings  # noqa: E402
from fallback import lenient_scan  # noqa: E402
from gitdir import handle_git_dir  # noqa: E402
from prescan import prescan_file, prescan_hook_dir  # noqa: E402
from vcs_hooks import (HOOK_CONFIGS, handle_envrc, handle_hook_config,  # noqa: E402
                       handle_instructions, handle_package_hooks, scan_hook_dir)
from vscode_tasks import handle_tasks, handle_workspace  # noqa: E402

INSTRUCTION_EXTS = (".md", ".txt", ".rst", ".adoc", ".sh", ".bash", ".zsh", ".ps1", ".mk",
                    ".json", ".yml", ".yaml", ".toml", ".py", ".js", ".cjs", ".mjs", ".ts")
INSTRUCTION_NAMES = {"makefile", "gnumakefile", "justfile", ".envrc", "rakefile", "dockerfile"}
INSTRUCTION_PREFIXES = ("readme", "contributing", "install", "setup", "bootstrap")
AGENT_CONFIGS = {(".claude", "settings.json"), (".claude", "settings.local.json"),
                 (".gemini", "settings.json"), (".cursor", "hooks.json")}
MAX_ERRORS = 10
DEFAULT_BUDGET = 90.0  # seconds; the scanner's hard timeout is larger
LENIENT_EXTS = (".json", ".code-workspace")
MAX_WORKSPACES = 200  # *.code-workspace files analysed (root first); the rest -> WARN
MAX_FALLBACKS = 20  # malformed configs given the costly tolerant re-parse (run last)
PRESCAN_SHARE = 0.5  # pass 1 may use at most this share of the budget
MAX_FILE_SECONDS = 10.0  # per-file slice so no single file can eat the budget

Handler = Callable[[], Iterable[Finding]]


def pick_handler(repo: Repo, entry: Entry, tolerant: bool = False) -> Handler | None:
    """Handler for a config file, chosen by (case-insensitive) name and parent directory.

    Names come from the location tools load (vpath); content from rpath. tolerant
    re-parses broken JSONC the way VS Code / devcontainers do.
    """
    path, src = entry.vpath, entry.rpath

    def load(where: str) -> dict[str, Any]:
        return repo.load_jsonc(where, tolerant)

    parent_dir = os.path.dirname(path)
    parent, fname = os.path.basename(parent_dir).lower(), os.path.basename(path).lower()
    above, rel = os.path.dirname(parent_dir), repo.rel(path)
    grand = os.path.basename(above).lower()
    if parent == ".vscode" and fname in ("tasks.json", "settings.json"):
        handler = handle_tasks if fname == "tasks.json" else handle_settings
        return lambda: handler(repo, load(src), above, rel)
    if fname.endswith(".code-workspace"):
        return lambda: handle_workspace(repo, load(src), parent_dir, rel)
    if fname == ".devcontainer.json":
        return lambda: handle_devcontainer(repo, load(src), parent_dir, rel)
    if fname == "devcontainer.json" and ".devcontainer" in (parent, grand):
        root = above if parent == ".devcontainer" else os.path.dirname(above)
        return lambda: handle_devcontainer(repo, load(src), root, rel)
    if fname == ".envrc":
        return lambda: handle_envrc(repo, repo.read_text(src), parent_dir, rel)
    if fname in HOOK_CONFIGS:
        return lambda: handle_hook_config(repo.read_text(src), rel)
    if (parent, fname) in AGENT_CONFIGS:
        return lambda: handle_agent_settings(repo, load(src), (above, parent_dir), rel)
    if parent == ".codex" and fname == "config.toml":
        return lambda: handle_codex(repo.read_text(src), rel)
    if fname == "package.json":
        return lambda: handle_package_hooks(load(src), rel)
    return None


def is_instruction(repo: Repo, entry: Entry) -> bool:
    """Files that may tell the user to run `git config core.hooksPath ...`.

    CI definitions under .github/ run on CI runners, and test/example trees are
    not instructions to the user.
    """
    if entry.in_test or repo.rel(entry.vpath).lower().startswith(".github" + os.sep):
        return False
    fname = os.path.basename(entry.vpath).lower()
    return fname.endswith(INSTRUCTION_EXTS) or fname in INSTRUCTION_NAMES \
        or fname.startswith(INSTRUCTION_PREFIXES)


class Output:
    """Prints HIGH records immediately (flushed) so a killed run keeps them."""

    def __init__(self, repo: Repo) -> None:
        self.repo = repo
        self.seen: set[str] = set()
        self.infos: list[str] = []
        self.errors: list[str] = []
        self.fallbacks = 0  # tolerant re-parses run (pass 2, last)
        self.skipped = 0  # files left unanalysed (budget)
        self.candidates: dict[str, list[str]] = {}  # pass-1 HIGH candidates per file

    def prescan(self, key: str, details: list[str]) -> None:
        """Pass-1 HIGH candidates: printed and flushed now (survive a kill)."""
        for detail in details:
            print(f"P\t{detail}", flush=True)
        if details:
            self.candidates.setdefault(key, []).extend(details)

    def retract(self, key: str) -> None:
        """Pass 2 reached a full strict verdict for key: its own findings replace pass 1."""
        for detail in self.candidates.pop(key, []):
            print(f"X\t{detail}", flush=True)

    def add(self, items: Iterable[Finding]) -> None:
        """Record findings: every HIGH printed now; INFO capped separately (MAX_LIST).

        Benign entries can never crowd out a HIGH (no shared cap).
        """
        for item in items:
            if item.detail in self.seen:
                continue
            if item.level == HIGH:
                self.seen.add(item.detail)
                print(f"{HIGH}\t{item.detail}", flush=True)
            elif len(self.infos) < MAX_LIST:
                self.seen.add(item.detail)
                self.infos.append(item.detail)
        self.warn(self.repo.warnings)
        self.repo.warnings.clear()

    def warn(self, msgs: Iterable[str]) -> None:
        """Analysis warnings (deduplicated)."""
        for msg in msgs:
            if msg not in self.errors:
                self.errors.append(msg)

    def finish(self) -> None:
        """Print INFO and unparsed/warning records."""
        for detail in self.infos:
            print(f"{INFO}\t{detail}")
        for msg in self.errors[:MAX_ERRORS]:
            print(f"E\t{clean(msg)}")


def priority(repo: Repo, entry: Entry) -> tuple[int, int]:
    """Analysis tier, then depth.

    0: fixed root locations tools load on open (.vscode/, .devcontainer*, .envrc,
       .claude/, .cursor/, .gemini/, .codex/, .mcp.json, hook configs);
    1: root *.code-workspace (glob-discovered, capped); 2: nested configs;
    3: nested *.code-workspace (shared cap). Root hook dirs run between 0 and 1.
    """
    parts = repo.rel(entry.vpath).lower().split(os.sep)
    workspace = parts[-1].endswith(".code-workspace")
    if len(parts) == 1 and workspace:
        return 1, 1
    if workspace:
        return 3, len(parts)
    fixed = len(parts) <= 3 and (parts[0] in CONFIG_DIRS or parts[0] in CONFIG_FILES)
    return (0 if fixed else 2), len(parts)


class FileTimeout(BaseException):
    """One file exceeded its time slice (BaseException: handlers catch Exception)."""


def _expire(_signum: int, _frame: Any) -> None:
    raise FileTimeout


def sliced(slice_seconds: float, func: Callable[[], None]) -> bool:
    """Run func with a per-file wall-clock slice; False when it was cut off."""
    if not hasattr(signal, "setitimer"):
        func()
        return True
    previous = signal.signal(signal.SIGALRM, _expire)
    signal.setitimer(signal.ITIMER_REAL, slice_seconds)
    try:
        func()
        return True
    except FileTimeout:
        return False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_handler(repo: Repo, entry: Entry, out: Output, deferred: list[Entry]) -> None:
    """Strict parse and verdict of one config; a malformed one is deferred (re-parsed last)."""
    handler = pick_handler(repo, entry)
    if not handler:
        return
    rel = repo.rel(entry.vpath)
    try:
        out.add(handler())
        out.retract(entry.vpath)
        return
    except Exception as exc:  # malformed config: tolerant re-parse later, reported as WARN
        print(f"autoexec parse error: {rel}: {exc}", file=sys.stderr)
    out.errors.append(f"{rel}: config could not be parsed strictly")
    name = os.path.basename(entry.vpath).lower()
    if name.endswith(LENIENT_EXTS) and name != "package.json":
        deferred.append(entry)  # npm and TOML readers reject broken files: nothing runs


def run_fallback(repo: Repo, entry: Entry, out: Output) -> None:
    """Costly tolerant re-parse of a malformed config (bounded count, always last)."""
    if out.fallbacks >= MAX_FALLBACKS:
        out.skipped += 1  # pass-1 candidates for this file stand
        return
    out.fallbacks += 1
    rel = repo.rel(entry.vpath)
    recovered = pick_handler(repo, entry, tolerant=True)
    try:
        out.add(recovered() if recovered else [])
        out.add(lenient_scan(repo, repo.read_text(entry.rpath), entry.vpath, rel))
    except Exception as exc:  # pathological input: the strict-parse WARN stands
        print(f"autoexec tolerant parse error: {rel}: {exc}", file=sys.stderr)


def prescan_all(repo: Repo, configs: list[Entry], hook_dirs: dict[str, str],
                deadline: float, out: Output) -> bool:
    """Pass 1 over every candidate config and hook dir; False if its budget ran out."""
    items: list[tuple[str, Any]] = [("config", e) for e in configs] \
        + [("hooks", p) for p in sorted(hook_dirs)]
    for kind, item in items:
        if time.monotonic() > deadline:
            return False
        try:
            if kind == "config":
                out.prescan(item.vpath, prescan_file(repo, item.vpath, item.rpath))
            else:
                out.prescan(item, prescan_hook_dir(repo, item, hook_dirs[item]))
        except (OSError, ValueError, RecursionError) as exc:
            print(f"autoexec prescan error: {exc}", file=sys.stderr)
    return True


def analyse(repo: Repo, budget: float, out: Output) -> None:
    """Run every handler within a time budget; one malformed config never stops the others."""
    deadline = time.monotonic() + budget
    try:  # shipped .git/config and .git/hooks (static parse, git never run)
        out.add(handle_git_dir(repo))
    except (OSError, ValueError) as exc:
        out.warn([".git: metadata could not be analysed"])
        print(f"autoexec git dir error: {exc}", file=sys.stderr)
    found = discover(repo)
    out.add(found.findings)
    out.warn(found.warnings)
    hook_dirs = dict(found.hook_dirs)
    configs = sorted((e for e in found.entries if pick_handler(repo, e)),
                     key=lambda e: priority(repo, e))
    tier = {e: priority(repo, e)[0] for e in configs}
    workspaces = [e for e in configs if tier[e] in (1, 3)]
    capped = set(workspaces[MAX_WORKSPACES:])
    root_hooks = [p for p in hook_dirs if os.path.dirname(p) == repo.root]
    steps: list[tuple[str, Any]] = [("config", e) for e in configs if tier[e] == 0] \
        + [("hooks", p) for p in root_hooks] \
        + [("config", e) for e in configs if tier[e] == 1 and e not in capped] \
        + [("config", e) for e in configs if tier[e] == 2] \
        + [("config", e) for e in configs if tier[e] == 3 and e not in capped] \
        + [("instr", e) for e in found.entries if is_instruction(repo, e)]
    # Pass 1: cheap raw-text shapes over everything, before any costly parse
    start = time.monotonic()
    if not prescan_all(repo, configs, hook_dirs, start + budget * PRESCAN_SHARE, out):
        out.errors.insert(0, "raw-text prescan budget exhausted")
    # Pass 2: strict parse/verdicts; hook dirs queued by hooksPath instructions;
    # then every malformed re-parse LAST, across all file types
    file_slice = max(1.0, min(MAX_FILE_SECONDS, budget / 4))
    skipped = len(capped)
    deferred: list[Entry] = []
    left = run_steps(repo, steps, hook_dirs, deadline, file_slice, out, deferred)
    if left is None:
        later = [("hooks", p) for p in sorted(hook_dirs) if p not in root_hooks]
        left = run_steps(repo, later, hook_dirs, deadline, file_slice, out, deferred)
    if left is None:
        left = run_steps(repo, [("fallback", e) for e in deferred], hook_dirs, deadline,
                         file_slice, out, deferred)
    skipped += out.skipped
    if left is not None:
        skipped += left
        out.errors.insert(0, f"analysis time budget ({budget:.0f}s) exhausted")
    if skipped:
        # First, so a full warning list can never hide it
        out.errors.insert(0, f"{skipped} files not analysed (budget)")


def run_steps(repo: Repo, steps: list[tuple[str, Any]], hook_dirs: dict[str, str],
              deadline: float, file_slice: float, out: Output,
              deferred: list[Entry]) -> int | None:
    """Run steps in order, each within a time slice; returns the number of config/hook
    steps left when the budget ran out, else None."""
    for index, (kind, item) in enumerate(steps):
        if time.monotonic() > deadline:
            return sum(1 for k, _ in steps[index:] if k != "instr")
        name = repo.rel(item.vpath if isinstance(item, Entry) else item)
        slice_left = max(0.5, min(file_slice, deadline - time.monotonic()))
        if kind == "config":
            done = sliced(slice_left, lambda: run_handler(repo, item, out, deferred))
        elif kind == "fallback":
            done = sliced(slice_left, lambda: run_fallback(repo, item, out))
        elif kind == "hooks":
            done = sliced(slice_left, lambda: run_hook_dir(repo, item, hook_dirs[item], out))
        else:
            done = sliced(slice_left, lambda: run_instructions(repo, item, hook_dirs, out))
        if not done:
            out.errors.insert(0, f"{name}: not fully analysed (per-file time slice)")
    return None


def run_hook_dir(repo: Repo, path: str, why: str, out: Output) -> None:
    """Scan one hooks directory; an error never hides other findings."""
    try:
        out.add(scan_hook_dir(repo, path, why))
        out.retract(path)
    except (OSError, ValueError) as exc:
        out.errors.append(f"{repo.rel(path)}: hook dir unreadable")
        print(f"autoexec hook dir error: {repo.rel(path)}: {exc}", file=sys.stderr)


def run_instructions(repo: Repo, entry: Entry, hook_dirs: dict[str, str], out: Output) -> None:
    """core.hooksPath / fsmonitor instructions in one file."""
    try:
        text = repo.read_text(entry.rpath)
        out.add(handle_instructions(repo, text, os.path.dirname(entry.rpath),
                                    repo.rel(entry.vpath), hook_dirs))
    except (OSError, ValueError) as exc:  # unreadable file: other files still analysed
        print(f"autoexec read error: {repo.rel(entry.vpath)}: {exc}", file=sys.stderr)


def load_index_links(path: str | None) -> frozenset[str]:
    """NUL-separated repo-relative symlink paths from the git index (optional file)."""
    if not path:
        return frozenset()
    with open(path, "rb") as fh:
        raw = fh.read(16 * 1024 * 1024).decode("utf-8", errors="replace")
    return frozenset(os.path.normpath(p) for p in raw.split("\0") if p)


def main(argv: list[str]) -> int:
    """Entry point: `<target_dir> [index_links_file]`; prints H/I/E records."""
    if len(argv) not in (2, 3) or not os.path.isdir(argv[1]):
        print("usage: python3 checks/autoexec <target_dir> [index_links_file]", file=sys.stderr)
        return 2
    # Repo-derived text must never crash the report (e.g. lone surrogates)
    sys.stdout.reconfigure(errors="replace")
    try:
        budget = float(os.environ.get("AUTOEXEC_BUDGET_SECONDS", DEFAULT_BUDGET))
    except ValueError:
        budget = DEFAULT_BUDGET
    repo = Repo(os.path.realpath(argv[1]),
                index_links=load_index_links(argv[2] if len(argv) == 3 else None))
    out = Output(repo)
    analyse(repo, budget, out)
    out.finish()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
