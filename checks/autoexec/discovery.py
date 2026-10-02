"""Target walk: config files (case-insensitive), symlinked configs, hook directories."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from core import HIGH, Finding, Repo, finding
from vcs_hooks import HOOK_CONFIGS, HOOK_DIR_NAMES

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "site-packages"}
# Nested test/example trees: skipped for generic instruction scanning only
TEST_DIRS = {"test", "tests", "__tests__", "fixtures", "testdata", "spec", "examples"}
CONFIG_DIRS = {".vscode", ".devcontainer", ".claude", ".cursor", ".gemini", ".codex"} \
    | HOOK_DIR_NAMES
CONFIG_FILES = {".envrc", ".devcontainer.json", ".mcp.json"} | HOOK_CONFIGS
MAX_ENTRIES = 200_000
MAX_LINKED_DIRS = 64  # symlinked config dirs expanded (bounds symlink loops)


@dataclass(frozen=True)
class Entry:
    """A file as tools see it (vpath, used for naming) and where to read it (rpath)."""

    vpath: str
    rpath: str
    in_test: bool


@dataclass
class Discovery:
    """Everything the walk found."""

    entries: list[Entry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    hook_dirs: dict[str, str] = field(default_factory=dict)
    link_targets: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def is_config_name(name: str, in_config: bool) -> bool:
    """Names tools load automatically (compared case-insensitively: APFS/NTFS)."""
    lname = name.lower()
    return lname in CONFIG_DIRS or lname in CONFIG_FILES or in_config \
        or lname.endswith(".code-workspace")


def _visit_link(repo: Repo, out: Discovery, vpath: str, target: str | None,
                todo: list[tuple[str, str, bool, bool]], in_test: bool) -> None:
    """A symlinked config: analyse an in-repo target (WARN), flag an escaping one (HIGH)."""
    rel = repo.rel(vpath)
    if target is not None and target in out.link_targets:
        return  # already analysed through another link (symlink loops)
    if target is None:
        msg = "config path is a symlink leaving the repo (or dangling)"
        out.findings.append(finding(HIGH, rel, msg))
        return
    out.link_targets.add(target)
    out.warnings.append(f"{rel}: config path is a symlink to {repo.rel(target)}")
    if os.path.isdir(target):
        todo.append((vpath, target, True, in_test))
        if os.path.basename(vpath).lower() in HOOK_DIR_NAMES:
            out.hook_dirs.setdefault(target, os.path.basename(vpath))
    elif os.path.isfile(target):
        out.entries.append(Entry(vpath, target, in_test))


def discover(repo: Repo) -> Discovery:
    """Walk the target without following symlinks except in-repo config symlinks.

    repo.index_links: repo-relative paths git records as symlinks (mode 120000); in a
    clone with core.symlinks=false they are plain files holding the link text.
    """
    out = Discovery()
    todo: list[tuple[str, str, bool, bool]] = [(repo.root, repo.root, False, False)]
    # A real dir is walked once per location tools see it at (vdir): a symlinked
    # .vscode -> cfg/editor is analysed as .vscode even though cfg/editor is walked too
    visited: set[tuple[str, str]] = set()
    linked = 0
    while todo and len(out.entries) < MAX_ENTRIES:
        vdir, rdir, in_config, in_test = todo.pop()
        if (vdir, rdir) in visited:
            continue
        visited.add((vdir, rdir))
        if vdir != rdir:
            linked += 1
            if linked > MAX_LINKED_DIRS:
                continue
        try:
            items = sorted(os.scandir(rdir), key=lambda item: item.name)
        except OSError:
            continue  # unreadable directory: nothing a tool could load either
        for item in items:
            vpath, lname = os.path.join(vdir, item.name), item.name.lower()
            if item.is_symlink():
                if is_config_name(item.name, in_config):
                    target = repo.resolve_inside(item.path)
                    _visit_link(repo, out, vpath, target, todo, in_test)
            elif repo.index_links and repo.rel(item.path) in repo.index_links:
                if is_config_name(item.name, in_config):
                    target = repo.resolve_index_link(item.path)
                    _visit_link(repo, out, vpath, target, todo, in_test)
            elif item.is_dir(follow_symlinks=False) and item.name not in SKIP_DIRS:
                if lname in HOOK_DIR_NAMES:
                    out.hook_dirs.setdefault(item.path, item.name)
                todo.append((vpath, item.path, in_config or lname in CONFIG_DIRS,
                             in_test or lname in TEST_DIRS))
            elif item.is_file(follow_symlinks=False):
                out.entries.append(Entry(vpath, item.path, in_test))
    return out
