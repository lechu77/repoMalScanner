"""direnv .envrc, git hooks (core.hooksPath, husky, .githooks), lefthook, pre-commit."""
from __future__ import annotations

import os
import re
from typing import Any, Iterator

from core import (HIGH, INFO, PREFIX_CMDS, SEGMENT_SPLIT, SUBSTITUTION, Finding, Repo,
                  as_cmd, as_dict, clean, code_lines, finding, script_target_kind, script_verdict)
from patterns import INLINE, SCRIPT_DANGER, danger

DIRENV_SAFE = {"export", "PATH_add", "path_add", "MANPATH_add", "path_rm", "use", "layout",
               "dotenv", "dotenv_if_exists", "source_env", "source_env_if_exists", "source_up",
               "source_up_if_exists", "watch_file", "watch_dir", "env_vars_required",
               "strict_env", "unstrict_env", "log_status", "log_error", "unset", "if", "then",
               "else", "elif", "fi", "test", "[", "[[", "local", "set", "has", "expand_path",
               "find_up", "on_git_branch", "load_prefix", "echo", "true", "false", "return",
               "for", "do", "done", "while", "case", "esac", "{", "}", "source", ".",
               "user_rel_path", "direnv_version", "semver_search", "source_url", "fetchurl",
               "nix_direnv_version"}
# eval "$(tool init)" for well-known environment managers
EVAL_TOOL = re.compile(
    r"^eval\s+\"?\$\(\s*(pyenv|rbenv|nodenv|goenv|jenv|direnv|lorri|nix|nix-shell|conda|mise|rtx"
    r"|asdf|fnm|opam|brew|devbox|devenv|flox|luarocks|poetry|pdm|ssh-agent)\b[^)`;|&]*\)\"?\s*$")
REMOTE_SOURCE = re.compile(r"\b(fetchurl|source_url)\b|(^|[;&|]\s*)(source|\.)\s+<\(")
# direnv verifies `source_url URL sha256-...` / `fetchurl URL sha256-...` (vendored-equivalent)
PINNED_SOURCE = re.compile(
    r"^\s*(source_url|fetchurl)\s+\S+\s+[\"']?sha(256|384|512)-[A-Za-z0-9+/=]+[\"']?\s*$")
SUBST = re.compile(r"\$\(|`")
# Fragments left by splitting `2>&1` / `&>file` on & and | (not command words)
REDIRECT_WORD = re.compile(r"^(\d+|\d*[<>].*|[<>].*)$")
ASSIGN_OR_FUNC = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=|.*(\(\)|[{}:])$|^:$")
HOOK_DIR_NAMES = {".husky", ".githooks", ".git-hooks", "githooks"}
# git [-C dir] [-c k=v] config [set] [--opts] core.hooksPath <dir>
GIT_CONFIG = r"git\s+(?:-[Cc]\s+\S+\s+)*config\s+(?:set\s+)?"
HOOKS_PATH = re.compile(
    GIT_CONFIG + r"((?:--[a-z-]+\s+)*)core\.hookspath\s*[=\s]\s*[\"']?"
    r"(?:\$\(pwd\)/|\$PWD/|\$\{PWD\}/)?([^\s\"';&|)`]+)", re.I)
FSMONITOR = re.compile(
    GIT_CONFIG + r"(?:--[a-z-]+\s+)*core\.fsmonitor\s+[\"']?([^\s\"';&|)`]+)", re.I)
# Hooks git runs (githooks(5)); listed first so helper files cannot crowd them out
GIT_HOOKS = {"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
             "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
             "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update",
             "proc-receive", "post-receive", "post-update", "reference-transaction",
             "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
             "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
             "p4-post-changelist", "p4-pre-submit", "post-index-change"}
MAX_HOOK_FILES = 500
DISABLED_HOOKS = {"/dev/null", "NUL", "nul"}
HOOK_CONFIGS = {"lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml",
                "lefthook-local.yml", ".lefthook-local.yml", ".pre-commit-config.yaml",
                ".pre-commit-config.yml"}
YAML_CMD = re.compile(r"^(\s*)(?:-\s*)?(run|entry|script)\s*:\s*(.*)$")
BLOCK_SCALAR = re.compile(r"^[|>][-+0-9]*\s*$")


def sourced_verdict(repo: Repo, rel: str) -> str | None:
    """Content-only verdict for a sourced shell/env file (.envrc.local, .env.defaults).

    Sourced files are shell by definition, so the disguised-extension rule does not
    apply; only remote fetches, downloaders, inline interpreters, decoding and
    pipe-to-shell count (SCRIPT_DANGER includes REMOTE).
    """
    real, linked = repo.follow(rel)
    if linked and real is None:
        return f"repo file {rel} that is a symlink leaving the repo (or dangling)"
    if linked:
        repo.warn(f"{rel}: sourced file is a symlink to {real}")
        rel = real
    try:
        text = code_lines(repo.read_text(os.path.join(repo.root, rel)))
    except OSError:
        return None  # FIFO/unreadable: nothing the shell could source
    for line in (ln.strip() for ln in text.splitlines()):
        if EVAL_TOOL.match(line) or PINNED_SOURCE.match(line):
            continue
        # Local `eval "$env"` is normal in direnv libraries (devenv direnvrc); remote
        # fetches, inline interpreters, decoding and pipe-to-shell are not
        if REMOTE_SOURCE.search(line) or INLINE.search(line) or SCRIPT_DANGER.search(line):
            return f"repo file {rel} that fetches, decodes or evaluates code"
    return None


def file_verdict(repo: Repo, hit: tuple[str, bool]) -> str | None:
    """Verdict for a referenced repo file: content-only when it is sourced."""
    return sourced_verdict(repo, hit[0]) if hit[1] else script_verdict(repo, hit[0])


def envrc_line(repo: Repo, line: str, root: str) -> tuple[str, str] | None:
    """(level, reason) for one .envrc line, or None when it is plain env setup."""
    if PINNED_SOURCE.match(line):
        return INFO, "hash-pinned remote direnvrc"
    reason = ("remote source/fetchurl" if REMOTE_SOURCE.search(line) else None) or danger(line)
    if reason:
        return HIGH, f"runs {reason}"
    hit = script_target_kind(repo, line, (root,))
    if hit:
        hostile = file_verdict(repo, hit)
        verb = "sources" if hit[1] else "runs"
        return (HIGH, f"{verb} {hostile}") if hostile else (INFO, f"{verb} repo file {hit[0]}")
    if SUBST.search(line):
        return INFO, "command substitution"
    return None


def envrc_heads(line: str) -> list[str]:
    """Command words of every segment (after ; && || | & and if/then/!/[ ... ])."""
    heads = []
    for segment in SEGMENT_SPLIT.split(SUBSTITUTION.sub("X", line)):
        tokens = segment.split()
        while tokens and tokens[0] in PREFIX_CMDS:
            tokens = tokens[1:]
        if tokens and tokens[0] not in ("[", "[[", "test", "]", "]]") \
                and not REDIRECT_WORD.match(tokens[0]):
            heads.append(tokens[0])
    return heads


def handle_envrc(repo: Repo, text: str, root: str, rel: str) -> Iterator[Finding]:
    """direnv runs .envrc on `cd` once allowed: only stdlib env setup is expected."""
    unknown: list[str] = []
    for raw in re.sub(r"\\\n", " ", text).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or EVAL_TOOL.match(line):
            continue
        verdict = envrc_line(repo, line, root)
        if verdict and verdict[0] == HIGH:
            yield finding(HIGH, rel, f"direnv {verdict[1]}", line)
            return
        if verdict:
            yield finding(INFO, rel, verdict[1], line)
        for head in envrc_heads(line):
            if head not in DIRENV_SAFE and not ASSIGN_OR_FUNC.match(head) and head not in unknown:
                unknown.append(head)
    if unknown:
        yield finding(INFO, rel, "commands beyond direnv stdlib", ", ".join(unknown[:5]))


def hook_reason(repo: Repo, text: str, hook_dir: str) -> tuple[str, str] | None:
    """(reason, line) when a hook downloads/inlines code or runs a hostile repo file."""
    for line in text.splitlines():
        reason = danger(line)
        hit = None if reason else script_target_kind(repo, line, (repo.root, hook_dir))
        reason = reason or (hit and file_verdict(repo, hit))
        if reason:
            return reason, line
    reason = danger(text)  # patterns spanning lines
    return (reason, text) if reason else None


def scan_hook_dir(repo: Repo, path: str, why: str) -> Iterator[Finding]:
    """Hook scripts in a hooks directory that download, inline or decode code."""
    try:
        names = os.listdir(path)
    except OSError:
        return
    # Hook names git runs first, then the rest (helper scripts), bounded
    names = sorted(names, key=lambda n: (n not in GIT_HOOKS, n))[:MAX_HOOK_FILES]
    for name in names:
        if name.startswith(".") or name.endswith((".md", ".sample")):
            continue
        hook = os.path.join(path, name)
        real, linked = repo.follow(repo.rel(hook))
        if linked:
            if real is None:
                yield finding(HIGH, repo.rel(hook),
                              f"git hook ({why}) is a symlink leaving the repo (or dangling)")
                continue
            repo.warn(f"{repo.rel(hook)}: git hook is a symlink to {real}")
            hook = os.path.join(repo.root, real)
        elif not os.path.isfile(hook):
            continue
        try:
            text = code_lines(repo.read_text(hook))
        except OSError:
            continue  # FIFO/device or unreadable: nothing git could run
        hit = hook_reason(repo, text, path)
        if hit:
            yield finding(HIGH, repo.rel(hook), f"git hook ({why}) {hit[0]}", hit[1])


def handle_instructions(repo: Repo, text: str, base: str, rel: str,
                        hook_dirs: dict[str, str]) -> Iterator[Finding]:
    """Instructions that set core.hooksPath (target dir is queued) or core.fsmonitor."""
    lowered = text.lower()
    if "hookspath" not in lowered and "fsmonitor" not in lowered:
        return
    for match in HOOKS_PATH.finditer(text):
        target = match.group(2)
        if target in DISABLED_HOOKS:
            continue  # disables hooks (common in CI scripts)
        if "--global" in match.group(1) or "--system" in match.group(1):
            yield finding(HIGH, rel, "sets a global core.hooksPath (hooks for every repo)",
                          match.group(0))
            continue
        for start in (repo.root, base):
            path = repo.safe_path(os.path.join(start, target))
            if path and os.path.isdir(path):
                hook_dirs.setdefault(path, f"core.hooksPath via {clean(rel)[:40]}")
                break
        yield finding(INFO, rel, "sets core.hooksPath", target)
    for match in FSMONITOR.finditer(text):
        if match.group(1).lower() not in ("true", "false", "0", "1"):
            yield finding(HIGH, rel, "sets core.fsmonitor to a command (runs on git status)",
                          match.group(0))


def yaml_value(lines: list[str], index: int, indent: int, value: str) -> str:
    """Inline YAML value, or the block scalar (`|`/`>`) that follows the key."""
    if not BLOCK_SCALAR.match(value):
        return value
    block = []
    for nxt in lines[index + 1:]:
        if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
            break
        block.append(nxt)
    return "\n".join(block)


def handle_hook_config(text: str, rel: str) -> Iterator[Finding]:
    """lefthook `run:` / pre-commit `entry:` commands (line-based, no YAML dependency)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = YAML_CMD.match(line)
        if not match:
            if "git_url:" in line:
                yield finding(INFO, rel, "lefthook remote config", line.strip())
            continue
        value = yaml_value(lines, index, len(match.group(1)), match.group(3))
        reason = danger(code_lines(value))
        if reason:
            yield finding(HIGH, rel, f"hook {match.group(2)} ({reason})", value)


def handle_package_hooks(data: dict[str, Any], rel: str) -> Iterator[Finding]:
    """package.json husky v4 / simple-git-hooks inline hook commands."""
    husky = as_dict(as_dict(data.get("husky")).get("hooks"))
    tables = [husky, as_dict(data.get("simple-git-hooks"))]
    for table in tables:
        for hook, raw in table.items():
            cmd = as_cmd(raw)
            reason = danger(cmd)
            if reason:
                yield finding(HIGH, rel, f"git hook {clean(hook)[:30]} ({reason})", cmd)
