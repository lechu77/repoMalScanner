"""Pass 1: cheap raw-text detection over every auto-run config, before any parsing.

Crafted inputs (many malformed configs) can exhaust the time budget of the full
parse (pass 2). This pass reads a bounded, comment-stripped prefix of every
candidate file and matches only key/value shapes (`"initializeCommand": "..."`,
`"command": "..."` in a file with a folderOpen task, hook `run:` lines, hook
scripts), so plain strings and comments never trigger it. Its HIGH candidates are
printed at once (`P` records); pass 2 retracts them (`X`) only for files it parses
strictly to a full verdict. A malformed, timed-out or unreached file keeps them.
Every regex is linear or bounded; nothing is executed.
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterator

from core import Repo, clean, code_lines
from patterns import auto_run_danger, danger
from vcs_hooks import FSMONITOR, GIT_HOOKS, HOOK_CONFIGS, YAML_CMD

PREFIX = 128 * 1024
MAX_VALUE = 2000
MAX_HOOK_FILES = 100
STR = re.compile(r'"((?:[^"\\\n]|\\.){0,%d})"' % MAX_VALUE)
FOLDER_OPEN = re.compile(r'"runOn"\s*:\s*"(folderOpen|worktreeCreated)"', re.I)
TASK_KEY = re.compile(r'"command"\s*:\s*', re.I)
ARGS_KEY = re.compile(r'"args"\s*:\s*\[', re.I)
DC_KEY = re.compile(r'"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand'
                    r'|postStartCommand|postAttachCommand)"\s*:\s*', re.I)
HOOKS_KEY = re.compile(r'"hooks"\s*:', re.I)
AGENT_DIRS = {".claude", ".gemini", ".cursor"}
# interpreter running a non-script file (`node public/fonts/x.woff2`)
DISGUISED = re.compile(
    r"\b(node|nodejs|deno|bun|python[0-9.]*|ruby|perl|php|(ba|z)?sh)\s+[\"']?[\w./${}-]+\."
    r"(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp|bmp|txt|css|md|map|wasm|dat|bin|lock)"
    r"\b", re.I)


# One left-to-right pass (C speed): strings kept, comments dropped; an unterminated
# string/comment consumes the rest, so every character is visited once
TOKENS = re.compile(r'"(?:[^"\\\n]|\\.)*"?|//[^\n]*|/\*(?:[^*]|\*(?!/))*(?:\*/)?', re.S)


def strip_comments(text: str) -> str:
    """JSONC without comments (strings untouched)."""
    return TOKENS.sub(lambda m: "" if m.group(0)[:2] in ("//", "/*") else m.group(0), text)


def _decode(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def values_at(text: str, pos: int) -> list[str]:
    """String value(s) at pos: a string, or the strings of a bounded array/object."""
    match = STR.match(text, pos)
    if match:
        return [_decode(match.group(1))]
    if pos < len(text) and text[pos] in "[{":
        window = text[pos:pos + 4 * MAX_VALUE]
        end = window.find("]" if text[pos] == "[" else "}")
        return [_decode(m.group(1)) for m in STR.finditer(window[:end if end > 0 else None])]
    return []


def reason_for(cmd: str, auto: bool) -> str | None:
    """Danger of one command value (auto: runs unprompted, so unpinned fetches count)."""
    reason = auto_run_danger(cmd) if auto else danger(cmd)
    if reason:
        return reason
    if DISGUISED.search(cmd):
        return "interpreter runs a disguised non-script file"
    match = FSMONITOR.search(cmd)
    if match and match.group(1).lower() not in ("true", "false", "0", "1"):
        return "sets core.fsmonitor to a command"
    if re.search(r"core\.hookspath", cmd, re.I) and re.search(r"--(global|system)\b", cmd):
        return "sets a global core.hooksPath"
    return None


def scan_json(text: str, kind: str) -> Iterator[tuple[str, str]]:
    """(where, reason) for dangerous key/value shapes in comment-stripped JSONC."""
    if kind == "tasks":
        if not FOLDER_OPEN.search(text):
            return
        for match in TASK_KEY.finditer(text):
            cmd = " ".join(values_at(text, match.end()))
            args = ARGS_KEY.search(text, match.end(), match.end() + 1000)
            if args:
                cmd += " " + " ".join(values_at(text, args.end() - 1))
            reason = reason_for(cmd, True)
            if reason:
                yield "folderOpen task", reason
    elif kind == "devcontainer":
        for match in DC_KEY.finditer(text):
            host = match.group(1).lower() == "initializecommand"
            for cmd in values_at(text, match.end()):
                reason = reason_for(cmd, host)
                if reason:
                    yield match.group(1), reason
                    break
    elif kind == "agent" and HOOKS_KEY.search(text):
        for match in TASK_KEY.finditer(text):
            reason = reason_for(" ".join(values_at(text, match.end())), False)
            if reason:
                yield "agent hook", reason


def kind_of(vpath: str) -> str | None:
    """Pass-1 shape family of a config file (mirrors pick_handler names)."""
    parent = os.path.basename(os.path.dirname(vpath)).lower()
    grand = os.path.basename(os.path.dirname(os.path.dirname(vpath))).lower()
    name = os.path.basename(vpath).lower()
    if (parent == ".vscode" and name == "tasks.json") or name.endswith(".code-workspace"):
        return "tasks"
    if name == ".devcontainer.json" or (name == "devcontainer.json"
                                        and ".devcontainer" in (parent, grand)):
        return "devcontainer"
    if parent in AGENT_DIRS and name in ("settings.json", "settings.local.json", "hooks.json"):
        return "agent"
    if name in HOOK_CONFIGS:
        return "yaml"
    return None


def prescan_file(repo: Repo, vpath: str, rpath: str) -> list[str]:
    """HIGH candidate details for one config file."""
    kind = kind_of(vpath)
    if not kind:
        return []
    try:
        text = repo.read_text(rpath)[:PREFIX]
    except OSError:
        return []
    rel = repo.rel(vpath)
    out = []
    if kind == "yaml":
        for line in text.splitlines():
            match = YAML_CMD.match(line)
            reason = match and reason_for(code_lines(match.group(3)), False)
            if reason:
                out.append(clean(f"{rel}: hook {match.group(2)} ({reason}) [prescan]: "
                                 f"{match.group(3)}"))
                break
        return out
    for where, reason in scan_json(strip_comments(text.lstrip("\ufeff")), kind):
        out.append(clean(f"{rel}: {where} ({reason}) [prescan]"))
        break  # one candidate per file is enough to make it HIGH
    return out


def prescan_hook_dir(repo: Repo, path: str, why: str) -> list[str]:
    """HIGH candidates for hook scripts (git hook names first, bounded)."""
    try:
        names = sorted(os.listdir(path), key=lambda n: (n not in GIT_HOOKS, n))
    except OSError:
        return []
    for name in names[:MAX_HOOK_FILES]:
        if name.startswith(".") or name.endswith((".md", ".sample")):
            continue
        hook = repo.safe_path(os.path.join(path, name))
        if not hook or not os.path.isfile(hook):
            continue  # symlinked hooks are resolved by pass 2
        try:
            text = code_lines(repo.read_text(hook)[:PREFIX])
        except OSError:
            continue
        for line in text.splitlines():
            reason = reason_for(line, False)
            if reason:
                return [clean(f"{repo.rel(hook)}: git hook ({why}) {reason} [prescan]: {line}")]
    return []
