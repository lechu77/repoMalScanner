"""Shared primitives for the auto-execution-on-open check.

Untrusted-input rules: repo files are only parsed, never executed; paths never
leave the target or traverse symlinks; reads are capped and refuse FIFOs.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
from dataclasses import dataclass, field
from typing import Any

from patterns import SCRIPT_DANGER
from tolerant import parse_tolerant

HIGH = "H"
INFO = "I"
MAX_READ = 1024 * 1024
MAX_LIST = 50
MAX_LINK_HOPS = 8
MAX_LINK_TEXT = 4096
DETAIL_LEN = 160
INTERPRETERS = re.compile(
    r"^(node|nodejs|deno|bun|tsx|ts-node|python[0-9.]*|py|ruby|perl|php|(ba|z|da|k)?sh"
    r"|powershell(\.exe)?|pwsh|cmd(\.exe)?|osascript|wscript|cscript)$", re.I)
SCRIPT_EXT = re.compile(
    r"\.(sh|bash|zsh|ps1|psm1|bat|cmd|vbs|js|cjs|mjs|ts|mts|cts|jsx|tsx|py|rb|pl|php|exe|bin)$",
    re.I)
PREFIX_CMDS = {"sudo", "env", "exec", "command", "nohup", "if", "then", "else", "elif", "while",
               "until", "do", "!", "time", "{"}
VENDOR_PART = re.compile(r"(^|/)(node_modules|\.venv|venv|site-packages)/")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
RUNNER_RUN = re.compile(r"\b(npm|pnpm|yarn|bun)\s+(run(-script)?\s+)?([A-Za-z0-9:_.-]+)")
WS_VARS = ("${workspaceFolder}", "${workspaceRoot}", "${containerWorkspaceFolder}",
           "${localWorkspaceFolder}", "${PWD}", "$PWD", "${CLAUDE_PROJECT_DIR}",
           "$CLAUDE_PROJECT_DIR", "${GEMINI_PROJECT_DIR}", "$GEMINI_PROJECT_DIR",
           "${CURSOR_PROJECT_DIR}", "$CURSOR_PROJECT_DIR")


BIDI = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


@dataclass(frozen=True)
class Finding:
    """One auto-execution indicator: level HIGH (scored) or INFO (shown only)."""

    level: str
    detail: str


def clean(text: Any) -> str:
    """One-line, control-free, bounded rendering of repo-derived text."""
    # Lone surrogates (from JSON \ud800 escapes) cannot be printed as UTF-8
    text = str(text).encode("utf-8", "replace").decode("utf-8")
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
    text = BIDI.sub("", text)  # Trojan Source reordering / zero-width characters
    text = re.sub(r"\s+", " ", text).strip()
    return text[:DETAIL_LEN] + ("..." if len(text) > DETAIL_LEN else "")


def finding(level: str, rel: str, msg: str, cmd: str | None = None) -> Finding:
    """Build a Finding whose detail is `rel: msg[: cmd]`, sanitized."""
    suffix = f": {cmd}" if cmd is not None else ""
    return Finding(level, clean(f"{rel}: {msg}{suffix}"))


@dataclass(frozen=True)
class Repo:
    """The scan target: every path operation is confined to `root`.

    `scripts` caches parsed package.json scripts per directory (one parse each).
    """

    root: str
    scripts: dict[str, dict[str, Any]] = field(default_factory=dict, compare=False)
    # Repo-relative paths git records as symlinks (mode 120000): in our clone
    # (core.symlinks=false) they are plain files holding the link text
    index_links: frozenset[str] = field(default_factory=frozenset, compare=False)
    # Analysis warnings raised inside handlers (drained into E records)
    warnings: list[str] = field(default_factory=list, compare=False)

    def rel(self, path: str) -> str:
        """Path relative to the target root."""
        return os.path.relpath(path, self.root)

    def safe_path(self, path: str) -> str | None:
        """Normalized in-repo path with no symlink component, else None."""
        try:
            path = os.path.normpath(path)
            if not path.startswith(self.root + os.sep) or os.path.realpath(path) != path:
                return None
        except ValueError:
            return None  # embedded NUL byte: not a path git could have checked out
        return path

    def inside(self, path: str) -> str | None:
        """Normalized path if it lies under root (symlinks not checked), else None."""
        path = os.path.normpath(path)
        return path if "\0" not in path and path.startswith(self.root + os.sep) else None

    def is_link(self, path: str) -> bool:
        """In-repo path that is (or passes through) a symlink, real or from the git index."""
        if self.rel(path) in self.index_links:
            return True
        try:
            return os.path.islink(path) or os.path.realpath(path) != path
        except (OSError, ValueError):
            return False

    def resolve_inside(self, path: str) -> str | None:
        """Real target of a symlinked path if it stays inside the target root, else None."""
        try:
            target = os.path.realpath(path)
        except (OSError, ValueError):
            return None
        return target if self.safe_path(target) == target else None

    def resolve_index_link(self, path: str) -> str | None:
        """Existing in-repo target of an index symlink (chains followed), else None."""
        for _hop in range(MAX_LINK_HOPS):
            try:
                text = self.read_text(path)[:MAX_LINK_TEXT]
            except OSError:
                return None
            if not text or any(c in text for c in "\0\n\r"):
                return None
            target = os.path.normpath(os.path.join(os.path.dirname(path), text))
            if self.safe_path(target) != target:
                return None
            if self.rel(target) not in self.index_links:
                return target if os.path.exists(target) else None
            path = target
        return None

    def follow(self, rel: str) -> tuple[str | None, bool]:
        """(in-repo regular file to analyse, was a symlink) for a repo file.

        None means a symlink leaving the repo, dangling, or not a regular file.
        """
        path = os.path.normpath(os.path.join(self.root, rel))
        if not self.is_link(path):
            return rel, False
        if self.rel(path) in self.index_links:
            target = self.resolve_index_link(path)
        else:
            target = self.resolve_inside(path)
        ok = target is not None and os.path.isfile(target) and not os.path.islink(target)
        return (self.rel(target) if ok else None), True

    def warn(self, msg: str) -> None:
        """Record an analysis warning (reported as WARN, never CLEAN)."""
        if msg not in self.warnings:
            self.warnings.append(msg)

    def read_text(self, path: str) -> str:
        """Capped read of a regular file; never follows symlinks or blocks on FIFOs."""
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"not a regular file: {self.rel(path)}")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                return fh.read(MAX_READ).decode("utf-8", errors="ignore")
        finally:
            os.close(fd)

    def load_jsonc(self, path: str, tolerant: bool = False) -> dict[str, Any]:
        """Parse a JSON-with-comments file; a non-object document yields {}.

        tolerant: recover like VS Code's jsonc-parser instead of raising.
        """
        text = strip_jsonc(self.read_text(path).lstrip("\ufeff"))
        data = parse_tolerant(text) if tolerant else json.loads(text)
        return data if isinstance(data, dict) else {}


def _next_significant(text: str, start: int) -> str:
    """First non-whitespace character at or after start (index walk, no slicing)."""
    size = len(text)
    while start < size and text[start].isspace():
        start += 1
    return text[start] if start < size else ""


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, outside strings only."""
    out: list[str] = []
    i, size, in_str = 0, len(text), False
    while i < size:
        char = text[i]
        if in_str:
            out.append(char)
            if char == "\\" and i + 1 < size:
                out.append(text[i + 1])
                i += 1
            elif char == '"':
                in_str = False
        elif char == '"':
            in_str = True
            out.append(char)
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = size if end < 0 else end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = size if end < 0 else end + 2
            continue
        else:
            out.append(char)
        i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """Drop commas directly followed by } or ] (string contents are untouched)."""
    out: list[str] = []
    in_str, escaped = False, False
    for i, char in enumerate(text):
        if in_str:
            in_str = escaped or char != '"'
            escaped = not escaped and char == "\\"
        elif char == '"':
            in_str = True
        elif char == "," and _next_significant(text, i + 1) in ("}", "]"):
            continue
        out.append(char)
    return "".join(out)


def as_dict(value: Any) -> dict[str, Any]:
    """value if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """value as a list (scalars wrapped, None -> [])."""
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def as_cmd(value: Any) -> str:
    """Flatten a command (string, exec-form list, {value: ...}) to one string."""
    if isinstance(value, dict):
        value = value.get("value", "")
    if isinstance(value, list):
        return " ".join(as_cmd(item) for item in value)
    return value if isinstance(value, str) else ""


def code_lines(text: str) -> str:
    """Text without blank and comment-only lines (#, //, REM, ::)."""
    return "\n".join(line for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith(("#", "//", "REM ", "::")))


def resolve_ws(token: str, root: str) -> str:
    """Expand workspace variables; relative paths are taken from root."""
    for var in WS_VARS:
        token = token.replace(var, root)
    return token if os.path.isabs(token) else os.path.join(root, token)


def _tokens(part: str) -> list[str]:
    try:
        tokens = shlex.split(part)
    except ValueError:
        tokens = part.split()
    while tokens and (ASSIGNMENT.match(tokens[0]) or os.path.basename(tokens[0]) in PREFIX_CMDS):
        tokens = tokens[1:]
    return tokens


SOURCE_CMDS = {"source", ".", "source_env", "source_env_if_exists"}
SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|&\n]")
SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)")


def command_parts(cmd: str) -> list[str]:
    """Simple commands of a line, including the contents of $(...), `...`, <(...)."""
    texts = [cmd] + [next(g for g in m.groups() if g is not None)
                     for m in SUBSTITUTION.finditer(cmd)]
    return [part for text in texts for part in SEGMENT_SPLIT.split(text)]


def script_target_kind(repo: Repo, cmd: str,
                       roots: tuple[str, ...]) -> tuple[str, bool] | None:
    """(repo file, sourced?) for the file a command executes or sources, or None."""
    for part in command_parts(cmd):
        tokens = _tokens(part)
        if not tokens:
            continue
        head, cands = tokens[0], []
        if INTERPRETERS.match(os.path.basename(head)) or head in SOURCE_CMDS:
            cands = [t for t in tokens[1:] if not t.startswith("-")][:1]
        elif "/" in head or "\\" in head or SCRIPT_EXT.search(head) or head.startswith("$"):
            cands = [head]
        for cand in cands:
            for root in roots:
                path = repo.inside(resolve_ws(cand.replace("\\", "/"), root))
                if not path:
                    continue
                if repo.is_link(path):
                    # node_modules/.bin links of a local install are not repo content
                    if not VENDOR_PART.search(repo.rel(path)):
                        return repo.rel(path), head in SOURCE_CMDS
                elif os.path.isfile(path):
                    return repo.rel(path), head in SOURCE_CMDS
    return None


def script_target(repo: Repo, cmd: str, roots: tuple[str, ...]) -> str | None:
    """Repo file a command executes or sources (`node x.js`, `./run.sh`, `. x`), or None."""
    hit = script_target_kind(repo, cmd, roots)
    return hit[0] if hit else None


def script_verdict(repo: Repo, rel: str) -> str | None:
    """Reason a repo file run by an auto-run entry is hostile, or None.

    Disguised payloads (`node fonts/x.woff2`) and scripts that download or decode
    code are hostile; an ordinary build/watch script is not.
    """
    real, linked = repo.follow(rel)
    if linked and real is None:
        return f"repo script {rel} is a symlink leaving the repo (or dangling)"
    if linked:
        repo.warn(f"{rel}: auto-run script is a symlink to {real}")
    for name in {rel, real}:
        if not SCRIPT_EXT.search(name) and os.path.splitext(name)[1]:
            return f"disguised non-script file {name}"
    rel = real
    try:
        text = code_lines(repo.read_text(os.path.join(repo.root, rel)))
    except OSError:
        return None  # FIFO/unreadable: nothing an interpreter could load
    if SCRIPT_DANGER.search(text):
        return f"repo script {rel} downloads or decodes code"
    return None


def npm_scripts(repo: Repo, root: str) -> dict[str, Any]:
    """package.json scripts of a directory, parsed once per scan."""
    if root not in repo.scripts:
        path = repo.safe_path(os.path.join(root, "package.json"))
        scripts: dict[str, Any] = {}
        if path and os.path.isfile(path):
            try:
                scripts = as_dict(repo.load_jsonc(path).get("scripts"))
            except (OSError, ValueError, RecursionError):
                scripts = {}  # unreadable package.json: commands are analysed alone
        repo.scripts[root] = scripts
    return repo.scripts[root]


def expand_runner(repo: Repo, cmd: str, root: str) -> str:
    """Append the package.json script text that `npm run X` resolves to (one level)."""
    if not RUNNER_RUN.search(cmd):
        return cmd
    scripts = npm_scripts(repo, root)
    extra = [scripts[m.group(4)] for m in RUNNER_RUN.finditer(cmd)
             if isinstance(scripts.get(m.group(4)), str)]
    return " ; ".join([cmd] + extra)
