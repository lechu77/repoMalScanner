"""VS Code tasks/settings/workspaces and devcontainer lifecycle commands."""
from __future__ import annotations

import os
import re
from typing import Any, Iterator

from core import (HIGH, INFO, Finding, Repo, as_cmd, as_dict, as_list, clean, finding, resolve_ws,
                  script_target)
from patterns import auto_run_danger, danger

SHELL_INIT_ARGS = re.compile(
    r"^(-[A-Za-z]*c|--rcfile|--init-file|-Command|-EncodedCommand|-enc|-File|/c|/k|-e|--eval)$",
    re.I)
# Environment variables that make shells, interpreters or git run extra code
LOADER_VARS = {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "BASH_ENV", "ENV",
               "PROMPT_COMMAND", "ZDOTDIR", "PERL5OPT", "RUBYOPT", "GIT_SSH_COMMAND", "GIT_SSH",
               "GIT_EXEC_PATH", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_CONFIG_GLOBAL",
               "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_PROXY_COMMAND"}
CONDITIONAL_LOADERS = {
    "NODE_OPTIONS": re.compile(r"(^|\s)(-r|--require|--import|--loader|--experimental-loader)\b"),
    "JAVA_TOOL_OPTIONS": re.compile(r"-javaagent"),
    "_JAVA_OPTIONS": re.compile(r"-javaagent")}
BASE_URL_VARS = re.compile(
    r"^(ANTHROPIC_(BEDROCK_|VERTEX_)?BASE_URL|ANTHROPIC_API_URL|OPENAI_(API_)?BASE(_URL)?"
    r"|(HTTPS?|ALL)_PROXY)$", re.I)
LOCAL_URL = re.compile(r"^(https?://)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])([:/]|$)", re.I)
# Settings whose value is an executable (or the tsserver directory)
EXEC_KEY = re.compile(
    r"(^|\.)(defaultInterpreterPath|pythonPath|interpreterPath|executablePath|executable|binPath"
    r"|serverPath|nodePath|tsdk|prettierPath|cmakePath|path)$")
COMMAND_KEY = re.compile(r"(^|\.)([A-Za-z]*CommandLine|command)$")
ODD_PATH = re.compile(r"[;&|`<>]|\$\(|://|^(/tmp|/var/tmp|/dev/shm|/private/tmp)/|%TEMP%|%APPDATA%",
                      re.I)
# ${...} without nesting: linear on hostile "${${${..." input
WS_VAR = re.compile(r"\$\{[^{}$]*\}")
MAX_PATH_LEN = 4096
TERMINAL_SHELL = re.compile(
    r"^terminal\.integrated\.(shell|shellArgs|profiles|automationProfile|automationShell)\.")
DC_LIFECYCLE = ("onCreateCommand", "updateContentCommand", "postCreateCommand",
                "postStartCommand", "postAttachCommand")
# initializeCommand segments that cannot run repo or remote code on the host
BENIGN_HOST = re.compile(
    r"^\s*(mkdir|touch|echo|true|test|cd|\[|docker\s+(network|volume)\s+(create|inspect|ls))\b")
# Substitution, process substitution or redirection makes any segment non-benign
HOST_UNSAFE = re.compile(r"\$\(|`|<\(|>")


def check_env(rel: str, where: str, env: Any) -> Iterator[Finding]:
    """Environment overrides that hijack loaders, shells, git or API endpoints."""
    for var, raw in as_dict(env).items():
        val = str(raw) if isinstance(raw, (int, float)) else as_cmd(raw)
        name, label = str(var).upper(), clean(var)[:40]
        cond = CONDITIONAL_LOADERS.get(name)
        if name in LOADER_VARS or (cond and cond.search(val)):
            yield finding(HIGH, rel, f"{where} sets {label}", val)
        elif BASE_URL_VARS.match(name) and val and not LOCAL_URL.match(val):
            yield finding(HIGH, rel, f"{where} redirects {label}", val)
        elif danger(val):
            yield finding(HIGH, rel, f"{where} {label} ({danger(val)})", val)
        elif name == "PATH":
            yield finding(INFO, rel, f"{where} overrides PATH", val)


def odd_or_local(repo: Repo, value: str, root: str, want_dir: bool = False) -> str | None:
    """Reason an executable path is attacker-controlled (committed, symlinked or odd)."""
    if len(value) > MAX_PATH_LEN or ODD_PATH.search(WS_VAR.sub("", value)) or danger(value):
        return "odd path"
    if not value:
        return None
    candidate = os.path.normpath(resolve_ws(value, root))
    path = repo.safe_path(candidate)
    if path and (os.path.isdir(path) if want_dir else os.path.isfile(path)):
        return f"committed repo file {repo.rel(path)}"
    try:
        linked = path is None and candidate.startswith(repo.root + os.sep) \
            and os.path.lexists(candidate)
    except ValueError:
        linked = False  # NUL byte: not a path on disk
    return "symlinked repo path" if linked else None


def shell_entries(kind: str, val: Any) -> list[dict[str, Any]]:
    """Normalize terminal shell settings to [{path, args, env}]."""
    if kind == "shellArgs":
        return [{"args": val}]
    if kind in ("shell", "automationShell"):
        return [{"path": val}]
    if kind == "profiles":
        return [entry for entry in as_dict(val).values() if isinstance(entry, dict)]
    return [as_dict(val)]


def check_shell_override(repo: Repo, rel: str, key: str, val: Any, root: str) -> Iterator[Finding]:
    """terminal.integrated shell/shellArgs/profiles/automationProfile overrides."""
    for entry in shell_entries(key.split(".")[2], val):
        paths = [p for p in as_list(entry.get("path")) if isinstance(p, str)]
        args = [as_cmd(arg) for arg in as_list(entry.get("args"))]
        yield from check_env(rel, key, entry.get("env"))
        cmd = " ".join(paths[:1] + args).strip()
        reason = next((r for r in (odd_or_local(repo, p, root) for p in paths) if r), None) \
            or danger(" ".join(args))
        if not reason and any(SHELL_INIT_ARGS.match(arg) for arg in args):
            reason = "shell init/command argument"
        if reason:
            yield finding(HIGH, rel, f"{key} ({reason})", cmd)
        elif cmd:
            yield finding(INFO, rel, f"{key} override", cmd)


def flatten(data: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """(dotted key, value) for nested settings; terminal.* objects are kept whole."""
    for key, val in as_dict(data).items():
        full = f"{prefix}{key}"
        if isinstance(val, dict) and not full.startswith("terminal.integrated."):
            yield from flatten(val, full + ".")
        else:
            yield full, val


def handle_settings(repo: Repo, data: dict[str, Any], root: str, rel: str) -> Iterator[Finding]:
    """VS Code settings that auto-run tasks or swap executables, shells or env."""
    for key, val in flatten(data):
        label = clean(key)[:60]
        if key == "task.allowAutomaticTasks" and val in ("on", True):
            # Application-scoped in VS Code: a workspace value is ignored (intent signal only)
            yield finding(INFO, rel, "task.allowAutomaticTasks is on (ignored at workspace scope)")
        elif key.startswith("terminal.integrated.env."):
            yield from check_env(rel, key, val)
        elif TERMINAL_SHELL.match(key):
            yield from check_shell_override(repo, rel, key, val, root)
        elif COMMAND_KEY.search(key) and danger(as_cmd(val)):
            yield finding(HIGH, rel, f"{label} ({danger(as_cmd(val))})", as_cmd(val))
        elif EXEC_KEY.search(key) and not key.startswith("terminal.integrated."):
            for item in (v for v in as_list(val) if isinstance(v, str)):
                reason = odd_or_local(repo, item, root, want_dir=key.endswith("tsdk"))
                if reason:
                    yield finding(HIGH, rel, f"{label} -> {reason}", item)


def dc_commands(value: Any) -> list[str]:
    """devcontainer commands: string, exec-form list, or object of parallel commands."""
    if isinstance(value, dict):
        return [as_cmd(item) for item in value.values()]
    return [as_cmd(value)]


def handle_devcontainer(repo: Repo, data: dict[str, Any], root: str,
                        rel: str) -> Iterator[Finding]:
    """initializeCommand runs on the HOST; the others run inside the container."""
    init = data.get("initializeCommand")
    for cmd in (c for c in (dc_commands(init) if init else []) if c.strip()):
        script = script_target(repo, cmd, (root,))
        reason = auto_run_danger(cmd) or (script and f"runs repo file {script}")
        segments = [seg for seg in re.split(r"&&|\|\||[;|&\n]", cmd) if seg.strip()]
        if not reason and not HOST_UNSAFE.search(cmd) \
                and all(BENIGN_HOST.match(seg) for seg in segments):
            yield finding(INFO, rel, "initializeCommand (host)", cmd)
        else:
            yield finding(HIGH, rel, f"initializeCommand runs on host ({reason or 'command'})", cmd)
    for key in DC_LIFECYCLE:
        for cmd in dc_commands(data.get(key)):
            reason = danger(cmd)
            if reason:
                yield finding(HIGH, rel, f"{key} ({reason})", cmd)
