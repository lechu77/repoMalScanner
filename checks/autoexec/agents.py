"""Agent tool configs: Claude Code, Gemini CLI, Cursor hooks, Codex."""
from __future__ import annotations

import os
import re
from typing import Any, Iterator

from core import (HIGH, INFO, Finding, Repo, as_cmd, as_dict, as_list, clean, finding,
                  script_target, script_verdict)
from editors import check_env
from patterns import auto_run_danger, danger

BROAD_ALLOW = re.compile(r"^(\*|Bash|Bash\(\s*\**\s*(:\s*\**)?\s*\))$")
RISKY_ALLOW = re.compile(
    r"^Bash\(\s*(curl|wget|bash|sh|zsh|python[0-9.]*|node|eval|sudo|powershell|pwsh|npx|uvx)\b",
    re.I)
# Settings whose string value is a command the agent runs
COMMAND_SETTINGS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
                    "toolDiscoveryCommand", "toolCallCommand")
GEMINI_TOOL_COMMANDS = ("discoveryCommand", "callCommand")


def hook_commands(hooks: Any) -> Iterator[tuple[str, str]]:
    """(event, command) pairs from Claude/Gemini (nested) or Cursor (flat) hook tables."""
    for event, entries in as_dict(hooks).items():
        for entry in (as_dict(e) for e in as_list(entries)):
            inner = entry.get("hooks")
            for item in (as_list(inner) if inner is not None else [entry]):
                cmd = as_cmd(as_dict(item).get("command"))
                if cmd:
                    yield str(event), cmd


def agent_command(repo: Repo, rel: str, where: str, cmd: str,
                  roots: tuple[str, ...]) -> Finding:
    """HIGH if the command, or the repo script it runs, is hostile; else INFO."""
    reason = auto_run_danger(cmd)
    script = None if reason else script_target(repo, cmd, roots)
    if script:
        reason = script_verdict(repo, script)
    if reason:
        return finding(HIGH, rel, f"{where} ({reason})", cmd)
    return finding(INFO, rel, where, cmd)


def commands(data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(label, command) for hooks, statusLine and command-valued settings."""
    for event, cmd in hook_commands(data.get("hooks")):
        yield f"hook {clean(event)[:30]}", cmd
    status = as_dict(data.get("statusLine")).get("command")
    if isinstance(status, str):
        yield "statusLine", status
    for key in COMMAND_SETTINGS:
        if isinstance(data.get(key), str) and data[key].strip():
            yield key, data[key]
    tools = as_dict(data.get("tools"))
    for key in GEMINI_TOOL_COMMANDS:
        if isinstance(tools.get(key), str) and tools[key].strip():
            yield f"tools.{key}", tools[key]


def check_permissions(repo: Repo, data: dict[str, Any], root: str, rel: str) -> Iterator[Finding]:
    """Blanket shell permissions and auto-approval of project MCP servers."""
    perms = as_dict(data.get("permissions"))
    for rule in (r.strip() for r in as_list(perms.get("allow")) if isinstance(r, str)):
        if BROAD_ALLOW.match(rule):
            yield finding(HIGH, rel, "permissions.allow grants unrestricted shell", rule)
        elif RISKY_ALLOW.match(rule):
            yield finding(INFO, rel, "permissions.allow pre-approves an interpreter", rule)
    if perms.get("defaultMode") == "bypassPermissions":
        yield finding(HIGH, rel, "permissions.defaultMode is bypassPermissions")
    if data.get("enableAllProjectMcpServers") is True:
        mcp = repo.safe_path(os.path.join(root, ".mcp.json"))
        # Only meaningful when a project .mcp.json exists to be auto-started
        level = HIGH if mcp and os.path.isfile(mcp) else INFO
        yield finding(level, rel, "enableAllProjectMcpServers auto-approves .mcp.json servers")
    elif as_list(data.get("enabledMcpjsonServers")):
        names = ", ".join(map(str, as_list(data.get("enabledMcpjsonServers"))))
        yield finding(INFO, rel, "enabledMcpjsonServers pre-approves", names)


def handle_agent_settings(repo: Repo, data: dict[str, Any], roots: tuple[str, ...],
                          rel: str) -> Iterator[Finding]:
    """.claude/settings*.json, .gemini/settings.json, .cursor/hooks.json."""
    for where, cmd in commands(data):
        yield agent_command(repo, rel, where, cmd, roots)
    yield from check_env(rel, "env", data.get("env"))
    yield from check_permissions(repo, data, roots[0], rel)


def walk_toml(data: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """(dotted key, value) for every leaf of a TOML document."""
    for key, val in as_dict(data).items():
        if isinstance(val, dict):
            yield from walk_toml(val, f"{prefix}{key}.")
        else:
            yield f"{prefix}{key}", val


def handle_codex(text: str, rel: str) -> Iterator[Finding]:
    """.codex/config.toml: notify/MCP commands and sandbox escape settings."""
    import tomllib  # Python 3.11+; ImportError is reported as an unparsed config

    data = as_dict(tomllib.loads(text))
    for key, val in walk_toml(data):
        leaf = key.rsplit(".", 1)[-1]
        if leaf not in ("notify", "command") and not (leaf == "args" and key.startswith("mcp_")):
            continue
        cmd = as_cmd(val)
        if cmd and danger(cmd):
            yield finding(HIGH, rel, f"{clean(key)[:50]} ({danger(cmd)})", cmd)
        elif cmd and leaf == "notify":
            yield finding(INFO, rel, "notify command", cmd)
    if data.get("sandbox_mode") == "danger-full-access":
        yield finding(HIGH, rel, "sandbox_mode is danger-full-access")
    if data.get("approval_policy") == "never":
        yield finding(INFO, rel, "approval_policy is never")
