"""VS Code tasks (tasks.json and *.code-workspace) that run without a click."""
from __future__ import annotations

from typing import Any, Iterator

from core import (HIGH, INFO, MAX_LIST, Finding, Repo, as_cmd, as_dict, as_list, clean,
                  expand_runner, finding, script_target, script_verdict)
from editors import check_env, handle_settings
from patterns import auto_run_danger

TASK_OS_KEYS = ("windows", "osx", "linux")
# runOptions.runOn values VS Code honours case-insensitively (RunOnOptions.fromString)
AUTO_RUN_ON = {"folderopen": "folderOpen", "worktreecreated": "worktreeCreated"}


def config_scopes(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The tasks.json document plus its top-level windows/osx/linux sections."""
    return [data] + [data[k] for k in TASK_OS_KEYS if isinstance(data.get(k), dict)]


def all_tasks(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Tasks from `tasks` and from the per-OS `windows/osx/linux.tasks` arrays."""
    return [task for scope in config_scopes(data) for task in as_list(scope.get("tasks"))
            if isinstance(task, dict)]


def task_variants(task: dict[str, Any]) -> list[dict[str, Any]]:
    """The task plus its per-OS overrides."""
    return [task] + [task[k] for k in TASK_OS_KEYS if isinstance(task.get(k), dict)]


def task_commands(task: dict[str, Any], scopes: list[dict[str, Any]]) -> Iterator[str]:
    """Every command line a task can run: per-OS overrides plus inherited globals
    (top-level and per-OS `command`, `args`, `options.shell`)."""
    base_cmd = as_cmd(task.get("command"))
    if not base_cmd and task.get("type") == "npm" and isinstance(task.get("script"), str):
        base_cmd = f"npm run {task['script']}"
    seen: set[str] = set()
    for var in task_variants(task):
        for scope in scopes:
            shell = as_dict(as_dict(var.get("options")).get("shell")) \
                or as_dict(as_dict(task.get("options")).get("shell")) \
                or as_dict(as_dict(scope.get("options")).get("shell"))
            cmd = as_cmd(var.get("command")) or base_cmd or as_cmd(scope.get("command"))
            args = var.get("args", task.get("args", scope.get("args")))
            parts = [as_cmd(shell.get("executable")), as_cmd(shell.get("args")), cmd, as_cmd(args)]
            line = " ".join(part for part in parts if part)
            if line and line not in seen:
                seen.add(line)
                yield line


def task_envs(task: dict[str, Any], scopes: list[dict[str, Any]]) -> list[Any]:
    """options.env of the task, its per-OS overrides and the inherited globals."""
    return [as_dict(var.get("options")).get("env") for var in task_variants(task) + scopes]


def depends_closure(task: dict[str, Any], by_label: dict[str, Any]) -> list[dict[str, Any]]:
    """The task and every task reachable through dependsOn (they run with it)."""
    chain, todo, seen = [], [task], set()
    while todo and len(seen) < MAX_LIST:
        cur = todo.pop()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        chain.append(cur)
        for dep in as_list(cur.get("dependsOn")):
            dep_obj = as_dict(dep)
            name = dep if isinstance(dep, str) else dep_obj.get("label", dep_obj.get("task"))
            if isinstance(name, str) and name in by_label:
                todo.append(by_label[name])
    return chain


def command_reason(repo: Repo, line: str, root: str) -> str | None:
    """Why an auto-run command line is hostile (inline or via the repo file it runs)."""
    full = expand_runner(repo, line, root)
    script = script_target(repo, full, (root,))
    return auto_run_danger(full) or (script and script_verdict(repo, script))


def handle_tasks(repo: Repo, data: dict[str, Any], root: str, rel: str) -> Iterator[Finding]:
    """Tasks with runOptions.runOn folderOpen / worktreeCreated (run without a click).

    Command lines are analysed once per file (memo), so dependsOn fan-out stays linear.
    """
    scopes = config_scopes(data)
    tasks = all_tasks(data)
    by_label = {t["label"]: t for t in tasks if isinstance(t.get("label"), str)}
    memo: dict[str, str | None] = {}
    per_task: dict[int, list[str]] = {}
    for task in tasks:
        run_on = AUTO_RUN_ON.get(str(as_dict(task.get("runOptions")).get("runOn", "")).lower())
        if not run_on:
            continue
        where = f"{run_on} task '{clean(task.get('label', '?'))[:40]}'"
        chain = depends_closure(task, by_label)
        for t in chain:
            if id(t) not in per_task:
                per_task[id(t)] = list(task_commands(t, scopes))
        lines = list(dict.fromkeys(line for t in chain for line in per_task[id(t)]))
        for line in lines:
            if line not in memo:
                memo[line] = command_reason(repo, line, root)
        hit = next(((line, memo[line]) for line in lines if memo[line]), None)
        env_hits = [] if hit else [f for t in chain for env in task_envs(t, scopes)
                                   for f in check_env(rel, f"{where} options.env", env)
                                   if f.level == HIGH]
        if hit:
            yield finding(HIGH, rel, f"{where} ({hit[1]})", hit[0])
        elif env_hits:
            yield env_hits[0]
        else:
            yield finding(INFO, rel, where, " ; ".join(lines) or "(none)")


def handle_workspace(repo: Repo, data: dict[str, Any], root: str, rel: str) -> Iterator[Finding]:
    """*.code-workspace: embedded settings and tasks."""
    yield from handle_settings(repo, as_dict(data.get("settings")), root, rel)
    yield from handle_tasks(repo, as_dict(data.get("tasks")), root, rel)
