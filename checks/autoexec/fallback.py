"""Lenient scan of configs that strict JSON rejects but VS Code/devcontainers accept.

jsonc-parser (VS Code, devcontainers CLI) recovers from missing commas, trailing
garbage and raw newlines in strings, so a parse failure must not hide a command.
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterator

from core import HIGH, Finding, Repo, finding, script_target, script_verdict, strip_jsonc
from patterns import auto_run_danger

STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"', re.S)
MAX_LITERALS = 20_000


def literals(text: str) -> Iterator[str]:
    """Every JSON string literal in comment-stripped text (decoded when valid)."""
    for count, match in enumerate(STRING_LITERAL.finditer(strip_jsonc(text))):
        if count >= MAX_LITERALS:
            return
        raw = match.group(1)
        try:
            yield json.loads(f'"{raw}"')
        except ValueError:
            yield raw  # raw newline or bad escape: the tolerant parser keeps the text


def lenient_scan(repo: Repo, text: str, path: str, rel: str) -> Iterator[Finding]:
    """HIGH for any dangerous command-like literal in an unparseable config."""
    roots = (os.path.dirname(os.path.dirname(path)), os.path.dirname(path))
    for value in literals(text):
        # Only command-like literals (`node x.woff2`) are resolved, not bare paths
        script = script_target(repo, value, roots) if " " in value.strip() else None
        reason = auto_run_danger(value) or (script and script_verdict(repo, script))
        if reason:
            yield finding(HIGH, rel, f"unparseable config (tools parse it leniently) ({reason})",
                          value)
            return
