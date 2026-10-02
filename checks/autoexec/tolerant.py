"""Error-tolerant JSONC parser mirroring VS Code's jsonc-parser recovery.

VS Code (tasks.json, settings.json) and the devcontainers CLI parse with
jsonc-parser and ignore its error list: missing commas or colons, stray
brackets, unexpected tokens, raw control characters in strings and trailing
content are all recovered. This parser yields the same best-effort tree so a
one-character syntax error cannot hide a command from the normal handlers.
Input is comment-stripped JSONC text (core.strip_jsonc).
"""
from __future__ import annotations

import json
import re
from typing import Any

MAX_DEPTH = 200
TOKEN = re.compile(
    r'\s*(?:(?P<punct>[{}\[\]:,])|"(?P<str>(?:[^"\\]|\\.)*)(?:"|$)'
    r"|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(?P<word>[A-Za-z_]\w*)|(?P<other>\S))", re.S)
LITERALS = {"true": True, "false": False, "null": None}


class TolerantError(ValueError):
    """Raised when nesting exceeds MAX_DEPTH (the file is then reported unparsed)."""


def tokenize(text: str) -> list[tuple[str, Any]]:
    """(kind, value) tokens; strings decoded leniently, unknown characters kept as 'other'."""
    tokens: list[tuple[str, Any]] = []
    for match in TOKEN.finditer(text):
        kind = match.lastgroup
        if kind is None:
            continue
        raw = match.group(kind)
        if kind == "str":
            try:
                raw = json.loads(f'"{raw}"', strict=False)
            except ValueError:
                pass  # invalid escape: jsonc-parser keeps the text as is
        elif kind == "num":
            raw = float(raw) if any(c in raw for c in ".eE") else int(raw)
        elif kind == "word":
            kind, raw = ("lit", LITERALS[raw]) if raw in LITERALS else ("other", raw)
        tokens.append((kind, raw))
    return tokens


class Parser:
    """Recursive-descent parser that skips what it cannot use instead of failing."""

    def __init__(self, tokens: list[tuple[str, Any]]) -> None:
        self.tokens, self.pos = tokens, 0

    def peek(self) -> tuple[str, Any]:
        """Current token, or ('eof', None)."""
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ("eof", None)

    def value(self, depth: int) -> Any:
        """Parse one value; an unexpected token is skipped and yields None."""
        if depth > MAX_DEPTH:
            raise TolerantError("nesting too deep")
        kind, raw = self.peek()
        if kind == "eof":
            return None
        self.pos += 1
        if (kind, raw) == ("punct", "{"):
            return self.obj(depth + 1)
        if (kind, raw) == ("punct", "["):
            return self.arr(depth + 1)
        return raw if kind in ("str", "num", "lit") else None

    def obj(self, depth: int) -> dict[str, Any]:
        """Object body: missing commas/colons and stray tokens are tolerated."""
        out: dict[str, Any] = {}
        while True:
            kind, raw = self.peek()
            if kind == "eof" or (kind, raw) == ("punct", "}"):
                self.pos += kind != "eof"
                return out
            if kind != "str":
                self.pos += 1  # stray ',', ']', ':' or garbage
                continue
            self.pos += 1
            if self.peek() == ("punct", ":"):
                self.pos += 1
            if self.peek()[0] == "str" and self._next_is_colon():
                out[raw] = None  # missing value: the next string is a key
                continue
            out[raw] = self.value(depth)

    def _next_is_colon(self) -> bool:
        nxt = self.pos + 1
        return nxt < len(self.tokens) and self.tokens[nxt] == ("punct", ":")

    def arr(self, depth: int) -> list[Any]:
        """Array body: missing commas and stray tokens are tolerated."""
        out: list[Any] = []
        while True:
            kind, raw = self.peek()
            if kind == "eof" or (kind, raw) == ("punct", "]"):
                self.pos += kind != "eof"
                return out
            if kind == "punct" and raw in (",", ":", "}"):
                self.pos += 1
                continue
            out.append(self.value(depth))


def parse_tolerant(text: str) -> dict[str, Any]:
    """Best-effort object from broken JSONC; leading garbage and trailing content ignored."""
    parser = Parser(tokenize(text))
    while parser.peek()[0] != "eof":
        if parser.peek() == ("punct", "{"):
            parser.pos += 1
            return parser.obj(1)
        parser.pos += 1
    return {}
