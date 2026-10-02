"""Detection patterns shared by every auto-execution handler."""
from __future__ import annotations

import re

WS_PADDING = 40

# Downloaders and network clients (incl. `nc host port` exfiltration)
REMOTE = re.compile(
    r"\b(curl|wget|aria2c|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer"
    r"|bitsadmin|certutil|ncat|netcat|socat|tftp)\b|\bnc\s+-|\bnc\s+[\w.:-]+\s+\d{1,5}\b"
    r"|/dev/tcp/|\bfetch\s*\(|urllib\.request|requests\.(get|post)\s*\(|\bhttps?\.get\s*\("
    r"|DownloadString|DownloadFile|Net\.WebClient", re.I)
# Inline code interpreters and Windows LOLBins. PowerShell only with an inline
# command / encoded payload (a bare `pwsh` word or a `src/powershell` path is benign).
INLINE = re.compile(
    r"\b(node|nodejs|deno|bun)\s+(-e|--eval|-p|--print)\b|\bpython[0-9.]*\s+-[A-Za-z]*c\b"
    r"|\b(perl|ruby)\s+-[A-Za-z]*e\b|\bphp\s+-r\b"
    r"|\b(powershell|pwsh)(\.exe)?(\s+-\w+)*?\s+-(c|command|e|ec|enc|encodedcommand)\b"
    r"|\b(iex|Invoke-Expression)\b|\bosascript\s+-e\b|\b(mshta|rundll32|regsvr32)\b", re.I)
# Obfuscation, dynamic evaluation, pipe into a shell/python, whitespace padding
OBFUSC = re.compile(
    r"\bbase64\b|\batob\s*\(|fromCharCode|FromBase64String|(?<![\w.-])eval\b(?![.-])"
    r"|\bexec\s*\(|\bxxd\s+-r"
    r"|-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|(\\x[0-9a-fA-F]{2}){4,}"
    r"|\|\s*(sudo\s+)?(ba|z|da|k)?sh\b(?![|\\])(?!\)[$|)\\?*+])|\|\s*(sudo\s+)?python[0-9.]*\s*(-\s*)?($|[;&|)])"
    rf"|\S[ \t]{{{WS_PADDING},}}\S", re.I)
# Network, decode or reverse-shell primitives inside a repo file run by an auto-run
# entry (BeaverTail/OtterCookie loaders: axios/got/https + new Function/eval).
SCRIPT_DANGER = re.compile(
    REMOTE.pattern
    + r"|\baxios\b|\bgot\s*\(|node-fetch|\bundici\b|\b(https?|net|tls)\.(request|connect)\s*\("
    r"|require\(\s*[\"'](node:)?(https?|net|tls)[\"']\s*\)"
    r"|from\s+[\"'](node:)?(https?|net)[\"']|Buffer\.from\([^)]*[\"']base64"
    r"|\bbase64\s+(-d|--decode)|b64decode|\batob\s*\(|fromCharCode|FromBase64String"
    r"|\|\s*(sudo\s+)?(ba|z)?sh\b|os\.dup2|pty\.spawn|socket\.socket\("
    r"|(^|[;&|(`]|\$\()\s*[A-Za-z]*\$\{[A-Za-z_][A-Za-z0-9_]*\}[A-Za-z]+\b", re.I | re.M)
# Command word assembled from parameter expansion (`${c}rl`, `c${u}rl`) at command position
VAR_COMMAND = re.compile(
    r"(^|[;&|(`]|\$\()\s*([A-Za-z]*\$\{[A-Za-z_][A-Za-z0-9_]*\}[A-Za-z]+"
    r"|[A-Za-z]+\$[A-Za-z_][A-Za-z0-9_]*)\b", re.M)
EMPTY_QUOTES = re.compile(r"\"\"|''|\\(?=[A-Za-z])")
# Package runners that fetch and run registry code without a version pin
FETCH_RUNNER = re.compile(
    r"\b(?:(npx|bunx|pnpx)\s+(?=[^;&|]*(?:\s-y\b|\s--yes\b|@latest\b))"
    r"|uvx\s+|(?:pnpm|yarn)\s+dlx\s+)((?:-\S+\s+)*)([^\s;&|]+)")
PINNED = re.compile(r"(?<!^)@\d|==\d")


def normalize(cmd: str) -> str:
    """Undo trivial shell quoting splits (`cu""rl`, `s''h`, `c\\url`) before matching."""
    return EMPTY_QUOTES.sub("", cmd).replace("\\\n", " ")


def danger(cmd: str) -> str | None:
    """Reason a command downloads, inlines or obfuscates code, or None.

    `sh -c` / `cmd /c` wrappers are not flagged themselves (VS Code's own repo
    uses them in folderOpen tasks); the wrapped command text is analysed.
    """
    texts = (cmd, normalize(cmd))
    for name, pattern in (("downloader", REMOTE), ("inline interpreter", INLINE),
                          ("obfuscation/eval/pipe-to-shell", OBFUSC),
                          ("command name built from variables", VAR_COMMAND)):
        if any(pattern.search(text) for text in texts):
            return name
    return None


def unpinned_fetch(cmd: str) -> str | None:
    """Reason a command fetches and runs an unpinned registry package, or None."""
    for match in FETCH_RUNNER.finditer(cmd):
        pkg = match.group(3)
        if pkg.endswith("@latest") or not PINNED.search(pkg):
            return f"unpinned remote package {pkg}"
    return None


def auto_run_danger(cmd: str) -> str | None:
    """danger() plus unpinned package fetches (contexts that run unprompted)."""
    return danger(cmd) or unpinned_fetch(cmd)
