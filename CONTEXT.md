# CONTEXT

## Problem

AI-assisted coding ("vibe coding") has lowered the barrier for publishing malicious repositories. Attackers embed credential theft, data exfiltration, and supply chain hooks in code that looks legitimate — similar to the OpenClaw browser extension attack vector.

## Scope

This scanner is **not** a vulnerability scanner. It does not check for CVEs, outdated dependencies, or insecure coding patterns. It focuses exclusively on:

- Code that **steals credentials** (browser storage, OS keychain, SSH/AWS keys, high-entropy tokens)
- Code that **exfiltrates data** to external endpoints (webhooks, Telegram, Discord, Pastebin, ngrok)
- Code that **executes remote payloads** (`curl | bash`, `eval(fetch(...))`)
- Code that **obfuscates behavior** at runtime (base64 decode, `fromCharCode`)
- **Supply chain hooks** that run on install (`postinstall`, `preinstall`)
- **Compiled binaries** with embedded network syscalls

## Target User

A developer or security-conscious engineer who wants to quickly audit a public GitHub repo before cloning, running, or contributing to it.

## Non-Goals

- No dependency vulnerability scanning (CVEs)
- No SAST for code quality or security-by-design
- No license compliance
- No container/image scanning
- No dynamic analysis / sandboxed execution
