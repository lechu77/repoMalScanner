# Architecture Standards

## Principles
- Separate concerns: data layer, domain/business logic, presentation/interface.
- Keep business logic strictly out of the presentation layer.
- Use typed interfaces: use type hints (Python), TypeScript types, or equivalent.
- Handle errors explicitly: define and use domain-specific exceptions, never use bare except/catch.
- Favor immutable data.
- Ensure atomic writes for persistence (use a temporary file and rename).
- Add no external dependencies unless explicitly approved in TASKS.md.

## Prohibited Patterns
- No print()/console.log() for error reporting. Use proper logging or stderr.
- No I/O inside domain/business logic.
- No file reads/writes inside loops without batching.
- No global mutable state.
- No hardcoded paths, URLs, or credentials.
- No suppressing exceptions silently (do not use empty catch blocks).

## Project-Specific Architecture

`repoMalScanner` is structured into 4 sequential layers:

1. **Input & Isolation Layer**:
   - Parses CLI flags (`-r`, `--repo`, `--save`, `--no-interactive`, positional arguments).
   - Differentiates remote git repositories (shallow cloned into temporary directory) from local directories (scanned in-place).
   - Manages process-isolated sandbox directories (`tmp/scan-$$`) with POSIX `EXIT` traps for zero-residual cleanup.

2. **Analysis Engine (13 specialized, non-overlapping checks)**:
   - **Secrets & Static Credentials**: `gitleaks` for code and git history.
   - **Live Verified Secrets**: `trufflehog` with `--only-verified` filter.
   - **Supply Chain Security**: `semgrep` configured strictly with `p/supply-chain`.
   - **Behavioral Malware**: `yara` with behavioral rules (co-occurrence and execution proximity required).
   - **Developer & AI Credential Access**: Contextual grep for `~/.claude/`, `~/.cursor/`, `~/.ssh/`, and LLM API keys (`OPENAI_API_KEY`, etc.).
   - **Remote Code Execution**: Execution-bound detection distinguishing shell commands from documentation strings.
   - **Exfiltration Channels**: Regex targeting webhook endpoints and suspicious egress domains.
   - **Compiled Binaries**: `strings` analysis detecting socket syscalls in ELF, Mach-O, and PE files.
   - **Sensitive Files**: Discovery of committed `.env` variations.
   - **Lifecycle Script Abuse**: AST/Regex evaluation of `preinstall`, `postinstall`, `prepare` in `package.json` and `setup.py`.
   - **Dependency Typosquatting**: Levenshtein distance ≤1 against popular npm and PyPI packages.
   - **Agent & MCP Configurations**: Deep inspection of `mcpServers` across `mcp.json`, `claude_desktop_config.json`, and `.cursor/mcp.json` for unpinned executions and shell wrappers.
   - **Python Startup & Serialization**: Detection of `.pth` executable hooks and unsafe deserialization opcodes in `.pkl`, `.pt`, `.joblib`.

3. **Risk Scoring Engine**:
   - Multi-tier weights: High (30 pts, triggers non-interactive exit 1), Medium (20 pts), Low (10 pts).
   - Normalized 0–100 risk score based on cumulative triggered finding weights.

4. **Reporting & Presentation Layer**:
   - Formatted ANSI table with color-coded severity.
   - Machine and human-readable Markdown report generator in `out/`.
