# Tasks Backlog

> Managed autonomously by the **Leader** agent.
> You do NOT need to edit this file manually unless you want to add or reorder tasks.
> You can simply tell your AI in chat what you want to build, and the Leader will break it down here.

## Invariant
- Maximum **1** task in progress (`[/]`) at any time.

---

## Tasks

<!--
Format:
- [ ] [task_slug] Task title — Description and acceptance criteria
- [/] [task_slug] Task in progress (max 1)
- [x] [task_slug] Task completed (approved by Reviewer and Security Reviewer)
- [-] [task_slug] Task blocked (requires human decision)
-->

- [x] **skillspector_gate**: Integrate NVIDIA SkillSpector autonomous skill gate
- [x] **cli_repo_arg_and_fp_reduction**: CLI --repo execution improvement and false positive reduction in scanner rules
- [x] **stream_and_agent_protections**: Eliminate redundant checks (detect-secrets, raw HTTP grep) and add AI/MCP/agent attack vector checks
- [x] **fp_reduction_and_precision_tuning**: Refine YARA obfuscation, RCE targets, SSH identity filters, and setup.py checks to eliminate false positives
- [/] **autoexec_on_open**: Detect auto-execution on repo open — .vscode/tasks.json runOn folderOpen, .devcontainer postCreateCommand/postStartCommand, .envrc, git hooks (core.hooksPath instructions), .claude/settings.json hooks, .vscode/mcp.json
- [ ] **local_scan_guard**: Refuse local-path and file:// targets by default (they can carry an attacker-controlled .git); require explicit --allow-local with a visible warning; remote URLs (https/ssh/git@) are the default safe path; update tests to use --allow-local, README usage
- [ ] **agent_prompt_injection**: Detect prompt injection in agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, .cursor/rules, copilot-instructions.md) — invisible Unicode (tag chars, zero-width, bidi) and hostile directives
- [ ] **known_malicious_deps**: Integrate osv-scanner (MAL-* advisories) and guarddog; flag lockfile deps resolved from git/tarball/non-registry URLs
- [ ] **hiding_techniques**: Detect whitespace-padded payloads (long leading spaces), extension/magic-byte mismatch, obfuscated JS (_0x identifiers/entropy), Trojan Source bidi in code, password-protected archives and source-less binaries
- [ ] **repo_reputation**: gh api reputation signals — repo/owner age, star velocity, README pointing to exe/password zip, clone-of-popular-repo diff vs upstream
- [ ] **pickle_allowlist_hardening**: Follow-ups from security review — restrict torch.nn.modules rule to real module classes; tighten trust of repo-local names (aliased imports like `Popen as Runner`)
- [ ] **init_setup**: Initial project structure and setup baseline
