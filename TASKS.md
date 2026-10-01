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
- [ ] **init_setup**: Initial project structure and setup baseline
