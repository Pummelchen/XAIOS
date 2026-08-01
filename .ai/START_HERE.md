<!--
AI onboarding file.
Mode: refresh
Indexed base commit: 8404c1ec1b76c02157bb08d8a3a9466a93e5c2cb
Last refreshed: 2026-08-01
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Start here

Paste this prompt into a fresh AI coding session for XAIOS:

```text
You are working in the XAIOS repository. Start by reading AI_INDEX.md, AGENTS.md, .ai/PROJECT_MAP.md, .ai/COMMANDS.md, .ai/TESTING.md, and .ai/KNOWN_UNKNOWNS.md. For model work also read docs/MODEL-V2-SPECIFICATION.md, docs/ARCHITECTURE-ADAPTERS.md, docs/HARDWARE-BACKENDS.md, and docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md. Then inspect the current source files relevant to my task before proposing or making edits.

When you summarize the repo, separate verified facts, assumptions, inferences, unknowns, and conflicts. Treat onboarding docs as guidance only; current source code and build/test config are the source of truth.

Before editing, produce a concise plan with files to inspect/change and validations to run. Prefer small, reviewable changes. Do not modify generated build artifacts, do not create vendor/model-specific AI files, and do not make hardware performance claims from QEMU-only results. The model-v1 path is a fixture; production decode must fail explicitly until real execution exists.

After editing, report changed files, tests or commands run, tests skipped with reasons, and remaining risks.
```

## Reading order

1. `AI_INDEX.md`
2. `AGENTS.md`
3. `.ai/PROJECT_MAP.md`
4. `.ai/ARCHITECTURE.md`
5. `.ai/COMMANDS.md`
6. `.ai/TESTING.md`
7. `.ai/SECURITY.md`
8. `.ai/KNOWN_UNKNOWNS.md`

For large tasks, do not load every file at once. Start from the task map in `AI_INDEX.md`, then inspect the narrow source slice.

## Required behavior

- Inspect current source/config before editing.
- Cite source file paths in reasoning.
- Keep QEMU correctness evidence separate from hardware performance claims.
- Preserve human documentation edits when refreshing onboarding files.
- Require explicit human authorization before changing license terms, security policy, or performance claims without measurements.
