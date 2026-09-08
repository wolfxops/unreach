---
name: unreach
description: Find dead, unused, and orphan code. Use when the user asks about unused exports, orphan files, unreachable code, or dead dependencies.
---

# Unreach

Unreach is a deterministic dead-code scanner. Do not guess unused code.

When the user asks about dead, unused, orphan, or unreachable code:

1. Call MCP tool `unreach.scan` (optional `path`, `mock` for the fixture).
2. Call MCP tool `unreach.plan` for an ordered, non-destructive cleanup list.
3. Optionally call `unreach.explain` with a finding `id`.
4. Never delete files or apply a patch unless the user explicitly asks after reviewing the plan.

High-confidence findings are `block`. Guessed findings are `warn` or `note`.
