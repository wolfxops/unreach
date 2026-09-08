---
name: unreach
description: Find dead, unused, and orphan code with confidence scores. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, or cleanup before a refactor.
---

# Unreach

Do not guess unused code. Do not crawl the repository. Call the Unreach MCP:

1. `unreach.scan` — findings with `confidence` and `signals`; compact packet by default.
2. `unreach.workflow` — ordered verify → edit → validate → remember steps for this repo's
   languages and frameworks. Read only the files it names.
3. Act on `block` (≥ 0.85). Verify `warn`/`note` using the listed signals first.
4. Run the validate commands, propose a patch, never delete without explicit approval.
5. `unreach.remember` — record `keep` / `false_positive` / `resolved` so the next session
   skips already-triaged findings.
6. `unreach.explain` — optional paragraph for one finding id.
