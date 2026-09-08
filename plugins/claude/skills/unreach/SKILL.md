---
name: unreach
description: Find dead, unused, and orphan code with confidence scores. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, or cleanup before a refactor.
---

# Unreach

Unreach is a deterministic dead-code scanner with a confidence score per finding and
long-term memory. Do not guess unused code and do not crawl the repository.

When the user asks about dead, unused, orphan, or unreachable code:

1. Call MCP `unreach.scan` (optional `path`; `mock` for the fixture). The packet is compact:
   full evidence for new findings, one-liners for findings already seen, nothing for
   findings previously marked `keep`/`false_positive`.
2. Call MCP `unreach.workflow` and follow its steps in order. Only read the files and
   grep the patterns it names.
3. Treat `block` (confidence ≥ 0.85) as actionable; treat `warn`/`note` as needs-verification.
   Inspect the `signals` (framework decorator, string reference, dynamic import) before acting.
4. Run the workflow's validate commands. Propose a patch; never delete without explicit approval.
5. Call MCP `unreach.remember` with `keep`, `false_positive`, or `resolved` for each reviewed
   finding so the next session is cheaper.
6. Optionally call `unreach.explain` with a finding `id` for a paragraph.
