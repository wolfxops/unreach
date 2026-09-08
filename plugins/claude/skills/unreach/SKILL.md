---
name: unreach
description: Find dead, unused, and orphan code with confidence scores across 16 languages. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, or cleanup before a refactor.
---

# Unreach

Unreach is a deterministic dead-code scanner with a confidence score per finding,
a guided workflow, budgeted triage, and long-term memory. Do not guess unused code
and do not crawl the repository; the workflow tells you exactly what to read.

When the user asks about dead, unused, orphan, or unreachable code:

1. Call MCP `unreach.scan` (optional `path`; `mock` for the fixture). The packet is compact:
   full evidence for new findings, one-liners for findings already seen, nothing for
   findings previously marked `keep`/`false_positive`. Works for Python, TypeScript/JS,
   Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, Swift, Dart, Elixir, C/C++, Lua, Perl.
2. Call MCP `unreach.workflow` and follow its steps in order. Only read the files and grep
   the patterns it names; respect each step's `budget_hint`. Steps carry a `triage` label
   (`likely_dead` / `verify` / `keep`) — findings triaged `keep` are already skipped.
3. Treat `block` (confidence ≥ 0.85) as actionable after one grep. Treat `warn` as
   needs-verification: inspect the `signals` (framework decorator, string reference,
   dynamic import, whole-module import) before acting. `note` findings are leads only.
   Name-precision languages (Java, Kotlin, Scala, C#, PHP, Swift, Elixir) never reach `block`.
4. Do not call `unreach.triage` separately unless the user asks; the workflow already ran it
   (one batched model call at most, cached in memory, heuristic when no key is set).
5. Run the workflow's validate commands for the detected stack. Propose a patch; never
   delete without explicit approval.
6. Call MCP `unreach.remember` with `keep`, `false_positive`, or `resolved` for each reviewed
   finding so the next session is cheaper.
7. Optionally call `unreach.explain` with a finding `id`, or `unreach.languages` to show the
   support matrix.
