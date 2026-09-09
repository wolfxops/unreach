---
name: unreach
description: Find dead, unused, and orphan code with confidence scores, a judge/devil's advocate layer, and tabular output across 16 languages. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, scheduler jobs, or cleanup before a refactor.
---

# Unreach

Unreach is a deterministic dead-code scanner with a confidence score, a judge /
devil's advocate layer, a guided workflow, budgeted triage, and long-term memory.
Do not guess unused code and do not crawl the repository. Present findings as the
markdown table the tools return; do not rewrite them as prose.

When the user asks about dead, unused, orphan, unreachable, or "is this a cron job
/ hidden feature" code:

1. Call MCP `unreach.judge` (table by default) or `unreach.scan` with
   `format: "table"` (optional `path`; `mock` for the fixture). Show the table
   as-is. Columns: sev, confidence, kind, target, judge (`remove` / `verify` /
   `keep`), devil's advocate (hypothesis + `file:line`), next check, security,
   effort. Works for Python, TypeScript/JS, Go, Rust, Java, Kotlin, Scala, C#,
   Ruby, PHP, Swift, Dart, Elixir, C/C++, Lua, Perl.
2. Call MCP `unreach.workflow` and follow its steps in order. Only read the files
   and grep the patterns it names. The first verify step is the judge's
   `next_check`. Findings ruled `keep` (scheduler, container, serverless, CI,
   flag, keep-marker) are already skipped. `security_first` findings go first.
3. `remove` + `quick win` after one grep and the validate commands. `verify`
   means open the cited `file:line`. `keep` means record `unreach.remember keep`
   if you agree. `note` findings are leads only.
   Name-precision languages (Java, Kotlin, Scala, C#, PHP, Swift, Elixir) never
   reach `block`.
4. Do not call `unreach.triage` separately unless the user asks; the workflow
   already ran it. The model is a *second* devil's advocate on warn findings
   only (one batched call, cached, heuristic without a key).
5. Run the workflow's validate commands. Propose a patch; never delete without
   explicit approval. Never print secret values — the judge reports line numbers.
6. Call MCP `unreach.remember` with `keep`, `false_positive`, or `resolved` for
   each reviewed finding so the next session is cheaper.
7. Optionally call `unreach.explain` with a finding `id` (includes the judge
   rationale), or `unreach.languages` for the support matrix.
