---
name: unreach
description: Find dead, unused, and orphan code with confidence scores across 16 languages. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, or cleanup before a refactor.
---

# Unreach

Do not guess unused code. Do not crawl the repository. Call the Unreach MCP:

1. `unreach.scan` — findings with `confidence` and `signals`; compact packet by default.
   Covers Python, TypeScript/JS, Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, Swift,
   Dart, Elixir, C/C++, Lua, Perl.
2. `unreach.workflow` — ordered verify → edit → validate → remember steps for this repo's
   languages and frameworks, already ordered by triage verdicts. Read only the files it
   names; follow each `budget_hint`.
3. Act on `block` (≥ 0.85) after one grep. Verify `warn` using the listed signals first.
   `note` is a lead only. Name-precision languages (Java, C#, Swift, …) never reach `block`.
4. Run the validate commands, propose a patch, never delete without explicit approval.
5. `unreach.remember` — record `keep` / `false_positive` / `resolved` so the next session
   skips already-triaged findings.
6. `unreach.explain` — optional paragraph for one finding id. `unreach.languages` — support matrix.
