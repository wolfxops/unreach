---
name: unreach
description: Find dead, unused, and orphan code with confidence scores, a judge/devil's advocate layer, and tabular output across 16 languages. Use when the user asks about unused exports, orphan files, unreachable code, dead dependencies, scheduler jobs, or cleanup before a refactor.
---

# Unreach

Do not guess unused code. Do not crawl the repository. Present findings as the markdown table the tools return — never rewrite them as prose.

Call the Unreach MCP:

1. `unreach.judge` (default) or `unreach.scan` with `format: "table"`.
   Render the table as-is. Columns: sev, confidence, kind, target, judge
   (`remove` / `verify` / `keep`), devil's advocate (named hypothesis + file:line),
   next check, security, effort.
   Covers Python, TypeScript/JS, Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, Swift,
   Dart, Elixir, C/C++, Lua, Perl.
2. Treat `keep` as skip: a scheduler, Dockerfile/Procfile, serverless handler, CI
   script, reflection site, feature flag, or `unreach: keep` marker named it.
   Offer `unreach.remember` with `keep` if the user agrees.
3. Treat `remove` + `quick win` as first. If `security` is `remove_first`, handle
   those before anything else (dead eval/pickle/`verify=False`/secret-like literals
   are unmonitored attack surface). Values are never shown — only line numbers.
4. `unreach.workflow` — ordered verify → edit → validate → remember. Follow
   `next_check` / `budget_hint`. Read only the files it names. Findings the judge
   ruled `keep` are already omitted.
5. Run the validate commands, propose a patch, never delete without explicit approval.
6. `unreach.remember` — record `keep` / `false_positive` / `resolved`.
7. Optional: `unreach.explain` (includes the judge rationale), `unreach.languages`.
