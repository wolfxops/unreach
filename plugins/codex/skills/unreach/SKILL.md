---
name: unreach
description: Find dead, unused, and orphan code with confidence scores across 16 languages via the Unreach MCP.
---

When the user asks about dead/unused/orphan code: call MCP `unreach.scan`, then `unreach.workflow`, and follow its steps (read only the files it names; respect `budget_hint`; steps are already ordered by triage verdicts). Act on `block` findings (confidence ≥ 0.85) after one grep; verify `warn` via their `signals`; treat `note` as a lead. Run the validate commands for the detected stack (pytest, tsc, go test, cargo test, gradlew, dotnet, rspec, phpunit, swift test, flutter test, mix test…), propose a patch, never delete automatically. Finish with `unreach.remember` for each reviewed finding so the next session costs fewer tokens.
