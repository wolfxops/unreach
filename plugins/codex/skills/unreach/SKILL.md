---
name: unreach
description: Find dead, unused, and orphan code with confidence scores, a judge/devil's advocate layer, and tabular MCP output across 16 languages via the Unreach MCP.
---

When the user asks about dead/unused/orphan code: call MCP `unreach.judge` (markdown table by default) or `unreach.scan` with `format: "table"`, and present that table as-is (sev, confidence, judge `remove|verify|keep`, devil's advocate with file:line, next check, security, effort). Then `unreach.workflow` — follow its steps (read only the files it names; the first verify step is the judge's next check; `keep` findings are skipped; `security_first` goes first). Act on `remove` + `quick win` after one grep; open the cited file:line for `verify`; `remember keep` for scheduler/entry/flag hits. Run the validate commands for the detected stack, propose a patch, never delete automatically, never print secret values. Finish with `unreach.remember`.
