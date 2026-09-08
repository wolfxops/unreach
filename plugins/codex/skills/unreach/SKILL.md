---
name: unreach
description: Find dead, unused, and orphan code with confidence scores via the Unreach MCP.
---

When the user asks about dead/unused/orphan code: call MCP `unreach.scan`, then `unreach.workflow`, and follow its steps (read only the files it names). Act on `block` findings (confidence ≥ 0.85); verify `warn`/`note` via their `signals`. Run the validate commands, propose a patch, never delete automatically. Finish with `unreach.remember` for each reviewed finding so the next session costs fewer tokens.
