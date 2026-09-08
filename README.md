# Unreach

Find the code your agents keep rewriting around.

Dead-code scan for Claude, Cursor, and Codex.

One engine, not three products:

1. Deterministic CLI scanner (`unreach scan`)
2. One stdio **MCP** server (`unreach.scan`, `unreach.explain`, `unreach.plan`)
3. Thin plugins: **Claude Code**, **Cursor**, **Codex**

Dead-code detection does **not** require an LLM. The model only explains and ranks. Auto-delete is forbidden; `unreach.plan` emits an ordered suggestion list only.

## Install

```bash
pip install -e .
unreach scan --mock
```

Python 3.10+. `--mock` works with zero API keys.

```bash
pip install -e ".[dev]"
pytest -q
unreach scan fixtures/deadapp --mock
```

## CLI

```bash
unreach scan [PATH] [--mock] [--format json|md] [--lang auto|py|ts]
unreach plan [PATH] [--mock]
unreach mcp                       # stdio MCP
unreach explain FINDING_ID        # optional LLM; heuristic if no key
```

Exit `0` if no high-confidence dead code, `1` if any `block` finding, `2` on tool error.

v0 languages: Python first, TypeScript import graph second.

### Finding schema

```python
Finding(
  id: str,
  kind: str,          # unused_export | orphan_file | unused_dep | unreachable
  severity: str,      # block | warn | note
  path: str,
  symbol: str | None,
  why: str,
  evidence: list[str],
)
```

High-confidence findings only in `block`. Guessed findings are `warn` / `note`.

The fixture `fixtures/deadapp` produces at least:

- `pkg/orphan.py` — `orphan_file` / `block`
- `dead_symbol` — `unused_export` / `block`

## MCP

```bash
unreach mcp
```

| Tool | Input | Output |
|---|---|---|
| `unreach.scan` | `{ path?: string }` | findings JSON |
| `unreach.explain` | `{ id: string }` | paragraph (heuristic if no key) |
| `unreach.plan` | `{ path?: string }` | ordered deletions/refactors, **no file writes** |

OpenAI-compatible HTTP is used only if `explain` is called and `UNREACH_API_KEY` or `OPENAI_API_KEY` is set. No vendor SDKs.

## Plugins

Same engine. No second scanner.

### Claude Code

```text
/plugin marketplace add wolfxops/unreach
/plugin install unreach
```

Manifest: `plugins/claude/.claude-plugin/plugin.json`. Skill `unreach`: when the user asks about dead/unused/orphan code, call MCP `unreach.scan` then `unreach.plan`.

### Cursor

Manifest: `plugins/cursor/.cursor-plugin/plugin.json`. Skill + rule: do not guess unused code; call the MCP.

```json
{
  "mcpServers": {
    "unreach": {
      "command": "unreach",
      "args": ["mcp"]
    }
  }
}
```

### Codex

See `plugins/codex/README.md`. Stdio command for `~/.codex/config.toml`:

```toml
[mcp_servers.unreach]
command = "unreach"
args = ["mcp"]
```

## GitHub Action

```yaml
- uses: wolfxops/unreach@main
  with:
    path: .
```

## Docs

GitHub Pages: enable Settings → Pages → Branch: main → folder: `/docs`

Site: https://wolfxops.github.io/unreach/

## House map

- **Cosen** — runtime cost, traces, security
- **Quorum** — pre-merge four-desk PR review
- **Unreach** — whole-tree unused/unreachable code in the editor

## License

Apache-2.0. Vivek Singh, Pune. X: [wolfxops](https://x.com/wolfxops)
