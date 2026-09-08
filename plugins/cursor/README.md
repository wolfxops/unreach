# Unreach for Cursor

Same engine as the CLI. Do not guess unused code; call the MCP.

## MCP

Add to `.cursor/mcp.json` (project) or Cursor MCP settings:

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

Install the CLI first: `pip install -e .` then `unreach scan --mock`.

Skill: `skills/unreach/SKILL.md`. Rule: `rules/unreach.mdc`.
