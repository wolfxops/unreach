# Unreach for Claude Code

Same engine as the CLI: `unreach mcp` on stdio.

## Marketplace

```text
/plugin marketplace add wolfxops/unreach
/plugin install unreach
```

## MCP (manual)

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

When the user asks about dead or unused code, call `unreach.scan` then `unreach.plan`. Never delete files.
