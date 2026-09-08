# Unreach for Codex

Same engine as the CLI (`unreach mcp` on stdio). Not a second scanner.

## ~/.codex/config.toml

```toml
[mcp_servers.unreach]
command = "unreach"
args = ["mcp"]
```

Install: `pip install -e .` then `unreach scan --mock`.

When the user asks about dead or unused code, call `unreach.scan` then `unreach.plan`. Never delete files.
