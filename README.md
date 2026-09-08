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

## Built around the pain points

Research across knip / vulture / ts-prune issue trackers and agent post-mortems
(see [docs/research.html](https://wolfxops.github.io/unreach/research.html)) keeps
surfacing the same complaints. Each one maps to a mechanism:

| Pain point | Mechanism |
|---|---|
| False positives from dynamic imports, `getattr`, plugin registries, string-named modules | **Confidence signals** lower the score; only ≥ 0.85 is `block` |
| Framework code looks dead (FastAPI routes, Django models, Celery tasks, pytest fixtures) | **Framework profile**: entry roles, registration decorators, base classes |
| Auto-delete breaks things; agents trust tool output blindly | **Never delete.** `plan` + `workflow` require verify → validate → approval |
| Legacy debt blocks adoption; need a CI ratchet | **Memory** tracks first/last seen; `scan --only-new` fails only on new `block` |
| Enterprise wants code-scanning integration and an audit trail | `--format sarif`; decisions with notes in `.unreach/memory.json` |
| Agents re-read the repo every session and burn tokens | **Compact packets**: full evidence for new findings only; parse cache by content hash; workflow names exact files |

## CLI

```bash
unreach scan [PATH] [--mock] [--format json|md|sarif] [--lang auto|py|ts]
                   [--only-new] [--compact] [--min-confidence 0.25] [--no-memory]
unreach plan [PATH] [--mock]                 # ordered suggestions, never deletes
unreach workflow [PATH] [--format json|md]   # language-aware agent checklist
unreach explain FINDING_ID [PATH]            # optional LLM; heuristic if no key
unreach remember FINDING_ID --decision keep|false_positive|resolved [--note ...]
unreach memory [PATH] [--clear] [--forget FINDING_ID]
unreach mcp                                  # stdio MCP
```

Exit `0` if no high-confidence dead code, `1` if any `block` finding (only new ones with `--only-new`), `2` on tool error.

v0 languages: Python first, TypeScript import graph second.

### Finding schema

```python
Finding(
  id: str,
  kind: str,                 # unused_export | orphan_file | unused_dep | unreachable
  severity: str,             # block | warn | note  (derived from confidence)
  path: str,
  symbol: str | None,
  why: str,
  evidence: list[str],
  confidence: float,         # 0..1, deterministic
  signals: dict[str, float], # named adjustments that produced the score
)
```

### Confidence score

Base by kind (`orphan_file` 0.92, `unused_export` 0.88, `unused_dep` 0.60,
`unreachable` 0.50) plus named signals, clamped to [0.02, 0.99]:

| Signal | Δ |
|---|---|
| `framework_registration_decorator` (route, task, fixture, command…) | −0.60 |
| `main_guard` (`if __name__ == "__main__"`) | −0.45 |
| `module_getattr_lazy_export` (PEP 562) | −0.40 |
| `*_named_in_string_literal` / `framework_base_class` | −0.35 |
| `*_named_in_config` / `referenced_locally` / `module_imported_whole…` / `package_init` | −0.30 |
| `decorated_unknown` | −0.20 |
| `listed_in_dunder_all_public_api` | −0.15 |
| `repo_uses_dynamic_import` | −0.08 / −0.10 |
| `stable_across_runs` (from memory) | up to +0.03 |

`block` ≥ 0.85, `warn` ≥ 0.55, else `note`. Findings below `--min-confidence` (0.25) are dropped.

### Agent workflow

`unreach workflow` / MCP `unreach.workflow` returns ordered steps tuned to the
detected languages and frameworks (Django, Flask, FastAPI, Celery, SQLAlchemy,
Click, pytest, Next.js, React, Vite, Express/Nest; monorepos flagged):

1. **verify** — targeted `grep` and bounded `read` per finding; framework wiring checks
2. **edit** — propose a reviewable patch; deletion requires explicit approval
3. **validate** — `python -c "import pkg"`, `mypy`/`pyright`, `pytest`; `npx tsc --noEmit`, `vitest`/`jest`; re-scan
4. **remember** — `unreach.remember` so the next session starts from the new baseline

### Long-term memory

`.unreach/memory.json` (next to the scanned root, or `UNREACH_MEMORY_DIR`):

- `files` — SHA-256 → extracted facts; unchanged files are not re-parsed
- `findings` — first/last seen, seen_count, status `open`/`resolved`
- `decisions` — `keep` / `false_positive` / `resolved` with note and timestamp
- `runs` — last 50 runs with delta and cache stats

Token savings: MCP `unreach.scan` returns full evidence for **new** findings only,
`persisting_brief` one-liners for known ones, omits acknowledged ones, and reports
`tokens_saved_estimate`. Never stores source or secrets; safe to delete or commit
(commit it for a shared CI ratchet).

The fixture `fixtures/deadapp` produces at least:

- `pkg/orphan.py` — `orphan_file` / `block`
- `dead_symbol` — `unused_export` / `block`

## MCP

```bash
unreach mcp
```

| Tool | Input | Output |
|---|---|---|
| `unreach.scan` | `{ path?, only_new?, full?, min_confidence?, memory? }` | findings JSON with confidence; compact by default |
| `unreach.explain` | `{ id: string }` | paragraph (heuristic if no key) |
| `unreach.plan` | `{ path? }` | ordered deletions/refactors, **no file writes** |
| `unreach.workflow` | `{ path?, max_findings? }` | language-aware verify/edit/validate/remember steps |
| `unreach.remember` | `{ id, decision, note?, path? }` | stores a decision in memory |
| `unreach.memory` | `{ path?, clear? }` | runs, cache stats, open findings, decisions |

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
