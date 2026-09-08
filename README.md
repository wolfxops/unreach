# Unreach

Find the code your agents keep rewriting around.

Dead-code intelligence for Claude Code, Cursor, and Codex: a deterministic
reachability graph across **16 languages** and **45 frameworks**, an explainable
**confidence score** per finding, a **guided dynamic workflow** for the agent, a
**budgeted LLM triage** step that is asked once and cached, and **long-term
memory** so every following session costs fewer tokens.

One engine, not three products:

1. Deterministic CLI scanner (`unreach scan`)
2. One stdio **MCP** server (`unreach.scan`, `unreach.workflow`, `unreach.triage`, `unreach.plan`, `unreach.explain`, `unreach.remember`, `unreach.memory`, `unreach.languages`)
3. Thin plugins: **Claude Code**, **Cursor**, **Codex**

Detection does **not** require an LLM. The model only ranks and explains, and
only for ambiguous findings. Auto-delete is forbidden; `plan` and `workflow`
emit ordered suggestions only.

Docs: https://wolfxops.github.io/unreach/

## Install

```bash
pip install -e .
unreach scan --mock        # fixture scan, no API keys, exit 1 (block findings present)
unreach workflow --mock    # guided checklist with triage verdicts
unreach languages          # support matrix
```

Python 3.10+. Dev:

```bash
pip install -e ".[dev]"
pytest -q
```

## Built around the pain points

Research across knip / ts-prune / Vulture / deptry issue trackers and agent
post-mortems (see [research](https://wolfxops.github.io/unreach/research.html))
keeps surfacing the same complaints. Each maps to a mechanism:

| Pain point | Mechanism |
|---|---|
| False positives from dynamic imports, `getattr`, reflection, DI, string-named modules | **Confidence signals** lower the score; only ≥ 0.85 is `block`; name-precision languages capped at `warn` |
| Framework code looks dead (FastAPI routes, Django models, Spring beans, Rails models, Flutter widgets…) | **45-framework registry**: entry roles, registration decorators/annotations, base classes; detected from imports *and* manifests |
| Auto-delete breaks things; agents trust tool output blindly | **Never delete.** `plan` + `workflow` require verify → validate → approval |
| Legacy debt blocks adoption; need a CI ratchet | **Memory** tracks first/last seen; `scan --only-new` fails only on new `block` |
| Enterprise wants code-scanning integration and an audit trail | `--format sarif`; decisions with notes in `.unreach/memory.json` |
| Agents re-read the repo every session and burn tokens | **Compact packets** (−58% on a repeat visit, measured on the fixture); parse cache by content hash; workflow names exact files |
| "AI" tools spend model tokens on what a graph already knows | **Budgeted triage**: model sees `warn` findings only, once, batched, as evidence packets; verdicts cached by evidence digest |
| Polyglot estates, single-language tools | One `Finding` shape across 16 languages with **declared graph precision** |

## Languages and frameworks

| Tier | Languages | Precision | Detects |
|---|---|---|---|
| AST | Python | path | orphan_file, unused_export, unused_dep, unreachable |
| Import graph | TypeScript, JavaScript (+ `.vue`, `.svelte`) | path | orphan_file, unused_export |
| Reference graph | Go, Rust, Ruby, Dart, C/C++ headers, Lua, Perl | path | orphan_file (+ unused_export where exports are declared) |
| Reference graph | Java, Kotlin, Scala, C#, PHP, Swift, Elixir | name | orphan_file (+ unused_export where declared), capped at `warn` |

Frameworks (45): Django, Flask, FastAPI, pytest, Celery, SQLAlchemy, Click/Typer,
Airflow, Pydantic · Next.js, React, Vue, Nuxt, Angular, Svelte/SvelteKit, Remix,
Astro, Vite, Express/Koa/Fastify/Hono, NestJS, Electron, Jest/Vitest,
Playwright/Cypress · Gin/Echo/Fiber/Chi, Cobra · Actix/Axum/Rocket, Tokio, Clap ·
Spring, Quarkus, Micronaut, JUnit, Ktor, Android · ASP.NET Core, xUnit/NUnit ·
Rails, Sinatra, RSpec · Laravel, Symfony · SwiftUI/UIKit, Vapor · Flutter · Phoenix.

`unreach languages` prints the live matrix with validation commands. Adding a
language is one entry in `unreach/polyglot.py`.

## CLI

```bash
unreach scan      [PATH] [--mock] [--format json|md|sarif] [--lang LANG]
                         [--only-new] [--compact] [--min-confidence 0.25] [--no-memory]
unreach plan      [PATH] [--format json|md]              # ordered suggestions, never deletes
unreach workflow  [PATH] [--format json|md] [--max 12] [--no-triage] [--no-llm]
unreach triage    [PATH] [--format json|md] [--max-items 8] [--no-llm]
unreach explain   FINDING_ID [PATH]                      # optional LLM; heuristic if no key
unreach remember  FINDING_ID --decision keep|false_positive|resolved [--note ...] [--path PATH]
unreach memory    [PATH] [--clear] [--forget FINDING_ID]
unreach languages
unreach mcp                                              # stdio MCP
```

Exit `0` if no high-confidence dead code, `1` if any `block` finding (only new
ones with `--only-new`), `2` on tool error.

### Finding schema

```python
Finding(
  id: str,                   # kind:path[:symbol]
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
| `framework_registration_decorator` (route, task, fixture, component…) | −0.60 |
| `main_guard` (`if __name__ == "__main__"`) | −0.45 |
| `module_getattr_lazy_export` (PEP 562) | −0.40 |
| `*_named_in_string_literal` / `framework_base_class` | −0.35 |
| `*_named_in_config` / `referenced_locally` / `module_imported_whole…` / `package_init` | −0.30 |
| `<lang>_name_reference_graph` / `<lang>_token_match_heuristic` / `ts_regex_graph_*` | −0.30 |
| `name_token_seen_elsewhere` / `decorated_unknown` | −0.20 |
| `listed_in_dunder_all_public_api` | −0.15 |
| `repo_uses_dynamic_import` | −0.08 / −0.10 |
| `<lang>_path_resolved_graph` | −0.03 |
| `stable_across_runs` (from memory) | up to +0.03 |

`block` ≥ 0.85, `warn` ≥ 0.55, else `note`. Findings below `--min-confidence` (0.25) are dropped.

### Guided workflow and LLM budget

`unreach workflow` / MCP `unreach.workflow` returns ordered steps tuned to the
detected languages and frameworks:

1. **verify** — targeted `grep` and bounded `read` per finding; framework wiring and DI/reflection checks
2. **edit** — propose a reviewable patch; deletion requires explicit approval
3. **validate** — `python -c "import pkg"` / `mypy` / `pytest`; `npx tsc --noEmit` / `vitest`; `go build && go test`; `cargo check && cargo test`; `./gradlew test`; `dotnet build`; `bundle exec rspec`; `phpunit`; `swift test`; `flutter test`; `mix test`; `ctest`; `busted`; `prove`; then re-scan
4. **remember** — `unreach.remember` so the next session starts from the new baseline

The model is used deliberately, not by default:

- `block` findings are never sent (the graph already has the answer).
- `note` findings are never sent (too weak).
- `warn` findings are sent **once**, in **one batched call**, at most `--max-items`
  (8) per run, as compact evidence packets (`id · kind · path · symbol · confidence
  · signals · why`) — never file bodies.
- Verdicts (`likely_dead` / `verify` / `keep`) are cached in memory by evidence
  digest, so an unchanged finding is never asked about twice.
- Without a key, the same interface returns deterministic heuristic verdicts.

Verdicts reorder the workflow (`likely_dead` first, `keep` skipped) and set
per-step `budget_hint`s ("a single grep is enough" vs "read the grep hits").

### Long-term memory

`.unreach/memory.json` (next to the scanned root, or `UNREACH_MEMORY_DIR`):

- `files` — SHA-256 → extracted facts, every language; unchanged files are not re-parsed
- `findings` — first/last seen, seen_count, status `open`/`resolved`
- `decisions` — `keep` / `false_positive` / `resolved` with note and timestamp
- `llm` — triage verdicts keyed by evidence digest
- `runs` — last 50 runs with delta and cache stats

MCP `unreach.scan` returns full evidence for **new** findings only,
`persisting_brief` one-liners for known ones, omits acknowledged ones, trims the
profile on repeat visits, and reports `tokens_saved_estimate`. Never stores source
or secrets; safe to delete or commit (commit it for a shared CI ratchet and shared
triage verdicts).

The fixture `fixtures/deadapp` produces:

- `pkg/orphan.py` — `orphan_file` / `block` 0.92
- `dead_symbol` — `unused_export` / `block` 0.88
- `maybe_dead` — `unused_export` / `warn` 0.58 (module imported whole)

## MCP

```bash
unreach mcp
```

| Tool | Input | Output |
|---|---|---|
| `unreach.scan` | `{ path?, lang?, only_new?, full?, min_confidence?, memory? }` | findings JSON with confidence; compact by default |
| `unreach.workflow` | `{ path?, max_findings?, triage? }` | verify/edit/validate/remember steps ordered by triage; `llm` budget report |
| `unreach.triage` | `{ path?, max_items?, llm? }` | verdicts for warn findings; one batched call max; cached |
| `unreach.plan` | `{ path? }` | ordered deletions/refactors, **no file writes** |
| `unreach.explain` | `{ id }` | paragraph (heuristic if no key) |
| `unreach.remember` | `{ id, decision, note?, path? }` | stores a decision in memory |
| `unreach.memory` | `{ path?, clear? }` | runs, cache stats, open findings, decisions, verdicts |
| `unreach.languages` | `{}` | support matrix |

OpenAI-compatible HTTP is used only by `explain` and `triage`, and only if
`UNREACH_API_KEY` or `OPENAI_API_KEY` is set (`UNREACH_BASE_URL`, `UNREACH_MODEL`
optional). No vendor SDKs.

## Plugins

Same engine. No second scanner. Every skill teaches the loop
`scan → workflow → verify → validate → remember`.

### Claude Code

```text
/plugin marketplace add wolfxops/unreach
/plugin install unreach
```

Manifest: `plugins/claude/.claude-plugin/plugin.json`.

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
    format: sarif
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
