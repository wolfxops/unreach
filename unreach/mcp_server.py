"""Stdio MCP server.

Tools: unreach.scan, unreach.judge, unreach.explain, unreach.plan,
unreach.workflow, unreach.triage, unreach.remember, unreach.memory,
unreach.languages. One engine; the plugins only point here.

Every tool accepts ``format: "json" | "table"``. Tables are GitHub-flavoured
markdown, which Claude Code, Cursor and Codex render natively — that is the
plugin-facing output for humans; JSON is for agents that post-process.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from unreach import __version__
from unreach.confidence import DEFAULT_MIN_CONFIDENCE
from unreach.explain import explain as explain_finding
from unreach.memory import DECISIONS, Memory
from unreach.mock import default_mock_root
from unreach.plan import plan_payload
from unreach.render import render_judge, render_plan_table, render_result_table, render_triage_table, render_workflow_table
from unreach.scan import ScanResult, find_by_id, scan_repo, supported_languages
from unreach.support import languages_payload
from unreach.triage import triage
from unreach.workflow import build_workflow

PROTOCOL_VERSION = "2024-11-05"

_PATH_PROPS = {
    "path": {"type": "string", "description": "Repository or subdirectory to scan. Defaults to cwd."},
    "mock": {"type": "boolean", "description": "Fixture mode. No API keys required."},
    "lang": {"type": "string", "enum": supported_languages(), "description": "Language filter (default auto)."},
    "min_confidence": {
        "type": "number",
        "description": f"Drop findings below this confidence (default {DEFAULT_MIN_CONFIDENCE}).",
    },
    "memory": {"type": "boolean", "description": "Use .unreach/memory.json (default true)."},
    "judge": {"type": "boolean", "description": "Run the judge/critic layer (default true). False = raw scan confidence."},
    "format": {"type": "string", "enum": ["json", "table"], "description": "json (default for scan/plan/workflow/triage) or a markdown table for humans."},
}

TOOLS = [
    {
        "name": "unreach.scan",
        "description": (
            "Deterministic dead-code scan with confidence scores (unused exports, orphan files, "
            "unused deps). No LLM. Never deletes files. By default returns a compact packet: full "
            "evidence for NEW findings, one-liners for findings already seen in memory, and omits "
            "findings you previously marked keep/false_positive."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **_PATH_PROPS,
                "only_new": {"type": "boolean", "description": "Return only findings not seen before."},
                "full": {"type": "boolean", "description": "Return full evidence for every finding."},
            },
        },
    },
    {
        "name": "unreach.judge",
        "description": (
            "Judge/critic verdict per finding, as a markdown table by default. Prosecution = the scan's graph "
            "evidence; devil's advocate = 30+ named counter-hypotheses checked against real repository artifacts "
            "with file:line evidence (scheduled jobs, Dockerfile/Procfile/k8s entries, serverless handlers, CI and "
            "Makefile invocations, reflection, plugin registries, templates, feature flags, platform guards, "
            "generated code, migrations, public library surface, keep-markers, WIP hints); identification check "
            "(generic names, stem collisions, star re-exports, parse failures); security lens (eval/exec, unsafe "
            "deserialization, disabled TLS checks, exposed routes, secret-like literals — line numbers only); "
            "effort estimate. Verdict remove | verify | keep with the one next check that settles it. Deterministic, no LLM."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **{k: v for k, v in _PATH_PROPS.items() if k != "format"},
                "format": {"type": "string", "enum": ["table", "md", "json"], "description": "table (default) | md (table + case files) | json."},
            },
        },
    },
    {
        "name": "unreach.explain",
        "description": (
            "Explain one finding by id. Uses an OpenAI-compatible API only if a key is set; "
            "otherwise a heuristic paragraph."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "Finding id"}, **_PATH_PROPS},
            "required": ["id"],
        },
    },
    {
        "name": "unreach.plan",
        "description": "Ordered deletion/refactor suggestions ranked by confidence. Never writes files.",
        "inputSchema": {"type": "object", "properties": _PATH_PROPS},
    },
    {
        "name": "unreach.workflow",
        "description": (
            "Language- and framework-aware agent workflow for the current findings: exact files to "
            "read, grep patterns, validation commands, and a remember step. Follow it instead of "
            "crawling the repo."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **_PATH_PROPS,
                "max_findings": {"type": "integer", "description": "Cap findings in the workflow (default 12)."},
                "triage": {"type": "boolean", "description": "Attach triage verdicts (default true; LLM only if a key is set, else heuristic)."},
            },
        },
    },
    {
        "name": "unreach.triage",
        "description": (
            "Budgeted second opinion on ambiguous (warn) findings. Sends compact evidence packets — never "
            "file contents — for at most max_items findings in one call, caches verdicts "
            "(likely_dead | verify | keep) in memory by evidence digest, and never re-asks about unchanged "
            "findings. Without an API key returns deterministic heuristic verdicts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **_PATH_PROPS,
                "max_items": {"type": "integer", "description": "Max findings sent to the model per call (default 8)."},
                "llm": {"type": "boolean", "description": "Set false to force heuristic verdicts."},
            },
        },
    },
    {
        "name": "unreach.languages",
        "description": "Support matrix: languages, detection tier, graph precision, frameworks, validation commands.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "unreach.remember",
        "description": (
            "Store a decision for a finding in .unreach/memory.json so future scans skip it: "
            "keep (intentional), false_positive, or resolved."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "decision": {"type": "string", "enum": list(DECISIONS)},
                "note": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["id", "decision"],
        },
    },
    {
        "name": "unreach.memory",
        "description": "Summarize repository memory: runs, cached files, open findings, decisions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "clear": {"type": "boolean", "description": "Delete the memory file."},
            },
        },
    },
]


class Session:
    def __init__(self) -> None:
        self.result: ScanResult | None = None


def handle_request(message: dict[str, Any], session: Session) -> dict[str, Any] | None:
    method = message.get("method")
    req_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "unreach", "version": __version__},
            },
        }
    if method in {"notifications/initialized", "initialized"}:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            text = dispatch_tool(name, arguments, session)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        except Exception as exc:  # noqa: BLE001 — surface tool errors to the client
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"unreach error: {exc}"}],
                    "isError": True,
                },
            }
    if req_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def dispatch_tool(name: str, arguments: dict[str, Any], session: Session) -> str:
    fmt = str(arguments.get("format") or "json")
    if name == "unreach.scan":
        result = _scan(arguments, session)
        only_new = bool(arguments.get("only_new", False))
        compact = not bool(arguments.get("full", False))
        if fmt == "table":
            return render_result_table(result, only_new=only_new)
        return json.dumps(result.to_dict(compact=compact, only_new=only_new), indent=2)
    if name == "unreach.judge":
        result = _scan(arguments, session)
        return render_judge(result, fmt=str(arguments.get("format") or "table"))
    if name == "unreach.plan":
        result = _scan(arguments, session)
        if fmt == "table":
            return render_plan_table(result.findings, path=result.path)
        return json.dumps(plan_payload(result.findings, path=result.path), indent=2)
    if name == "unreach.workflow":
        result = _scan(arguments, session)
        verdicts = None
        if arguments.get("triage", True):
            root, _, _, _, memory = _scan_args(arguments)
            verdicts = triage(result.findings, Memory(_root_dir(root), enabled=memory))
        payload = build_workflow(
            result.profile,
            result.findings,
            delta=result.delta.to_dict(),
            max_findings=int(arguments.get("max_findings") or 12),
            triage=verdicts,
        )
        if fmt == "table":
            return render_workflow_table(payload)
        return json.dumps(payload, indent=2)
    if name == "unreach.triage":
        result = _scan(arguments, session)
        root, _, _, _, memory = _scan_args(arguments)
        use_llm = None if arguments.get("llm", True) else False
        payload = triage(
            result.findings,
            Memory(_root_dir(root), enabled=memory),
            max_items=int(arguments.get("max_items") or 8),
            use_llm=use_llm,
        )
        if fmt == "table":
            return render_triage_table(payload, result.findings)
        return json.dumps(payload, indent=2)
    if name == "unreach.languages":
        return json.dumps(languages_payload(), indent=2)
    if name == "unreach.explain":
        finding_id = arguments.get("id")
        if not finding_id:
            raise ValueError("id is required")
        result = session.result or _scan(arguments, session)
        finding = find_by_id(result.findings + result.suppressed, str(finding_id))
        if finding is None:
            result = _scan(arguments, session)
            finding = find_by_id(result.findings + result.suppressed, str(finding_id))
        if finding is None:
            raise ValueError(f"unknown finding id: {finding_id}")
        return explain_finding(finding)
    if name == "unreach.remember":
        finding_id = arguments.get("id")
        decision = arguments.get("decision")
        if not finding_id or not decision:
            raise ValueError("id and decision are required")
        root, _, _, _, _ = _scan_args(arguments)
        mem = Memory(root)
        entry = mem.remember(str(finding_id), str(decision), str(arguments.get("note") or ""))
        mem.save()
        session.result = None
        return json.dumps({"id": finding_id, **entry, "memory": str(mem.path)}, indent=2)
    if name == "unreach.memory":
        root, _, _, _, _ = _scan_args(arguments)
        mem = Memory(root)
        if arguments.get("clear"):
            mem.clear()
            session.result = None
            return json.dumps({"cleared": str(mem.path)})
        payload = mem.summary()
        payload["decisions"] = mem.decisions()
        return json.dumps(payload, indent=2)
    raise ValueError(f"unknown tool: {name}")


def _scan(arguments: dict[str, Any], session: Session) -> ScanResult:
    root, mock, lang, min_confidence, memory = _scan_args(arguments)
    judge = bool(arguments.get("judge", True))
    result = scan_repo(root, mock=mock, lang=lang, memory=memory, min_confidence=min_confidence, judge=judge)
    session.result = result
    return result


def _root_dir(path: Path) -> Path:
    resolved = path.resolve()
    return resolved.parent if resolved.is_file() else resolved


def _scan_args(arguments: dict[str, Any]) -> tuple[Path, bool, str, float, bool]:
    mock = bool(arguments.get("mock", False))
    raw = arguments.get("path")
    if raw:
        path = Path(raw)
    elif mock:
        path = default_mock_root() or Path.cwd()
    else:
        path = Path.cwd()
    lang = str(arguments.get("lang") or "auto")
    min_confidence = float(arguments.get("min_confidence") or DEFAULT_MIN_CONFIDENCE)
    memory = bool(arguments.get("memory", True))
    return path, mock, lang, min_confidence, memory


def _read_message(stdin) -> dict[str, Any] | None:
    line = stdin.readline()
    if not line:
        return None
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1])
        while True:
            header = stdin.readline()
            if header in (b"\r\n", b"\n", b""):
                break
        body = stdin.read(length)
        return json.loads(body.decode("utf-8"))
    stripped = line.strip()
    if not stripped:
        return _read_message(stdin)
    return json.loads(stripped.decode("utf-8"))


def _write_message(message: dict[str, Any]) -> None:
    body = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def serve() -> int:
    session = Session()
    stdin = sys.stdin.buffer
    while True:
        try:
            message = _read_message(stdin)
        except json.JSONDecodeError as exc:
            _write_message(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc}"},
                }
            )
            continue
        if message is None:
            return 0
        reply = handle_request(message, session)
        if reply is not None:
            _write_message(reply)
    return 0
