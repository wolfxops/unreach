"""Stdio MCP server: unreach.scan, unreach.explain, unreach.plan."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from unreach import __version__
from unreach.explain import explain as explain_finding
from unreach.mock import default_mock_root
from unreach.plan import plan_payload
from unreach.scan import Finding, find_by_id, scan_path

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "unreach.scan",
        "description": (
            "Deterministic dead-code scan (unused exports, orphan files, unused deps). "
            "Does not use an LLM. Never deletes files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repository or subdirectory to scan. Defaults to cwd.",
                },
                "mock": {
                    "type": "boolean",
                    "description": "Use mock/fixture mode. No API keys required.",
                },
                "lang": {
                    "type": "string",
                    "enum": ["auto", "py", "ts"],
                    "description": "Language filter. Default auto.",
                },
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
            "properties": {
                "id": {"type": "string", "description": "Finding id from unreach.scan"},
                "path": {"type": "string"},
                "mock": {"type": "boolean"},
            },
            "required": ["id"],
        },
    },
    {
        "name": "unreach.plan",
        "description": (
            "Ordered deletion/refactor suggestions. Never writes or deletes files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "mock": {"type": "boolean"},
            },
        },
    },
]


class Session:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.path: str = str(Path.cwd())


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
    if name == "unreach.scan":
        path, mock, lang = _scan_args(arguments)
        session.findings = scan_path(path, mock=mock, lang=lang)
        session.path = str(path)
        from unreach.render import render_scan

        return render_scan(session.findings, path=str(path), fmt="json")
    if name == "unreach.plan":
        path, mock, lang = _scan_args(arguments)
        session.findings = scan_path(path, mock=mock, lang=lang)
        session.path = str(path)
        return json.dumps(plan_payload(session.findings, path=str(path)), indent=2)
    if name == "unreach.explain":
        finding_id = arguments.get("id")
        if not finding_id:
            raise ValueError("id is required")
        path, mock, lang = _scan_args(arguments)
        if not session.findings:
            session.findings = scan_path(path, mock=mock, lang=lang)
            session.path = str(path)
        finding = find_by_id(session.findings, str(finding_id))
        if finding is None:
            session.findings = scan_path(path, mock=mock, lang=lang)
            finding = find_by_id(session.findings, str(finding_id))
        if finding is None:
            raise ValueError(f"unknown finding id: {finding_id}")
        return explain_finding(finding)
    raise ValueError(f"unknown tool: {name}")


def _scan_args(arguments: dict[str, Any]) -> tuple[Path, bool, str]:
    mock = bool(arguments.get("mock", False))
    raw = arguments.get("path")
    if raw:
        path = Path(raw)
    elif mock:
        path = default_mock_root() or Path.cwd()
    else:
        path = Path.cwd()
    lang = str(arguments.get("lang") or "auto")
    return path, mock, lang


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
