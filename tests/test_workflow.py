from __future__ import annotations

import json
from pathlib import Path

from unreach.cli import main
from unreach.mcp_server import Session, handle_request
from unreach.render import render_sarif, render_workflow
from unreach.scan import scan_repo
from unreach.workflow import build_workflow

DEADAPP = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"


def test_python_workflow_has_verify_edit_validate_remember() -> None:
    result = scan_repo(DEADAPP, memory=False)
    payload = build_workflow(result.profile, result.findings, delta=result.delta.to_dict())
    phases = [step["phase"] for step in payload["steps"]]
    assert phases[0] == "verify"
    assert "edit" in phases and "validate" in phases and phases[-1] == "remember"
    assert payload["auto_delete"] is False
    commands = [s.get("command", "") for s in payload["steps"]]
    assert any("pytest" in c for c in commands)
    assert any("import pkg" in c for c in commands)
    greps = {s.get("grep") for s in payload["steps"]}
    assert "dead_symbol" in greps and "pkg.orphan" in greps
    md = render_workflow(payload)
    assert "## verify" in md and "unreach.remember" in md


def test_typescript_workflow_uses_tsc(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "main": "src/index.ts", "devDependencies": {"typescript": "5", "vitest": "1"}}))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("import { a } from './lib'\nconsole.log(a)\n")
    (tmp_path / "src" / "lib.ts").write_text("export const a = 1\nexport const b = 2\n")
    (tmp_path / "src" / "orphan.ts").write_text("export const z = 3\n")
    result = scan_repo(tmp_path, memory=False)
    assert result.profile.primary == "ts"
    assert result.profile.type_checker == "tsc"
    payload = build_workflow(result.profile, result.findings)
    commands = [s.get("command", "") for s in payload["steps"]]
    assert any("tsc --noEmit" in c for c in commands)
    assert any("vitest" in c for c in commands)
    assert any(s.get("read") == ["package.json", "tsconfig.json"] or "package.json" in s.get("read", []) for s in payload["steps"])


def test_workflow_cli_and_mcp(capsys) -> None:
    assert main(["workflow", str(DEADAPP), "--no-memory", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["selected_findings"]
    session = Session()
    reply = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "unreach.workflow", "arguments": {"path": str(DEADAPP), "memory": False}},
        },
        session,
    )
    text = reply["result"]["content"][0]["text"]
    assert '"phase": "remember"' in text


def test_sarif_output() -> None:
    result = scan_repo(DEADAPP, memory=False)
    sarif = json.loads(render_sarif(result.findings))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "unreach"
    assert {r["ruleId"] for r in run["results"]} == {"orphan_file", "unused_export"}
    assert all("confidence" in r["properties"] for r in run["results"])


def test_mcp_scan_compact_after_memory(isolated_memory: Path) -> None:
    session = Session()
    args = {"path": str(DEADAPP)}
    first = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "unreach.scan", "arguments": args}}, session)
    second = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "unreach.scan", "arguments": args}}, session)
    first_payload = json.loads(first["result"]["content"][0]["text"])
    second_payload = json.loads(second["result"]["content"][0]["text"])
    assert len(first_payload["findings"]) == 5
    assert second_payload["findings"] == []
    assert len(second_payload["persisting_brief"]) == 5
    assert len(second["result"]["content"][0]["text"]) < len(first["result"]["content"][0]["text"])
    remembered = handle_request(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "unreach.remember", "arguments": {**args, "id": "orphan_file:pkg/orphan.py", "decision": "false_positive", "note": "plugin"}}},
        session,
    )
    assert '"decision": "false_positive"' in remembered["result"]["content"][0]["text"]
    third = json.loads(handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "unreach.scan", "arguments": args}}, session)["result"]["content"][0]["text"])
    assert third["suppressed"][0]["id"] == "orphan_file:pkg/orphan.py"
    assert all(b["id"] != "orphan_file:pkg/orphan.py" for b in third.get("persisting_brief", []))
