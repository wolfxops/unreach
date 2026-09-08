import json
from pathlib import Path

import pytest

from unreach import triage as tri
from unreach.cli import main
from unreach.mcp_server import Session, handle_request
from unreach.memory import Memory
from unreach.scan import Finding, scan_repo
from unreach.workflow import build_workflow

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _finding(fid: str, severity: str, confidence: float, signals: dict | None = None) -> Finding:
    return Finding(
        id=fid,
        kind=fid.split(":")[0],
        severity=severity,
        path=fid.split(":")[1],
        symbol=fid.split(":")[2] if fid.count(":") > 1 else None,
        why="why",
        confidence=confidence,
        signals=signals or {},
    )


def test_block_and_note_are_never_sent(isolated_memory, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(tri, "available", lambda: True)

    def fake_chat(messages, **kwargs):
        calls.append(json.loads(messages[1]["content"]))
        items = calls[-1]["items"]
        return json.dumps({"verdicts": {i["id"]: {"verdict": "likely_dead", "reason": "ok"} for i in items}}), {"model": "fake", "prompt_tokens": 10}

    monkeypatch.setattr(tri, "chat", fake_chat)
    mem = Memory(tmp_path)
    findings = [
        _finding("orphan_file:a.py", "block", 0.92),
        _finding("unused_export:b.py:x", "warn", 0.6),
        _finding("unused_dep:pyproject.toml:z", "note", 0.4),
    ]
    out = tri.triage(findings, mem)
    assert out["llm"]["called"] and out["llm"]["asked"] == 1
    assert out["llm"]["skipped_block"] == 1 and out["llm"]["skipped_note"] == 1
    sent_ids = {i["id"] for i in calls[0]["items"]}
    assert sent_ids == {"unused_export:b.py:x"}
    assert set(calls[0]["items"][0]) == {"id", "kind", "path", "symbol", "confidence", "signals", "why"}
    assert out["verdicts"]["unused_export:b.py:x"]["verdict"] == "likely_dead"


def test_verdicts_cached_and_not_reasked(isolated_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(tri, "available", lambda: True)
    count = {"n": 0}

    def fake_chat(messages, **kwargs):
        count["n"] += 1
        items = json.loads(messages[1]["content"])["items"]
        return json.dumps({"verdicts": {i["id"]: {"verdict": "verify", "reason": "grep it"} for i in items}}), {"model": "fake"}

    monkeypatch.setattr(tri, "chat", fake_chat)
    findings = [_finding("unused_export:b.py:x", "warn", 0.6)]
    tri.triage(findings, Memory(tmp_path))
    second = tri.triage(findings, Memory(tmp_path))
    assert count["n"] == 1
    assert second["llm"]["cached"] == 1 and not second["llm"]["called"]
    # Changed evidence → digest changes → asked again
    changed = [_finding("unused_export:b.py:x", "warn", 0.6, {"symbol_named_in_string_literal": -0.35})]
    third = tri.triage(changed, Memory(tmp_path))
    assert count["n"] == 2 and third["llm"]["asked"] == 1


def test_budget_caps_items_per_call(isolated_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(tri, "available", lambda: True)
    sizes = []

    def fake_chat(messages, **kwargs):
        items = json.loads(messages[1]["content"])["items"]
        sizes.append(len(items))
        return json.dumps({"verdicts": {i["id"]: {"verdict": "likely_dead", "reason": "ok"} for i in items}}), {"model": "fake"}

    monkeypatch.setattr(tri, "chat", fake_chat)
    findings = [_finding(f"unused_export:m{i}.py:s{i}", "warn", 0.6) for i in range(12)]
    out = tri.triage(findings, Memory(tmp_path), max_items=5)
    assert sizes == [5]
    assert out["llm"]["deferred"] == 7
    # Deferred findings still receive deterministic heuristic verdicts.
    assert len(out["verdicts"]) == 12
    assert out["llm"]["heuristic"] == 7


def test_heuristic_without_key(isolated_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(tri, "available", lambda: False)
    findings = [
        _finding("unused_export:a.py:handler", "warn", 0.6, {"framework_registration_decorator": -0.6}),
        _finding("unused_export:a.py:name", "warn", 0.6, {"symbol_named_in_string_literal": -0.35}),
        _finding("orphan_file:b.py", "warn", 0.8),
    ]
    out = tri.triage(findings, Memory(tmp_path))
    v = out["verdicts"]
    assert v["unused_export:a.py:handler"]["verdict"] == "keep"
    assert v["unused_export:a.py:name"]["verdict"] == "verify"
    assert v["orphan_file:b.py"]["verdict"] == "likely_dead"
    assert not out["llm"]["enabled"] and out["llm"]["heuristic"] == 3


def test_llm_failure_falls_back_to_heuristic(isolated_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(tri, "available", lambda: True)

    def broken(messages, **kwargs):
        raise tri.LLMUnavailable("boom")

    monkeypatch.setattr(tri, "chat", broken)
    out = tri.triage([_finding("orphan_file:b.py", "warn", 0.8)], Memory(tmp_path))
    assert out["verdicts"]["orphan_file:b.py"]["model"] == "heuristic"
    assert not out["llm"]["enabled"]


def test_workflow_uses_verdicts_for_order_and_skips_keep(isolated_memory, tmp_path):
    result = scan_repo(FIXTURES / "deadapp", mock=True, memory=False)
    findings = list(result.findings)
    warn = [f for f in findings if f.severity == "warn"]
    assert warn, "fixture must produce warn findings"
    verdicts = {"verdicts": {warn[0].id: {"verdict": "keep", "reason": "framework"}}, "llm": {"called": False}}
    payload = build_workflow(result.profile, findings, triage=verdicts)
    assert warn[0].id in payload["kept_by_triage"]
    assert warn[0].id not in payload["selected_findings"]
    assert payload["llm"]["policy"]


def test_cli_and_mcp_triage(isolated_memory, capsys, monkeypatch):
    monkeypatch.setattr(tri, "available", lambda: False)
    assert main(["triage", str(FIXTURES / "deadapp"), "--mock", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["llm"]["enabled"] is False
    assert payload["verdicts"]
    session = Session()
    reply = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "unreach.triage", "arguments": {"mock": True, "path": str(FIXTURES / "deadapp"), "llm": False}},
        },
        session,
    )
    body = json.loads(reply["result"]["content"][0]["text"])
    assert set(body) == {"verdicts", "llm"}
    reply = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "unreach.workflow", "arguments": {"mock": True, "path": str(FIXTURES / "deadapp")}},
        },
        session,
    )
    wf = json.loads(reply["result"]["content"][0]["text"])
    assert "llm" in wf and any(s.get("triage") for s in wf["steps"])
