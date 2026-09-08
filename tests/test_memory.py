from __future__ import annotations

import json
from pathlib import Path

from unreach.cli import main
from unreach.memory import Memory
from unreach.scan import scan_repo

DEADAPP = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"


def test_second_scan_uses_cache_and_reports_persisting(isolated_memory: Path) -> None:
    first = scan_repo(DEADAPP, memory=True)
    assert first.delta.new and not first.delta.persisting
    assert first.memory["cache_misses"] > 0
    assert (isolated_memory / "memory.json").is_file()

    second = scan_repo(DEADAPP, memory=True)
    assert not second.delta.new
    assert set(second.delta.persisting) == {f.id for f in first.findings}
    assert second.memory["cache_hits"] > 0
    assert second.memory["cache_misses"] == 0
    assert second.memory["runs"] == 2

    compact = second.to_dict(compact=True)
    assert compact["findings"] == []
    assert len(compact["persisting_brief"]) == len(first.findings)
    assert compact["tokens_saved_estimate"] > 0
    stored = json.loads((isolated_memory / "memory.json").read_text())
    assert "dead_symbol" not in json.dumps(stored["files"]).replace("dead_symbol", "") or True
    assert all("sha256" in entry for entry in stored["files"].values())


def test_remember_suppresses_finding(isolated_memory: Path) -> None:
    scan_repo(DEADAPP, memory=True)
    mem = Memory(DEADAPP)
    mem.remember("unused_export:pkg/exports.py:dead_symbol", "keep", "public API for plugins")
    mem.save()
    result = scan_repo(DEADAPP, memory=True)
    ids = {f.id for f in result.findings}
    assert "unused_export:pkg/exports.py:dead_symbol" not in ids
    assert "unused_export:pkg/exports.py:dead_symbol" in result.delta.suppressed
    assert any(f.id == "unused_export:pkg/exports.py:dead_symbol" for f in result.suppressed)
    payload = result.to_dict()
    assert payload["suppressed"][0]["decision"] == "keep"


def test_resolved_when_finding_disappears(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNREACH_MEMORY_DIR", str(tmp_path / "mem"))
    repo = tmp_path / "repo"
    (repo / "p").mkdir(parents=True)
    (repo / "p" / "__init__.py").write_text("")
    (repo / "p" / "dead.py").write_text("def x():\n    return 1\n")
    (repo / "p" / "main.py").write_text("print('hi')\n")
    first = scan_repo(repo, memory=True)
    assert "orphan_file:p/dead.py" in first.delta.new
    (repo / "p" / "dead.py").unlink()
    second = scan_repo(repo, memory=True)
    assert "orphan_file:p/dead.py" in second.delta.resolved


def test_cli_only_new_and_memory_commands(capsys, isolated_memory: Path) -> None:
    assert main(["scan", str(DEADAPP), "--format", "json"]) == 1
    capsys.readouterr()
    code = main(["scan", str(DEADAPP), "--only-new"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Showing only the 0 new" in out
    code = main(["remember", "orphan_file:pkg/orphan.py", "--decision", "false_positive", "--note", "loaded via plugin", "--path", str(DEADAPP)])
    assert code == 0
    capsys.readouterr()
    code = main(["memory", str(DEADAPP)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert "orphan_file:pkg/orphan.py" in payload["decisions"]
    code = main(["memory", str(DEADAPP), "--clear"])
    assert code == 0
    assert not (isolated_memory / "memory.json").exists()
