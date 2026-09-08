from __future__ import annotations

from pathlib import Path

from unreach.cli import main

DEADAPP = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"


def test_scan_mock_exits_one_on_block(capsys) -> None:
    code = main(["scan", str(DEADAPP), "--mock"])
    captured = capsys.readouterr()
    assert code == 1
    assert "dead_symbol" in captured.out
    assert "orphan.py" in captured.out


def test_scan_json_format(capsys) -> None:
    code = main(["scan", str(DEADAPP), "--mock", "--format", "json"])
    captured = capsys.readouterr()
    assert code == 1
    assert '"kind": "unused_export"' in captured.out
    assert '"auto_delete": false' in captured.out


def test_plan_cli_mentions_no_delete(capsys) -> None:
    code = main(["plan", str(DEADAPP), "--mock"])
    captured = capsys.readouterr()
    assert code == 1
    assert "never deletes" in captured.out.lower() or "Never deletes" in captured.out
    assert (DEADAPP / "pkg" / "orphan.py").is_file()


def test_explain_heuristic_without_key(capsys, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("UNREACH_API_KEY", raising=False)
    code = main(
        [
            "explain",
            "unused_export:pkg/exports.py:dead_symbol",
            str(DEADAPP),
            "--mock",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "dead_symbol" in captured.out


def test_unknown_command_help() -> None:
    code = main([])
    assert code == 2


def test_missing_path_errors() -> None:
    code = main(["scan", "/no/such/unreach-path", "--mock"])
    assert code == 2


def test_plugin_manifests_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    assert (root / "plugins" / "claude" / ".claude-plugin" / "plugin.json").is_file()
    assert (root / "plugins" / "cursor" / ".cursor-plugin" / "plugin.json").is_file()
    assert (root / "plugins" / "codex" / "README.md").is_file()
    assert (root / "docs" / "index.html").is_file()

