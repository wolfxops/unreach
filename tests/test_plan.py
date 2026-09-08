from __future__ import annotations

from pathlib import Path

from unreach.plan import build_plan, plan_payload
from unreach.scan import scan_path

DEADAPP = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"


def test_plan_is_ordered_and_non_destructive() -> None:
    orphan_before = (DEADAPP / "pkg" / "orphan.py").read_text(encoding="utf-8")
    exports_before = (DEADAPP / "pkg" / "exports.py").read_text(encoding="utf-8")
    findings = scan_path(DEADAPP, mock=True, lang="py")
    steps = build_plan(findings)
    assert steps
    payload = plan_payload(findings, path=str(DEADAPP))
    assert payload["auto_delete"] is False
    actions = [step.action for step in steps]
    if "remove_export" in actions and "delete_file_manual" in actions:
        assert actions.index("remove_export") < actions.index("delete_file_manual")
    assert any(step.symbol == "dead_symbol" for step in steps)
    assert any(step.path.endswith("pkg/orphan.py") for step in steps)
    assert (DEADAPP / "pkg" / "orphan.py").read_text(encoding="utf-8") == orphan_before
    assert (DEADAPP / "pkg" / "exports.py").read_text(encoding="utf-8") == exports_before
    assert (DEADAPP / "pkg" / "orphan.py").is_file()


def test_plan_never_includes_write_action() -> None:
    findings = scan_path(DEADAPP, mock=True, lang="py")
    for step in build_plan(findings):
        assert step.action != "delete"
        assert "write" not in step.action
