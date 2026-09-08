from __future__ import annotations

from pathlib import Path

from unreach.confidence import BLOCK_AT, WARN_AT, Signals, score, severity_for
from unreach.scan import scan_repo


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_severity_thresholds() -> None:
    assert severity_for(BLOCK_AT) == "block"
    assert severity_for(WARN_AT) == "warn"
    assert severity_for(WARN_AT - 0.01) == "note"
    s = Signals()
    s.add("x", -0.5)
    assert score("orphan_file", s) < BLOCK_AT


def test_framework_decorator_lowers_confidence(tmp_path: Path) -> None:
    _write(tmp_path, "svc/__init__.py", "")
    _write(
        tmp_path,
        "svc/routes.py",
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.get('/health')\ndef health():\n    return {'ok': True}\n\n"
        "def helper_unused():\n    return 1\n",
    )
    _write(tmp_path, "svc/main.py", "from fastapi import FastAPI\nfrom svc.routes import router\napp = FastAPI()\napp.include_router(router)\n")
    result = scan_repo(tmp_path, memory=False)
    by_symbol = {f.symbol: f for f in result.findings}
    assert "fastapi" in result.profile.frameworks
    assert "health" not in by_symbol or by_symbol["health"].severity != "block"
    assert by_symbol["helper_unused"].severity == "block"
    if "health" in by_symbol:
        assert "framework_registration_decorator" in by_symbol["health"].signals


def test_string_reference_and_main_guard_lower_orphan_confidence(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/core.py", "import importlib\n\ndef load(name):\n    return importlib.import_module('app.plugins.' + name)\n")
    _write(tmp_path, "app/plugins/__init__.py", "")
    _write(tmp_path, "app/plugins/csv_export.py", "def run():\n    return 'csv'\n")
    _write(tmp_path, "app/tool_script.py", "def go():\n    return 1\n\nif __name__ == '__main__':\n    go()\n")
    _write(tmp_path, "app/truly_dead.py", "def nothing():\n    return None\n")
    _write(tmp_path, "run.py", "from app.core import load\nprint(load('csv_export'))\n")
    _write(tmp_path, "config.yaml", "plugins:\n  - app.plugins.csv_export\n")
    result = scan_repo(tmp_path, memory=False)
    by_path = {f.path: f for f in result.findings if f.kind == "orphan_file"}
    assert by_path["app/truly_dead.py"].severity in {"block", "warn"}
    assert by_path["app/truly_dead.py"].confidence > by_path.get("app/tool_script.py", by_path["app/truly_dead.py"]).confidence or "app/tool_script.py" not in by_path
    if "app/tool_script.py" in by_path:
        assert "main_guard" in by_path["app/tool_script.py"].signals
        assert by_path["app/tool_script.py"].severity != "block"
    if "app/plugins/csv_export.py" in by_path:
        assert by_path["app/plugins/csv_export.py"].severity != "block"
        assert "module_named_in_config" in by_path["app/plugins/csv_export.py"].signals


def test_min_confidence_filters_notes(tmp_path: Path) -> None:
    _write(tmp_path, "m/__init__.py", "")
    _write(tmp_path, "m/a.py", "def _private_unused():\n    pass\n\ndef used():\n    return 1\n")
    _write(tmp_path, "m/main.py", "from m.a import used\nused()\n")
    low = scan_repo(tmp_path, memory=False, min_confidence=0.1)
    high = scan_repo(tmp_path, memory=False, min_confidence=0.9)
    assert any(f.kind == "unreachable" for f in low.findings)
    assert not any(f.kind == "unreachable" for f in high.findings)
