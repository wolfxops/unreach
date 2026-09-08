from pathlib import Path

import pytest

from unreach.cli import main
from unreach.langs import FRAMEWORKS
from unreach.mcp_server import Session, handle_request
from unreach.polyglot import LANGS
from unreach.scan import scan_repo, supported_languages
from unreach.support import languages_payload

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "polyglot"


def _ids(result):
    return {f.id: f for f in result.findings}


@pytest.mark.parametrize(
    "lang, orphan, blocked",
    [
        ("go", "orphan_file:internal/orphan/orphan.go", True),
        ("rust", "orphan_file:src/orphan.rs", True),
        ("ruby", "orphan_file:lib/lonely.rb", True),
        ("dart", "orphan_file:lib/lonely.dart", True),
        ("c", "orphan_file:src/lonely.h", True),
        ("lua", "orphan_file:lua/app/lonely.lua", True),
        ("java", "orphan_file:src/main/java/com/acme/util/Lonely.java", False),
        ("csharp", "orphan_file:Lonely.cs", False),
        ("php", "orphan_file:src/Lonely.php", False),
    ],
)
def test_orphan_detected_per_language(isolated_memory, lang, orphan, blocked):
    result = scan_repo(FIXTURES / lang, memory=False)
    found = _ids(result)
    assert orphan in found, sorted(found)
    finding = found[orphan]
    if blocked:
        assert finding.severity == "block", finding
    else:
        # name-precision graphs never reach block on their own
        assert finding.severity == "warn", finding
        assert any(k.endswith("_name_reference_graph") for k in finding.signals)


@pytest.mark.parametrize(
    "lang, referenced",
    [
        ("go", "internal/used/used.go"),
        ("rust", "src/used.rs"),
        ("ruby", "lib/used.rb"),
        ("dart", "lib/used.dart"),
        ("c", "src/used.h"),
        ("lua", "lua/app/used.lua"),
        ("java", "src/main/java/com/acme/util/Greeter.java"),
        ("csharp", "Greeter.cs"),
        ("php", "src/Greeter.php"),
    ],
)
def test_referenced_files_are_not_orphans(isolated_memory, lang, referenced):
    result = scan_repo(FIXTURES / lang, memory=False)
    assert f"orphan_file:{referenced}" not in _ids(result)


def test_entry_points_are_not_orphans(isolated_memory):
    go = _ids(scan_repo(FIXTURES / "go", memory=False))
    assert "orphan_file:cmd/app/main.go" not in go
    rb = _ids(scan_repo(FIXTURES / "ruby", memory=False))
    assert "orphan_file:main.rb" not in rb
    cs = _ids(scan_repo(FIXTURES / "csharp", memory=False))
    assert "orphan_file:Program.cs" not in cs
    c = _ids(scan_repo(FIXTURES / "c", memory=False))
    assert "orphan_file:src/main.c" not in c


def test_go_unused_export_is_warn_not_block(isolated_memory):
    found = _ids(scan_repo(FIXTURES / "go", memory=False))
    finding = found["unused_export:internal/used/used.go:Unused"]
    assert finding.severity == "warn"
    assert "unused_export:internal/used/used.go:Greeting" not in found


def test_frameworks_detected_from_manifests(isolated_memory):
    expect = {
        "go": "gin",
        "rust": "actix",
        "java": "spring",
        "ruby": "rails",
        "dart": "flutter",
        "csharp": "aspnet",
        "php": "laravel",
    }
    for lang, framework in expect.items():
        profile = scan_repo(FIXTURES / lang, memory=False).profile
        assert framework in profile.frameworks, (lang, profile.frameworks)
        assert profile.primary == lang
        assert profile.validate_commands.get(lang), lang


def test_support_matrix_counts():
    payload = languages_payload()
    assert payload["counts"]["languages"] >= 16
    assert payload["counts"]["frameworks"] >= 30
    assert len(FRAMEWORKS) == payload["counts"]["frameworks"]
    for spec in FRAMEWORKS.values():
        assert spec["language"] in {"py", "ts"} | set(LANGS)
    assert set(supported_languages()) == {"auto", "py", "ts", *LANGS}


def test_lang_filter_and_unknown_language(isolated_memory):
    result = scan_repo(FIXTURES / "go", memory=False, lang="go")
    assert result.profile.languages == {"go": 3}
    with pytest.raises(ValueError):
        scan_repo(FIXTURES / "go", memory=False, lang="cobol")


def test_facts_cached_in_memory(isolated_memory):
    first = scan_repo(FIXTURES / "rust")
    assert first.memory["cache_misses"] == 3
    second = scan_repo(FIXTURES / "rust")
    assert second.memory["cache_hits"] == 3
    assert second.memory["cache_misses"] == 0
    assert second.delta.persisting and not second.delta.new


def test_cli_languages_and_workflow_for_go(isolated_memory, capsys):
    assert main(["languages"]) == 0
    out = capsys.readouterr().out
    assert "Go" in out and "reference-graph" in out
    assert main(["workflow", str(FIXTURES / "go"), "--format", "json"]) == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    commands = [s.get("command") for s in payload["steps"] if s.get("command")]
    assert "go build ./..." in commands and "go test ./..." in commands
    assert payload["profile"]["primary"] == "go"


def test_mcp_languages_tool():
    session = Session()
    reply = handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "unreach.languages", "arguments": {}}},
        session,
    )
    payload = __import__("json").loads(reply["result"]["content"][0]["text"])
    assert payload["counts"]["frameworks"] >= 30
