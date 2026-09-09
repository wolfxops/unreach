"""Judge / critic layer: devil's advocate, identification check, security lens, tables."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unreach import critic
from unreach.cli import main
from unreach.mcp_server import Session, handle_request
from unreach.scan import scan_repo

DEADAPP = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"


def _by_id(result):
    return {f.id: f for f in result.findings}


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_scheduled_job_flips_block_to_keep_with_evidence() -> None:
    result = scan_repo(DEADAPP, memory=False)
    nightly = _by_id(result)["orphan_file:pkg/nightly.py"]
    critique = nightly.critique
    assert critique["verdict"] == "keep"
    assert nightly.severity != "block"
    assert critique["raw_confidence"] > nightly.confidence == critique["confidence"]
    names = [o["hypothesis"] for o in critique["objections"]]
    assert "scheduled_job" in names
    evidence = next(o for o in critique["objections"] if o["hypothesis"] == "scheduled_job")["evidence"][0]
    assert evidence["where"] == "ops/crontab:2"
    assert "pkg.nightly" in evidence["line"]
    assert "ops/crontab:2" in critique["next_check"]
    assert "judge_scheduled_job" in nightly.signals
    # Without the judge the same finding is a plain warn from the config signal alone.
    raw = _by_id(scan_repo(DEADAPP, memory=False, judge=False))["orphan_file:pkg/nightly.py"]
    assert raw.critique is None and raw.confidence == critique["raw_confidence"]


def test_clean_findings_stay_block_and_quick_win() -> None:
    result = scan_repo(DEADAPP, memory=False)
    orphan = _by_id(result)["orphan_file:pkg/orphan.py"]
    assert orphan.severity == "block"
    assert orphan.critique["verdict"] == "remove"
    assert orphan.critique["hypotheses_checked"] >= 25
    assert not [o for o in orphan.critique["objections"] if o["penalty"] > 0]
    assert orphan.critique["quick_win"] is True
    assert orphan.critique["effort"]["size"] == "trivial"


def test_security_lens_prioritises_risky_dead_code() -> None:
    result = scan_repo(DEADAPP, memory=False)
    legacy = _by_id(result)["orphan_file:pkg/legacy_export.py"]
    markers = {m["marker"]: m for m in legacy.critique["security"]["markers"]}
    assert "unsafe_deserialization" in markers
    assert markers["unsafe_deserialization"]["lines"] == [7]
    assert legacy.critique["security_priority"] == "remove_first"
    assert "pickle" not in json.dumps(legacy.critique)  # only line numbers, never the code


def test_secret_like_literal_is_reported_by_line_only(tmp_path: Path) -> None:
    _write(tmp_path, "app/main.py", "from app import used\nprint(used.x)\n")
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/used.py", "x = 1\n")
    _write(tmp_path, "app/old_client.py", "import requests\nAPI_KEY = 'sk-" + "a" * 30 + "'\n\ndef call():\n    return requests.get('https://x', verify=False)\n")
    result = scan_repo(tmp_path, memory=False)
    finding = _by_id(result)["orphan_file:app/old_client.py"]
    markers = {m["marker"]: m["lines"] for m in finding.critique["security"]["markers"]}
    assert markers["secret_like_literal"] == [2]
    assert markers["tls_or_verification_disabled"] == [5]
    assert "sk-" not in json.dumps(finding.to_dict())


@pytest.mark.parametrize(
    "artifact, content, hypothesis",
    [
        ("Dockerfile", 'FROM python:3.12\nCMD ["python", "-m", "app.worker"]\n', "container_or_process_entry"),
        ("Procfile", "worker: python -m app.worker\n", "container_or_process_entry"),
        ("serverless.yml", "service: x\nfunctions:\n  worker:\n    handler: app/worker.handler\n", "serverless_handler"),
        (".github/workflows/nightly.yml", "on:\n  schedule:\n    - cron: '0 2 * * *'\njobs:\n  run:\n    steps:\n      - run: python -m app.worker\n", "scheduled_job"),
        ("Makefile", "worker:\n\tpython -m app.worker\n", "ci_or_build_invocation"),
        ("k8s/cron.yaml", "apiVersion: batch/v1\nkind: CronJob\nspec:\n  schedule: '0 2 * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n            - command: ['python', '-m', 'app.worker']\n", "scheduled_job"),
        ("infra/main.tf", 'resource "aws_lambda_function" "w" {\n  handler = "app/worker.handler"\n}\n', "infrastructure_manifest"),
        (".vscode/launch.json", '{"configurations": [{"program": "${workspaceFolder}/app/worker.py"}]}\n', "ide_or_runner_config"),
        ("templates/index.html", "<button onclick=\"worker()\">{% load worker %}</button>\n", "template_reference"),
    ],
)
def test_artifact_hypotheses_find_hidden_entry_points(tmp_path: Path, artifact: str, content: str, hypothesis: str) -> None:
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/main.py", "from app import used\nprint(used.x)\n")
    _write(tmp_path, "app/used.py", "x = 1\n")
    _write(tmp_path, "app/worker.py", "def handler(event, context):\n    return 1\n")
    _write(tmp_path, artifact, content)
    result = scan_repo(tmp_path, memory=False)
    finding = _by_id(result)["orphan_file:app/worker.py"]
    names = {o["hypothesis"]: o for o in finding.critique["objections"]}
    assert hypothesis in names, names.keys()
    where = names[hypothesis]["evidence"][0]["where"]
    assert where.startswith(artifact + ":")
    assert finding.critique["verdict"] == "keep"
    assert finding.severity != "block"


def test_in_file_hypotheses_flag_dormant_not_dead(tmp_path: Path) -> None:
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/main.py", "from app import used\nprint(used.x)\n")
    _write(tmp_path, "app/used.py", "x = 1\n")
    _write(
        tmp_path,
        "app/flagged.py",
        "import os\n\nif os.environ.get('FEATURE_NEW_BILLING'):\n    ENABLED = True\n\n@scheduler.scheduled_job('cron', hour=2)\ndef sweep():\n    pass\n",
    )
    _write(tmp_path, "app/win_only.py", "import sys\nif sys.platform == 'win32':\n    pass\n")
    _write(tmp_path, "app/gen_pb2.py", "# Generated by the protocol buffer compiler.  DO NOT EDIT!\nX = 1\n")
    _write(tmp_path, "app/kept.py", "# unreach: keep — loaded by the ops runbook\nVALUE = 1\n")
    result = scan_repo(tmp_path, memory=False)
    found = _by_id(result)

    flagged = found["orphan_file:app/flagged.py"].critique
    names = {o["hypothesis"] for o in flagged["objections"]}
    assert {"feature_flag_or_env_gate", "scheduler_registration_in_file"} <= names
    assert flagged["verdict"] in {"verify", "keep"}

    win = found["orphan_file:app/win_only.py"].critique
    assert "platform_or_build_conditional" in {o["hypothesis"] for o in win["objections"]}

    gen = found["orphan_file:app/gen_pb2.py"].critique
    gen_obj = next(o for o in gen["objections"] if o["hypothesis"] == "generated_code")
    assert any("DO NOT EDIT" in e["line"] for e in gen_obj["evidence"])
    assert "generator" in gen["next_check"]

    kept = found["orphan_file:app/kept.py"].critique
    assert kept["verdict"] == "keep"
    assert kept["objections"][0]["hypothesis"] == "explicit_keep_marker"
    assert found["orphan_file:app/kept.py"].severity == "note"


def test_reflection_and_convention_for_exports(tmp_path: Path) -> None:
    reflect = tmp_path / "reflect"
    _write(reflect, "app/__init__.py", "")
    _write(
        reflect,
        "app/main.py",
        "import importlib\nmod = importlib.import_module('app.plugins')\nfn = getattr(mod, 'run_export')\nprint(fn)\n",
    )
    _write(reflect, "app/plugins.py", "def run_export():\n    return 1\n")
    result = scan_repo(reflect, memory=False)
    found = _by_id(result)
    critique = found["orphan_file:app/plugins.py"].critique
    hyps = {o["hypothesis"]: o for o in critique["objections"]}
    assert "dynamic_loading_or_reflection" in hyps
    assert hyps["dynamic_loading_or_reflection"]["evidence"][0]["where"].startswith("app/main.py:")
    # scan already priced the string literal in; the judge halves its own penalty to avoid double counting
    assert hyps["dynamic_loading_or_reflection"]["penalty"] == pytest.approx(0.175)
    assert critique["verdict"] == "keep"

    cmds = tmp_path / "cmds"
    _write(cmds, "app/__init__.py", "")
    _write(cmds, "app/main.py", "from app.cmds import used_cmd\nprint(used_cmd())\n")
    _write(cmds, "app/cmds.py", "def used_cmd():\n    return 0\n\n\ndef ExportCommand():\n    return 2\n\n\ndef plain_dead():\n    return 3\n")
    result = scan_repo(cmds, memory=False)
    found = _by_id(result)
    command = found["unused_export:app/cmds.py:ExportCommand"].critique
    assert "convention_dispatched_name" in {o["hypothesis"] for o in command["objections"]}
    assert command["verdict"] == "verify"

    plain = found["unused_export:app/cmds.py:plain_dead"].critique
    assert plain["verdict"] == "remove"
    assert not [o for o in plain["objections"] if o["penalty"] > 0]


def test_identification_check_lowers_certainty(tmp_path: Path) -> None:
    _write(tmp_path, "src/index.ts", "export * from './lib'\nimport './boot'\n")
    _write(tmp_path, "src/boot.ts", "console.log('boot')\n")
    _write(tmp_path, "src/lib.ts", "export const util = 1\nexport const specificThing = 2\n")
    _write(tmp_path, "packages/a/package.json", '{"name": "a"}')
    _write(tmp_path, "packages/b/package.json", '{"name": "b"}')
    _write(tmp_path, "package.json", '{"name": "root", "private": true, "workspaces": ["packages/*"]}')
    result = scan_repo(tmp_path, memory=False)
    found = _by_id(result)
    export = found["unused_export:src/lib.ts:specificThing"].critique
    ident = {o["hypothesis"] for o in export["identification"]}
    assert {"star_reexports_present", "unresolved_workspace_imports"} <= ident
    barrel = {o["hypothesis"] for o in export["objections"]}
    assert "barrel_star_reexport" in barrel
    generic = found["unused_export:src/lib.ts:util"].critique
    assert "generic_name" in {o["hypothesis"] for o in generic["identification"]}
    assert "orphan_file:src/boot.ts" not in found  # side-effect import is an import edge


def test_public_library_surface_only_for_published_packages(tmp_path: Path) -> None:
    _write(tmp_path, "pyproject.toml", '[project]\nname = "mylib"\nversion = "0.1"\n')
    _write(tmp_path, "mylib/__init__.py", "from mylib.core import a\n__all__ = ['a']\n")
    _write(tmp_path, "mylib/core.py", "def a():\n    return 1\n\n\ndef beta_helper():\n    return 2\n")
    result = scan_repo(tmp_path, memory=False)
    b = _by_id(result)["unused_export:mylib/core.py:beta_helper"].critique
    assert "public_library_surface" in {o["hypothesis"] for o in b["objections"]}
    assert b["verdict"] == "verify"

    app = tmp_path / "app"
    _write(app, "pyproject.toml", '[project]\nname = "myapp"\nversion = "0.1"\nclassifiers = ["Private :: Do Not Upload"]\n')
    _write(app, "myapp/__init__.py", "")
    _write(app, "myapp/main.py", "from myapp import core\nprint(core.a())\n")
    _write(app, "myapp/core.py", "def a():\n    return 1\n\n\ndef beta_helper():\n    return 2\n")
    result = scan_repo(app, memory=False)
    b = _by_id(result)["unused_export:myapp/core.py:beta_helper"].critique
    assert "public_library_surface" not in {o["hypothesis"] for o in b["objections"]}


def test_artifact_index_redacts_and_categorises(tmp_path: Path) -> None:
    _write(tmp_path, "deploy/Dockerfile", "ENV TOKEN=ghp_" + "x" * 40 + "\nCMD python -m svc.job\n")
    _write(tmp_path, "docs/guide.md", "Run `svc.job` nightly.\n")
    index = critic.ArtifactIndex(tmp_path)
    assert "container" in index.categories["deploy/Dockerfile"]
    assert "docs" in index.categories["docs/guide.md"]
    hits = index.locate(["svc.job"], categories={"container"})
    assert hits and hits[0].where == "deploy/Dockerfile:2"
    assert "ghp_" not in json.dumps([h.to_dict() for h in index.locate(["TOKEN"])])
    assert "svc.job" in index.config_tokens
    assert "guide" not in index.config_tokens  # docs never count as configuration


def test_judge_cli_table_and_mcp(capsys) -> None:
    assert main(["judge", str(DEADAPP), "--no-memory"]) == 1
    out = capsys.readouterr().out
    assert "| # | sev | confidence | kind | target | judge | devil's advocate | next check | security | effort |" in out
    assert "scheduled_job @ ops/crontab:2" in out
    assert "remove_first" in out
    assert "quick win" in out

    assert main(["judge", str(DEADAPP), "--no-memory", "--format", "md"]) == 1
    md = capsys.readouterr().out
    assert "## Case files" in md and "Prosecution:" in md and "Defense:" in md

    assert main(["judge", str(DEADAPP), "--no-memory", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["verdicts"]["keep"] == 1
    assert payload["auto_delete"] is False

    session = Session()
    reply = handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "unreach.judge", "arguments": {"path": str(DEADAPP), "memory": False}}},
        session,
    )
    text = reply["result"]["content"][0]["text"]
    assert text.startswith("# Unreach judge") and "| keep |" in text


def test_table_format_everywhere(capsys) -> None:
    for cmd in (["scan"], ["plan"], ["workflow", "--no-triage"], ["triage", "--no-llm"]):
        main([cmd[0], str(DEADAPP), "--no-memory", "--format", "table", *cmd[1:]])
        out = capsys.readouterr().out
        assert out.count("|---|") >= 1 or "No warn findings" in out, cmd
    session = Session()
    for tool in ("unreach.scan", "unreach.plan", "unreach.workflow", "unreach.triage"):
        reply = handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {"path": str(DEADAPP), "memory": False, "format": "table", "llm": False}}},
            session,
        )
        text = reply["result"]["content"][0]["text"]
        assert "|---|" in text or "No warn findings" in text, tool


def test_workflow_uses_judge_next_check_and_skips_keep() -> None:
    result = scan_repo(DEADAPP, memory=False)
    from unreach.workflow import build_workflow

    payload = build_workflow(result.profile, result.findings, delta=result.delta.to_dict())
    assert "orphan_file:pkg/nightly.py" in payload["kept_by_judge"]
    assert "orphan_file:pkg/nightly.py" not in payload["selected_findings"]
    assert "orphan_file:pkg/legacy_export.py" in payload["security_first"]
    assert "orphan_file:pkg/orphan.py" in payload["quick_wins"]
    actions = " ".join(s["action"] for s in payload["steps"])
    assert "security marker" in actions
    judged = [s for s in payload["steps"] if s.get("judge")]
    assert judged and any("remove 0.92" in s["judge"] for s in judged)


def test_triage_heuristic_and_packet_carry_judge(isolated_memory, tmp_path, monkeypatch) -> None:
    from unreach import triage as tri
    from unreach.memory import Memory

    result = scan_repo(DEADAPP, memory=False)
    maybe = _by_id(result)["unused_export:pkg/hooks.py:maybe_dead"]
    verdict, reason = tri.heuristic_verdict(maybe)
    assert verdict == "verify" and reason.startswith("judge:")
    pkt = tri.packet(maybe)
    assert pkt["judge"]["verdict"] == "verify" and pkt["judge"]["checked"] >= 25

    sent = []
    monkeypatch.setattr(tri, "available", lambda: True)

    def fake_chat(messages, **kwargs):
        sent.append(messages)
        items = json.loads(messages[1]["content"])["items"]
        return json.dumps({"verdicts": {i["id"]: {"counter": "could be a template tag", "verdict": "verify", "reason": "ok"} for i in items}}), {"model": "fake"}

    monkeypatch.setattr(tri, "chat", fake_chat)
    out = tri.triage(result.findings, Memory(tmp_path))
    assert "devil's advocate" in sent[0][0]["content"]
    entry = out["verdicts"]["unused_export:pkg/hooks.py:maybe_dead"]
    assert entry["counter"] == "could be a template tag"
