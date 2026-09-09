"""Unreach CLI: scan, judge, plan, workflow, triage, explain, remember, memory, languages, mcp."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from unreach import __version__
from unreach.confidence import DEFAULT_MIN_CONFIDENCE
from unreach.explain import explain as explain_finding
from unreach.memory import DECISIONS, Memory
from unreach.mock import default_mock_root
from unreach.render import render_judge, render_languages, render_plan, render_result, render_triage, render_workflow
from unreach.scan import find_by_id, scan_repo, supported_languages
from unreach.support import languages_payload
from unreach.triage import triage
from unreach.workflow import build_workflow


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(list(sys.argv[1:] if argv is None else argv))
    except KeyboardInterrupt:
        print("unreach: interrupted", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"unreach: {exc}", file=sys.stderr)
        return 2


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="unreach",
        description="Find the code your agents keep rewriting around.",
    )
    parser.add_argument("--version", action="version", version=f"unreach {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    scan_p = sub.add_parser("scan", help="Deterministic dead-code scan with confidence scores")
    _add_common(scan_p)
    scan_p.add_argument("--format", choices=("json", "md", "sarif", "table"), default="md")
    scan_p.add_argument("--only-new", action="store_true", help="Show only findings not seen in memory")
    scan_p.add_argument("--compact", action="store_true", help="Persisting findings as one-liners (JSON)")

    judge_p = sub.add_parser("judge", help="Judge/critic table: prosecution vs devil's advocate per finding, verdict, next check, security, effort")
    _add_common(judge_p)
    judge_p.add_argument("--format", choices=("table", "md", "json"), default="table")

    plan_p = sub.add_parser("plan", help="Ordered cleanup suggestions (never deletes)")
    _add_common(plan_p)
    plan_p.add_argument("--format", choices=("json", "md", "table"), default="md")

    wf_p = sub.add_parser("workflow", help="Language-aware agent workflow for the current findings")
    _add_common(wf_p)
    wf_p.add_argument("--format", choices=("json", "md", "table"), default="md")
    wf_p.add_argument("--max", type=int, default=12, help="Max findings to include")
    wf_p.add_argument("--no-triage", action="store_true", help="Skip triage verdicts (LLM or heuristic)")
    wf_p.add_argument("--no-llm", action="store_true", help="Use heuristic triage even if an API key is set")

    tri_p = sub.add_parser("triage", help="Budgeted LLM/heuristic second opinion on ambiguous (warn) findings; verdicts cached in memory")
    _add_common(tri_p)
    tri_p.add_argument("--format", choices=("json", "md", "table"), default="md")
    tri_p.add_argument("--max-items", type=int, default=8, help="Max findings sent to the model per run")
    tri_p.add_argument("--no-llm", action="store_true", help="Heuristic verdicts only")

    sub.add_parser("languages", help="List supported languages, frameworks, and graph precision")

    explain_p = sub.add_parser("explain", help="Explain one finding (LLM optional)")
    explain_p.add_argument("finding_id")
    _add_common(explain_p)

    rem_p = sub.add_parser("remember", help="Store a decision for a finding in .unreach/memory.json")
    rem_p.add_argument("finding_id")
    rem_p.add_argument("--decision", choices=DECISIONS, required=True)
    rem_p.add_argument("--note", default="")
    rem_p.add_argument("--path", default=None, help="Repository root (default cwd)")

    mem_p = sub.add_parser("memory", help="Show or clear repository memory")
    mem_p.add_argument("path", nargs="?", default=None)
    mem_p.add_argument("--clear", action="store_true")
    mem_p.add_argument("--forget", metavar="FINDING_ID", help="Drop one remembered decision")

    sub.add_parser("mcp", help="Start stdio MCP server")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2
    if args.cmd == "mcp":
        from unreach.mcp_server import serve

        return serve()
    if args.cmd == "languages":
        sys.stdout.write(render_languages(languages_payload()))
        return 0
    if args.cmd == "remember":
        root = _resolve_path(args.path, mock=False)
        mem = Memory(root)
        entry = mem.remember(args.finding_id, args.decision, args.note)
        mem.save()
        print(json.dumps({"id": args.finding_id, **entry, "memory": str(mem.path)}, indent=2))
        return 0
    if args.cmd == "memory":
        root = _resolve_path(args.path, mock=False)
        mem = Memory(root)
        if args.clear:
            mem.clear()
            print(f"cleared {mem.path}")
            return 0
        if args.forget:
            removed = mem.forget(args.forget)
            mem.save()
            print(json.dumps({"forgot": args.forget, "removed": removed}))
            return 0
        payload = mem.summary()
        payload["decisions"] = mem.decisions()
        print(json.dumps(payload, indent=2))
        return 0

    path = _resolve_path(getattr(args, "path", None), mock=args.mock)
    result = scan_repo(
        path,
        mock=args.mock,
        lang=args.lang,
        memory=not args.no_memory,
        min_confidence=args.min_confidence,
        judge=not args.no_judge,
    )
    if args.cmd == "judge":
        sys.stdout.write(render_judge(result, fmt=args.format))
        return _exit_code(result)
    if args.cmd == "scan":
        sys.stdout.write(
            render_result(result, fmt=args.format, only_new=args.only_new, compact=args.compact)
        )
        return _exit_code(result, only_new=args.only_new)
    if args.cmd == "plan":
        sys.stdout.write(render_plan(result.findings, path=str(path), fmt=args.format))
        return _exit_code(result)
    if args.cmd == "workflow":
        verdicts = None
        if not args.no_triage:
            mem = Memory(Path(path).resolve() if Path(path).is_dir() else Path(path).resolve().parent, enabled=not args.no_memory)
            verdicts = triage(result.findings, mem, use_llm=False if args.no_llm else None)
        payload = build_workflow(
            result.profile, result.findings, delta=result.delta.to_dict(), max_findings=args.max, triage=verdicts
        )
        sys.stdout.write(render_workflow(payload, fmt=args.format))
        return 0
    if args.cmd == "triage":
        mem = Memory(Path(path).resolve() if Path(path).is_dir() else Path(path).resolve().parent, enabled=not args.no_memory)
        payload = triage(result.findings, mem, max_items=args.max_items, use_llm=False if args.no_llm else None)
        sys.stdout.write(render_triage(payload, result.findings, fmt=args.format))
        return 0
    if args.cmd == "explain":
        finding = find_by_id(result.findings + result.suppressed, args.finding_id)
        if finding is None:
            print(f"unreach: unknown finding id: {args.finding_id}", file=sys.stderr)
            return 2
        sys.stdout.write(explain_finding(finding) + "\n")
        return 0
    parser.print_help()
    return 2


def _exit_code(result, *, only_new: bool = False) -> int:
    findings = result.new_findings() if only_new else result.findings
    return 1 if any(f.severity == "block" for f in findings) else 0


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=None, help="Path to scan")
    parser.add_argument("--mock", action="store_true", help="Fixture/mock mode; no API keys")
    parser.add_argument("--lang", choices=supported_languages(), default="auto", metavar="LANG",
                        help="auto (default) or one of: " + ", ".join(supported_languages()[1:]))
    parser.add_argument("--no-memory", action="store_true", help="Do not read or write .unreach/memory.json")
    parser.add_argument("--no-judge", action="store_true", help="Skip the judge/critic layer (raw scan confidence)")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help=f"Drop findings below this confidence (default {DEFAULT_MIN_CONFIDENCE})",
    )


def _resolve_path(path: str | None, *, mock: bool) -> Path:
    if path:
        return Path(path)
    if mock:
        found = default_mock_root()
        if found:
            return found
    return Path.cwd()


if __name__ == "__main__":
    raise SystemExit(main())
