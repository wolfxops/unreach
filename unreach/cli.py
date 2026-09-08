"""Unreach CLI: scan, plan, explain, mcp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from unreach import __version__
from unreach.explain import explain as explain_finding
from unreach.mock import default_mock_root
from unreach.render import render_plan, render_scan
from unreach.scan import find_by_id, has_block, scan_path


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

    scan_p = sub.add_parser("scan", help="Deterministic dead-code scan")
    _add_path(scan_p)
    scan_p.add_argument("--mock", action="store_true", help="Fixture/mock mode; no API keys")
    scan_p.add_argument("--format", choices=("json", "md"), default="md")
    scan_p.add_argument("--lang", choices=("auto", "py", "ts"), default="auto")

    plan_p = sub.add_parser("plan", help="Ordered cleanup suggestions (never deletes)")
    _add_path(plan_p)
    plan_p.add_argument("--mock", action="store_true")
    plan_p.add_argument("--format", choices=("json", "md"), default="md")
    plan_p.add_argument("--lang", choices=("auto", "py", "ts"), default="auto")

    explain_p = sub.add_parser("explain", help="Explain one finding (LLM optional)")
    explain_p.add_argument("finding_id")
    _add_path(explain_p)
    explain_p.add_argument("--mock", action="store_true")
    explain_p.add_argument("--lang", choices=("auto", "py", "ts"), default="auto")

    sub.add_parser("mcp", help="Start stdio MCP server")

    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2
    if args.cmd == "mcp":
        from unreach.mcp_server import serve

        return serve()
    if args.cmd == "scan":
        path = _resolve_path(getattr(args, "path", None), mock=args.mock)
        findings = scan_path(path, mock=args.mock, lang=args.lang)
        sys.stdout.write(render_scan(findings, path=str(path), fmt=args.format))
        return 1 if has_block(findings) else 0
    if args.cmd == "plan":
        path = _resolve_path(getattr(args, "path", None), mock=args.mock)
        findings = scan_path(path, mock=args.mock, lang=args.lang)
        sys.stdout.write(render_plan(findings, path=str(path), fmt=args.format))
        return 1 if has_block(findings) else 0
    if args.cmd == "explain":
        path = _resolve_path(getattr(args, "path", None), mock=args.mock)
        findings = scan_path(path, mock=args.mock, lang=args.lang)
        finding = find_by_id(findings, args.finding_id)
        if finding is None:
            print(f"unreach: unknown finding id: {args.finding_id}", file=sys.stderr)
            return 2
        sys.stdout.write(explain_finding(finding) + "\n")
        return 0
    parser.print_help()
    return 2


def _add_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=None, help="Path to scan")


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
