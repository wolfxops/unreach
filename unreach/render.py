"""Markdown and JSON renderers for scan and plan output."""

from __future__ import annotations

import json

from unreach.plan import PlanStep, plan_payload
from unreach.scan import Finding, findings_to_json


def render_scan(findings: list[Finding], *, path: str, fmt: str) -> str:
    if fmt == "json":
        return findings_to_json(findings, path=path)
    return render_scan_md(findings, path=path)


def render_scan_md(findings: list[Finding], *, path: str) -> str:
    blocks = sum(1 for f in findings if f.severity == "block")
    warns = sum(1 for f in findings if f.severity == "warn")
    notes = sum(1 for f in findings if f.severity == "note")
    lines = [
        "# Unreach scan",
        "",
        f"Path: `{path}`",
        f"Findings: **{len(findings)}** ({blocks} block, {warns} warn, {notes} note)",
        "",
        "High-confidence findings are `block`. Guessed findings are `warn` or `note`.",
        "Unreach never deletes files.",
        "",
    ]
    if not findings:
        lines.append("No dead-code findings.")
        return "\n".join(lines) + "\n"
    for finding in findings:
        symbol = f" `{finding.symbol}`" if finding.symbol else ""
        lines.extend(
            [
                f"## {finding.severity}  {finding.kind}{symbol}",
                "",
                f"- id: `{finding.id}`",
                f"- path: `{finding.path}`",
                f"- {finding.why}",
            ]
        )
        for item in finding.evidence:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_plan(findings: list[Finding], *, path: str, fmt: str = "md") -> str:
    payload = plan_payload(findings, path=path)
    if fmt == "json":
        return json.dumps(payload, indent=2)
    return render_plan_md(steps=[PlanStep(**step) for step in payload["steps"]], path=path)


def render_plan_md(steps: list[PlanStep], *, path: str) -> str:
    lines = [
        "# Unreach plan",
        "",
        f"Path: `{path}`",
        "",
        "Unreach **never deletes files**. This is an ordered suggestion list, not a patch.",
        "",
    ]
    if not steps:
        lines.append("No cleanup steps.")
        return "\n".join(lines) + "\n"
    for step in steps:
        target = f"`{step.symbol}` in `{step.path}`" if step.symbol else f"`{step.path}`"
        lines.extend(
            [
                f"{step.order}. **{step.action}** {target} ({step.severity})",
                f"   {step.reason}",
                f"   finding: `{step.finding_id}`",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
