"""Markdown, JSON, and SARIF renderers for scan, plan, and workflow output."""

from __future__ import annotations

import json
from typing import Any

from unreach import __version__
from unreach.plan import PlanStep, plan_payload
from unreach.scan import Finding, ScanResult, findings_to_json


def render_scan(findings: list[Finding], *, path: str, fmt: str) -> str:
    if fmt == "json":
        return findings_to_json(findings, path=path)
    if fmt == "sarif":
        return render_sarif(findings)
    return render_scan_md(findings, path=path)


def render_result(result: ScanResult, *, fmt: str, only_new: bool = False, compact: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(compact=compact, only_new=only_new), indent=2)
    if fmt == "sarif":
        return render_sarif(result.new_findings() if only_new else result.findings)
    return render_result_md(result, only_new=only_new)


def render_result_md(result: ScanResult, *, only_new: bool = False) -> str:
    findings = result.new_findings() if only_new else result.findings
    counts = result.counts()
    delta = result.delta
    profile = result.profile
    lines = [
        "# Unreach scan",
        "",
        f"Path: `{result.path}`",
        f"Languages: {', '.join(f'{k}={v}' for k, v in profile.languages.items()) or 'none'}"
        + (f" · frameworks: {', '.join(profile.frameworks)}" if profile.frameworks else "")
        + (" · monorepo" if profile.monorepo else ""),
        f"Findings: **{counts['total']}** ({counts['block']} block, {counts['warn']} warn, {counts['note']} note)",
        f"Delta vs memory: {len(delta.new)} new · {len(delta.persisting)} persisting · "
        f"{len(delta.resolved)} resolved · {len(delta.suppressed)} suppressed by decisions",
        "",
        "Severity comes from a deterministic confidence score (block ≥ 0.85, warn ≥ 0.55).",
        "Unreach never deletes files.",
        "",
    ]
    if only_new:
        lines.append(f"Showing only the {len(findings)} new finding(s).")
        lines.append("")
    if not findings:
        lines.append("No dead-code findings.")
        return "\n".join(lines) + "\n"
    new_ids = set(delta.new)
    for finding in findings:
        symbol = f" `{finding.symbol}`" if finding.symbol else ""
        tag = " (new)" if finding.id in new_ids and delta.persisting else ""
        lines.extend(
            [
                f"## {finding.severity} {finding.confidence:.2f}  {finding.kind}{symbol}{tag}",
                "",
                f"- id: `{finding.id}`",
                f"- path: `{finding.path}`",
                f"- {finding.why}",
            ]
        )
        for item in finding.evidence:
            lines.append(f"- {item}")
        lines.append("")
    if result.suppressed:
        lines.append(f"Suppressed by remembered decisions: {len(result.suppressed)}")
        for finding in result.suppressed:
            decision = result.memory.get("decisions", {}).get(finding.id, {})
            lines.append(f"- `{finding.id}` — {decision.get('decision', '?')} {decision.get('note', '')}".rstrip())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


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
                f"## {finding.severity} {finding.confidence:.2f}  {finding.kind}{symbol}",
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
                f"{step.order}. **{step.action}** {target} ({step.severity}, confidence {step.confidence:.2f})",
                f"   {step.reason}",
                f"   finding: `{step.finding_id}`",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_workflow(payload: dict[str, Any], *, fmt: str = "md") -> str:
    if fmt == "json":
        return json.dumps(payload, indent=2)
    profile = payload.get("profile", {})
    lines = [
        "# Unreach workflow",
        "",
        f"Primary language: `{profile.get('primary', 'none')}`"
        + (f" · frameworks: {', '.join(profile.get('frameworks', []))}" if profile.get("frameworks") else "")
        + (" · monorepo" if profile.get("monorepo") else ""),
        f"Selected findings: {len(payload.get('selected_findings', []))}"
        + (f" (+{payload['omitted_findings']} omitted, lower confidence)" if payload.get("omitted_findings") else ""),
        "",
        "Auto-delete is forbidden. Follow the steps in order; stop if any verify step fails.",
        "",
    ]
    current_phase = None
    for step in payload.get("steps", []):
        if step["phase"] != current_phase:
            current_phase = step["phase"]
            lines.append(f"## {current_phase}")
            lines.append("")
        lines.append(f"- **{step['id']}** {step['action']}")
        lines.append(f"  - why: {step['why']}")
        if step.get("finding_id"):
            lines.append(f"  - finding: `{step['finding_id']}`")
        if step.get("grep"):
            lines.append(f"  - grep: `{step['grep']}`")
        if step.get("read"):
            lines.append(f"  - read: {', '.join(f'`{p}`' for p in step['read'])}")
        if step.get("command"):
            lines.append(f"  - run: `{step['command']}`")
        if step.get("tool"):
            lines.append(f"  - tool: `{step['tool']}`")
        if step.get("budget_hint"):
            lines.append(f"  - budget: {step['budget_hint']}")
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(findings: list[Finding]) -> str:
    level_for = {"block": "error", "warn": "warning", "note": "note"}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rules.setdefault(
            finding.kind,
            {
                "id": finding.kind,
                "name": finding.kind.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f"Unreach {finding.kind.replace('_', ' ')}"},
                "helpUri": "https://wolfxops.github.io/unreach/cli.html",
                "properties": {"tags": ["dead-code", "maintainability"]},
            },
        )
        results.append(
            {
                "ruleId": finding.kind,
                "level": level_for.get(finding.severity, "note"),
                "message": {"text": finding.why},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                        }
                    }
                ],
                "partialFingerprints": {"unreachId": finding.id},
                "properties": {
                    "confidence": finding.confidence,
                    "symbol": finding.symbol,
                    "signals": finding.signals,
                    "evidence": finding.evidence,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "unreach",
                        "version": __version__,
                        "informationUri": "https://github.com/wolfxops/unreach",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
