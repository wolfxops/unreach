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
    if fmt == "table":
        return findings_table(findings)
    return render_scan_md(findings, path=path)


def render_result(result: ScanResult, *, fmt: str, only_new: bool = False, compact: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(compact=compact, only_new=only_new), indent=2)
    if fmt == "sarif":
        return render_sarif(result.new_findings() if only_new else result.findings)
    if fmt == "table":
        return render_result_table(result, only_new=only_new)
    return render_result_md(result, only_new=only_new)


# --------------------------------------------------------------------------- #
# Tables (the plugin-facing format: agents render markdown tables natively)
# --------------------------------------------------------------------------- #


def _cell(value: Any) -> str:
    text = str(value if value is not None else "—")
    return text.replace("|", "\\|").replace("\n", " ").strip() or "—"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return "\n".join(lines)


def _target(finding: Finding) -> str:
    return f"`{finding.path}` :: `{finding.symbol}`" if finding.symbol else f"`{finding.path}`"


def _conf_cell(finding: Finding) -> str:
    raw = (finding.critique or {}).get("raw_confidence")
    if raw is not None and abs(raw - finding.confidence) >= 0.005:
        return f"{finding.confidence:.2f} (scan {raw:.2f})"
    return f"{finding.confidence:.2f}"


def _objections_cell(finding: Finding, *, limit: int = 3) -> str:
    critique = finding.critique or {}
    objections = [o for o in critique.get("objections", []) if o.get("penalty", 0) > 0]
    flags = [o["hypothesis"] for o in critique.get("objections", []) if o.get("penalty", 0) == 0]
    parts = []
    for objection in objections[:limit]:
        where = objection["evidence"][0]["where"] if objection.get("evidence") else ""
        parts.append(f"{objection['hypothesis']}" + (f" @ {where}" if where and not where.endswith(":0") else ""))
    if len(objections) > limit:
        parts.append(f"+{len(objections) - limit} more")
    if not parts:
        parts.append(f"none of {critique.get('hypotheses_checked', 0)} hypotheses" if critique else "not judged")
    if flags:
        parts.append("flags: " + ", ".join(flags))
    return "; ".join(parts)


def _security_cell(finding: Finding) -> str:
    critique = finding.critique or {}
    security = critique.get("security") or {}
    markers = security.get("markers") or []
    if not markers:
        return "—"
    label = critique.get("security_priority", "review")
    bits = []
    for marker in markers[:3]:
        lines = marker.get("lines") or []
        bits.append(marker["marker"] + (f" L{','.join(str(n) for n in lines[:3])}" if lines else ""))
    return f"**{label}**: " + "; ".join(bits)


def _effort_cell(finding: Finding) -> str:
    critique = finding.critique or {}
    effort = critique.get("effort") or {}
    if not effort:
        return "—"
    win = " · quick win" if critique.get("quick_win") else ""
    return f"{effort.get('size', '?')} · ~{effort.get('minutes_estimate', '?')}m{win}"


FINDINGS_HEADERS = ["#", "sev", "confidence", "kind", "target", "judge", "devil's advocate", "next check", "security", "effort"]


def findings_table(findings: list[Finding]) -> str:
    rows: list[list[Any]] = []
    for index, finding in enumerate(findings, start=1):
        critique = finding.critique or {}
        rows.append(
            [
                index,
                finding.severity,
                _conf_cell(finding),
                finding.kind,
                _target(finding),
                critique.get("verdict", "—"),
                _objections_cell(finding),
                critique.get("next_check", "—"),
                _security_cell(finding),
                _effort_cell(finding),
            ]
        )
    return markdown_table(FINDINGS_HEADERS, rows) + "\n"


def judge_summary(findings: list[Finding]) -> dict[str, Any]:
    verdicts = {"remove": 0, "verify": 0, "keep": 0, "unjudged": 0}
    hypotheses = 0
    objections = 0
    quick_wins = 0
    security = {"remove_first": 0, "review": 0}
    raised = 0
    for finding in findings:
        critique = finding.critique
        if not critique:
            verdicts["unjudged"] += 1
            continue
        verdicts[critique["verdict"]] = verdicts.get(critique["verdict"], 0) + 1
        hypotheses += critique.get("hypotheses_checked", 0)
        objections += sum(1 for o in critique.get("objections", []) if o.get("penalty", 0) > 0)
        quick_wins += 1 if critique.get("quick_win") else 0
        priority = critique.get("security_priority")
        if priority in security:
            security[priority] += 1
        if abs(critique.get("raw_confidence", finding.confidence) - finding.confidence) >= 0.005:
            raised += 1
    return {
        "findings": len(findings),
        "verdicts": verdicts,
        "hypotheses_checked": hypotheses,
        "objections_sustained": objections,
        "confidence_adjusted": raised,
        "quick_wins": quick_wins,
        "security": security,
    }


def _summary_line(summary: dict[str, Any]) -> str:
    v = summary["verdicts"]
    return (
        f"Judge: **{v.get('remove', 0)} remove** · {v.get('verify', 0)} verify · {v.get('keep', 0)} keep"
        f" — {summary['hypotheses_checked']} counter-hypotheses checked, {summary['objections_sustained']} sustained,"
        f" {summary['confidence_adjusted']} confidence(s) adjusted · {summary['quick_wins']} quick win(s)"
        f" · security: {summary['security']['remove_first']} remove-first, {summary['security']['review']} review"
    )


def render_result_table(result: ScanResult, *, only_new: bool = False) -> str:
    findings = result.new_findings() if only_new else result.findings
    counts = result.counts()
    profile = result.profile
    head = [
        f"**Unreach scan** `{result.path}` — {counts['total']} finding(s): {counts['block']} block · {counts['warn']} warn · {counts['note']} note"
        + (f" · {', '.join(profile.frameworks)}" if profile.frameworks else ""),
        _summary_line(judge_summary(findings)),
        "",
    ]
    if not findings:
        return "\n".join(head) + "No dead-code findings.\n"
    tail = ["", "Confidence shown after the judge layer (scan value in parentheses when it changed). Unreach never deletes files."]
    if result.suppressed:
        tail.append(f"Suppressed by remembered decisions: {len(result.suppressed)}.")
    return "\n".join(head) + "\n" + findings_table(findings) + "\n".join(tail) + "\n"


def render_judge(result: ScanResult, *, fmt: str = "table") -> str:
    findings = result.findings
    summary = judge_summary(findings)
    if fmt == "json":
        payload = {
            "tool": "unreach",
            "version": __version__,
            "path": result.path,
            "auto_delete": False,
            "summary": summary,
            "critiques": [
                {**(f.critique or {"finding_id": f.id, "verdict": None}), "kind": f.kind, "path": f.path, "symbol": f.symbol, "severity": f.severity}
                for f in findings
            ],
        }
        return json.dumps(payload, indent=2)
    lines = [
        f"# Unreach judge — `{result.path}`",
        "",
        _summary_line(summary),
        "",
        "Prosecution = the scan's graph evidence. Devil's advocate = named counter-hypotheses checked against real artifacts "
        "(schedulers, entry points, CI, reflection, templates, flags, …). Judge = verdict after both, with the one check that settles it.",
        "",
    ]
    if not findings:
        lines.append("No findings to judge.")
        return "\n".join(lines) + "\n"
    lines.append(findings_table(findings).rstrip())
    if fmt == "table":
        return "\n".join(lines) + "\n"
    lines.append("")
    lines.append("## Case files")
    for finding in findings:
        critique = finding.critique
        if not critique:
            continue
        lines.extend(["", f"### {critique['verdict']} {finding.confidence:.2f} — `{finding.id}`", "", critique["rationale"]])
        for objection in critique.get("objections", []):
            tag = objection["strength"]
            lines.append(f"- **{objection['hypothesis']}** [{tag}, {-objection['penalty']:+.2f}] — {objection['note']}")
            for ev in objection.get("evidence", [])[:3]:
                if ev["where"].endswith(":0"):
                    lines.append(f"  - {ev['line']}")
                else:
                    lines.append(f"  - `{ev['where']}` · {ev['category']} · `{ev['line']}`")
        for item in critique.get("identification", []):
            if item.get("penalty", 0) > 0:
                lines.append(f"- identification: **{item['hypothesis']}** ({-item['penalty']:+.2f}) — {item['note']}")
        security = critique.get("security") or {}
        for marker in security.get("markers", []):
            where = f" lines {', '.join(str(n) for n in marker['lines'])}" if marker.get("lines") else ""
            lines.append(f"- security: **{marker['marker']}**{where} — {marker['note']}")
        if critique.get("next_check"):
            lines.append(f"- next check: {critique['next_check']}")
    return "\n".join(lines).rstrip() + "\n"


def render_plan_table(findings: list[Finding], *, path: str) -> str:
    payload = plan_payload(findings, path=path)
    rows = [
        [s["order"], s["action"], f"`{s['path']}`" + (f" :: `{s['symbol']}`" if s.get("symbol") else ""), s["severity"], f"{s['confidence']:.2f}", s["reason"]]
        for s in payload["steps"]
    ]
    head = f"**Unreach plan** `{path}` — {len(rows)} step(s). Unreach never deletes files; this is an ordered suggestion list.\n\n"
    return head + markdown_table(["#", "action", "target", "sev", "conf", "reason"], rows) + "\n"


def render_workflow_table(payload: dict[str, Any]) -> str:
    rows = []
    for step in payload.get("steps", []):
        how = []
        if step.get("grep"):
            how.append(f"grep `{step['grep']}`")
        if step.get("read"):
            how.append("read " + ", ".join(f"`{p}`" for p in step["read"][:3]))
        if step.get("command"):
            how.append(f"run `{step['command']}`")
        if step.get("tool"):
            how.append(f"tool `{step['tool']}`")
        rows.append([step["id"], step["phase"], step["action"], "; ".join(how), step.get("judge") or step.get("triage") or "—", step.get("finding_id") or "—"])
    profile = payload.get("profile", {})
    head = (
        f"**Unreach workflow** — primary `{profile.get('primary', 'none')}`"
        + (f" · {', '.join(profile.get('frameworks', []))}" if profile.get("frameworks") else "")
        + f" · {len(payload.get('selected_findings', []))} selected"
        + (f" · {len(payload.get('kept_by_judge', []))} kept by judge" if payload.get("kept_by_judge") else "")
        + "\n\n"
    )
    return head + markdown_table(["step", "phase", "action", "how", "judge / triage", "finding"], rows) + "\n"


def render_triage_table(payload: dict[str, Any], findings: list[Finding]) -> str:
    by_id = {f.id: f for f in findings}
    order = {"likely_dead": 0, "verify": 1, "keep": 2}
    rows = []
    for fid, entry in sorted(payload.get("verdicts", {}).items(), key=lambda kv: (order.get(kv[1].get("verdict"), 9), kv[0])):
        finding = by_id.get(fid)
        rows.append([
            entry.get("verdict"),
            f"{finding.confidence:.2f}" if finding else "—",
            f"`{fid}`",
            entry.get("counter") or "—",
            entry.get("reason", ""),
            entry.get("model", ""),
        ])
    llm = payload.get("llm", {})
    head = (
        f"**Unreach triage** — {'model ' + str(llm.get('model') or 'enabled') if llm.get('enabled') else 'heuristic (no API key)'}"
        f" · asked {llm.get('asked', 0)} · cached {llm.get('cached', 0)} · heuristic {llm.get('heuristic', 0)}"
        f" · skipped {llm.get('skipped_block', 0)} block + {llm.get('skipped_note', 0)} note\n\n"
    )
    if not rows:
        return head + "No warn findings to triage.\n"
    return head + markdown_table(["verdict", "conf", "finding", "devil's advocate", "reason", "source"], rows) + "\n"


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
        if finding.critique:
            lines.append(f"- judge: **{finding.critique['verdict']}** — {finding.critique.get('next_check') or ''}".rstrip(" —"))
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
    if fmt == "table":
        return render_plan_table(findings, path=path)
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
    if fmt == "table":
        return render_workflow_table(payload)
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
        if step.get("judge"):
            lines.append(f"  - judge: {step['judge']}")
        if step.get("triage"):
            lines.append(f"  - triage: {step['triage']}")
        if step.get("budget_hint"):
            lines.append(f"  - budget: {step['budget_hint']}")
    llm = payload.get("llm") or {}
    if llm:
        lines.append("")
        lines.append("## llm budget")
        lines.append("")
        lines.append(f"- policy: {llm.get('policy', '')}")
        if "called" in llm:
            lines.append(
                f"- this run: {'model called' if llm.get('called') else 'no model call'} · asked {llm.get('asked', 0)} · "
                f"cached {llm.get('cached', 0)} · heuristic {llm.get('heuristic', 0)} · "
                f"skipped {llm.get('skipped_block', 0)} block + {llm.get('skipped_note', 0)} note"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_triage(payload: dict[str, Any], findings: list[Finding], *, fmt: str = "md") -> str:
    if fmt == "json":
        return json.dumps(payload, indent=2)
    if fmt == "table":
        return render_triage_table(payload, findings)
    llm = payload.get("llm", {})
    verdicts = payload.get("verdicts", {})
    by_id = {f.id: f for f in findings}
    lines = [
        "# Unreach triage",
        "",
        f"Model: {'enabled (' + str(llm.get('model') or 'OpenAI-compatible') + ')' if llm.get('enabled') else 'not configured — deterministic heuristic verdicts'}",
        f"Asked {llm.get('asked', 0)} · cached {llm.get('cached', 0)} · heuristic {llm.get('heuristic', 0)} · "
        f"skipped {llm.get('skipped_block', 0)} block (certain) + {llm.get('skipped_note', 0)} note (too weak)"
        + (f" · deferred {llm['deferred']} to next run" if llm.get("deferred") else ""),
        "",
        "Verdicts are cached in .unreach/memory.json by evidence digest; unchanged findings are never re-asked.",
        "",
    ]
    if not verdicts:
        lines.append("No warn findings to triage.")
        return "\n".join(lines) + "\n"
    order = {"likely_dead": 0, "verify": 1, "keep": 2}
    for fid, entry in sorted(verdicts.items(), key=lambda kv: (order.get(kv[1].get("verdict"), 9), kv[0])):
        finding = by_id.get(fid)
        conf = f" {finding.confidence:.2f}" if finding else ""
        counter = f" · devil's advocate: {entry['counter']}" if entry.get("counter") else ""
        lines.append(f"- **{entry.get('verdict')}**{conf} `{fid}` — {entry.get('reason', '')}{counter} _({entry.get('model', '')})_")
    return "\n".join(lines).rstrip() + "\n"


def render_languages(payload: dict[str, Any], *, fmt: str = "md") -> str:
    if fmt == "json":
        return json.dumps(payload, indent=2)
    counts = payload["counts"]
    lines = [
        "# Unreach support matrix",
        "",
        f"{counts['languages']} languages · {counts['frameworks']} frameworks",
        "",
        payload["precision_note"],
        "",
        "| language | tier | precision | detects | frameworks |",
        "|---|---|---|---|---|",
    ]
    for lang in payload["languages"]:
        lines.append(
            f"| {lang['name']} | {lang['tier']} | {lang['precision']} | {', '.join(lang['detects'])} | {', '.join(lang['frameworks']) or '—'} |"
        )
    return "\n".join(lines) + "\n"


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
                    **(
                        {
                            "judgeVerdict": finding.critique["verdict"],
                            "rawConfidence": finding.critique["raw_confidence"],
                            "securityPriority": finding.critique["security_priority"],
                        }
                        if finding.critique
                        else {}
                    ),
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
