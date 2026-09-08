"""Ordered cleanup plan. Never writes or deletes files."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from unreach.scan import Finding

KIND_ORDER = {
    "unused_export": 0,
    "unused_dep": 1,
    "unreachable": 2,
    "orphan_file": 3,
}

ACTION_FOR_KIND = {
    "unused_export": "remove_export",
    "unused_dep": "drop_dep",
    "unreachable": "review_symbol",
    "orphan_file": "delete_file_manual",
}


@dataclass
class PlanStep:
    order: int
    action: str
    path: str
    symbol: str | None
    reason: str
    finding_id: str
    severity: str
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def build_plan(findings: list[Finding]) -> list[PlanStep]:
    ranked = sorted(
        findings,
        key=lambda f: (KIND_ORDER.get(f.kind, 9), -f.confidence, f.path, f.symbol or ""),
    )
    steps: list[PlanStep] = []
    for index, finding in enumerate(ranked, start=1):
        action = ACTION_FOR_KIND.get(finding.kind, "review")
        if finding.kind == "orphan_file":
            reason = (
                f"Manually delete `{finding.path}` only after confirming it is not an "
                f"entry point. {finding.why}"
            )
        elif finding.kind == "unused_export":
            reason = (
                f"Remove export `{finding.symbol}` from `{finding.path}` "
                f"(or stop exporting it). {finding.why}"
            )
        elif finding.kind == "unused_dep":
            reason = f"Consider dropping `{finding.symbol}` from `{finding.path}`. {finding.why}"
        else:
            reason = finding.why
        if finding.severity != "block":
            reason += f" Confidence {finding.confidence:.2f}: verify before acting."
        steps.append(
            PlanStep(
                order=index,
                action=action,
                path=finding.path,
                symbol=finding.symbol,
                reason=reason,
                finding_id=finding.id,
                severity=finding.severity,
                confidence=finding.confidence,
            )
        )
    return steps


def plan_payload(findings: list[Finding], *, path: str) -> dict:
    steps = build_plan(findings)
    return {
        "tool": "unreach",
        "auto_delete": False,
        "path": path,
        "summary": (
            "Ordered suggestions only. Unreach does not delete files or apply patches."
        ),
        "steps": [step.to_dict() for step in steps],
    }
