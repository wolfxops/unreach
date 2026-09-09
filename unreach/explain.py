"""Explain a finding. LLM is optional; heuristic is the default."""

from __future__ import annotations

import json

from unreach.llm import LLMUnavailable, available, chat
from unreach.scan import Finding


def explain(finding: Finding) -> str:
    if available():
        try:
            return _llm_explain(finding)
        except LLMUnavailable:
            return heuristic(finding)
    return heuristic(finding)


def heuristic(finding: Finding) -> str:
    bits = [
        f"Unreach classified `{finding.id}` as {finding.kind} ({finding.severity}, confidence {finding.confidence:.2f}).",
        finding.why,
    ]
    negatives = sorted((k, v) for k, v in finding.signals.items() if v < 0)
    if negatives:
        bits.append(
            "Confidence was lowered by: "
            + ", ".join(f"{name} ({delta:+.2f})" for name, delta in negatives)
            + "."
        )
    if finding.symbol:
        bits.append(
            f"The symbol `{finding.symbol}` can be removed from the public surface of "
            f"`{finding.path}` after confirming no dynamic import or runtime getattr."
        )
    else:
        bits.append(
            f"`{finding.path}` has no importers in the static graph. Do not delete it "
            "until you confirm it is not an entry point, plugin, or test helper."
        )
    if finding.evidence:
        bits.append("Evidence: " + "; ".join(e for e in finding.evidence if not e.startswith("signal ")) + ".")
    if finding.critique:
        bits.append(finding.critique["rationale"])
        if finding.critique.get("next_check"):
            bits.append("Next check: " + finding.critique["next_check"])
    bits.append("Unreach never deletes files; use `unreach workflow` for the verification steps.")
    return " ".join(bits)


def _llm_explain(finding: Finding) -> str:
    packet = {k: v for k, v in finding.to_dict().items() if k not in {"evidence", "critique"}} | {
        "evidence": [e for e in finding.evidence if not e.startswith("signal ")][:6]
    }
    if finding.critique:
        packet["judge"] = {
            "verdict": finding.critique["verdict"],
            "rationale": finding.critique["rationale"],
            "next_check": finding.critique.get("next_check"),
        }
    text, _usage = chat(
        [
            {
                "role": "system",
                "content": (
                    "You explain static dead-code findings in one short paragraph. "
                    "Never recommend automatic deletion. Do not invent other unused files. "
                    "Mention which confidence signals matter most."
                ),
            },
            {"role": "user", "content": json.dumps(packet)},
        ],
        max_tokens=300,
    )
    return text
