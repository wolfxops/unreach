"""Budgeted LLM triage.

The scanner is deterministic; the model is used only where it adds value:
ranking and second-opinion on *ambiguous* (``warn``) findings. Policy:

* ``block`` findings are never sent (the evidence already suffices).
* ``note`` findings are never sent (too weak to be worth tokens).
* ``warn`` findings are sent **once**, in **one batched call**, as compact
  evidence packets (id, kind, path, symbol, signals, why) — never file bodies.
* Verdicts are cached in memory keyed by a digest of the evidence, so an
  unchanged finding is never asked about again.
* Without a key the same interface returns deterministic heuristic verdicts,
  so workflows behave identically offline.
* The judge layer (``unreach.critic``) runs first and deterministically. Its
  verdict, sustained objections and identification caveats travel in the packet,
  and the model is asked to act as a *second* devil's advocate: name the
  strongest reason the code could still be live that the judge missed, then
  decide.

Verdicts: ``likely_dead`` | ``verify`` | ``keep``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from unreach.llm import LLMUnavailable, available, chat
from unreach.memory import Memory, estimate_tokens
from unreach.scan import Finding

VERDICTS = ("likely_dead", "verify", "keep")
DEFAULT_MAX_ITEMS = 8
STRONG_NEGATIVE = {
    "framework_registration_decorator",
    "framework_base_class",
    "module_getattr_lazy_export",
    "main_guard",
    "framework_entry_role",
}
SOFT_NEGATIVE = {
    "module_named_in_string_literal",
    "symbol_named_in_string_literal",
    "module_named_in_config",
    "symbol_named_in_config",
    "decorated_unknown",
    "module_imported_whole_attribute_access_possible",
}


def evidence_digest(finding: Finding) -> str:
    raw = json.dumps(
        {"id": finding.id, "path": finding.path, "symbol": finding.symbol, "signals": finding.signals, "confidence": finding.confidence},
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def judge_brief(finding: Finding) -> dict[str, Any] | None:
    """Compact judge summary for the model: verdict plus where the defense found evidence."""
    critique = finding.critique
    if not critique:
        return None
    objections = [
        f"{o['hypothesis']}@{o['evidence'][0]['where']}" if o.get("evidence") and not o["evidence"][0]["where"].endswith(":0") else o["hypothesis"]
        for o in critique.get("objections", [])
        if o.get("penalty", 0) > 0
    ][:4]
    caveats = [o["hypothesis"] for o in critique.get("identification", []) if o.get("penalty", 0) > 0][:3]
    brief: dict[str, Any] = {"verdict": critique["verdict"], "checked": critique.get("hypotheses_checked", 0)}
    if objections:
        brief["objections"] = objections
    if caveats:
        brief["caveats"] = caveats
    if critique.get("security", {}).get("markers"):
        brief["security"] = [m["marker"] for m in critique["security"]["markers"][:3]]
    return brief


def packet(finding: Finding) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": finding.id,
        "kind": finding.kind,
        "path": finding.path,
        "symbol": finding.symbol,
        "confidence": finding.confidence,
        "signals": finding.signals,
        "why": finding.why,
    }
    brief = judge_brief(finding)
    if brief:
        data["judge"] = brief
    return data


def heuristic_verdict(finding: Finding) -> tuple[str, str]:
    critique = finding.critique
    if critique:
        sustained = [o for o in critique.get("objections", []) if o.get("penalty", 0) > 0]
        top = sustained[0]["hypothesis"] if sustained else None
        if critique["verdict"] == "keep":
            return "keep", f"judge: {top or 'defense'} sustained; treat as reachable until the named artifact says otherwise"
        if critique["verdict"] == "remove":
            return "likely_dead", f"judge: none of {critique.get('hypotheses_checked', 0)} counter-hypotheses held; validate, then propose removal"
        return "verify", f"judge: {critique.get('next_check') or 'one targeted check settles it'}"
    names = {k for k, v in finding.signals.items() if v < 0}
    if names & STRONG_NEGATIVE:
        return "keep", "framework or entry-point signal present; treat as intentionally reachable until proven otherwise"
    if names & SOFT_NEGATIVE:
        return "verify", "dynamic or string reference signal present; grep the named reference before acting"
    if finding.confidence >= 0.7:
        return "likely_dead", "no reachability signals; import graph alone supports removal after validation"
    return "verify", "moderate confidence without decisive signals"


def triage(
    findings: list[Finding],
    memory: Memory,
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    use_llm: bool | None = None,
) -> dict[str, Any]:
    """Return {"verdicts": {id: {...}}, "llm": {...stats}} and persist verdicts."""
    llm_ok = available() if use_llm is None else (use_llm and available())
    store = memory.data.setdefault("llm", {})
    verdicts: dict[str, dict[str, Any]] = {}
    stats = {
        "enabled": bool(llm_ok),
        "called": False,
        "asked": 0,
        "cached": 0,
        "heuristic": 0,
        "skipped_block": 0,
        "skipped_note": 0,
        "deferred": 0,
        "prompt_tokens_estimate": 0,
        "model": None,
    }

    to_ask: list[Finding] = []
    for finding in findings:
        if finding.severity == "block":
            stats["skipped_block"] += 1
            continue
        if finding.severity == "note":
            stats["skipped_note"] += 1
            continue
        digest = evidence_digest(finding)
        cached = store.get(finding.id)
        if cached and cached.get("digest") == digest and (cached.get("model") != "heuristic" or not llm_ok):
            verdicts[finding.id] = cached
            stats["cached"] += 1
            continue
        to_ask.append(finding)

    if llm_ok and to_ask:
        batch = to_ask[:max_items]
        stats["deferred"] = max(0, len(to_ask) - len(batch))
        try:
            answers, usage = _ask(batch)
            stats["called"] = True
            stats["asked"] = len(batch)
            stats["model"] = usage.get("model")
            stats["prompt_tokens_estimate"] = usage.get("prompt_tokens") or estimate_tokens(json.dumps([packet(f) for f in batch]))
            for finding in batch:
                answer = answers.get(finding.id) or {}
                verdict = answer.get("verdict") if answer.get("verdict") in VERDICTS else None
                if verdict is None:
                    verdict, reason = heuristic_verdict(finding)
                    model = "heuristic"
                else:
                    reason = str(answer.get("reason", ""))[:300]
                    model = str(usage.get("model") or "llm")
                entry = _entry(finding, verdict, reason, model)
                if answer.get("counter"):
                    entry["counter"] = str(answer["counter"])[:200]
                store[finding.id] = entry
                verdicts[finding.id] = entry
            to_ask = to_ask[len(batch):]
        except LLMUnavailable:
            stats["enabled"] = False

    for finding in to_ask:
        verdict, reason = heuristic_verdict(finding)
        entry = _entry(finding, verdict, reason, "heuristic")
        store[finding.id] = entry
        verdicts[finding.id] = entry
        stats["heuristic"] += 1

    memory.dirty = True
    memory.save()
    return {"verdicts": verdicts, "llm": stats}


def _entry(finding: Finding, verdict: str, reason: str, model: str) -> dict[str, Any]:
    from unreach.memory import _now

    return {"digest": evidence_digest(finding), "verdict": verdict, "reason": reason, "model": model, "at": _now()}


def _ask(batch: list[Finding]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    system = (
        "You are the second reviewer of static dead-code findings. A deterministic judge already checked "
        "named counter-hypotheses (scheduled jobs, CLI/container/serverless entry points, CI scripts, reflection, "
        "templates, plugin registries, feature flags, platform guards, generated code, public library surface) and "
        "reports its verdict and evidence under `judge`. For each item, first play devil's advocate: name the single "
        "strongest reason the code could still be live that the judge could have missed (be concrete: which mechanism, "
        "which file to look in). Then decide one verdict: likely_dead (safe to propose removal after tests), verify "
        "(a targeted check is needed first), or keep (probably reachable). Use only the given signals and judge notes; "
        "you cannot see the code. Never recommend deleting anything automatically. Respond with JSON: "
        '{"verdicts": {"<id>": {"counter": "<= 15 words", "verdict": "...", "reason": "<= 20 words"}}}'
    )
    text, usage = chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps({"items": [packet(f) for f in batch]})},
        ],
        max_tokens=90 * len(batch) + 80,
        json_mode=True,
    )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable("non-JSON triage response") from exc
    verdicts = data.get("verdicts") if isinstance(data, dict) else None
    if not isinstance(verdicts, dict):
        raise LLMUnavailable("triage response missing verdicts")
    return verdicts, usage
