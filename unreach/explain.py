"""Explain a finding. LLM is optional; heuristic is the default."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from unreach.scan import Finding

DEFAULT_MODEL = os.environ.get("UNREACH_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"


def api_key() -> str | None:
    return os.environ.get("UNREACH_API_KEY") or os.environ.get("OPENAI_API_KEY") or None


def base_url() -> str:
    return (
        os.environ.get("UNREACH_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or "https://api.openai.com"
    ).rstrip("/")


def explain(finding: Finding) -> str:
    key = api_key()
    if key:
        try:
            return _llm_explain(finding, key)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return heuristic(finding)
    return heuristic(finding)


def heuristic(finding: Finding) -> str:
    bits = [
        f"Unreach classified `{finding.id}` as {finding.kind} ({finding.severity}).",
        finding.why,
    ]
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
        bits.append("Evidence: " + "; ".join(finding.evidence) + ".")
    bits.append("Unreach never deletes files; use `unreach plan` for an ordered suggestion list.")
    return " ".join(bits)


def _llm_explain(finding: Finding, key: str) -> str:
    url = f"{base_url()}/v1/chat/completions"
    payload = {
        "model": DEFAULT_MODEL,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You explain static dead-code findings. Be concise. "
                    "Never recommend automatic deletion. Do not invent other unused files."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(finding.to_dict(), indent=2),
            },
        ],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = json.loads(response.read().decode("utf-8"))
    text = body["choices"][0]["message"]["content"]
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty LLM response")
    return text.strip()
