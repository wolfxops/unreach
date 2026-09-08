"""Minimal OpenAI-compatible HTTP client. No vendor SDKs.

Used only by ``explain`` and ``triage``. Detection never calls this module.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MODEL = os.environ.get("UNREACH_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"


class LLMUnavailable(RuntimeError):
    """Raised when no key is configured or the call fails."""


def api_key() -> str | None:
    return os.environ.get("UNREACH_API_KEY") or os.environ.get("OPENAI_API_KEY") or None


def base_url() -> str:
    return (
        os.environ.get("UNREACH_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or "https://api.openai.com"
    ).rstrip("/")


def available() -> bool:
    return api_key() is not None and os.environ.get("UNREACH_NO_LLM") is None


def chat(messages: list[dict[str, str]], *, max_tokens: int = 600, json_mode: bool = False, timeout: int = 30) -> tuple[str, dict[str, Any]]:
    """Return (content, usage). Raises LLMUnavailable on any failure."""
    key = api_key()
    if not key:
        raise LLMUnavailable("no UNREACH_API_KEY / OPENAI_API_KEY")
    payload: dict[str, Any] = {
        "model": DEFAULT_MODEL,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    request = urllib.request.Request(
        f"{base_url()}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise LLMUnavailable(str(exc)) from exc
    try:
        text = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMUnavailable("malformed response") from exc
    if not isinstance(text, str) or not text.strip():
        raise LLMUnavailable("empty response")
    usage = body.get("usage") or {}
    return text.strip(), {
        "model": body.get("model", DEFAULT_MODEL),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
    }
