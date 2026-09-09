"""Secret redaction shared by the scanner, the judge, and every renderer."""

from __future__ import annotations

import re

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)"
        r"\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
]


def redact_text(text: str) -> str:
    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def has_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)
