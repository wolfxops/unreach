"""Machine-readable support matrix: languages, precision, frameworks."""

from __future__ import annotations

from typing import Any

from unreach.langs import FRAMEWORKS, LANGUAGE_NAMES
from unreach.polyglot import LANGS

TIERS = {
    "py": {"tier": "ast", "precision": "path", "detects": ["orphan_file", "unused_export", "unused_dep", "unreachable"], "suffixes": [".py"]},
    "ts": {"tier": "regex-graph", "precision": "path", "detects": ["orphan_file", "unused_export"], "suffixes": [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".vue", ".svelte"]},
}


def languages_payload() -> dict[str, Any]:
    languages: list[dict[str, Any]] = []
    for key in ("py", "ts"):
        languages.append({"key": key, "name": LANGUAGE_NAMES[key], **TIERS[key], "frameworks": _frameworks_for(key), "validate": []})
    for key, spec in LANGS.items():
        languages.append(
            {
                "key": key,
                "name": spec.name,
                "tier": "reference-graph",
                "precision": spec.precision,
                "detects": ["orphan_file"] + (["unused_export"] if spec.exports else []),
                "suffixes": list(spec.suffixes),
                "frameworks": _frameworks_for(key),
                "validate": list(spec.validate),
                "manifests": list(spec.manifests),
            }
        )
    return {
        "tool": "unreach",
        "languages": languages,
        "frameworks": sorted(FRAMEWORKS),
        "counts": {"languages": len(languages), "frameworks": len(FRAMEWORKS)},
        "precision_note": (
            "path: imports resolve to files, findings may reach block. "
            "name: references are type/module tokens, findings capped at warn."
        ),
    }


def _frameworks_for(lang_key: str) -> list[str]:
    return sorted(name for name, spec in FRAMEWORKS.items() if spec["language"] == lang_key)
