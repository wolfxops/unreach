"""Deterministic confidence scoring.

Every finding carries a ``confidence`` in [0, 1] built from named signals.
Severity is derived from confidence, so only high-confidence findings are
``block``. No LLM is involved; the score is reproducible and explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BLOCK_AT = 0.85
WARN_AT = 0.55
DEFAULT_MIN_CONFIDENCE = 0.25

BASE_BY_KIND = {
    "orphan_file": 0.92,
    "unused_export": 0.88,
    "unused_dep": 0.60,
    "unreachable": 0.50,
}


@dataclass
class Signals:
    """Named adjustments. Positive raises confidence, negative lowers it."""

    values: dict[str, float] = field(default_factory=dict)

    def add(self, name: str, delta: float) -> None:
        self.values[name] = round(self.values.get(name, 0.0) + delta, 3)

    def total(self) -> float:
        return sum(self.values.values())


def score(kind: str, signals: Signals) -> float:
    base = BASE_BY_KIND.get(kind, 0.5)
    value = base + signals.total()
    return round(min(0.99, max(0.02, value)), 2)


def severity_for(confidence: float) -> str:
    if confidence >= BLOCK_AT:
        return "block"
    if confidence >= WARN_AT:
        return "warn"
    return "note"


def orphan_signals(
    *,
    module_name: str,
    role: str,
    has_main_guard: bool,
    name_in_strings: bool,
    name_in_config: bool,
    repo_dynamic_import: bool,
    module_dynamic_import: bool,
    is_package_init: bool,
    seen_count: int,
) -> Signals:
    s = Signals()
    s.add("no_importers", 0.0)
    if role == "entry":
        s.add("framework_entry_role", -0.55)
    if has_main_guard:
        s.add("main_guard", -0.45)
    if name_in_strings:
        s.add("module_named_in_string_literal", -0.35)
    if name_in_config:
        s.add("module_named_in_config", -0.30)
    if repo_dynamic_import:
        s.add("repo_uses_dynamic_import", -0.10)
    if module_dynamic_import:
        s.add("module_uses_dynamic_import", -0.05)
    if is_package_init:
        s.add("package_init", -0.30)
    if module_name.split(".")[-1].startswith("_"):
        s.add("private_module_name", 0.02)
    s.add("stable_across_runs", min(0.03, 0.01 * max(0, seen_count - 1)))
    return s


def export_signals(
    *,
    symbol: str,
    decorators: list[str],
    bases: list[str],
    framework_decorators: set[str],
    framework_bases: set[str],
    used_locally: bool,
    whole_module_imported: bool,
    name_in_strings: bool,
    name_in_config: bool,
    module_has_getattr: bool,
    repo_dynamic_import: bool,
    in_all: bool,
    seen_count: int,
) -> Signals:
    s = Signals()
    s.add("not_imported_by_name", 0.0)
    if used_locally:
        s.add("referenced_locally", -0.30)
    if whole_module_imported:
        s.add("module_imported_whole_attribute_access_possible", -0.30)
    if decorators:
        known = [d for d in decorators if _matches_any(d, framework_decorators)]
        if known:
            s.add("framework_registration_decorator", -0.60)
        else:
            s.add("decorated_unknown", -0.20)
    if bases:
        known_bases = [b for b in bases if _matches_any(b, framework_bases)]
        if known_bases:
            s.add("framework_base_class", -0.35)
        else:
            s.add("subclass_of_external", -0.10)
    if name_in_strings:
        s.add("symbol_named_in_string_literal", -0.35)
    if name_in_config:
        s.add("symbol_named_in_config", -0.30)
    if module_has_getattr:
        s.add("module_getattr_lazy_export", -0.40)
    if repo_dynamic_import:
        s.add("repo_uses_dynamic_import", -0.08)
    if in_all:
        s.add("listed_in_dunder_all_public_api", -0.15)
    if symbol.isupper():
        s.add("constant_like_name", -0.05)
    s.add("stable_across_runs", min(0.03, 0.01 * max(0, seen_count - 1)))
    return s


def dep_signals(*, dep: str, name_in_config: bool, has_bin_usage: bool, seen_count: int) -> Signals:
    s = Signals()
    s.add("not_imported_anywhere", 0.0)
    if name_in_config:
        s.add("dependency_named_in_config_or_scripts", -0.30)
    if has_bin_usage:
        s.add("cli_binary_use", -0.30)
    if dep.startswith(("types-", "@types/")) or dep in {"pytest", "mypy", "ruff", "black", "isort", "flake8", "pyright", "eslint", "prettier", "typescript"}:
        s.add("tooling_dependency", -0.25)
    s.add("stable_across_runs", min(0.03, 0.01 * max(0, seen_count - 1)))
    return s


def _matches_any(name: str, candidates: set[str]) -> bool:
    if not name:
        return False
    tail = name.split(".")[-1]
    return name in candidates or tail in candidates
