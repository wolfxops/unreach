"""Dynamic agentic workflow.

Given a repository profile (languages, frameworks, monorepo) and the current
findings, produce an ordered, machine-readable checklist an agent should follow
before touching code. It is data, not prose: each step has an ``action``, an
optional shell ``command`` or ``read`` target, and a ``why``.

The workflow is deliberately token-frugal: it points the agent at the exact
files and grep patterns to inspect instead of "read the repo". When triage
verdicts are supplied (from ``unreach.triage``), ambiguous findings are ordered
and annotated so the agent spends its reads where they matter.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from unreach.langs import LANGUAGE_NAMES, PY_SUFFIXES, TS_SUFFIXES, Profile
from unreach.polyglot import LANGS, lang_for_suffix
from unreach.scan import Finding

VERDICT_ORDER = {"likely_dead": 0, None: 1, "verify": 2, "keep": 3}


@dataclass
class Step:
    id: str
    phase: str  # verify | edit | validate | remember
    action: str
    why: str
    finding_id: str | None = None
    command: str | None = None
    read: list[str] = field(default_factory=list)
    grep: str | None = None
    tool: str | None = None
    budget_hint: str | None = None
    triage: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], "")}


def build_workflow(
    profile: Profile,
    findings: list[Finding],
    *,
    delta: dict[str, Any] | None = None,
    max_findings: int = 12,
    triage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    steps: list[Step] = []
    counter = 0
    verdicts: dict[str, dict[str, Any]] = (triage or {}).get("verdicts", {})
    llm_stats: dict[str, Any] = (triage or {}).get("llm", {})

    def nxt(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter:02d}"

    def verdict_of(f: Finding) -> str | None:
        entry = verdicts.get(f.id)
        return entry.get("verdict") if entry else None

    new_ids = set((delta or {}).get("new", []))
    persisting_ids = set((delta or {}).get("persisting", []))
    ranked = sorted(
        findings,
        key=lambda f: (
            f.id not in new_ids if new_ids else False,
            0 if f.severity == "block" else 1,
            VERDICT_ORDER.get(verdict_of(f), 1),
            -f.confidence,
            f.kind,
            f.path,
        ),
    )
    selected = [f for f in ranked if verdict_of(f) != "keep"][:max_findings]
    kept = [f.id for f in ranked if verdict_of(f) == "keep"]

    steps.append(
        Step(
            id=nxt("ctx"),
            phase="verify",
            action="Read only the files named in this workflow. Do not crawl the repository.",
            why="Findings already carry the import-graph evidence; re-reading the tree wastes tokens.",
            budget_hint=(
                f"{len(persisting_ids)} findings persist from a previous run and were already triaged; "
                "skip them unless new evidence appears."
                if persisting_ids
                else "First run for this repository; all findings are new."
            ),
        )
    )
    if kept:
        steps.append(
            Step(
                id=nxt("ctx"),
                phase="verify",
                action=f"Skip {len(kept)} finding(s) triaged as `keep` (framework or entry signals). Record them with unreach.remember if you agree.",
                why="Triage already judged these reachable; re-verifying them is the most common token sink.",
                budget_hint=", ".join(kept[:6]) + (" ..." if len(kept) > 6 else ""),
            )
        )

    for finding in selected:
        steps.extend(_steps_for_finding(finding, profile, nxt, verdicts.get(finding.id)))

    steps.extend(_validation_steps(profile, nxt, selected))
    phase_order = {"verify": 0, "edit": 1, "validate": 2, "remember": 3}
    steps.sort(key=lambda s: phase_order.get(s.phase, 9))
    steps.append(
        Step(
            id=nxt("mem"),
            phase="remember",
            action="Record a decision for each finding you reviewed via unreach.remember (keep | false_positive | resolved).",
            why="Decisions are stored in .unreach/memory.json so the next session does not re-triage the same findings.",
            tool="unreach.remember",
        )
    )

    return {
        "tool": "unreach",
        "auto_delete": False,
        "profile": profile.to_dict(),
        "policy": {
            "block_threshold": 0.85,
            "warn_threshold": 0.55,
            "delete_requires": "explicit user approval after validation steps pass",
        },
        "llm": {
            "policy": "model sees only warn findings, once, as compact evidence packets; verdicts are cached by evidence digest",
            **llm_stats,
        },
        "selected_findings": [f.id for f in selected],
        "kept_by_triage": kept,
        "omitted_findings": max(0, len(findings) - len(selected) - len(kept)),
        "steps": [s.to_dict() for s in steps],
    }


def _steps_for_finding(finding: Finding, profile: Profile, nxt, verdict: dict[str, Any] | None) -> list[Step]:
    steps: list[Step] = []
    lang = _lang_for(finding.path)
    symbol = finding.symbol
    module = _module_for(finding.path)
    verdict_name = verdict.get("verdict") if verdict else None
    verdict_reason = verdict.get("reason") if verdict else None
    lang_name = LANGUAGE_NAMES.get(lang, lang)

    if finding.kind == "orphan_file":
        grep_target = module if lang == "py" else _stem(finding.path)
        steps.append(
            Step(
                id=nxt("verify"),
                phase="verify",
                action=f"Confirm nothing references `{grep_target}` outside the static {lang_name} graph.",
                why="Orphan files are only safe to remove when no dynamic import, config, script, or entry point names them.",
                finding_id=finding.id,
                grep=grep_target,
                read=[finding.path],
                budget_hint=_budget_hint(verdict_name, "Read the first 40 lines of the file for an entry guard, plugin registration, or side-effect imports."),
                triage=_triage_label(verdict_name, verdict_reason),
            )
        )
        if lang == "py" and profile.frameworks:
            steps.append(
                Step(
                    id=nxt("verify"),
                    phase="verify",
                    action=f"Check framework wiring for {', '.join(profile.frameworks)}: settings INSTALLED_APPS, router includes, entry_points, celery autodiscover.",
                    why="Framework-loaded modules are the top source of false positives.",
                    finding_id=finding.id,
                    grep=module.split(".")[-1],
                )
            )
        if lang == "ts":
            steps.append(
                Step(
                    id=nxt("verify"),
                    phase="verify",
                    action="Check package.json main/exports/bin, tsconfig paths, and bundler entry config for this file.",
                    why="Bundlers and package manifests reference files without import statements.",
                    finding_id=finding.id,
                    read=[p for p in ("package.json", "tsconfig.json") if p in profile.package_manifests or p == "tsconfig.json"],
                )
            )
        if lang in LANGS:
            steps.append(
                Step(
                    id=nxt("verify"),
                    phase="verify",
                    action=f"Check {lang_name} build wiring ({', '.join(LANGS[lang].manifests)}) and reflection/DI registration for `{_stem(finding.path)}`.",
                    why=f"{lang_name} findings come from a {LANGS[lang].precision}-precision reference graph; build files and DI containers can load files without imports.",
                    finding_id=finding.id,
                    read=[m for m in LANGS[lang].manifests if "*" not in m],
                )
            )
        steps.append(
            Step(
                id=nxt("edit"),
                phase="edit",
                action=f"If verified: propose deleting `{finding.path}` in a patch. Do not delete without user approval.",
                why=f"confidence {finding.confidence:.2f} ({finding.severity}). {finding.why}",
                finding_id=finding.id,
                triage=_triage_label(verdict_name, None),
            )
        )
    elif finding.kind == "unused_export":
        steps.append(
            Step(
                id=nxt("verify"),
                phase="verify",
                action=f"Grep for `{symbol}` as a string, attribute, reflection target, or re-export across the repo.",
                why="Exports reached via getattr/reflection, __all__ re-exports, plugin registries, or templates are not in the import graph.",
                finding_id=finding.id,
                grep=symbol,
                read=[finding.path],
                budget_hint=_budget_hint(verdict_name, "Read only the definition block of the symbol, not the whole file."),
                triage=_triage_label(verdict_name, verdict_reason),
            )
        )
        if lang == "py" and profile.decorators:
            steps.append(
                Step(
                    id=nxt("verify"),
                    phase="verify",
                    action=f"Confirm `{symbol}` is not registered by a framework decorator ({', '.join(sorted(profile.decorators)[:6])}).",
                    why="Decorated handlers, fixtures, tasks and commands are invoked by the framework, not imported.",
                    finding_id=finding.id,
                )
            )
        steps.append(
            Step(
                id=nxt("edit"),
                phase="edit",
                action=f"If verified: remove `{symbol}` from `{finding.path}` (or make it private) in a reviewable patch.",
                why=f"confidence {finding.confidence:.2f} ({finding.severity}). {finding.why}",
                finding_id=finding.id,
                triage=_triage_label(verdict_name, None),
            )
        )
    elif finding.kind == "unused_dep":
        steps.append(
            Step(
                id=nxt("verify"),
                phase="verify",
                action=f"Check scripts, Dockerfiles, CI, and plugin configs for the `{symbol}` binary or entry point.",
                why="Dependencies used as CLI tools or plugins never appear in imports.",
                finding_id=finding.id,
                grep=symbol or "",
                read=[finding.path],
                triage=_triage_label(verdict_name, verdict_reason),
            )
        )
        steps.append(
            Step(
                id=nxt("edit"),
                phase="edit",
                action=f"If verified: drop `{symbol}` from `{finding.path}` and refresh the lockfile.",
                why=f"confidence {finding.confidence:.2f} ({finding.severity}).",
                finding_id=finding.id,
            )
        )
    else:
        steps.append(
            Step(
                id=nxt("verify"),
                phase="verify",
                action=f"Review `{symbol}` in `{finding.path}`; it is private and unreferenced.",
                why=finding.why,
                finding_id=finding.id,
                read=[finding.path],
                triage=_triage_label(verdict_name, verdict_reason),
            )
        )
    return steps


def _triage_label(verdict: str | None, reason: str | None) -> str | None:
    if not verdict:
        return None
    return f"{verdict}: {reason}" if reason else verdict


def _budget_hint(verdict: str | None, default: str) -> str:
    if verdict == "likely_dead":
        return "Triage says likely dead: a single grep is enough; skip reading the file unless the grep hits."
    if verdict == "verify":
        return "Triage flagged a dynamic/string reference: read the grep hits, not the whole file."
    return default


def _validation_steps(profile: Profile, nxt, selected: list[Finding]) -> list[Step]:
    steps: list[Step] = []
    langs = {_lang_for(f.path) for f in selected} | ({profile.primary} if profile.primary != "none" else set())
    if "py" in langs:
        modules = sorted({_module_for(f.path).split(".")[0] for f in selected if _lang_for(f.path) == "py" and f.kind != "unused_dep"})
        if modules:
            steps.append(
                Step(
                    id=nxt("validate"),
                    phase="validate",
                    action="Import-check the touched packages after edits.",
                    why="Catches broken re-exports immediately and cheaply.",
                    command="python -c \"" + "; ".join(f"import {m}" for m in modules[:6]) + "\"",
                )
            )
        if profile.type_checker in {"mypy", "pyright"}:
            steps.append(
                Step(
                    id=nxt("validate"),
                    phase="validate",
                    action=f"Run {profile.type_checker} on the changed files.",
                    why="Type checker confirms no remaining references.",
                    command=f"{profile.type_checker} .",
                )
            )
        steps.append(
            Step(
                id=nxt("validate"),
                phase="validate",
                action="Run the test suite.",
                why="Behavioral safety net before proposing the deletion patch.",
                command="pytest -q" if (profile.test_runner or "pytest") == "pytest" else profile.test_runner,
            )
        )
    if "ts" in langs:
        if profile.type_checker == "tsc":
            steps.append(
                Step(
                    id=nxt("validate"),
                    phase="validate",
                    action="Type-check the project.",
                    why="tsc --noEmit reveals removed exports still referenced by type-only imports.",
                    command="npx tsc --noEmit",
                )
            )
        runner = profile.test_runner or "npm test"
        steps.append(
            Step(
                id=nxt("validate"),
                phase="validate",
                action="Run the JS/TS test suite.",
                why="Behavioral safety net before proposing the deletion patch.",
                command=f"npx {runner} run" if runner in {"vitest", "jest"} else runner,
            )
        )
    for key in sorted(langs - {"py", "ts"}):
        for command in profile.validate_commands.get(key, LANGS[key].validate if key in LANGS else []):
            steps.append(
                Step(
                    id=nxt("validate"),
                    phase="validate",
                    action=f"Run the {LANGUAGE_NAMES.get(key, key)} compiler/test step.",
                    why="Compiled languages surface removed-symbol errors at build time; run before proposing the patch.",
                    command=command,
                )
            )
    steps.append(
        Step(
            id=nxt("validate"),
            phase="validate",
            action="Re-run unreach.scan and confirm the finding is gone and no new block findings appeared.",
            why="Closes the loop and updates memory so the next session starts from the new baseline.",
            tool="unreach.scan",
        )
    )
    return steps


def _lang_for(path: str) -> str:
    if path.endswith(PY_SUFFIXES) or path.endswith(("pyproject.toml", "requirements.txt")):
        return "py"
    if path.endswith(TS_SUFFIXES) or path.endswith("package.json"):
        return "ts"
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    return lang_for_suffix(suffix) or "ts"


def _module_for(path: str) -> str:
    stem = path[:-3] if path.endswith(".py") else path
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


def _stem(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    for suffix in (".d.ts",):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name.rsplit(".", 1)[0] if "." in name else name
