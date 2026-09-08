"""Deterministic dead-code scan. No LLM required."""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from unreach import __version__, graph, polyglot
from unreach import confidence as conf
from unreach.langs import PY_SUFFIXES, TS_SUFFIXES, Profile, detect_profile, file_role
from unreach.memory import Delta, Memory


def supported_languages() -> list[str]:
    return ["auto", "py", "ts", *polyglot.LANGS]

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".unreach",
    ".pytest_cache",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    "site-packages",
    ".eggs",
    ".next",
    "coverage",
    "target",
    "vendor",
    "Pods",
    ".gradle",
    "obj",
    "_build",
    "deps",
    ".dart_tool",
    "DerivedData",
}

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
]


@dataclass
class Finding:
    id: str
    kind: str
    severity: str
    path: str
    symbol: str | None
    why: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    signals: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    findings: list[Finding]
    profile: Profile
    delta: Delta
    memory: dict[str, Any]
    suppressed: list[Finding] = field(default_factory=list)
    min_confidence: float = conf.DEFAULT_MIN_CONFIDENCE

    def counts(self) -> dict[str, int]:
        return _counts(self.findings)

    def has_block(self) -> bool:
        return has_block(self.findings)

    def new_findings(self) -> list[Finding]:
        new_ids = set(self.delta.new)
        return [f for f in self.findings if f.id in new_ids]

    def to_dict(self, *, compact: bool = False, only_new: bool = False) -> dict[str, Any]:
        new_ids = set(self.delta.new)
        if only_new:
            full = [f for f in self.findings if f.id in new_ids]
            brief = [f for f in self.findings if f.id not in new_ids]
        elif compact:
            full = [f for f in self.findings if f.id in new_ids or not self.delta.persisting]
            brief = [f for f in self.findings if f.id not in {x.id for x in full}]
        else:
            full, brief = list(self.findings), []
        payload: dict[str, Any] = {
            "tool": "unreach",
            "version": __version__,
            "path": self.path,
            "auto_delete": False,
            "profile": self.profile.to_dict(),
            "counts": self.counts(),
            "min_confidence": self.min_confidence,
            "findings": [f.to_dict() for f in full],
            "delta": self.delta.to_dict(),
            "memory": self.memory,
        }
        if brief:
            payload["persisting_brief"] = [
                {"id": f.id, "severity": f.severity, "confidence": f.confidence} for f in brief
            ]
            full_size = len(json.dumps([f.to_dict() for f in brief]))
            brief_size = len(json.dumps(payload["persisting_brief"]))
            payload["tokens_saved_estimate"] = max(0, (full_size - brief_size) // 4)
        if self.suppressed:
            payload["suppressed"] = [
                {"id": f.id, "decision": self.memory.get("decisions", {}).get(f.id, {}).get("decision")}
                for f in self.suppressed
            ]
        return payload


def redact_text(text: str) -> str:
    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def finding_id(kind: str, path: str, symbol: str | None = None) -> str:
    posix = path.replace("\\", "/")
    if symbol:
        return f"{kind}:{posix}:{symbol}"
    return f"{kind}:{posix}"


def iter_source_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in suffixes:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def rel_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def scan_repo(
    path: str | Path,
    *,
    mock: bool = False,
    lang: str = "auto",
    memory: bool = True,
    min_confidence: float = conf.DEFAULT_MIN_CONFIDENCE,
    record: bool = True,
) -> ScanResult:
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    if root.is_file():
        root = root.parent

    if lang not in {"auto", "py", "ts"} and lang not in polyglot.LANGS:
        raise ValueError(f"unknown language '{lang}'; choose from {', '.join(supported_languages())}")
    mem = Memory(root, enabled=memory)
    py_files = iter_source_files(root, PY_SUFFIXES) if lang in {"auto", "py"} else []
    ts_files = iter_source_files(root, TS_SUFFIXES) if lang in {"auto", "ts"} else []
    if lang == "auto":
        other_files = iter_source_files(root, polyglot.all_suffixes())
    elif lang in polyglot.LANGS:
        other_files = iter_source_files(root, polyglot.LANGS[lang].suffixes)
    else:
        other_files = []
    profile = detect_profile(root, py_files, ts_files, other_files)

    findings: list[Finding] = []
    if py_files:
        findings.extend(_scan_python(root, py_files, profile, mem))
        findings.extend(_scan_python_deps(root, py_files, profile, mem))
    if ts_files:
        findings.extend(_scan_typescript(root, ts_files, profile, mem))
    if other_files:
        findings.extend(_scan_polyglot(root, other_files, profile, mem))

    findings = [_redact_finding(f) for f in findings]
    findings = _dedupe(findings)
    if mock:
        from unreach.mock import ensure_mock_findings

        findings = ensure_mock_findings(root, findings)

    findings = [f for f in findings if f.confidence >= min_confidence]
    findings.sort(key=lambda f: (-f.confidence, f.kind, f.path, f.symbol or ""))

    if record and mem.enabled:
        delta = mem.record_run(findings, profile=profile.to_dict())
    else:
        delta = Delta(new=[f.id for f in findings])
    suppressed_ids = set(delta.suppressed)
    suppressed = [f for f in findings if f.id in suppressed_ids]
    visible = [f for f in findings if f.id not in suppressed_ids]
    mem.save()
    summary = mem.summary()
    summary["decisions"] = {fid: d for fid, d in mem.decisions().items() if fid in suppressed_ids}
    return ScanResult(
        path=str(path),
        findings=visible,
        profile=profile,
        delta=delta,
        memory=summary,
        suppressed=suppressed,
        min_confidence=min_confidence,
    )


def scan_path(path: str | Path, *, mock: bool = False, lang: str = "auto", memory: bool = False) -> list[Finding]:
    """Backwards-compatible helper returning only the findings list."""
    return scan_repo(path, mock=mock, lang=lang, memory=memory).findings


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #


def _scan_python(root: Path, files: list[Path], profile: Profile, mem: Memory) -> list[Finding]:
    modules = graph.build_python_graph(root, files, cache=mem)
    imported_modules = graph.imported_module_set(modules)
    repo_dynamic = any(m.dynamic_import for m in modules.values())
    profile.dynamic_import_anywhere = repo_dynamic
    all_strings: set[str] = set()
    for module in modules.values():
        all_strings.update(module.strings)
    config_tokens = profile.config_tokens
    findings: list[Finding] = []

    for module in modules.values():
        rel = module.rel_path
        role = file_role(rel, profile)
        if role == "test":
            continue
        is_pkg_init = Path(rel).name == "__init__.py"
        used_as_pkg = module.name in imported_modules or any(
            other.startswith(module.name + ".") for other in imported_modules
        )
        if is_pkg_init and used_as_pkg:
            continue
        if module.name not in imported_modules:
            if role == "entry" and not module.has_main_guard:
                # Framework/entry files are loaded by convention. Never a finding.
                continue
            leaf = module.name.split(".")[-1]
            signals = conf.orphan_signals(
                module_name=module.name,
                role=role,
                has_main_guard=module.has_main_guard,
                name_in_strings=_name_in(all_strings, module.name, leaf, exclude=module.strings),
                name_in_config=_name_in(config_tokens, module.name, rel, rel.replace("/", ".")[:-3]),
                repo_dynamic_import=repo_dynamic,
                module_dynamic_import=module.dynamic_import,
                is_package_init=is_pkg_init,
                seen_count=mem.seen_count(finding_id("orphan_file", rel)),
            )
            score = conf.score("orphan_file", signals)
            findings.append(
                Finding(
                    id=finding_id("orphan_file", rel),
                    kind="orphan_file",
                    severity=conf.severity_for(score),
                    path=rel,
                    symbol=None,
                    why=f"{rel} is never imported by another module.",
                    evidence=[
                        f"module {module.name} has no importers",
                        f"role: {role}",
                        *_signal_evidence(signals),
                    ],
                    confidence=score,
                    signals=signals.values,
                )
            )
            continue
        if module.star_imported:
            continue
        in_all = _module_declares_all(module)
        for export in module.exports:
            if export.startswith("_") or export in module.imported_names:
                continue
            used_locally = export in module.local_uses
            signals = conf.export_signals(
                symbol=export,
                decorators=module.decorated.get(export, []),
                bases=module.bases.get(export, []),
                framework_decorators=profile.decorators,
                framework_bases=profile.bases,
                used_locally=used_locally,
                whole_module_imported=module.whole_module_imported,
                name_in_strings=_name_in(all_strings, export, f"{module.name}.{export}", exclude=None),
                name_in_config=_name_in(config_tokens, export, f"{module.name}:{export}", f"{module.name}.{export}"),
                module_has_getattr=module.has_module_getattr,
                repo_dynamic_import=repo_dynamic,
                in_all=in_all,
                seen_count=mem.seen_count(finding_id("unused_export", rel, export)),
            )
            score = conf.score("unused_export", signals)
            why = f"Exported symbol `{export}` in {rel} is never imported."
            if used_locally:
                why = (
                    f"Exported symbol `{export}` in {rel} is never imported from another module "
                    "(it is still referenced locally)."
                )
            findings.append(
                Finding(
                    id=finding_id("unused_export", rel, export),
                    kind="unused_export",
                    severity=conf.severity_for(score),
                    path=rel,
                    symbol=export,
                    why=why,
                    evidence=[
                        f"defined in module {module.name}",
                        f"imported names from this module: {sorted(module.imported_names) or 'none'}",
                        f"local references: {'yes' if used_locally else 'none observed'}",
                        *_signal_evidence(signals),
                    ],
                    confidence=score,
                    signals=signals.values,
                )
            )
        for name, lineno in module.private_defs.items():
            if name in module.local_uses or name in module.imported_names:
                continue
            signals = conf.Signals()
            if module.decorated.get(name):
                signals.add("decorated", -0.2)
            score = conf.score("unreachable", signals)
            findings.append(
                Finding(
                    id=finding_id("unreachable", rel, name),
                    kind="unreachable",
                    severity=conf.severity_for(score),
                    path=rel,
                    symbol=name,
                    why=f"`{name}` in {rel} is never referenced in the scanned graph.",
                    evidence=[f"defined around line {lineno}", *_signal_evidence(signals)],
                    confidence=score,
                    signals=signals.values,
                )
            )
    return findings


def _module_declares_all(module: graph.PyModule) -> bool:
    text = _read(module.path)
    return "__all__" in text


def _name_in(pool: set[str], *names: str, exclude: set[str] | None = None) -> bool:
    for name in names:
        if not name or len(name) < 3:
            continue
        if name in pool and (exclude is None or name not in exclude):
            return True
    return False


def _signal_evidence(signals: conf.Signals) -> list[str]:
    out: list[str] = []
    for name, delta in sorted(signals.values.items(), key=lambda kv: kv[1]):
        if delta == 0:
            continue
        out.append(f"signal {name}: {delta:+.2f}")
    return out


# --------------------------------------------------------------------------- #
# TypeScript / JavaScript
# --------------------------------------------------------------------------- #


def _scan_typescript(root: Path, files: list[Path], profile: Profile, mem: Memory) -> list[Finding]:
    modules = graph.build_typescript_graph(root, files, cache=mem)
    imported = graph.ts_imported_set(modules)
    repo_dynamic = any(m.dynamic_import for m in modules.values())
    profile.dynamic_import_anywhere = profile.dynamic_import_anywhere or repo_dynamic
    all_strings: set[str] = set()
    for module in modules.values():
        all_strings.update(module.strings)
    findings: list[Finding] = []
    for module in modules.values():
        rel = module.rel_path
        role = file_role(rel, profile)
        if role in {"test", "config"}:
            continue
        stem = module.key.rsplit("/", 1)[-1]
        if module.key not in imported:
            if role == "entry":
                continue
            signals = conf.orphan_signals(
                module_name=module.key.replace("/", "."),
                role=role,
                has_main_guard=False,
                name_in_strings=_name_in(all_strings, stem, module.key, f"./{module.key}", exclude=module.strings),
                name_in_config=_name_in(profile.config_tokens, rel, module.key, f"./{rel}", f"./{module.key}"),
                repo_dynamic_import=repo_dynamic,
                module_dynamic_import=module.dynamic_import,
                is_package_init=False,
                seen_count=mem.seen_count(finding_id("orphan_file", rel)),
            )
            signals.add("ts_regex_graph", -0.05)
            score = conf.score("orphan_file", signals)
            findings.append(
                Finding(
                    id=finding_id("orphan_file", rel),
                    kind="orphan_file",
                    severity=conf.severity_for(score),
                    path=rel,
                    symbol=None,
                    why=f"{rel} is never imported by another TypeScript/JavaScript module.",
                    evidence=["no importer edges in the TS/JS import graph", f"role: {role}", *_signal_evidence(signals)],
                    confidence=score,
                    signals=signals.values,
                )
            )
            continue
        if module.namespace_imported:
            continue
        for export in module.exports:
            if export in module.imported_names:
                continue
            signals = conf.export_signals(
                symbol=export,
                decorators=[],
                bases=[],
                framework_decorators=profile.decorators,
                framework_bases=profile.bases,
                used_locally=False,
                whole_module_imported=False,
                name_in_strings=_name_in(all_strings, export, exclude=module.strings),
                name_in_config=_name_in(profile.config_tokens, export),
                module_has_getattr=False,
                repo_dynamic_import=repo_dynamic,
                in_all=False,
                seen_count=mem.seen_count(finding_id("unused_export", rel, export)),
            )
            signals.add("ts_regex_graph_default_reexport_unknown", -0.30)
            score = conf.score("unused_export", signals)
            findings.append(
                Finding(
                    id=finding_id("unused_export", rel, export),
                    kind="unused_export",
                    severity=conf.severity_for(score),
                    path=rel,
                    symbol=export,
                    why=f"Exported `{export}` in {rel} is not referenced by a named import.",
                    evidence=["TypeScript unused-export detection is heuristic", *_signal_evidence(signals)],
                    confidence=score,
                    signals=signals.values,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Other languages (generic reference graph)
# --------------------------------------------------------------------------- #


def _scan_polyglot(root: Path, files: list[Path], profile: Profile, mem: Memory) -> list[Finding]:
    pfiles = polyglot.build_poly_graph(root, files, cache=mem)
    referrers = polyglot.referenced_files(pfiles)
    export_index = polyglot.ExportIndex(pfiles)
    findings: list[Finding] = []
    for pf in pfiles.values():
        spec = polyglot.LANGS[pf.lang]
        role = file_role(pf.rel, profile)
        if pf.test or role in {"test", "config"}:
            continue
        if pf.entry or role == "entry":
            continue
        stem = Path(pf.rel).stem
        precision_signal = (
            (f"{pf.lang}_path_resolved_graph", -0.03)
            if spec.precision == "path"
            else (f"{pf.lang}_name_reference_graph", -0.30)
        )
        if not referrers[pf.rel]:
            signals = conf.orphan_signals(
                module_name=stem,
                role=role,
                has_main_guard=False,
                name_in_strings=False,
                name_in_config=_name_in(profile.config_tokens, pf.rel, stem, *sorted(pf.ids)[:4]),
                repo_dynamic_import=False,
                module_dynamic_import=False,
                is_package_init=False,
                seen_count=mem.seen_count(finding_id("orphan_file", pf.rel)),
            )
            if len(stem) >= 3 and export_index.used_elsewhere(pf.rel, stem):
                signals.add("name_token_seen_elsewhere", -0.20)
            signals.add(*precision_signal)
            score = conf.score("orphan_file", signals)
            findings.append(
                Finding(
                    id=finding_id("orphan_file", pf.rel),
                    kind="orphan_file",
                    severity=conf.severity_for(score),
                    path=pf.rel,
                    symbol=None,
                    why=f"{pf.rel} is never referenced by another {spec.name} file.",
                    evidence=[
                        f"{spec.name} graph precision: {spec.precision}",
                        f"identifiers other files could use: {sorted(pf.ids)[:4]}",
                        f"role: {role}",
                        *_signal_evidence(signals),
                    ],
                    confidence=score,
                    signals=signals.values,
                )
            )
            continue
        if not spec.exports:
            continue
        for symbol in pf.exports:
            if len(symbol) < 3 or symbol.lower() in {"main", "new", "init", "run", "setup", "index", "call", "self"}:
                continue
            if export_index.used_elsewhere(pf.rel, symbol):
                continue
            signals = conf.Signals()
            signals.add("not_referenced_by_other_files", 0.0)
            signals.add(f"{pf.lang}_token_match_heuristic", -0.30)
            if _name_in(profile.config_tokens, symbol):
                signals.add("symbol_named_in_config", -0.30)
            signals.add("stable_across_runs", min(0.03, 0.01 * max(0, mem.seen_count(finding_id("unused_export", pf.rel, symbol)) - 1)))
            score = conf.score("unused_export", signals)
            findings.append(
                Finding(
                    id=finding_id("unused_export", pf.rel, symbol),
                    kind="unused_export",
                    severity=conf.severity_for(score),
                    path=pf.rel,
                    symbol=symbol,
                    why=f"Public `{symbol}` in {pf.rel} is not referenced by any other {spec.name} file.",
                    evidence=[f"{spec.name} export detection is token-based (heuristic)", *_signal_evidence(signals)],
                    confidence=score,
                    signals=signals.values,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Python dependencies
# --------------------------------------------------------------------------- #


def _scan_python_deps(root: Path, files: list[Path], profile: Profile, mem: Memory) -> list[Finding]:
    declared = _declared_python_deps(root)
    if not declared:
        return []
    imported_top: set[str] = set()
    for path in files:
        tree = _safe_ast(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_top.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported_top.add(node.module.split(".")[0])
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    findings: list[Finding] = []
    for dep, source in declared:
        import_name = _dep_to_import_name(dep)
        if import_name in stdlib or import_name in imported_top or dep in imported_top:
            continue
        if import_name in {"unreach", "setuptools", "wheel", "pip"}:
            continue
        signals = conf.dep_signals(
            dep=dep,
            name_in_config=_name_in(profile.config_tokens - {dep}, dep, import_name) or _bin_in_scripts(root, dep),
            has_bin_usage=_bin_in_scripts(root, dep),
            seen_count=mem.seen_count(finding_id("unused_dep", source, dep)),
        )
        score = conf.score("unused_dep", signals)
        findings.append(
            Finding(
                id=finding_id("unused_dep", source, dep),
                kind="unused_dep",
                severity=conf.severity_for(score),
                path=source,
                symbol=dep,
                why=f"Declared dependency `{dep}` is never imported under {root.name}.",
                evidence=[
                    "unused dependency detection is guessed, never a blocker on its own",
                    f"normalized import name: {import_name}",
                    *_signal_evidence(signals),
                ],
                confidence=score,
                signals=signals.values,
            )
        )
    return findings


def _bin_in_scripts(root: Path, dep: str) -> bool:
    for name in ("Makefile", "Dockerfile", "tox.ini", "noxfile.py", ".pre-commit-config.yaml"):
        path = root / name
        if path.is_file() and re.search(rf"\b{re.escape(dep)}\b", _read(path)):
            return True
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for path in workflows.glob("*.yml"):
            if re.search(rf"\b{re.escape(dep)}\b", _read(path)):
                return True
    return False


def _dep_to_import_name(dep: str) -> str:
    return dep.replace("-", "_").lower()


def _declared_python_deps(root: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    req = root / "requirements.txt"
    if req.is_file():
        for line in req.read_text(encoding="utf-8").splitlines():
            name = _requirement_name(line)
            if name:
                found.append((name, "requirements.txt"))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        for name in _pyproject_deps(pyproject):
            found.append((name, "pyproject.toml"))
    return found


def _requirement_name(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    for sep in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if sep in line:
            line = line.split(sep, 1)[0]
            break
    line = line.split(";", 1)[0].split("[", 1)[0].strip()
    return line or None


def _pyproject_deps(path: Path) -> list[str]:
    text = _read(path)
    names: list[str] = []
    in_project = False
    in_deps = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = stripped in {"[project]", "[project.optional-dependencies]"}
            in_deps = False
            continue
        if not in_project:
            continue
        if not in_deps and re.match(r"^[\w.-]+\s*=\s*\[", stripped):
            names.extend(_strings_in(stripped.split("=", 1)[1]))
            in_deps = not stripped.rstrip().endswith("]")
            continue
        if in_deps:
            names.extend(_strings_in(stripped))
            if "]" in stripped:
                in_deps = False
    return [n for n in names if n]


def _strings_in(text: str) -> list[str]:
    out: list[str] = []
    for match in re.findall(r"['\"]([^'\"]+)['\"]", text):
        name = _requirement_name(match)
        if name:
            out.append(name)
    return out


def _safe_ast(path: Path) -> ast.AST | None:
    text = _read(path)
    if not text:
        return None
    try:
        return ast.parse(text, filename=str(path))
    except SyntaxError:
        return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _redact_finding(finding: Finding) -> Finding:
    return Finding(
        id=finding.id,
        kind=finding.kind,
        severity=finding.severity,
        path=redact_text(finding.path),
        symbol=finding.symbol,
        why=redact_text(finding.why),
        evidence=[redact_text(item) for item in finding.evidence],
        confidence=finding.confidence,
        signals=finding.signals,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out


def findings_to_json(findings: list[Finding], *, path: str) -> str:
    payload = {
        "tool": "unreach",
        "version": __version__,
        "path": path,
        "auto_delete": False,
        "findings": [f.to_dict() for f in findings],
        "counts": _counts(findings),
    }
    return json.dumps(payload, indent=2)


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"block": 0, "warn": 0, "note": 0, "total": len(findings)}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def has_block(findings: list[Finding]) -> bool:
    return any(f.severity == "block" for f in findings)


def find_by_id(findings: list[Finding], finding_id_value: str) -> Finding | None:
    for finding in findings:
        if finding.id == finding_id_value:
            return finding
    return None
