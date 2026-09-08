"""Deterministic dead-code scan. No LLM required."""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from unreach import graph

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

ENTRY_PY = {
    "__main__.py",
    "main.py",
    "app.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "setup.py",
    "conftest.py",
    "cli.py",
}

ENTRY_TS = {
    "index.ts",
    "index.tsx",
    "index.js",
    "main.ts",
    "main.tsx",
    "main.js",
    "app.ts",
    "app.tsx",
    "app.js",
    "vite.config.ts",
    "vite.config.js",
    "next.config.js",
    "next.config.ts",
}


@dataclass
class Finding:
    id: str
    kind: str
    severity: str
    path: str
    symbol: str | None
    why: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


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


def is_test_path(path: Path) -> bool:
    name = path.name
    parts = {p.lower() for p in path.parts}
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or name.endswith(".test.tsx")
        or name.endswith(".spec.ts")
        or name.endswith(".spec.tsx")
        or "tests" in parts
        or "test" in parts
        or "__tests__" in parts
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def scan_path(path: str | Path, *, mock: bool = False, lang: str = "auto") -> list[Finding]:
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    if root.is_file():
        root = root.parent

    findings: list[Finding] = []
    if lang in {"auto", "py"}:
        findings.extend(_scan_python(root))
    if lang in {"auto", "ts"}:
        findings.extend(_scan_typescript(root))
    if lang in {"auto", "py"}:
        findings.extend(_scan_python_deps(root))

    findings = [_redact_finding(f) for f in findings]
    findings = _dedupe(findings)
    if mock:
        from unreach.mock import ensure_mock_findings

        findings = ensure_mock_findings(root, findings)
    return findings


def _redact_finding(finding: Finding) -> Finding:
    return Finding(
        id=finding.id,
        kind=finding.kind,
        severity=finding.severity,
        path=redact_text(finding.path),
        symbol=finding.symbol,
        why=redact_text(finding.why),
        evidence=[redact_text(item) for item in finding.evidence],
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


def _scan_python(root: Path) -> list[Finding]:
    files = iter_source_files(root, (".py",))
    modules = graph.build_python_graph(root, files)
    imported_modules = graph.imported_module_set(modules)
    findings: list[Finding] = []

    for module in modules.values():
        rel = module.rel_path
        if is_test_path(Path(rel)):
            continue
        is_entry = Path(rel).name in ENTRY_PY
        is_pkg_init = Path(rel).name == "__init__.py"
        used_as_pkg = module.name in imported_modules or any(
            other.startswith(module.name + ".") for other in imported_modules
        )
        if is_pkg_init and used_as_pkg:
            continue
        if module.name not in imported_modules and not is_entry:
            findings.append(
                Finding(
                    id=finding_id("orphan_file", rel),
                    kind="orphan_file",
                    severity="block",
                    path=rel,
                    symbol=None,
                    why=f"{rel} is never imported by another module.",
                    evidence=[
                        f"module {module.name} has no importers",
                        f"not treated as an entry file ({Path(rel).name})",
                    ],
                )
            )
            continue
        if module.name not in imported_modules:
            continue
        if modules[module.name].whole_module_imported:
            # Attribute access cannot be proven unused with high confidence.
            export_severity = "warn"
        else:
            export_severity = "block"
        for export in module.exports:
            if export.startswith("_"):
                continue
            if export in module.imported_names:
                continue
            if module.star_imported:
                continue
            used_locally = export in module.local_uses
            severity = "warn" if used_locally or export_severity == "warn" else "block"
            why = f"Exported symbol `{export}` in {rel} is never imported."
            if used_locally:
                why = (
                    f"Exported symbol `{export}` in {rel} is never imported "
                    "from another module (it is still referenced locally)."
                )
            findings.append(
                Finding(
                    id=finding_id("unused_export", rel, export),
                    kind="unused_export",
                    severity=severity,
                    path=rel,
                    symbol=export,
                    why=why,
                    evidence=[
                        f"defined in module {module.name}",
                        f"imported names from this module: {sorted(module.imported_names) or 'none'}",
                        f"local references: {'yes' if used_locally else 'none observed'}",
                    ],
                )
            )
        for name, lineno in module.private_defs.items():
            if name in module.local_uses or name in module.imported_names:
                continue
            findings.append(
                Finding(
                    id=finding_id("unreachable", rel, name),
                    kind="unreachable",
                    severity="note",
                    path=rel,
                    symbol=name,
                    why=f"`{name}` in {rel} is never referenced in the scanned graph.",
                    evidence=[f"defined around line {lineno}"],
                )
            )
    return findings


def _scan_typescript(root: Path) -> list[Finding]:
    files = iter_source_files(root, (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs"))
    if not files:
        return []
    modules = graph.build_typescript_graph(root, files)
    imported = graph.ts_imported_set(modules)
    findings: list[Finding] = []
    for module in modules.values():
        rel = module.rel_path
        if is_test_path(Path(rel)):
            continue
        name = Path(rel).name
        if module.key not in imported and name not in ENTRY_TS:
            findings.append(
                Finding(
                    id=finding_id("orphan_file", rel),
                    kind="orphan_file",
                    severity="block",
                    path=rel,
                    symbol=None,
                    why=f"{rel} is never imported by another TypeScript/JavaScript module.",
                    evidence=["no importer edges in the TS/JS import graph"],
                )
            )
            continue
        if module.namespace_imported:
            continue
        for export in module.exports:
            if export in module.imported_names:
                continue
            findings.append(
                Finding(
                    id=finding_id("unused_export", rel, export),
                    kind="unused_export",
                    severity="warn",
                    path=rel,
                    symbol=export,
                    why=f"Exported `{export}` in {rel} is not referenced by a named import.",
                    evidence=["TypeScript unused-export detection is heuristic (warn)"],
                )
            )
    return findings


def _scan_python_deps(root: Path) -> list[Finding]:
    declared = _declared_python_deps(root)
    if not declared:
        return []
    imported_top: set[str] = set()
    for path in iter_source_files(root, (".py",)):
        if is_test_path(path):
            continue
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
        if import_name in stdlib:
            continue
        if import_name in imported_top or dep in imported_top:
            continue
        if import_name in {"unreach", "setuptools", "wheel", "pip", "pytest"}:
            continue
        rel = source
        findings.append(
            Finding(
                id=finding_id("unused_dep", rel, dep),
                kind="unused_dep",
                severity="warn",
                path=rel,
                symbol=dep,
                why=f"Declared dependency `{dep}` is never imported under {root.name}.",
                evidence=[
                    "unused dependency detection is guessed (warn), not a blocker",
                    f"normalized import name: {import_name}",
                ],
            )
        )
    return findings


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
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = stripped in {"[project]", "[project.optional-dependencies]"}
            if stripped == "[project]":
                in_deps = False
            continue
        if stripped.startswith("dependencies") and "=" in stripped:
            in_deps = True
            if "[" in stripped and "]" in stripped:
                names.extend(_strings_in(stripped))
                in_deps = "[" not in stripped or stripped.rstrip().endswith("]")
            continue
        if in_deps:
            if stripped.startswith("[") or (stripped.startswith("[") is False and stripped.startswith("[")):
                pass
            if stripped.startswith("[") or re.match(r"^[a-zA-Z0-9_.-]+\s*=", stripped) and not stripped.startswith('"'):
                if not stripped.startswith('"') and not stripped.startswith("'") and "=" in stripped:
                    in_deps = False
                    continue
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


def findings_to_json(findings: list[Finding], *, path: str) -> str:
    payload = {
        "tool": "unreach",
        "version": __import__("unreach").__version__,
        "path": path,
        "auto_delete": False,
        "findings": [f.to_dict() for f in findings],
        "counts": _counts(findings),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


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
