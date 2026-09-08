"""Import graphs for Python and TypeScript. Deterministic; no LLM.

Parsing is split into two phases so results can be cached:

1. ``extract_python_facts`` turns one file into a JSON-serializable dict.
2. ``build_python_graph`` links facts into modules.

The optional ``cache`` object (see ``unreach.memory``) lets a second scan skip
re-parsing files whose content hash did not change.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

TS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:type\s+)?(?:[\s\S]*?\sfrom\s+)?|export\s+(?:type\s+)?[\s\S]*?\sfrom\s+|require\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)
TS_EXPORT_FN_RE = re.compile(
    r"export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var|enum|type|interface)\s+(\w+)"
)
TS_EXPORT_NAMED_RE = re.compile(r"export\s+(?:type\s+)?\{([^}]+)\}")
TS_IMPORT_NAMED_RE = re.compile(
    r"""import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"""
)
TS_IMPORT_STAR_RE = re.compile(
    r"""import\s+(?:type\s+)?\*\s+as\s+\w+\s+from\s+['"]([^'"]+)['"]"""
)
TS_DYNAMIC_IMPORT_RE = re.compile(r"\bimport\s*\(")
TS_STRING_RE = re.compile(r"""['"`]([A-Za-z_][\w./-]{2,})['"`]""")

FACTS_VERSION = 3


class FactsCache(Protocol):
    def get(self, rel: str, digest: str) -> dict[str, Any] | None: ...

    def put(self, rel: str, digest: str, facts: dict[str, Any]) -> None: ...


@dataclass
class PyModule:
    name: str
    rel_path: str
    path: Path
    is_package: bool
    exports: list[str] = field(default_factory=list)
    private_defs: dict[str, int] = field(default_factory=dict)
    local_uses: set[str] = field(default_factory=set)
    imported_names: set[str] = field(default_factory=set)
    star_imported: bool = False
    whole_module_imported: bool = False
    referenced: bool = False
    imports_modules: set[str] = field(default_factory=set)
    decorated: dict[str, list[str]] = field(default_factory=dict)
    bases: dict[str, list[str]] = field(default_factory=dict)
    strings: set[str] = field(default_factory=set)
    has_main_guard: bool = False
    dynamic_import: bool = False
    has_module_getattr: bool = False
    raw_imports: list[tuple[str, list[str], bool, bool]] = field(default_factory=list)
    digest: str = ""


@dataclass
class TsModule:
    key: str
    rel_path: str
    exports: list[str] = field(default_factory=list)
    imported_names: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    namespace_imported: bool = False
    dynamic_import: bool = False
    strings: set[str] = field(default_factory=set)
    digest: str = ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def module_name_for(root: Path, path: Path) -> tuple[str, bool]:
    rel = path.resolve().relative_to(root.resolve())
    parts = list(rel.with_suffix("").parts)
    is_package = path.name == "__init__.py"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


# --------------------------------------------------------------------------- #
# Python facts extraction (cacheable)
# --------------------------------------------------------------------------- #


def extract_python_facts(text: str, module_name: str, is_package: bool) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "v": FACTS_VERSION,
        "exports": [],
        "private_defs": {},
        "local_uses": [],
        "imports": [],
        "decorated": {},
        "bases": {},
        "strings": [],
        "has_main_guard": False,
        "dynamic_import": False,
        "has_module_getattr": False,
        "parse_ok": True,
    }
    try:
        tree = ast.parse(text)
    except SyntaxError:
        facts["parse_ok"] = False
        return facts

    exports, private = _python_defs(tree)
    facts["exports"] = exports
    facts["private_defs"] = private
    defined = set(exports) | set(private)
    facts["local_uses"] = sorted(_local_name_uses(tree, defined))
    facts["imports"] = [
        [imported, sorted(names), star, whole]
        for imported, names, star, whole in _python_imports(tree, module_name, is_package)
    ]
    facts["decorated"] = _decorators(tree)
    facts["bases"] = _bases(tree)
    facts["strings"] = sorted(_string_literals(tree))
    facts["has_main_guard"] = _has_main_guard(tree)
    facts["dynamic_import"] = _uses_dynamic_import(tree)
    facts["has_module_getattr"] = any(
        isinstance(node, ast.FunctionDef) and node.name == "__getattr__"
        for node in (tree.body if isinstance(tree, ast.Module) else [])
    )
    return facts


def build_python_graph(
    root: Path, files: list[Path], cache: FactsCache | None = None
) -> dict[str, PyModule]:
    modules: dict[str, PyModule] = {}
    for path in files:
        name, is_package = module_name_for(root, path)
        if not name:
            name = path.stem
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        module = PyModule(name=name, rel_path=rel, path=path, is_package=is_package)
        text = _read(path)
        module.digest = sha256_text(text)
        facts = cache.get(rel, module.digest) if cache is not None else None
        if facts is None or facts.get("v") != FACTS_VERSION:
            facts = extract_python_facts(text, name, is_package)
            if cache is not None:
                cache.put(rel, module.digest, facts)
        _apply_facts(module, facts)
        modules[name] = module

    for module in modules.values():
        for imported, names, star, whole in module.raw_imports:
            target = _resolve_module(imported, modules)
            if target is None:
                continue
            module.imports_modules.add(target)
            target_mod = modules[target]
            if star:
                target_mod.star_imported = True
            if whole:
                target_mod.whole_module_imported = True
            target_mod.imported_names.update(names)
            target_mod.referenced = True
            for parent in _parents(target):
                if parent in modules:
                    modules[parent].referenced = True
    return modules


def _apply_facts(module: PyModule, facts: dict[str, Any]) -> None:
    module.exports = list(facts.get("exports", []))
    module.private_defs = {k: int(v) for k, v in facts.get("private_defs", {}).items()}
    module.local_uses = set(facts.get("local_uses", []))
    module.decorated = {k: list(v) for k, v in facts.get("decorated", {}).items()}
    module.bases = {k: list(v) for k, v in facts.get("bases", {}).items()}
    module.strings = set(facts.get("strings", []))
    module.has_main_guard = bool(facts.get("has_main_guard", False))
    module.dynamic_import = bool(facts.get("dynamic_import", False))
    module.has_module_getattr = bool(facts.get("has_module_getattr", False))
    module.raw_imports = [
        (str(item[0]), list(item[1]), bool(item[2]), bool(item[3]))
        for item in facts.get("imports", [])
    ]


def imported_module_set(modules: dict[str, PyModule]) -> set[str]:
    used: set[str] = set()
    for module in modules.values():
        used.update(module.imports_modules)
        for target in module.imports_modules:
            used.update(_parents(target))
        if module.referenced or module.star_imported or module.whole_module_imported:
            used.add(module.name)
    return used


def _parents(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[:i]) for i in range(1, len(parts))]


def _resolve_module(name: str, known: dict[str, PyModule]) -> str | None:
    if name in known:
        return name
    # `from pkg.mod import thing` where `pkg.mod.thing` is itself a module.
    head, _, _tail = name.rpartition(".")
    if head and head in known:
        return None
    return None


def _python_imports(
    tree: ast.AST, module_name: str, is_package: bool
) -> list[tuple[str, set[str], bool, bool]]:
    out: list[tuple[str, set[str], bool, bool]] = []
    bound: dict[str, str] = {}  # local alias → module it refers to
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, set(), False, True))
                bound[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            target = _abs_from(module_name, is_package, node.module, node.level)
            if not target:
                continue
            names: set[str] = set()
            star = False
            for alias in node.names:
                if alias.name == "*":
                    star = True
                else:
                    names.add(alias.name)
            out.append((target, names, star, False))
            # `from pkg import submodule` also references pkg.submodule.
            for alias in node.names:
                if alias.name != "*":
                    out.append((f"{target}.{alias.name}", set(), False, True))
                    bound[alias.asname or alias.name] = f"{target}.{alias.name}"
    if bound:
        # `hooks.on_event()` after `from pkg import hooks` names a live export.
        attr_uses: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                chain = _dotted_chain(node)
                if not chain or chain[0] not in bound:
                    continue
                base = bound[chain[0]]
                rest = chain[1:]
                for i, attr in enumerate(rest):
                    module_path = ".".join([base, *rest[:i]])
                    attr_uses.setdefault(module_path, set()).add(attr)
        for module_path, attrs in attr_uses.items():
            out.append((module_path, attrs, False, False))
    return out


def _dotted_chain(node: ast.AST) -> list[str]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return []


def _abs_from(
    module_name: str, is_package: bool, imported: str | None, level: int
) -> str | None:
    if level == 0:
        return imported
    parts = module_name.split(".")
    if not is_package:
        parts = parts[:-1]
    if level > 1:
        drop = level - 1
        if drop > len(parts):
            return None
        parts = parts[: len(parts) - drop]
    if imported:
        parts = parts + imported.split(".")
    return ".".join(p for p in parts if p) or None


def _python_defs(tree: ast.AST) -> tuple[list[str], dict[str, int]]:
    public: list[str] = []
    private: dict[str, int] = {}
    all_names: list[str] | None = None
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("__"):
                continue
            if node.name.startswith("_"):
                private[node.name] = getattr(node, "lineno", 1)
            else:
                public.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    parsed = _const_list(node.value)
                    if parsed is not None:
                        all_names = parsed
                elif isinstance(target, ast.Name) and not target.id.startswith("_"):
                    public.append(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if not node.target.id.startswith("_"):
                public.append(node.target.id)
    if all_names is not None:
        public = list(all_names)
    seen: set[str] = set()
    ordered: list[str] = []
    for name in public:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered, private


def _const_list(node: ast.AST) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        names: list[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                names.append(elt.value)
            else:
                return None
        return names
    return None


def _local_name_uses(tree: ast.AST, defined: set[str]) -> set[str]:
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in defined:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in defined:
            used.add(node.attr)
    return used


def _decorators(tree: ast.AST) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [_dotted(dec) for dec in node.decorator_list]
            names = [n for n in names if n]
            if names:
                out[node.name] = names
    return out


def _bases(tree: ast.AST) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        if isinstance(node, ast.ClassDef) and node.bases:
            names = [_dotted(base) for base in node.bases]
            out[node.name] = [n for n in names if n]
    return out


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _string_literals(tree: ast.AST, limit: int = 400) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip()
            if 3 <= len(value) <= 120 and re.fullmatch(r"[A-Za-z_][\w./:-]*", value):
                out.add(value)
                if len(out) >= limit:
                    break
    return out


def _has_main_guard(tree: ast.AST) -> bool:
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        if isinstance(node, ast.If):
            test = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            if "__name__" in test and "__main__" in test:
                return True
    return False


def _uses_dynamic_import(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in {
                "importlib.import_module",
                "import_module",
                "__import__",
                "getattr",
                "globals",
                "pkgutil.iter_modules",
                "entry_points",
                "importlib.metadata.entry_points",
            }:
                return True
    return False


def _read(path: Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


# --------------------------------------------------------------------------- #
# TypeScript / JavaScript
# --------------------------------------------------------------------------- #


def extract_ts_facts(text: str) -> dict[str, Any]:
    exports = TS_EXPORT_FN_RE.findall(text)
    for group in TS_EXPORT_NAMED_RE.findall(text):
        exports.extend(_split_names(group))
    return {
        "v": FACTS_VERSION,
        "exports": list(dict.fromkeys(exports)),
        "imports": TS_IMPORT_RE.findall(text),
        "named": [[_split_names(names), spec] for names, spec in TS_IMPORT_NAMED_RE.findall(text)],
        "star": TS_IMPORT_STAR_RE.findall(text),
        "dynamic_import": bool(TS_DYNAMIC_IMPORT_RE.search(text)),
        "strings": sorted(set(TS_STRING_RE.findall(text)))[:400],
    }


def build_typescript_graph(
    root: Path, files: list[Path], cache: FactsCache | None = None
) -> dict[str, TsModule]:
    modules: dict[str, TsModule] = {}
    facts_by_key: dict[str, dict[str, Any]] = {}
    for path in files:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        key = _ts_key(rel)
        text = _read(path)
        digest = sha256_text(text)
        facts = cache.get(rel, digest) if cache is not None else None
        if facts is None or facts.get("v") != FACTS_VERSION:
            facts = extract_ts_facts(text)
            if cache is not None:
                cache.put(rel, digest, facts)
        modules[key] = TsModule(
            key=key,
            rel_path=rel,
            exports=list(facts.get("exports", [])),
            dynamic_import=bool(facts.get("dynamic_import", False)),
            strings=set(facts.get("strings", [])),
            digest=digest,
        )
        facts_by_key[key] = facts

    known = set(modules)
    for module in modules.values():
        facts = facts_by_key[module.key]
        for spec in facts.get("imports", []):
            target = _resolve_ts_spec(module.rel_path, spec, known)
            if target:
                module.imports.add(target)
        for names, spec in facts.get("named", []):
            target = _resolve_ts_spec(module.rel_path, spec, known)
            if target and target in modules:
                modules[target].imported_names.update(names)
        for spec in facts.get("star", []):
            target = _resolve_ts_spec(module.rel_path, spec, known)
            if target and target in modules:
                modules[target].namespace_imported = True
    return modules


def ts_imported_set(modules: dict[str, TsModule]) -> set[str]:
    used: set[str] = set()
    for module in modules.values():
        used.update(module.imports)
    for module in modules.values():
        if module.imported_names or module.namespace_imported:
            used.add(module.key)
    return used


def _ts_key(rel: str) -> str:
    for suffix in (".d.ts", ".tsx", ".ts", ".jsx", ".js", ".mts", ".cts", ".mjs", ".vue", ".svelte"):
        if rel.endswith(suffix):
            rel = rel[: -len(suffix)]
            break
    if rel.endswith("/index"):
        rel = rel[: -len("/index")]
    return rel


def _resolve_ts_spec(from_rel: str, spec: str, known: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base = Path(from_rel).parent / spec
    candidates = [
        Path(*base.parts).as_posix(),
        (Path(*base.parts) / "index").as_posix(),
    ]
    resolved: list[str] = []
    for candidate in candidates:
        parts: list[str] = []
        for part in Path(candidate).parts:
            if part == "..":
                if parts:
                    parts.pop()
            elif part != ".":
                parts.append(part)
        resolved.append("/".join(parts))
    for candidate in resolved:
        stripped = _ts_key(candidate)
        if stripped in known:
            return stripped
        if candidate in known:
            return candidate
    return None


def _split_names(group: str) -> list[str]:
    names: list[str] = []
    for part in group.split(","):
        token = part.strip()
        if token.startswith("type "):
            token = token[len("type ") :].strip()
        token = token.split(" as ")[0].strip()
        if token:
            names.append(token)
    return names
