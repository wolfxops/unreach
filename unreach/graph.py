"""Import graphs for Python and TypeScript. Deterministic; no LLM."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

TS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:type\s+)?(?:[\s\S]*?\sfrom\s+)?|export\s+(?:type\s+)?[\s\S]*?\sfrom\s+|require\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)
TS_EXPORT_FN_RE = re.compile(
    r"export\s+(?:async\s+)?(?:function|class|const|let|var|enum|type|interface)\s+(\w+)"
)
TS_EXPORT_NAMED_RE = re.compile(r"export\s+(?:type\s+)?\{([^}]+)\}")
TS_IMPORT_NAMED_RE = re.compile(
    r"""import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"""
)
TS_IMPORT_STAR_RE = re.compile(
    r"""import\s+(?:type\s+)?\*\s+as\s+\w+\s+from\s+['"]([^'"]+)['"]"""
)


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


@dataclass
class TsModule:
    key: str
    rel_path: str
    exports: list[str] = field(default_factory=list)
    imported_names: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    namespace_imported: bool = False


def module_name_for(root: Path, path: Path) -> tuple[str, bool]:
    rel = path.resolve().relative_to(root.resolve())
    parts = list(rel.with_suffix("").parts)
    is_package = path.name == "__init__.py"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def build_python_graph(root: Path, files: list[Path]) -> dict[str, PyModule]:
    modules: dict[str, PyModule] = {}
    for path in files:
        name, is_package = module_name_for(root, path)
        if not name:
            name = path.stem
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        modules[name] = PyModule(name=name, rel_path=rel, path=path, is_package=is_package)

    for module in modules.values():
        tree = _parse(module.path)
        if tree is None:
            continue
        module.exports, module.private_defs = _python_defs(tree)
        module.local_uses = _local_name_uses(tree, defined=set(module.exports) | set(module.private_defs))
        for imported, names, star, whole in _python_imports(tree, module):
            target = _resolve_module(imported, set(modules))
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

    # Second pass: any module that appears in imports_modules is imported.
    for module in modules.values():
        for target in module.imports_modules:
            if target in modules:
                modules[target].referenced = True
            for parent in _parents(target):
                if parent in modules:
                    modules[parent].referenced = True
    return modules


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


def _resolve_module(name: str, known: set[str]) -> str | None:
    if name in known:
        return name
    return None


def _python_imports(
    tree: ast.AST, module: PyModule
) -> list[tuple[str, set[str], bool, bool]]:
    out: list[tuple[str, set[str], bool, bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, set(), False, True))
        elif isinstance(node, ast.ImportFrom):
            target = _abs_from(module, node.module, node.level)
            if not target:
                continue
            names: set[str] = set()
            star = False
            whole = False
            for alias in node.names:
                if alias.name == "*":
                    star = True
                else:
                    names.add(alias.name)
            out.append((target, names, star, whole))
    return out


def _abs_from(module: PyModule, imported: str | None, level: int) -> str | None:
    if level == 0:
        return imported
    parts = module.name.split(".")
    if not module.is_package:
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
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_") and not node.name.startswith("__"):
                private[node.name] = getattr(node, "lineno", 1)
            elif not node.name.startswith("__"):
                public.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    parsed = _const_list(node.value)
                    if parsed is not None:
                        all_names = parsed
                elif isinstance(target, ast.Name) and not target.id.startswith("_"):
                    if _looks_like_export_assign(node):
                        public.append(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if not node.target.id.startswith("_"):
                public.append(node.target.id)
    if all_names is not None:
        public = [name for name in all_names]
    # Deduplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for name in public:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered, private


def _looks_like_export_assign(node: ast.Assign) -> bool:
    # Skip `x = import` style noise; keep simple constants and names.
    return True


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
    defined_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined_nodes.add(id(node))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in defined:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in defined:
            used.add(node.attr)
    return used


def _parse(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None


def build_typescript_graph(root: Path, files: list[Path]) -> dict[str, TsModule]:
    modules: dict[str, TsModule] = {}
    for path in files:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        key = _ts_key(rel)
        text = _read(path)
        exports = TS_EXPORT_FN_RE.findall(text)
        for group in TS_EXPORT_NAMED_RE.findall(text):
            exports.extend(_split_names(group))
        modules[key] = TsModule(key=key, rel_path=rel, exports=list(dict.fromkeys(exports)))

    known = set(modules)
    for module in modules.values():
        text = _read(root / module.rel_path)
        for spec in TS_IMPORT_RE.findall(text):
            target = _resolve_ts_spec(module.rel_path, spec, known)
            if target:
                module.imports.add(target)
        for names, spec in TS_IMPORT_NAMED_RE.findall(text):
            target = _resolve_ts_spec(module.rel_path, spec, known)
            if target and target in modules:
                modules[target].imported_names.update(_split_names(names))
        for spec in TS_IMPORT_STAR_RE.findall(text):
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
    for suffix in (".d.ts", ".tsx", ".ts", ".jsx", ".js", ".mts", ".cts", ".mjs"):
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
    # Normalize .. and .
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
        if candidate in known:
            return candidate
    return None


def _split_names(group: str) -> list[str]:
    names: list[str] = []
    for part in group.split(","):
        token = part.strip()
        if not token or token.startswith("type "):
            token = token.removeprefix("type ").strip()
        token = token.split(" as ")[0].strip()
        if token:
            names.append(token)
    return names


def _read(path: Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
