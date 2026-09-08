"""Language, framework, and workspace detection. Deterministic; no LLM.

The profile drives two things:

* framework-aware entry roles (a Django ``urls.py`` is not an orphan), and
* the dynamic agentic workflow (which checks an agent must run per language).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

PY_SUFFIXES = (".py",)
TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs")

# Framework → (import markers, file-role patterns that are implicit entry points)
FRAMEWORKS: dict[str, dict[str, list[str]]] = {
    "django": {
        "imports": ["django"],
        "entry_files": [
            "models.py",
            "urls.py",
            "admin.py",
            "apps.py",
            "views.py",
            "forms.py",
            "signals.py",
            "settings.py",
            "manage.py",
            "wsgi.py",
            "asgi.py",
            "celery.py",
        ],
        "entry_dirs": ["migrations", "management/commands", "templatetags"],
        "decorators": ["receiver", "register", "admin.register", "shared_task", "task"],
        "bases": ["models.Model", "Model", "ModelAdmin", "AppConfig", "Command", "TestCase"],
    },
    "flask": {
        "imports": ["flask"],
        "entry_files": ["app.py", "wsgi.py", "routes.py", "views.py"],
        "entry_dirs": [],
        "decorators": ["route", "get", "post", "put", "delete", "patch", "before_request", "errorhandler", "cli.command", "command"],
        "bases": ["MethodView", "View"],
    },
    "fastapi": {
        "imports": ["fastapi", "starlette"],
        "entry_files": ["main.py", "app.py", "router.py", "routes.py", "dependencies.py"],
        "entry_dirs": ["routers", "routes", "api"],
        "decorators": ["get", "post", "put", "delete", "patch", "api_route", "websocket", "on_event", "middleware", "exception_handler"],
        "bases": ["BaseModel", "APIRouter", "HTTPException"],
    },
    "pytest": {
        "imports": ["pytest"],
        "entry_files": ["conftest.py"],
        "entry_dirs": ["tests", "test"],
        "decorators": ["fixture", "pytest.fixture", "hookimpl", "pytest.hookimpl", "mark", "pytest.mark"],
        "bases": [],
    },
    "celery": {
        "imports": ["celery"],
        "entry_files": ["celery.py", "tasks.py"],
        "entry_dirs": [],
        "decorators": ["task", "shared_task", "app.task", "celery.task"],
        "bases": ["Task"],
    },
    "sqlalchemy": {
        "imports": ["sqlalchemy", "alembic"],
        "entry_files": ["env.py", "models.py"],
        "entry_dirs": ["alembic", "migrations", "versions"],
        "decorators": ["listens_for", "event.listens_for", "validates", "hybrid_property"],
        "bases": ["Base", "DeclarativeBase"],
    },
    "click": {
        "imports": ["click", "typer"],
        "entry_files": ["cli.py", "__main__.py", "commands.py"],
        "entry_dirs": ["commands"],
        "decorators": ["command", "group", "cli.command", "app.command", "callback"],
        "bases": [],
    },
    "nextjs": {
        "imports": ["next"],
        "entry_files": ["next.config.js", "next.config.ts", "next.config.mjs", "middleware.ts", "layout.tsx", "page.tsx", "route.ts", "loading.tsx", "error.tsx", "not-found.tsx", "_app.tsx", "_document.tsx"],
        "entry_dirs": ["pages", "app", "api"],
        "decorators": [],
        "bases": [],
    },
    "react": {
        "imports": ["react"],
        "entry_files": ["index.tsx", "main.tsx", "App.tsx", "index.jsx", "main.jsx"],
        "entry_dirs": [],
        "decorators": [],
        "bases": ["React.Component", "Component"],
    },
    "vite": {
        "imports": ["vite"],
        "entry_files": ["vite.config.ts", "vite.config.js", "vite.config.mts"],
        "entry_dirs": [],
        "decorators": [],
        "bases": [],
    },
    "express": {
        "imports": ["express", "koa", "fastify", "@nestjs/core"],
        "entry_files": ["server.ts", "server.js", "index.ts", "index.js", "app.ts", "app.js", "main.ts"],
        "entry_dirs": ["routes", "controllers", "middleware"],
        "decorators": ["Controller", "Get", "Post", "Injectable", "Module"],
        "bases": [],
    },
}

GENERIC_ENTRY_PY = {
    "__main__.py",
    "main.py",
    "app.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "setup.py",
    "conftest.py",
    "cli.py",
    "noxfile.py",
    "tasks.py",
    "fabfile.py",
}
GENERIC_ENTRY_TS = {
    "index.ts",
    "index.tsx",
    "index.js",
    "main.ts",
    "main.tsx",
    "main.js",
    "app.ts",
    "app.tsx",
    "app.js",
    "server.ts",
    "server.js",
}
CONFIG_SUFFIXES = (".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".txt", ".env", ".sh", ".mk")
CONFIG_NAMES = {"Dockerfile", "Makefile", "Procfile", "Justfile"}
TOKEN_RE = re.compile(r"[A-Za-z_][\w./:-]{2,}")


@dataclass
class Profile:
    languages: dict[str, int] = field(default_factory=dict)
    primary: str = "none"
    frameworks: list[str] = field(default_factory=list)
    monorepo: bool = False
    workspaces: list[str] = field(default_factory=list)
    package_manifests: list[str] = field(default_factory=list)
    package_entries: list[str] = field(default_factory=list)
    entry_files: set[str] = field(default_factory=set)
    entry_dirs: set[str] = field(default_factory=set)
    decorators: set[str] = field(default_factory=set)
    bases: set[str] = field(default_factory=set)
    dynamic_import_anywhere: bool = False
    config_tokens: set[str] = field(default_factory=set)
    test_runner: str | None = None
    type_checker: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in ("entry_files", "entry_dirs", "decorators", "bases"):
            data[key] = sorted(data[key])
        data.pop("config_tokens", None)
        data["config_token_count"] = len(self.config_tokens)
        return data


def detect_profile(root: Path, py_files: list[Path], ts_files: list[Path]) -> Profile:
    profile = Profile()
    profile.languages = {}
    if py_files:
        profile.languages["py"] = len(py_files)
    if ts_files:
        profile.languages["ts"] = len(ts_files)
    if profile.languages:
        profile.primary = max(profile.languages, key=lambda k: profile.languages[k])

    imported_top = _top_level_imports(py_files, ts_files)
    for name, spec in FRAMEWORKS.items():
        if any(marker in imported_top for marker in spec["imports"]):
            profile.frameworks.append(name)
    _read_manifests(root, profile, imported_top)

    profile.entry_files = set(GENERIC_ENTRY_PY) | set(GENERIC_ENTRY_TS)
    profile.entry_dirs = set()
    for name in profile.frameworks:
        spec = FRAMEWORKS[name]
        profile.entry_files.update(spec["entry_files"])
        profile.entry_dirs.update(spec["entry_dirs"])
        profile.decorators.update(spec["decorators"])
        profile.bases.update(spec["bases"])
    profile.config_tokens = _config_tokens(root)
    return profile


def _top_level_imports(py_files: list[Path], ts_files: list[Path]) -> set[str]:
    found: set[str] = set()
    import_re_py = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", re.MULTILINE)
    import_re_ts = re.compile(r"""(?:from|require\()\s*['"](@?[A-Za-z][\w./-]*)['"]""")
    for path in py_files[:2000]:
        text = _read(path)
        found.update(import_re_py.findall(text))
    for path in ts_files[:2000]:
        text = _read(path)
        for spec in import_re_ts.findall(text):
            found.add(spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2]))
    return found


def _read_manifests(root: Path, profile: Profile, imported_top: set[str]) -> None:
    pkg = root / "package.json"
    if pkg.is_file():
        profile.package_manifests.append("package.json")
        try:
            data = json.loads(_read(pkg) or "{}")
        except json.JSONDecodeError:
            data = {}
        workspaces = data.get("workspaces")
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages", [])
        if isinstance(workspaces, list) and workspaces:
            profile.monorepo = True
            profile.workspaces = [str(w) for w in workspaces]
        for key in ("main", "module", "types", "browser"):
            value = data.get(key)
            if isinstance(value, str):
                profile.package_entries.append(value)
        bin_field = data.get("bin")
        if isinstance(bin_field, str):
            profile.package_entries.append(bin_field)
        elif isinstance(bin_field, dict):
            profile.package_entries.extend(str(v) for v in bin_field.values())
        exports = data.get("exports")
        profile.package_entries.extend(_flatten_exports(exports))
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if "next" in deps and "nextjs" not in profile.frameworks:
            profile.frameworks.append("nextjs")
        if "vitest" in deps:
            profile.test_runner = "vitest"
        elif "jest" in deps:
            profile.test_runner = "jest"
        if "typescript" in deps:
            profile.type_checker = "tsc"
    if (root / "pnpm-workspace.yaml").is_file():
        profile.monorepo = True
        profile.package_manifests.append("pnpm-workspace.yaml")
    if (root / "lerna.json").is_file() or (root / "nx.json").is_file() or (root / "turbo.json").is_file():
        profile.monorepo = True
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        profile.package_manifests.append("pyproject.toml")
        text = _read(pyproject)
        if "pytest" in text or "pytest" in imported_top:
            profile.test_runner = profile.test_runner or "pytest"
        if "[tool.mypy]" in text:
            profile.type_checker = profile.type_checker or "mypy"
        if "[tool.pyright]" in text:
            profile.type_checker = profile.type_checker or "pyright"
        for match in re.finditer(r"^\s*([\w.-]+)\s*=\s*['\"]([\w.]+):[\w]+['\"]", text, re.MULTILINE):
            profile.package_entries.append(match.group(2))
    if "pytest" in imported_top and profile.test_runner is None:
        profile.test_runner = "pytest"
    nested = [p for p in root.glob("*/pyproject.toml")] + [p for p in root.glob("packages/*/package.json")]
    if len(nested) >= 2:
        profile.monorepo = True
        profile.workspaces.extend(sorted(str(p.parent.relative_to(root)) for p in nested)[:20])


def _flatten_exports(value) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_flatten_exports(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(_flatten_exports(item))
    return out


def _config_tokens(root: Path) -> set[str]:
    tokens: set[str] = set()
    count = 0
    for path in root.rglob("*"):
        if count >= 400:
            break
        if not path.is_file():
            continue
        if any(part in {".git", "node_modules", ".venv", "venv", "__pycache__", ".unreach", "dist", "build"} for part in path.parts):
            continue
        if path.suffix not in CONFIG_SUFFIXES and path.name not in CONFIG_NAMES:
            continue
        if path.stat().st_size > 512_000:
            continue
        count += 1
        text = _read(path)
        for match in TOKEN_RE.findall(text):
            tokens.add(match)
            if len(tokens) > 60_000:
                return tokens
    return tokens


def file_role(rel: str, profile: Profile) -> str:
    """Return entry | test | config | source for a repository-relative path."""
    parts = Path(rel).parts
    name = Path(rel).name
    lowered = {p.lower() for p in parts}
    if name.startswith("test_") or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".spec.js", ".test.js")):
        return "test"
    if lowered & {"tests", "test", "__tests__", "spec"}:
        return "test"
    if name in profile.entry_files:
        return "entry"
    for entry_dir in profile.entry_dirs:
        segs = entry_dir.split("/")
        for i in range(len(parts) - len(segs)):
            if list(parts[i : i + len(segs)]) == segs:
                return "entry"
    posix = Path(rel).as_posix()
    for entry in profile.package_entries:
        cleaned = entry.lstrip("./")
        if cleaned and (posix == cleaned or posix.startswith(cleaned.rsplit(".", 1)[0])):
            return "entry"
        if "." not in cleaned and cleaned.replace("/", ".") in posix.replace("/", ".").rsplit(".", 1)[0]:
            return "entry"
    if name.endswith(".d.ts") or name in {"__init__.py"} or name.startswith("."):
        return "config"
    return "source"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
