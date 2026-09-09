"""Language, framework, and workspace detection. Deterministic; no LLM.

The profile drives:

* framework-aware entry roles (a Django ``urls.py`` is not an orphan),
* confidence signals (registration decorators, framework base classes), and
* the dynamic agentic workflow (validation commands per language).

Frameworks are detected from two sources: import statements in source files
and dependency names in manifests (package.json, pyproject.toml, go.mod,
Cargo.toml, pom.xml, build.gradle, *.csproj, Gemfile, composer.json,
Package.swift, pubspec.yaml, mix.exs).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from unreach.polyglot import LANGS, lang_for_suffix

PY_SUFFIXES = (".py",)
TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".vue", ".svelte")

LANGUAGE_NAMES = {
    "py": "Python",
    "ts": "TypeScript / JavaScript",
    **{key: spec.name for key, spec in LANGS.items()},
}

# name → {language, imports, deps, entry_files, entry_dirs, decorators, bases}
FRAMEWORKS: dict[str, dict] = {
    # ---- Python ------------------------------------------------------------
    "django": {
        "language": "py", "imports": ["django"], "deps": ["django"],
        "entry_files": ["models.py", "urls.py", "admin.py", "apps.py", "views.py", "forms.py", "signals.py", "settings.py", "manage.py", "wsgi.py", "asgi.py", "celery.py", "serializers.py", "tasks.py"],
        "entry_dirs": ["migrations", "management/commands", "templatetags"],
        "decorators": ["receiver", "register", "admin.register", "shared_task", "task", "api_view", "action"],
        "bases": ["models.Model", "Model", "ModelAdmin", "AppConfig", "Command", "TestCase", "APIView", "ViewSet", "ModelViewSet", "Serializer", "ModelSerializer"],
    },
    "flask": {
        "language": "py", "imports": ["flask"], "deps": ["flask"],
        "entry_files": ["app.py", "wsgi.py", "routes.py", "views.py"], "entry_dirs": ["blueprints"],
        "decorators": ["route", "get", "post", "put", "delete", "patch", "before_request", "after_request", "errorhandler", "cli.command", "command", "teardown_appcontext"],
        "bases": ["MethodView", "View"],
    },
    "fastapi": {
        "language": "py", "imports": ["fastapi", "starlette"], "deps": ["fastapi", "starlette"],
        "entry_files": ["main.py", "app.py", "router.py", "routes.py", "dependencies.py"], "entry_dirs": ["routers", "routes", "api", "endpoints"],
        "decorators": ["get", "post", "put", "delete", "patch", "api_route", "websocket", "on_event", "middleware", "exception_handler"],
        "bases": ["BaseModel", "APIRouter", "HTTPException", "BaseSettings"],
    },
    "pytest": {
        "language": "py", "imports": ["pytest"], "deps": ["pytest"],
        "entry_files": ["conftest.py"], "entry_dirs": ["tests", "test"],
        "decorators": ["fixture", "pytest.fixture", "hookimpl", "pytest.hookimpl", "mark", "pytest.mark", "parametrize"],
        "bases": [],
    },
    "celery": {
        "language": "py", "imports": ["celery"], "deps": ["celery"],
        "entry_files": ["celery.py", "tasks.py", "celeryconfig.py"], "entry_dirs": [],
        "decorators": ["task", "shared_task", "app.task", "celery.task", "periodic_task"],
        "bases": ["Task"],
    },
    "sqlalchemy": {
        "language": "py", "imports": ["sqlalchemy", "alembic"], "deps": ["sqlalchemy", "alembic"],
        "entry_files": ["env.py", "models.py", "base.py"], "entry_dirs": ["alembic", "migrations", "versions"],
        "decorators": ["listens_for", "event.listens_for", "validates", "hybrid_property", "declared_attr"],
        "bases": ["Base", "DeclarativeBase"],
    },
    "click": {
        "language": "py", "imports": ["click", "typer"], "deps": ["click", "typer"],
        "entry_files": ["cli.py", "__main__.py", "commands.py"], "entry_dirs": ["commands"],
        "decorators": ["command", "group", "cli.command", "app.command", "callback", "option", "argument"],
        "bases": [],
    },
    "airflow": {
        "language": "py", "imports": ["airflow"], "deps": ["apache-airflow", "airflow"],
        "entry_files": [], "entry_dirs": ["dags", "plugins"],
        "decorators": ["task", "dag", "task_group"], "bases": ["BaseOperator", "BaseHook", "BaseSensorOperator"],
    },
    "pydantic": {
        "language": "py", "imports": ["pydantic"], "deps": ["pydantic"],
        "entry_files": [], "entry_dirs": [],
        "decorators": ["validator", "field_validator", "model_validator", "root_validator", "computed_field"],
        "bases": ["BaseModel", "BaseSettings"],
    },
    # ---- JavaScript / TypeScript -------------------------------------------
    "nextjs": {
        "language": "ts", "imports": ["next"], "deps": ["next"],
        "entry_files": ["next.config.js", "next.config.ts", "next.config.mjs", "middleware.ts", "layout.tsx", "page.tsx", "route.ts", "loading.tsx", "error.tsx", "not-found.tsx", "_app.tsx", "_document.tsx", "instrumentation.ts"],
        "entry_dirs": ["pages", "app", "api"], "decorators": [], "bases": [],
    },
    "react": {
        "language": "ts", "imports": ["react"], "deps": ["react"],
        "entry_files": ["index.tsx", "main.tsx", "App.tsx", "index.jsx", "main.jsx", "App.jsx"], "entry_dirs": [],
        "decorators": [], "bases": ["React.Component", "Component", "PureComponent"],
    },
    "vue": {
        "language": "ts", "imports": ["vue"], "deps": ["vue"],
        "entry_files": ["main.ts", "main.js", "App.vue", "vite.config.ts", "vue.config.js"], "entry_dirs": ["pages", "layouts"],
        "decorators": [], "bases": [],
    },
    "nuxt": {
        "language": "ts", "imports": ["nuxt", "#app", "#imports"], "deps": ["nuxt"],
        "entry_files": ["nuxt.config.ts", "nuxt.config.js", "app.vue", "error.vue"],
        "entry_dirs": ["pages", "layouts", "middleware", "plugins", "server", "composables", "components"],
        "decorators": [], "bases": [],
    },
    "angular": {
        "language": "ts", "imports": ["@angular/core"], "deps": ["@angular/core"],
        "entry_files": ["main.ts", "app.module.ts", "app.config.ts", "app.routes.ts", "polyfills.ts", "test.ts"],
        "entry_dirs": [], "decorators": ["Component", "Injectable", "NgModule", "Directive", "Pipe"], "bases": [],
    },
    "svelte": {
        "language": "ts", "imports": ["svelte", "@sveltejs/kit", "$app"], "deps": ["svelte", "@sveltejs/kit"],
        "entry_files": ["svelte.config.js", "+page.svelte", "+layout.svelte", "+page.ts", "+page.server.ts", "+layout.ts", "+server.ts", "hooks.server.ts", "hooks.client.ts", "app.html", "App.svelte"],
        "entry_dirs": ["routes"], "decorators": [], "bases": [],
    },
    "remix": {
        "language": "ts", "imports": ["@remix-run/node", "@remix-run/react", "react-router"], "deps": ["@remix-run/react", "react-router"],
        "entry_files": ["root.tsx", "entry.client.tsx", "entry.server.tsx", "remix.config.js", "react-router.config.ts"],
        "entry_dirs": ["routes"], "decorators": [], "bases": [],
    },
    "astro": {
        "language": "ts", "imports": ["astro"], "deps": ["astro"],
        "entry_files": ["astro.config.mjs", "astro.config.ts"], "entry_dirs": ["pages", "layouts", "content"],
        "decorators": [], "bases": [],
    },
    "vite": {
        "language": "ts", "imports": ["vite"], "deps": ["vite"],
        "entry_files": ["vite.config.ts", "vite.config.js", "vite.config.mts"], "entry_dirs": [], "decorators": [], "bases": [],
    },
    "express": {
        "language": "ts", "imports": ["express", "koa", "fastify", "hono"], "deps": ["express", "koa", "fastify", "hono"],
        "entry_files": ["server.ts", "server.js", "index.ts", "index.js", "app.ts", "app.js", "main.ts"],
        "entry_dirs": ["routes", "controllers", "middleware", "middlewares"], "decorators": [], "bases": [],
    },
    "nestjs": {
        "language": "ts", "imports": ["@nestjs/core", "@nestjs/common"], "deps": ["@nestjs/core"],
        "entry_files": ["main.ts", "app.module.ts"], "entry_dirs": [],
        "decorators": ["Controller", "Get", "Post", "Put", "Delete", "Patch", "Injectable", "Module", "Resolver", "Query", "Mutation"], "bases": [],
    },
    "electron": {
        "language": "ts", "imports": ["electron"], "deps": ["electron"],
        "entry_files": ["main.ts", "main.js", "preload.ts", "preload.js", "electron.vite.config.ts"], "entry_dirs": [],
        "decorators": [], "bases": [],
    },
    "jest": {
        "language": "ts", "imports": ["@jest/globals", "vitest"], "deps": ["jest", "vitest"],
        "entry_files": ["jest.config.js", "jest.config.ts", "vitest.config.ts", "vitest.setup.ts", "setupTests.ts"],
        "entry_dirs": ["__tests__", "__mocks__"], "decorators": [], "bases": [],
    },
    "playwright": {
        "language": "ts", "imports": ["@playwright/test", "cypress"], "deps": ["@playwright/test", "cypress"],
        "entry_files": ["playwright.config.ts", "cypress.config.ts", "cypress.config.js"], "entry_dirs": ["e2e", "cypress"],
        "decorators": [], "bases": [],
    },
    # ---- Go ----------------------------------------------------------------
    "gin": {"language": "go", "imports": ["github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/gofiber/fiber", "github.com/gorilla/mux", "github.com/go-chi/chi"],
            "deps": ["github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/gofiber/fiber", "github.com/gorilla/mux", "github.com/go-chi/chi"],
            "entry_files": ["main.go", "routes.go", "router.go", "server.go"], "entry_dirs": ["cmd", "handlers", "handler", "api", "internal/handlers"], "decorators": [], "bases": []},
    "cobra": {"language": "go", "imports": ["github.com/spf13/cobra", "github.com/urfave/cli"], "deps": ["github.com/spf13/cobra", "github.com/urfave/cli"],
              "entry_files": ["root.go", "main.go"], "entry_dirs": ["cmd"], "decorators": [], "bases": []},
    # ---- Rust --------------------------------------------------------------
    "actix": {"language": "rust", "imports": ["actix_web", "axum", "rocket", "warp"], "deps": ["actix-web", "axum", "rocket", "warp"],
              "entry_files": ["main.rs", "routes.rs", "handlers.rs"], "entry_dirs": ["routes", "handlers", "bin"], "decorators": [], "bases": []},
    "tokio": {"language": "rust", "imports": ["tokio"], "deps": ["tokio"], "entry_files": ["main.rs"], "entry_dirs": ["bin"], "decorators": [], "bases": []},
    "clap": {"language": "rust", "imports": ["clap"], "deps": ["clap"], "entry_files": ["main.rs", "cli.rs"], "entry_dirs": ["bin"], "decorators": [], "bases": []},
    # ---- JVM ---------------------------------------------------------------
    "spring": {"language": "java", "imports": ["org.springframework"], "deps": ["spring-boot", "org.springframework"],
               "entry_files": ["Application.java", "Application.kt"], "entry_dirs": ["controller", "controllers", "config", "configuration", "repository", "entity", "resources"],
               "decorators": ["Component", "Service", "Repository", "Controller", "RestController", "Configuration", "Bean", "Entity", "Scheduled", "EventListener"], "bases": []},
    "quarkus": {"language": "java", "imports": ["io.quarkus", "jakarta.ws.rs", "javax.ws.rs"], "deps": ["quarkus", "io.quarkus"],
                "entry_files": [], "entry_dirs": ["resources"], "decorators": ["Path", "ApplicationScoped", "Inject", "Produces"], "bases": []},
    "micronaut": {"language": "java", "imports": ["io.micronaut"], "deps": ["micronaut", "io.micronaut"],
                  "entry_files": ["Application.java"], "entry_dirs": [], "decorators": ["Controller", "Singleton", "Factory"], "bases": []},
    "junit": {"language": "java", "imports": ["org.junit", "org.testng"], "deps": ["junit", "org.junit", "testng"],
              "entry_files": [], "entry_dirs": ["test"], "decorators": ["Test", "BeforeEach", "AfterEach", "ParameterizedTest"], "bases": []},
    "ktor": {"language": "kotlin", "imports": ["io.ktor"], "deps": ["io.ktor", "ktor"],
             "entry_files": ["Application.kt", "Routing.kt", "Plugins.kt"], "entry_dirs": ["plugins", "routes"], "decorators": [], "bases": []},
    "android": {"language": "kotlin", "imports": ["android.", "androidx."], "deps": ["androidx", "com.android.application", "com.android.library"],
                "entry_files": ["MainActivity.kt", "MainActivity.java", "MainApplication.kt", "AndroidManifest.xml"],
                "entry_dirs": ["ui", "viewmodel", "res"], "decorators": ["Composable", "HiltViewModel", "AndroidEntryPoint", "Preview"], "bases": ["Activity", "AppCompatActivity", "Fragment", "ViewModel", "Application", "Service", "BroadcastReceiver"]},
    # ---- .NET --------------------------------------------------------------
    "aspnet": {"language": "csharp", "imports": ["Microsoft.AspNetCore"], "deps": ["Microsoft.AspNetCore", "Microsoft.NET.Sdk.Web"],
               "entry_files": ["Program.cs", "Startup.cs"], "entry_dirs": ["Controllers", "Pages", "Views", "Migrations", "Areas"],
               "decorators": ["ApiController", "Route", "HttpGet", "HttpPost", "Authorize"], "bases": ["ControllerBase", "Controller", "PageModel", "DbContext", "Hub", "BackgroundService"]},
    "xunit": {"language": "csharp", "imports": ["Xunit", "NUnit.Framework", "Microsoft.VisualStudio.TestTools"], "deps": ["xunit", "NUnit", "MSTest"],
              "entry_files": [], "entry_dirs": [], "decorators": ["Fact", "Theory", "Test", "TestMethod"], "bases": []},
    # ---- Ruby --------------------------------------------------------------
    "rails": {"language": "ruby", "imports": ["rails", "active_record", "action_controller"], "deps": ["rails"],
              "entry_files": ["config.ru", "Rakefile", "application.rb", "routes.rb", "schema.rb", "seeds.rb"],
              "entry_dirs": ["app", "config", "db", "lib/tasks"], "decorators": [], "bases": ["ApplicationRecord", "ApplicationController", "ApplicationJob", "ApplicationMailer", "ActiveRecord::Base"]},
    "sinatra": {"language": "ruby", "imports": ["sinatra"], "deps": ["sinatra"], "entry_files": ["app.rb", "config.ru"], "entry_dirs": [], "decorators": [], "bases": ["Sinatra::Base"]},
    "rspec": {"language": "ruby", "imports": ["rspec"], "deps": ["rspec", "rspec-rails", "minitest"], "entry_files": ["spec_helper.rb", "rails_helper.rb"], "entry_dirs": ["spec", "test"], "decorators": [], "bases": []},
    # ---- PHP ---------------------------------------------------------------
    "laravel": {"language": "php", "imports": ["Illuminate\\"], "deps": ["laravel/framework"],
                "entry_files": ["artisan", "index.php"], "entry_dirs": ["routes", "config", "database", "app/Providers", "app/Http", "app/Console", "resources"],
                "decorators": [], "bases": ["Model", "Controller", "ServiceProvider", "Command", "Job", "Migration", "Seeder", "Middleware"]},
    "symfony": {"language": "php", "imports": ["Symfony\\"], "deps": ["symfony/framework-bundle", "symfony/symfony"],
                "entry_files": ["index.php", "Kernel.php", "console"], "entry_dirs": ["config", "src/Controller", "src/Command", "migrations", "templates"],
                "decorators": ["Route", "AsCommand", "AsEventListener"], "bases": ["AbstractController", "Command", "Bundle", "Kernel"]},
    # ---- Swift / Dart / Elixir -------------------------------------------
    "swiftui": {"language": "swift", "imports": ["SwiftUI", "UIKit"], "deps": [],
                "entry_files": ["App.swift", "ContentView.swift", "AppDelegate.swift", "SceneDelegate.swift"], "entry_dirs": ["Views", "Preview Content"],
                "decorators": ["main", "Observable", "Model"], "bases": ["View", "App", "ObservableObject", "UIViewController", "XCTestCase"]},
    "vapor": {"language": "swift", "imports": ["Vapor"], "deps": ["vapor"], "entry_files": ["configure.swift", "routes.swift", "entrypoint.swift"], "entry_dirs": ["Controllers", "Migrations"], "decorators": [], "bases": ["Migration", "Model", "RouteCollection"]},
    "flutter": {"language": "dart", "imports": ["package:flutter/"], "deps": ["flutter"],
                "entry_files": ["main.dart", "firebase_options.dart"], "entry_dirs": ["test", "integration_test", "android", "ios"], "decorators": [], "bases": ["StatelessWidget", "StatefulWidget", "State", "ChangeNotifier"]},
    "phoenix": {"language": "elixir", "imports": ["Phoenix"], "deps": ["phoenix"],
                "entry_files": ["router.ex", "endpoint.ex", "application.ex", "repo.ex", "telemetry.ex", "mix.exs"],
                "entry_dirs": ["controllers", "live", "channels", "priv/repo/migrations", "config"], "decorators": [], "bases": []},
}

GENERIC_ENTRY_PY = {
    "__main__.py", "main.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "setup.py",
    "conftest.py", "cli.py", "noxfile.py", "tasks.py", "fabfile.py",
}
GENERIC_ENTRY_TS = {
    "index.ts", "index.tsx", "index.js", "main.ts", "main.tsx", "main.js", "app.ts", "app.tsx", "app.js", "server.ts", "server.js",
}
CONFIG_SUFFIXES = (".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".txt", ".env", ".sh", ".mk", ".xml", ".gradle", ".kts", ".csproj", ".sln", ".rb", ".exs")
CONFIG_NAMES = {"Dockerfile", "Makefile", "Procfile", "Justfile", "Gemfile", "go.mod", "cpanfile"}
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
    validate_commands: dict[str, list[str]] = field(default_factory=dict)
    parse_failures: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in ("entry_files", "entry_dirs", "decorators", "bases"):
            data[key] = sorted(data[key])
        data.pop("config_tokens", None)
        data["config_token_count"] = len(self.config_tokens)
        data["language_names"] = {k: LANGUAGE_NAMES.get(k, k) for k in self.languages}
        return data


def detect_profile(
    root: Path,
    py_files: list[Path],
    ts_files: list[Path],
    other_files: list[Path] | None = None,
    *,
    config_tokens: set[str] | None = None,
) -> Profile:
    profile = Profile()
    if py_files:
        profile.languages["py"] = len(py_files)
    if ts_files:
        profile.languages["ts"] = len(ts_files)
    for path in other_files or []:
        key = lang_for_suffix(path.suffix)
        if key:
            profile.languages[key] = profile.languages.get(key, 0) + 1
    if profile.languages:
        profile.primary = max(profile.languages, key=lambda k: profile.languages[k])

    imported_top = _top_level_imports(py_files, ts_files, other_files or [])
    deps = _manifest_deps(root, profile)
    for name, spec in FRAMEWORKS.items():
        if any(_import_matches(marker, imported_top) for marker in spec["imports"]) or any(
            _dep_matches(dep, deps) for dep in spec["deps"]
        ):
            profile.frameworks.append(name)

    profile.entry_files = set(GENERIC_ENTRY_PY) | set(GENERIC_ENTRY_TS)
    for name in profile.frameworks:
        spec = FRAMEWORKS[name]
        profile.entry_files.update(spec["entry_files"])
        profile.entry_dirs.update(spec["entry_dirs"])
        profile.decorators.update(spec["decorators"])
        profile.bases.update(spec["bases"])
    for key in profile.languages:
        if key in LANGS:
            profile.validate_commands[key] = list(LANGS[key].validate)
    if "py" in profile.languages:
        cmds = ["python -c \"import <package>\""]
        if profile.type_checker in {"mypy", "pyright"}:
            cmds.append(f"{profile.type_checker} .")
        cmds.append("pytest -q" if (profile.test_runner or "pytest") == "pytest" else str(profile.test_runner))
        profile.validate_commands["py"] = cmds
    if "ts" in profile.languages:
        cmds = []
        if profile.type_checker == "tsc":
            cmds.append("npx tsc --noEmit")
        runner = profile.test_runner or "npm test"
        cmds.append(f"npx {runner} run" if runner in {"vitest", "jest"} else runner)
        profile.validate_commands["ts"] = cmds
    profile.config_tokens = set(config_tokens) if config_tokens is not None else _config_tokens(root)
    return profile


def _import_matches(marker: str, imported: set[str]) -> bool:
    if marker in imported:
        return True
    if marker.endswith((".", "/", "\\")):
        return any(item.startswith(marker) for item in imported)
    return any(item == marker or item.startswith(marker + "/") or item.startswith(marker + ".") for item in imported)


def _dep_matches(dep: str, deps: set[str]) -> bool:
    low = dep.lower()
    return any(d == low or d.startswith(low + "/") or d.startswith(low + ":") or d.startswith(low + ".") for d in deps)


def _top_level_imports(py_files: list[Path], ts_files: list[Path], other_files: list[Path]) -> set[str]:
    found: set[str] = set()
    import_re_py = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", re.MULTILINE)
    import_re_ts = re.compile(r"""(?:from|require\(|import\()\s*['"](@?[A-Za-z#$][\w./-]*)['"]""")
    import_re_generic = re.compile(
        r"""^\s*(?:import|use|using|require|require_relative|include)\s+(?:static\s+)?["']?([A-Za-z@#$][\w.:/\\-]*)""",
        re.MULTILINE,
    )
    for path in py_files[:2000]:
        found.update(import_re_py.findall(_read(path)))
    for path in ts_files[:2000]:
        for spec in import_re_ts.findall(_read(path)):
            found.add(spec)
            found.add(spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2]))
    for path in other_files[:3000]:
        text = _read(path)
        found.update(import_re_generic.findall(text))
        if path.suffix == ".go":
            found.update(re.findall(r'"([\w./-]+)"', text))
        if path.suffix == ".php":
            found.update(m + "\\" for m in re.findall(r"^\s*use\s+([A-Z]\w*)\\", text, re.MULTILINE))
        if path.suffix in {".swift", ".ex", ".exs"}:
            found.update(re.findall(r"^\s*(?:import|use|alias)\s+([A-Z]\w*)", text, re.MULTILINE))
        if path.suffix == ".dart":
            found.update(re.findall(r"""import\s+['"]([\w:/.]+)""", text))
    return found


def _manifest_deps(root: Path, profile: Profile) -> set[str]:
    deps: set[str] = set()
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
        profile.package_entries.extend(_flatten_exports(data.get("exports")))
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {}), **data.get("peerDependencies", {})}
        deps.update(k.lower() for k in all_deps)
        if "vitest" in all_deps:
            profile.test_runner = "vitest"
        elif "jest" in all_deps:
            profile.test_runner = "jest"
        if "typescript" in all_deps:
            profile.type_checker = "tsc"
    if (root / "pnpm-workspace.yaml").is_file():
        profile.monorepo = True
        profile.package_manifests.append("pnpm-workspace.yaml")
    if any((root / n).is_file() for n in ("lerna.json", "nx.json", "turbo.json")):
        profile.monorepo = True
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        profile.package_manifests.append("pyproject.toml")
        text = _read(pyproject)
        deps.update(m.lower() for m in re.findall(r"""^\s*["']([A-Za-z0-9_.-]+)""", text, re.MULTILINE))
        if "pytest" in text:
            profile.test_runner = profile.test_runner or "pytest"
        if "[tool.mypy]" in text:
            profile.type_checker = profile.type_checker or "mypy"
        if "[tool.pyright]" in text:
            profile.type_checker = profile.type_checker or "pyright"
        for match in re.finditer(r"^\s*([\w.-]+)\s*=\s*['\"]([\w.]+):[\w]+['\"]", text, re.MULTILINE):
            profile.package_entries.append(match.group(2))
    req = root / "requirements.txt"
    if req.is_file():
        profile.package_manifests.append("requirements.txt")
        deps.update(m.lower() for m in re.findall(r"^\s*([A-Za-z0-9_.-]+)", _read(req), re.MULTILINE))
    simple_manifests = {
        "go.mod": r"^\s*(?:require\s+)?([\w./-]+)\s+v[\d.]",
        "Cargo.toml": r"^\s*([A-Za-z0-9_-]+)\s*=",
        "Gemfile": r"""^\s*gem\s+['"]([\w-]+)""",
        "composer.json": r'"([\w-]+/[\w-]+)"\s*:',
        "Package.swift": r"""\.package\([^)]*?["']([\w.-]+)["']|name:\s*["'](\w+)["']""",
        "pubspec.yaml": r"^\s{2}([\w_]+)\s*:",
        "mix.exs": r"\{:(\w+),",
        "build.sbt": r'"([\w.-]+)"\s*%%?\s*"([\w.-]+)"',
    }
    for name, pattern in simple_manifests.items():
        path = root / name
        if not path.is_file():
            continue
        profile.package_manifests.append(name)
        for match in re.findall(pattern, _read(path), re.MULTILINE):
            items = match if isinstance(match, tuple) else (match,)
            deps.update(item.lower() for item in items if item)
    for gradle in list(root.glob("build.gradle*")) + list(root.glob("*/build.gradle*"))[:20]:
        profile.package_manifests.append(gradle.name)
        deps.update(m.lower() for m in re.findall(r"""['"]([\w.-]+:[\w.-]+)""", _read(gradle)))
        deps.update(m.lower() for m in re.findall(r"""id\s*\(?['"]([\w.-]+)['"]""", _read(gradle)))
    pom = root / "pom.xml"
    if pom.is_file():
        profile.package_manifests.append("pom.xml")
        text = _read(pom)
        deps.update(m.lower() for m in re.findall(r"<groupId>([\w.-]+)</groupId>", text))
        deps.update(m.lower() for m in re.findall(r"<artifactId>([\w.-]+)</artifactId>", text))
    for proj in list(root.glob("*.csproj")) + list(root.glob("*/*.csproj"))[:20]:
        profile.package_manifests.append(proj.name)
        text = _read(proj)
        deps.update(m.lower() for m in re.findall(r'PackageReference\s+Include="([\w.]+)"', text))
        deps.update(m.lower() for m in re.findall(r'Sdk="([\w.]+)"', text))
    nested = list(root.glob("*/pyproject.toml")) + list(root.glob("packages/*/package.json")) + list(root.glob("*/go.mod")) + list(root.glob("*/Cargo.toml"))
    if len(nested) >= 2:
        profile.monorepo = True
        profile.workspaces.extend(sorted(str(p.parent.relative_to(root)) for p in nested)[:20])
    if (root / "Cargo.toml").is_file() and "[workspace]" in _read(root / "Cargo.toml"):
        profile.monorepo = True
    if (root / "go.work").is_file():
        profile.monorepo = True
    return deps


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
        if any(part in {".git", "node_modules", ".venv", "venv", "__pycache__", ".unreach", "dist", "build", "target", "vendor"} for part in path.parts):
            continue
        if path.suffix not in CONFIG_SUFFIXES and path.name not in CONFIG_NAMES:
            continue
        if path.suffix in {".rb", ".exs"} and path.name not in {"Gemfile", "mix.exs", "config.exs", "routes.rb"}:
            continue
        try:
            if path.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        count += 1
        for match in TOKEN_RE.findall(_read(path)):
            tokens.add(match)
            if len(tokens) > 60_000:
                return tokens
    return tokens


def file_role(rel: str, profile: Profile) -> str:
    """Return entry | test | config | source for a repository-relative path."""
    parts = Path(rel).parts
    name = Path(rel).name
    lowered = {p.lower() for p in parts}
    if name.startswith("test_") or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".spec.js", ".test.js", ".stories.tsx", ".stories.ts")):
        return "test"
    if lowered & {"tests", "test", "__tests__", "spec", "__mocks__", "e2e", "cypress"}:
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
