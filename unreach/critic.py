"""Judge / critic layer: an adversarial second pass over every finding.

The scanner is the *prosecution*: it says "nothing imports this". This module
runs the *defense* — a devil's advocate that checks named counter-hypotheses
against real repository artifacts and returns ``file:line`` evidence — then a
*judge* combines both into a verdict, an adjusted confidence, and the single
next check that would settle the case.

Counter-hypotheses cover the ways code stays live without an import edge:

* scheduled jobs (crontab, celery beat, k8s CronJob, GitHub Actions
  ``schedule:``, systemd timers, Quartz/APScheduler decorators),
* CLI / container / serverless / CI entry points (``console_scripts``,
  ``python -m``, Dockerfile ``CMD``, Procfile, ``handler:`` in serverless.yml,
  Makefile and workflow steps),
* dynamic loading (reflection, ``importlib``, ``Class.forName``, DI/plugin
  registries, entry-point groups),
* templates, IDE run configs, infrastructure manifests, documentation,
* published library surfaces (external consumers the graph cannot see),
* dormant-not-dead code (feature flags, platform guards, conditional
  compilation, migrations, generated code, deprecation windows),
* convention-dispatched names (``clean_<field>``, ``getServerSideProps``, ...),
* explicit ``unreach: keep`` markers and work-in-progress hints from git.

Two further checks ride along:

* **identification** — how sure are we the finding points at the right thing
  (generic names, stem collisions, star re-exports, parse failures,
  unresolved workspace imports)?
* **security lens** — is the dead code also risky (secret-like literals,
  ``eval``, unsafe deserialization, disabled TLS verification, exposed routes)?
  Risky dead code is prioritised for removal; only line numbers are reported.

Everything here is deterministic. No LLM. Evidence lines are redacted and
truncated. The layer never deletes anything.
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from unreach import confidence as conf
from unreach.langs import TOKEN_RE, Profile
from unreach.redact import SECRET_PATTERNS, redact_text

if TYPE_CHECKING:  # pragma: no cover
    from unreach.scan import Finding

VERDICTS = ("remove", "verify", "keep")
MAX_PENALTY = 0.85
MAX_EVIDENCE = 4
MAX_ARTIFACT_FILES = 3000
MAX_ARTIFACT_BYTES = 512_000
MAX_SOURCE_INDEX_FILES = 6000
MAX_TOKENS_PER_FILE = 4000
GIT_RECENT_DAYS = 14

# --------------------------------------------------------------------------- #
# Artifact index: every non-source file that can name code without importing it
# --------------------------------------------------------------------------- #

WORD_RE = re.compile(r"[A-Za-z_]\w{2,}")
SKIP_PARTS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules", ".unreach",
    ".pytest_cache", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache", "site-packages", ".eggs",
    ".next", "coverage", "target", "vendor", "Pods", ".gradle", "obj", "_build", "deps", ".dart_tool",
    "DerivedData",
}
ARTIFACT_SUFFIXES = {
    ".toml", ".yaml", ".yml", ".json", ".json5", ".ini", ".cfg", ".conf", ".txt", ".env", ".properties",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".mk", ".xml", ".gradle", ".kts", ".csproj", ".sln",
    ".props", ".plist", ".service", ".timer", ".socket", ".tf", ".tfvars", ".hcl", ".bicep", ".nix",
    ".md", ".mdx", ".rst", ".adoc", ".ipynb",
    ".html", ".htm", ".jinja", ".jinja2", ".j2", ".tmpl", ".tpl", ".hbs", ".mustache", ".erb", ".haml",
    ".slim", ".twig", ".cshtml", ".razor", ".ejs", ".pug", ".njk", ".liquid", ".xaml", ".storyboard", ".xib",
    ".sql", ".graphql", ".gql", ".proto", ".dockerfile", ".code-workspace", ".sbt", ".cmake", ".bzl", ".bazel",
}
ARTIFACT_NAMES = {
    "Dockerfile", "Containerfile", "Makefile", "GNUmakefile", "Procfile", "Justfile", "justfile", "crontab",
    "Jenkinsfile", "Vagrantfile", "Rakefile", "Gemfile", "Brewfile", "Podfile", "Fastfile", "Appfile",
    "CMakeLists.txt", "BUILD", "BUILD.bazel", "WORKSPACE", "Tiltfile", "Earthfile", "go.mod", "cpanfile",
    "Taskfile.yml", "Caddyfile", "Procfile.dev", ".gitlab-ci.yml", ".travis.yml", ".pre-commit-config.yaml",
    "mix.exs", "config.exs", "routes.rb", "schedule.rb", "sidekiq.yml",
}
# Ruby/Elixir source files are also "artifacts" only when they are wiring files.
ARTIFACT_SOURCE_NAMES = {"Gemfile", "Rakefile", "Fastfile", "Appfile", "Podfile", "Brewfile", "Vagrantfile", "mix.exs", "config.exs", "routes.rb", "schedule.rb", "noxfile.py", "tasks.py", "fabfile.py", "setup.py", "conftest.py"}

CATEGORY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("scheduler", re.compile(r"(?i)(?:^|/)(?:crontab|cron\.d/|cron\.(?:daily|hourly|weekly)|schedule\.rb|sidekiq\.yml|beat|scheduler?\.|.*cron.*\.(?:ya?ml|json|txt)$|.*\.timer$|celerybeat)")),
    ("ci", re.compile(r"(?:^|/)(?:\.github/workflows/|\.gitlab-ci\.yml|\.circleci/|Jenkinsfile|azure-pipelines[^/]*\.ya?ml|bitbucket-pipelines\.yml|\.travis\.yml|buildkite/|\.buildkite/|Makefile|GNUmakefile|justfile|Justfile|tox\.ini|noxfile\.py|\.pre-commit-config\.yaml|Taskfile\.ya?ml|Rakefile|package\.json|Earthfile|Tiltfile|cloudbuild\.ya?ml|codemagic\.yaml|Fastfile|BUILD(?:\.bazel)?|WORKSPACE|CMakeLists\.txt|.*\.cmake|.*\.mk|.*\.bzl|build\.gradle(?:\.kts)?|.*\.sbt|pom\.xml|.*\.csproj|.*\.sln)$")),
    ("container", re.compile(r"(?i)(?:^|/)(?:Dockerfile[^/]*|Containerfile|.*\.dockerfile|docker-compose[^/]*\.ya?ml|compose[^/]*\.ya?ml|Procfile[^/]*|supervisord?\.conf|.*\.service|.*\.socket|ecosystem\.config\.js|pm2\.json|nodemon\.json|Caddyfile|nginx\.conf|uwsgi\.ini|gunicorn\.conf\.py)$")),
    ("serverless", re.compile(r"(?i)(?:^|/)(?:serverless[^/]*\.ya?ml|template\.ya?ml|samconfig\.toml|function\.json|host\.json|vercel\.json|netlify\.toml|firebase\.json|wrangler\.toml|app\.yaml|app\.yml|now\.json|fly\.toml|render\.yaml|railway\.json|zappa_settings\.json|chalice/config\.json|.*\.function\.json)$")),
    ("infra", re.compile(r"(?i)(?:^|/)(?:.*\.tf|.*\.tfvars|.*\.hcl|.*\.bicep|Pulumi[^/]*\.ya?ml|cdk\.json|Chart\.ya?ml|values[^/]*\.ya?ml|.*cloudformation.*|.*\.nix|kustomization\.ya?ml|skaffold\.ya?ml|helmfile\.ya?ml|ansible[^/]*\.ya?ml|playbook[^/]*\.ya?ml)$")),
    ("ide", re.compile(r"(?:^|/)(?:\.vscode/[^/]+\.json|\.idea/[^/]+\.xml|\.run/[^/]+\.xml|[^/]+\.code-workspace|\.devcontainer/[^/]+|launch\.json|tasks\.json)$")),
    ("script", re.compile(r"(?i)(?:^|/)(?:scripts?/[^/]+|bin/[^/]+|tools?/[^/]+|hooks?/[^/]+|.*\.(?:sh|bash|zsh|ps1|bat|cmd))$")),
    ("template", re.compile(r"(?i).*\.(?:html?|jinja2?|j2|tmpl|tpl|hbs|mustache|erb|haml|slim|twig|cshtml|razor|ejs|pug|njk|liquid|xaml|storyboard|xib)$")),
    ("docs", re.compile(r"(?i)(?:^|/)(?:README[^/]*|CHANGELOG[^/]*|CONTRIBUTING[^/]*|docs?/.*|.*\.(?:md|mdx|rst|adoc|ipynb))$")),
    ("package_manifest", re.compile(r"(?:^|/)(?:pyproject\.toml|setup\.cfg|setup\.py|package\.json|Cargo\.toml|go\.mod|Gemfile|[^/]+\.gemspec|composer\.json|Package\.swift|pubspec\.yaml|mix\.exs|pom\.xml|build\.gradle(?:\.kts)?|[^/]+\.csproj|cpanfile|deno\.json|bun\.toml)$")),
]
CONFIG_CATEGORIES = {"scheduler", "ci", "container", "serverless", "infra", "ide", "script", "package_manifest", "config"}
K8S_RE = re.compile(r"^\s*kind:\s*(?:CronJob|Job|Deployment|Pod|StatefulSet|DaemonSet)\b", re.MULTILINE)
SERVERLESS_HEAD_RE = re.compile(r"AWS::Serverless|AWS::Lambda|functions:\s*$|\"bindings\"|runtime:\s*(?:python|nodejs|go|java|dotnet|ruby)", re.MULTILINE)
SCHEDULE_LINE_RE = re.compile(
    r"(?i)\bcron\b|crontab|schedule[ds]?\b|@(?:daily|hourly|weekly|monthly|yearly|reboot)|\bevery\s+\d|\binterval\b|beat_schedule|OnCalendar|rate\(\d|CronJob|periodic|\btimer\b|\bnightly\b|\bat\s+\d{1,2}:\d{2}\b|^\s*(?:[\d*/,-]+\s+){4}[\d*/,-]+\s+\S"
)


@dataclass
class Evidence:
    where: str
    line: str
    category: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ArtifactIndex:
    """Token index over non-source repository files, with line-level lookup."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.files: dict[str, list[str]] = {}
        self.categories: dict[str, set[str]] = {}
        self.token_files: dict[str, set[str]] = {}
        self.tokens: set[str] = set()
        self.config_tokens: set[str] = set()
        self._build()

    def _build(self) -> None:
        count = 0
        for path in sorted(self.root.rglob("*")):
            if count >= MAX_ARTIFACT_FILES:
                break
            if not path.is_file() or path.is_symlink():
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            rel = path.relative_to(self.root).as_posix()
            if not self._is_artifact(path, rel):
                continue
            try:
                if path.stat().st_size > MAX_ARTIFACT_BYTES:
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            count += 1
            lines = text.splitlines()
            self.files[rel] = lines
            cats = self._categorize(rel, text[:4000])
            self.categories[rel] = cats
            is_config = bool(cats & CONFIG_CATEGORIES)
            seen: set[str] = set()
            for match in TOKEN_RE.findall(text):
                if match in seen:
                    continue
                seen.add(match)
                self.token_files.setdefault(match, set()).add(rel)
                self.tokens.add(match)
                if is_config:
                    self.config_tokens.add(match)
                if len(seen) > MAX_TOKENS_PER_FILE * 2:
                    break
            for match in WORD_RE.findall(text):
                if match in seen:
                    continue
                seen.add(match)
                self.token_files.setdefault(match, set()).add(rel)
                if len(seen) > MAX_TOKENS_PER_FILE * 3:
                    break

    @staticmethod
    def _is_artifact(path: Path, rel: str) -> bool:
        name = path.name
        if name in ARTIFACT_NAMES or name in ARTIFACT_SOURCE_NAMES:
            return True
        if name.startswith("Dockerfile") or name.startswith("Procfile") or name.startswith(".env"):
            return True
        if path.suffix in ARTIFACT_SUFFIXES:
            return True
        if path.suffix == "" and ("/bin/" in f"/{rel}" or "/scripts/" in f"/{rel}" or rel.startswith(("bin/", "scripts/", "hooks/", ".githooks/"))):
            return True
        return False

    @staticmethod
    def _categorize(rel: str, head: str) -> set[str]:
        cats: set[str] = set()
        for name, pattern in CATEGORY_RULES:
            if pattern.search(rel):
                cats.add(name)
        if K8S_RE.search(head):
            cats.add("container")
            if "CronJob" in head:
                cats.add("scheduler")
        if SERVERLESS_HEAD_RE.search(head) and rel.endswith((".yml", ".yaml", ".json", ".toml")):
            cats.add("serverless")
        if rel.startswith(".github/workflows/") and re.search(r"^\s*schedule:\s*$", head, re.MULTILINE):
            cats.add("scheduler")
        if "docs" in cats:
            # Rendered documentation is not a runtime template.
            cats.discard("template")
        if not cats:
            cats.add("config" if not rel.endswith((".md", ".rst", ".mdx", ".adoc")) else "docs")
        return cats

    def locate(
        self,
        needles: list[str],
        *,
        categories: set[str] | None = None,
        line_filter: re.Pattern[str] | None = None,
        limit: int = MAX_EVIDENCE,
    ) -> list[Evidence]:
        out: list[Evidence] = []
        seen: set[str] = set()
        for needle in needles:
            if len(needle) < 3:
                continue
            key = _last_word(needle)
            candidates = self.token_files.get(needle, set()) | self.token_files.get(key, set())
            pattern = _boundary_re(needle)
            for rel in sorted(candidates):
                cats = self.categories.get(rel, set())
                if categories is not None and not (cats & categories):
                    continue
                for lineno, line in enumerate(self.files.get(rel, []), start=1):
                    if not pattern.search(line):
                        continue
                    if line_filter is not None and not line_filter.search(line):
                        continue
                    where = f"{rel}:{lineno}"
                    if where in seen:
                        continue
                    seen.add(where)
                    out.append(Evidence(where=where, line=_snippet(line), category=_primary(cats)))
                    if len(out) >= limit:
                        return out
        return out


def _last_word(needle: str) -> str:
    words = WORD_RE.findall(needle)
    return words[-1] if words else needle


def _boundary_re(needle: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w]){re.escape(needle)}(?![\w])")


def _snippet(line: str, limit: int = 110) -> str:
    text = redact_text(line.strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _primary(cats: set[str]) -> str:
    for name in ("scheduler", "serverless", "container", "ci", "infra", "ide", "package_manifest", "script", "template", "docs", "config"):
        if name in cats:
            return name
    return "config"


# --------------------------------------------------------------------------- #
# Source-side lookups (reflection targets, barrels, test-only references)
# --------------------------------------------------------------------------- #


class SourceIndex:
    """Lazy word index over scanned source files (built only when a hypothesis needs it)."""

    def __init__(self, root: Path, rels: list[str], is_test: Callable[[str], bool]) -> None:
        self.root = root
        self.rels = rels[:MAX_SOURCE_INDEX_FILES]
        self.is_test = is_test
        self._built = False
        self.word_files: dict[str, set[str]] = {}
        self._lines: dict[str, list[str]] = {}

    def _build(self) -> None:
        if self._built:
            return
        self._built = True
        for rel in self.rels:
            text = _read(self.root / rel)
            if not text:
                continue
            seen: set[str] = set()
            for match in WORD_RE.findall(text):
                if match in seen:
                    continue
                seen.add(match)
                self.word_files.setdefault(match, set()).add(rel)
                if len(seen) > MAX_TOKENS_PER_FILE:
                    break

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            self._lines[rel] = _read(self.root / rel).splitlines()
        return self._lines[rel]

    def locate(self, word: str, *, exclude: str, line_filter: re.Pattern[str] | None = None, only_tests: bool | None = None, limit: int = MAX_EVIDENCE) -> list[Evidence]:
        self._build()
        out: list[Evidence] = []
        pattern = _boundary_re(word)
        for rel in sorted(self.word_files.get(word, set())):
            if rel == exclude:
                continue
            if only_tests is not None and self.is_test(rel) != only_tests:
                continue
            for lineno, line in enumerate(self.lines(rel), start=1):
                if not pattern.search(line):
                    continue
                if line_filter is not None and not line_filter.search(line):
                    continue
                out.append(Evidence(where=f"{rel}:{lineno}", line=_snippet(line), category="test" if self.is_test(rel) else "source"))
                if len(out) >= limit:
                    return out
        return out


# --------------------------------------------------------------------------- #
# Context shared by all hypotheses for one scan
# --------------------------------------------------------------------------- #


@dataclass
class Context:
    root: Path
    profile: Profile
    artifacts: ArtifactIndex
    sources: SourceIndex
    stems: Counter
    recent_files: set[str]
    library: str | None
    star_reexports: list[Evidence]
    parse_failures: int
    _texts: dict[str, str] = field(default_factory=dict)

    def text(self, rel: str) -> str:
        if rel not in self._texts:
            self._texts[rel] = _read(self.root / rel)
        return self._texts[rel]

    def lines(self, rel: str) -> list[str]:
        return self.text(rel).splitlines()


def build_context(
    root: Path,
    profile: Profile,
    source_rels: list[str],
    *,
    artifacts: ArtifactIndex | None = None,
    parse_failures: int = 0,
) -> Context:
    from unreach.langs import file_role

    root = Path(root).resolve()
    artifacts = artifacts or ArtifactIndex(root)
    sources = SourceIndex(root, source_rels, lambda rel: file_role(rel, profile) == "test")
    stems = Counter(_stem(rel) for rel in source_rels)
    return Context(
        root=root,
        profile=profile,
        artifacts=artifacts,
        sources=sources,
        stems=stems,
        recent_files=_git_recent(root),
        library=_library_manifest(root, artifacts),
        star_reexports=_star_reexports(root, source_rels),
        parse_failures=parse_failures,
    )


def _git_recent(root: Path) -> set[str]:
    if not any((p / ".git").exists() for p in (root, *root.parents)):
        return set()
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5, check=False)
        if top.returncode != 0:
            return set()
        toplevel = Path(top.stdout.strip()).resolve()
        log = subprocess.run(
            ["git", "-C", str(root), "log", f"--since={GIT_RECENT_DAYS}.days", "--diff-filter=A", "--name-only", "--pretty=format:", "--", "."],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return set()
    try:
        prefix = root.relative_to(toplevel).as_posix()
    except ValueError:
        return set()
    prefix = "" if prefix in {".", ""} else prefix + "/"
    files: set[str] = set()
    for line in log.stdout.splitlines():
        line = line.strip()
        if line and line.startswith(prefix):
            files.add(line[len(prefix):])
    return files


# (manifest, evidence the package is *published*, evidence it is an application instead)
LIBRARY_RULES = [
    ("pyproject.toml", re.compile(r"^\s*\[project\][\s\S]*?^\s*name\s*=", re.MULTILINE), re.compile(r"(?i)private\s*=\s*true|Private\s*::|package-mode\s*=\s*false", re.MULTILINE)),
    ("package.json", re.compile(r'"name"\s*:[\s\S]*"(?:main|module|exports|types|typings)"\s*:|"(?:main|module|exports|types|typings)"\s*:[\s\S]*"name"\s*:'), re.compile(r'"private"\s*:\s*true')),
    ("Cargo.toml", re.compile(r"^\s*\[lib\]|^\s*description\s*=[\s\S]*^\s*license(?:-file)?\s*=|^\s*license(?:-file)?\s*=[\s\S]*^\s*description\s*=", re.MULTILINE), re.compile(r"^\s*publish\s*=\s*false", re.MULTILINE)),
    ("composer.json", re.compile(r'"type"\s*:\s*"library"'), re.compile(r"$^")),
    ("Package.swift", re.compile(r"products:\s*\[[\s\S]*\.library\("), re.compile(r"$^")),
    ("pubspec.yaml", re.compile(r"^description:[\s\S]*^(?:homepage|repository):|^(?:homepage|repository):[\s\S]*^description:", re.MULTILINE), re.compile(r"^publish_to:\s*none|^\s*sdk:\s*flutter", re.MULTILINE)),
    ("mix.exs", re.compile(r"package:\s*package\(\)|package:\s*\["), re.compile(r"$^")),
    ("build.gradle", re.compile(r"maven-publish|publishing\s*\{"), re.compile(r"$^")),
    ("build.gradle.kts", re.compile(r"maven-publish|publishing\s*\{"), re.compile(r"$^")),
    ("pom.xml", re.compile(r"<distributionManagement>|maven-deploy-plugin|nexus-staging|<packaging>(?:jar|aar)</packaging>[\s\S]*<scm>"), re.compile(r"$^")),
]
# Orphan files are only reachable by external consumers in languages that include
# files by path/package automatically. Rust needs `mod x;`, C needs an include, etc.
LIBRARY_ORPHAN_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".go", ".dart", ".rb", ".php", ".ex", ".exs")


def _library_manifest(root: Path, artifacts: ArtifactIndex) -> str | None:
    for name, positive, negative in LIBRARY_RULES:
        lines = artifacts.files.get(name)
        if lines is None:
            continue
        text = "\n".join(lines)
        if positive.search(text) and not negative.search(text):
            return name
    for gemspec in root.glob("*.gemspec"):
        return gemspec.name
    return None


STAR_REEXPORT_RE = re.compile(r"^\s*export\s+\*\s+from\s+['\"]|^\s*from\s+[\w.]+\s+import\s+\*", re.MULTILINE)


def _star_reexports(root: Path, source_rels: list[str]) -> list[Evidence]:
    out: list[Evidence] = []
    for rel in source_rels[:MAX_SOURCE_INDEX_FILES]:
        if not rel.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs")):
            continue
        text = _read(root / rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if STAR_REEXPORT_RE.match(line):
                out.append(Evidence(where=f"{rel}:{lineno}", line=_snippet(line), category="source"))
                break
        if len(out) >= 6:
            break
    return out


# --------------------------------------------------------------------------- #
# Hypotheses (the devil's advocate)
# --------------------------------------------------------------------------- #


@dataclass
class Hypothesis:
    name: str
    strength: str  # strong | medium | weak | info
    penalty: float
    kinds: tuple[str, ...]
    note: str
    next_check: str
    check: Callable[["Finding", Context, "Needles"], list[Evidence]]


@dataclass
class Objection:
    hypothesis: str
    strength: str
    penalty: float
    note: str
    evidence: list[Evidence]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "strength": self.strength,
            "penalty": self.penalty,
            "note": self.note,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Needles:
    exact: list[str]
    words: list[str]
    module: str
    stem: str
    symbol: str | None

    @property
    def all(self) -> list[str]:
        return self.exact + self.words


GENERIC_NAMES = {
    "main", "run", "app", "index", "utils", "util", "helpers", "helper", "common", "core", "base", "types",
    "config", "settings", "constants", "models", "model", "views", "view", "test", "tests", "lib", "api",
    "handler", "handlers", "service", "services", "server", "client", "data", "misc", "tools", "setup",
    "init", "new", "get", "set", "load", "save", "start", "stop", "update", "create", "delete", "remove",
    "process", "execute", "call", "build", "make", "default", "value", "item", "items", "result", "status",
    "error", "errors", "logger", "log", "cache", "store", "state", "context", "manager", "factory",
}

ALL_KINDS = ("orphan_file", "unused_export", "unused_dep", "unreachable")
CODE_KINDS = ("orphan_file", "unused_export", "unreachable")
SYMBOL_KINDS = ("unused_export", "unreachable")

SCHEDULER_IN_FILE_RE = re.compile(
    r"@(?:\w+\.)?(?:scheduled_job|periodic_task|on_after_configure|repeat_every|cron|interval|scheduled)\b"
    r"|@Scheduled\b|@Cron\(|@Interval\(|@Timeout\(|@EnableScheduling|schedule\.every|cron\.schedule\(|node-cron|nodeCron"
    r"|BackgroundScheduler|BlockingScheduler|AsyncIOScheduler|IntervalTrigger|CronTrigger|beat_schedule|crontab\("
    r"|Sidekiq::Cron|sidekiq-cron|Sidekiq::Scheduler|whenever|every\s+\d+\.(?:minutes?|hours?|days?)|Quartz|JobBuilder|TriggerBuilder"
    r"|time\.NewTicker|cron\.New\(|robfig/cron|gocron|Hangfire|RecurringJob|IHostedService|BackgroundService|Timer\.periodic"
    r"|Task\.Delay|setInterval\(|@nestjs/schedule|Bull\.|BullMQ|Agenda\(|node-schedule|Oban\.|Quantum\.|:crontab|DispatchQueue\.main\.asyncAfter"
)
CLI_ARGS_IN_FILE_RE = re.compile(
    r"argparse|ArgumentParser|\bclick\.|@click|typer\.|sys\.argv|docopt|fire\.Fire|flag\.Parse\(|os\.Args|process\.argv|commander|yargs|meow\b|oclif"
    r"|clap::|structopt|OptionParser|Thor\b|cobra\.|urfave/cli|\bgetopt|\bgetopts\b|GetOpt|System\.CommandLine|CommandLineParser|args\[0\]|ArgParser\(|OptionParser\("
)
HANDLER_IN_FILE_RE = re.compile(
    r"def\s+(?:lambda_)?handler\s*\(\s*event\s*,\s*context|exports\.handler\s*=|export\s+(?:const|async function|function)\s+handler\b|func\s+Handler\("
    r"|functions_framework|@functions\.|azure\.functions|func\.HttpRequest|APIGatewayProxy|lambda\.Start\(|lambda_handler|context\.Context,\s*\w+\s+events\."
    r"|HttpTrigger|\[FunctionName\(|@app\.function_name|Handler<|RequestHandler<|firebase-functions|onRequest\(|onCall\(|onSchedule\(|export\s+default\s+\{\s*(?:async\s+)?fetch"
)
REGISTRY_IN_FILE_RE = re.compile(
    r"__init_subclass__|\bregistry\[|REGISTRY\b|\bregister\(|@register\b|pkg_resources|entry_points\(|importlib\.metadata|@hookimpl|pluggy"
    r"|ServiceLoader|META-INF/services|\[Export\(|@AutoService|@Plugin\b|@Extension\b|addPlugin|registerPlugin|plugins\.push|\.use\(\w+Plugin|@Component\b|@Service\b|@Repository\b|@Bean\b|@Injectable\b|@Controller\b|services\.Add(?:Scoped|Singleton|Transient)|\bdefine_method|inherited\(|Rails::Engine|Rails::Railtie|@impl\b|use\s+GenServer|Behaviour"
)
FLAG_IN_FILE_RE = re.compile(
    r"(?i)feature[_-]?flags?|is_enabled\(|flags?\.(?:is_)?(?:enabled|active|on)\b|launchdarkly|ldclient|unleash|split\.io|flagsmith|growthbook|optimizely|waffle\.|posthog\.isFeatureEnabled|isFeatureEnabled|useFeatureFlag|useFlag\("
    r"|\bFEATURE_[A-Z_]+|\bENABLE_[A-Z_]+|settings\.(?:ENABLE|FEATURE)|process\.env\.(?:FEATURE|ENABLE)|(?:environ|getenv|ENV)\W{1,4}(?:FEATURE|ENABLE)|#if\s+FEATURE|cfg\(feature|remoteConfig|RemoteConfig|experiment(?:s)?\.(?:is_)?(?:enabled|active|variant)|\bkill[_-]?switch"
)
PLATFORM_IN_FILE_RE = re.compile(
    r"sys\.platform|os\.name\s*==|platform\.system\(\)|platform\.machine\(\)|#\[cfg\(|//\s*\+build|//go:build|#if\s+(?:defined\(|os\(|TARGET_|_WIN32|__APPLE__|__linux__|__ANDROID__|__EMSCRIPTEN__|DEBUG\b)|#ifdef\s|Platform\.is\w+|kIsWeb|defaultTargetPlatform|@available\(|process\.platform|navigator\.(?:userAgent|platform)|@unittest\.skipIf|@pytest\.mark\.skipif|RuntimeInformation\.IsOSPlatform|Environment\.OSVersion|System\.getProperty\(\"os\.name|Build\.VERSION\.SDK_INT|@TargetApi|@RequiresApi|if\s+\(?\s*(?:IS_)?(?:DEBUG|__DEV__|import\.meta\.env\.DEV|process\.env\.NODE_ENV)"
)
PLATFORM_FILENAME_RE = re.compile(r"[_.](?:windows|win32|win|linux|darwin|macos|unix|posix|android|ios|web|wasm|wasi|arm64|amd64|x86|freebsd|js|native|desktop|mobile|debug|release|dev|prod|staging)\.(?:go|py|rs|dart|swift|c|cc|cpp|h|hpp|kt|ts|tsx|js|jsx|cs|rb|ex|lua|pl)$")
GENERATED_RE = re.compile(r"(?i)code generated|do not edit|autogenerated|auto-generated|generated by|@generated|<auto-generated|automatically generated|this file was generated|generated file")
GENERATED_PATH_RE = re.compile(r"(?i)(?:_pb2(?:_grpc)?\.py|\.pb\.(?:go|cc|h|dart|swift|rs)|\.g\.(?:dart|cs|kt|swift)|\.freezed\.dart|\.gr\.dart|\.designer\.cs|\.generated\.(?:ts|js|cs|go|swift|kt)|\.gen\.(?:go|ts|js)|_gen\.go|_generated\.(?:go|py|ts)|\.d\.ts|Generated|(?:^|/)(?:generated|gen|__generated__|codegen|_generated|autogen)/|(?:^|/)migrations/\d)")
MIGRATION_PATH_RE = re.compile(r"(?i)(?:^|/)(?:migrations?|migrate|alembic|versions|seeds?|seeders?|fixtures|schema|db/migrate|flyway|liquibase|changelogs?)/|(?:^|/)(?:\d{3,}_|V\d+__|\d{14}_|R__)\w+\.\w+$|(?:^|/)(?:schema|structure)\.(?:rb|sql|prisma|graphql)$")
SUBSCRIBER_IN_FILE_RE = re.compile(
    r"\.connect\(\s*\w|@receiver\b|\.subscribe\(|@subscribe\b|@Subscribe\b|emitter\.on\(|bus\.on\(|\.addEventListener\(|EventEmitter|@KafkaListener|@RabbitListener|@EventListener|@SqsListener|@JmsListener|@StreamListener|@ServiceActivator|@MessageMapping|@Consumer\b|KafkaConsumer|consumer\.subscribe|pubsub\.subscribe|\.listen\(\s*['\"]|@socketio\.on|@sio\.(?:on|event)|@bot\.(?:event|command|listen)|@client\.event|@commands\.command|@dp\.message|@app\.on_event|@event\.listens_for|post_save\.connect|pre_save\.connect|signal\.signal\(|Signal\(\)|NotificationCenter|@IBAction|@objc\s+func|addObserver|EventBus|@Listener\b|@OnEvent\b|@EventPattern\b|@MessagePattern\b|handle_info\(|handle_cast\(|handle_call\(|Phoenix\.PubSub|@app\.post_load|@app\.before_first_request|on_message|on_ready|on_startup|on_shutdown"
)
KEEP_MARKER_RE = re.compile(r"unreach:\s*(?:keep|ignore)|unreach-(?:keep|ignore)|noqa:\s*unreach|@unreach-keep")
DEPRECATION_RE = re.compile(r"(?i)@deprecated\b|\bdeprecated\b|#\[deprecated|\[Obsolete|@Deprecated|warnings\.warn\([^)]*Deprecat|DeprecationWarning|\bsunset\b|remove(?:d)? in v?\d|removal[_ ]date|end[_ -]of[_ -]life|EOL\b")
WIP_RE = re.compile(r"(?i)\bWIP\b|work in progress|not (?:yet )?(?:used|wired|hooked up|connected|implemented|enabled)|coming soon|phase\s*[2-9]|TODO:?\s*(?:wire|hook|connect|enable|use|integrate|call)|FIXME:?\s*(?:wire|hook|connect|enable)|placeholder|stub(?:bed)?\b|experimental|behind (?:a )?flag|next (?:release|sprint|milestone)|under (?:construction|development)")
SHEBANG_RE = re.compile(r"\A#!")
CONVENTION_SYMBOL_RE = re.compile(
    r"^(?:on_|handle_|do_|visit_|resolve_|test_|pytest_|before_|after_|pre_|post_|upgrade$|downgrade$|migrate$|bootstrap$|provide$|configure$|register$|install$|uninstall$|activate$|deactivate$|setup$|teardown$|setUp|tearDown|run$|main$|handler$|callback$|hook$|middleware$|lambda_handler$|application$|urlpatterns$|default_app_config$|celery$|dag$|DAG$|schema$|Meta$|Config$|up$|down$|boot$|load$|init$|plugin$)"
    r"|(?:Command|Migration|Job|Worker|Task|Listener|Handler|Controller|Middleware|Filter|Interceptor|Provider|Module|Serializer|ViewSet|Resolver|Subscriber|Consumer|Processor|Extension|Loader|Plugin|Service|Repository|Guard|Pipe|Resource|Mailer|Seeder|Operator|Sensor|Bean|Configuration|Validator|Policy|Cog|Skill|Hook)$"
)
FRAMEWORK_CONVENTION_EXPORTS = {
    "getServerSideProps", "getStaticProps", "getStaticPaths", "getInitialProps", "generateMetadata", "generateStaticParams",
    "generateViewport", "generateSitemaps", "metadata", "viewport", "dynamic", "dynamicParams", "revalidate", "fetchCache",
    "runtime", "preferredRegion", "maxDuration", "loader", "clientLoader", "action", "clientAction", "meta", "links", "headers",
    "handle", "shouldRevalidate", "ErrorBoundary", "HydrateFallback", "load", "prerender", "ssr", "csr", "trailingSlash",
    "entries", "config", "middleware", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "default", "setup",
    "teardown", "up", "down", "register", "activate", "deactivate", "main", "run", "handler", "lambda_handler",
    "urlpatterns", "application", "app", "api", "router", "schema", "resolvers", "typeDefs", "DAG", "dag", "Meta",
    "Config", "plugin", "default_app_config", "install", "uninstall", "boot", "provides", "registerHooks", "onLoad",
    "onUnload", "onEnable", "onDisable", "onCreate", "onDestroy", "onStart", "onStop", "pytest_configure",
    "pytest_addoption", "pytest_collection_modifyitems", "pytest_plugins", "pytest_sessionstart", "conftest",
    "setUpModule", "tearDownModule", "setUpClass", "tearDownClass", "setUp", "tearDown", "loadTests", "load_tests",
    "describe", "it", "test", "bench", "fuzz", "benchmark", "init", "New", "Main", "Startup", "Program", "Application",
}
CONTRACT_DEF_RE_TEMPLATE = (
    r"export\s+(?:declare\s+)?(?:type|interface|enum|abstract\s+class)\s+{sym}\b"
    r"|class\s+{sym}\s*\([^)]*\b(?:Protocol|TypedDict|ABC|ABCMeta|Enum|IntEnum|StrEnum|Flag|NamedTuple|Generic|BaseModel|TypedDict|Interface)\b[^)]*\)"
    r"|(?:pub\s+)?trait\s+{sym}\b|protocol\s+{sym}\b|(?:public\s+)?interface\s+{sym}\b|abstract\s+class\s+{sym}\b|typedef\s+.*\b{sym}\s*;|struct\s+{sym}\b|enum\s+{sym}\b|type\s+{sym}\s+interface\b|@runtime_checkable\s*\n\s*class\s+{sym}\b"
)
REFLECTION_LINE_RE = re.compile(
    r"importlib|__import__|import_module|\bgetattr\(|globals\(\)\[|locals\(\)\[|pkgutil|\bimport\(|\brequire\(|Class\.forName|getMethod\(|getDeclaredMethod|Type\.GetType|Activator\.|Assembly\.Load|reflect\.|const_get|constantize|\bsend\(\s*:|public_send|\bmethod\(\s*:|\bnew Function\(|String\.to_(?:existing_)?atom|Module\.concat|Kernel\.apply|apply\(\s*[A-Z]|dlopen|dlsym|GetProcAddress|NSClassFromString|NSSelectorFromString|#selector|loadClass|newInstance|CreateInstance|\bregistry\b|REGISTRY|HANDLERS|COMMANDS|ROUTES|TASKS|JOBS|PLUGINS|handlers?\s*\[|commands?\s*\[|routes?\s*\[|\.get\(\s*['\"]\w+['\"]\s*\)\s*\("
)
TEMPLATE_HINT_RE = re.compile(r"\{\{|\{%|<%|v-|@click|hx-|x-data|x-on|ng-|\(click\)|on\w+=|th:|asp-|@Html|@model|render|include|extends|load\s+\w+|url\s+['\"]|\|\s*\w+")
SIDE_EFFECT_IMPORT_RE_TEMPLATE = r"^\s*import\s+['\"][^'\"]*{stem}(?:\.\w+)?['\"]|require\(\s*['\"][^'\"]*{stem}(?:\.\w+)?['\"]\s*\)\s*;?\s*$|importlib\.import_module\(\s*['\"][\w.]*{stem}['\"]"


def _needles(finding: "Finding") -> Needles:
    path = finding.path
    stem = _stem(path)
    module = _module_for(path)
    exact: list[str] = []
    words: list[str] = []
    if finding.kind == "orphan_file":
        exact.extend([path, path.rsplit(".", 1)[0] if "." in path.rsplit("/", 1)[-1] else path, module])
        if len(stem) >= 4 and stem.lower() not in GENERIC_NAMES:
            words.append(stem)
    elif finding.kind in SYMBOL_KINDS and finding.symbol:
        sym = finding.symbol
        exact.extend([f"{module}:{sym}", f"{module}.{sym}", f"{path}::{sym}", f"{stem}.{sym}", f"{stem}::{sym}", f"{stem}#{sym}"])
        if len(sym) >= 3 and sym.lower() not in GENERIC_NAMES:
            words.append(sym)
    elif finding.kind == "unused_dep" and finding.symbol:
        words.append(finding.symbol)
    exact = [n for n in dict.fromkeys(exact) if n and len(n) >= 3]
    return Needles(exact=exact, words=words, module=module, stem=stem, symbol=finding.symbol)


def _in_file(ctx: Context, rel: str, pattern: re.Pattern[str], *, category: str = "source", limit: int = MAX_EVIDENCE, head: int | None = None) -> list[Evidence]:
    out: list[Evidence] = []
    for lineno, line in enumerate(ctx.lines(rel), start=1):
        if head is not None and lineno > head:
            break
        if pattern.search(line):
            out.append(Evidence(where=f"{rel}:{lineno}", line=_snippet(line), category=category))
            if len(out) >= limit:
                break
    return out


def _near_symbol(ctx: Context, finding: "Finding", pattern: re.Pattern[str], *, radius: int = 3) -> list[Evidence]:
    """Match ``pattern`` within ``radius`` lines of the symbol's definition (or anywhere for files)."""
    lines = ctx.lines(finding.path)
    if not finding.symbol:
        return _in_file(ctx, finding.path, pattern)
    def_re = re.compile(rf"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:pub(?:\(crate\))?\s+)?(?:public\s+|private\s+|protected\s+|static\s+|final\s+|abstract\s+|open\s+|internal\s+)*(?:def|class|function|fn|func|struct|enum|trait|interface|type|const|let|var|val|module|object|record|protocol|extension|defmodule|sub|local\s+function)?\s*\b{re.escape(finding.symbol)}\b")
    out: list[Evidence] = []
    for lineno, line in enumerate(lines, start=1):
        if not def_re.search(line):
            continue
        lo, hi = max(1, lineno - radius), min(len(lines), lineno + radius)
        for n in range(lo, hi + 1):
            if pattern.search(lines[n - 1]):
                out.append(Evidence(where=f"{finding.path}:{n}", line=_snippet(lines[n - 1]), category="source"))
        break
    return out[:MAX_EVIDENCE]


# ---- checks ---------------------------------------------------------------- #


def _chk_scheduled_job(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    hits = ctx.artifacts.locate(n.all, categories={"scheduler"})
    if hits:
        return hits
    return ctx.artifacts.locate(n.all, categories={"ci", "container", "config", "infra", "serverless", "script"}, line_filter=SCHEDULE_LINE_RE)


def _chk_scheduler_registration(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return _in_file(ctx, f.path, SCHEDULER_IN_FILE_RE)


def _chk_cli_entry(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    invoke = re.compile(r"(?i)\b(?:python3?|py|node|deno|bun|ruby|go\s+run|java|dotnet|php|perl|lua|dart|swift|mix|elixir|bundle\s+exec|cargo\s+run|npx|pnpm|yarn|npm\s+run|exec|sh|bash|zsh|-m)\b|console_scripts|entry.?points|\"bin\"|^\s*bin\s*=|scripts\s*[:=]|\[project\.scripts\]|\[tool\.poetry\.scripts\]|^\s*\w[\w-]*\s*=\s*['\"][\w.]+:\w+['\"]")
    hits = ctx.artifacts.locate(n.all, categories={"script", "package_manifest", "ci", "container", "config"}, line_filter=invoke)
    return hits


def _chk_container_entry(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"container"})


def _chk_serverless(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"serverless"})


def _chk_handler_signature(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return _in_file(ctx, f.path, HANDLER_IN_FILE_RE)


def _chk_ci(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"ci"})


def _chk_infra(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"infra"})


def _chk_ide(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"ide"})


def _chk_plugin_entry_point(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    line_filter = re.compile(r"(?i)entry.?points|plugins?|pytest11|providers|extensions|hooks?|contributes|activationEvents|\"main\"|\"exports\"|\"module\"|\"types\"|^\s*\[project\.(?:scripts|gui-scripts|entry-points)")
    return ctx.artifacts.locate(n.all, categories={"package_manifest", "config"}, line_filter=line_filter)


def _chk_registry_pattern(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return _in_file(ctx, f.path, REGISTRY_IN_FILE_RE)


def _chk_dynamic_loading(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    out: list[Evidence] = []
    for word in n.words + [n.stem] if f.kind == "orphan_file" else n.words:
        if len(word) < 3 or word.lower() in GENERIC_NAMES:
            continue
        out.extend(ctx.sources.locate(word, exclude=f.path, line_filter=REFLECTION_LINE_RE, only_tests=False))
        if len(out) >= MAX_EVIDENCE:
            break
    return out[:MAX_EVIDENCE]


def _chk_side_effect_import(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind != "orphan_file" or len(n.stem) < 3:
        return []
    pattern = re.compile(SIDE_EFFECT_IMPORT_RE_TEMPLATE.format(stem=re.escape(n.stem)))
    return ctx.sources.locate(n.stem, exclude=f.path, line_filter=pattern)


def _chk_template(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"template"})


def _chk_docs(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return ctx.artifacts.locate(n.all, categories={"docs"}, limit=2)


def _chk_public_library(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if not ctx.library or f.kind not in {"orphan_file", "unused_export"}:
        return []
    if f.kind == "orphan_file" and not f.path.endswith(LIBRARY_ORPHAN_SUFFIXES):
        return []
    depth = f.path.count("/")
    top_level = depth <= 2 or f.path.endswith(("__init__.py", "index.ts", "index.js", "lib.rs", "mod.rs", "index.d.ts"))
    in_all = "listed_in_dunder_all_public_api" in f.signals
    if not (top_level or in_all):
        return []
    lines = ctx.artifacts.files.get(ctx.library, [])
    for lineno, line in enumerate(lines, start=1):
        if re.search(r'^\s*(?:name\s*=|"name"\s*:|\[package\]|\[project\]|s\.name|name:)', line):
            return [Evidence(where=f"{ctx.library}:{lineno}", line=_snippet(line), category="package_manifest")]
    return [Evidence(where=f"{ctx.library}:1", line=_snippet(lines[0] if lines else ctx.library), category="package_manifest")]


def _chk_feature_flag(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    return _in_file(ctx, f.path, FLAG_IN_FILE_RE)


def _chk_platform(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    out: list[Evidence] = []
    if PLATFORM_FILENAME_RE.search(f.path):
        out.append(Evidence(where=f"{f.path}:0", line=f"filename suffix suggests a platform/build variant: {f.path.rsplit('/', 1)[-1]}", category="source"))
    out.extend(_in_file(ctx, f.path, PLATFORM_IN_FILE_RE, limit=MAX_EVIDENCE - len(out)))
    return out


def _chk_generated(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    out: list[Evidence] = []
    if GENERATED_PATH_RE.search(f.path):
        out.append(Evidence(where=f"{f.path}:0", line="path matches a code-generation naming convention", category="source"))
    out.extend(_in_file(ctx, f.path, GENERATED_RE, head=25, limit=2))
    return out


def _chk_migration(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        return []
    if MIGRATION_PATH_RE.search(f.path):
        return [Evidence(where=f"{f.path}:0", line="path matches a migration/seed/schema convention loaded by tooling", category="source")]
    return []


def _chk_convention(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind not in SYMBOL_KINDS or not f.symbol:
        return []
    sym = f.symbol
    if sym in FRAMEWORK_CONVENTION_EXPORTS or CONVENTION_SYMBOL_RE.search(sym) or re.fullmatch(r"__\w+__", sym):
        return [Evidence(where=f"{f.path}:0", line=f"`{sym}` matches a convention-dispatched name (framework/tool looks it up by name)", category="source")]
    return []


def _chk_subscriber(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        return []
    return _in_file(ctx, f.path, SUBSCRIBER_IN_FILE_RE)


def _chk_contract(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind not in SYMBOL_KINDS or not f.symbol:
        return []
    pattern = re.compile(CONTRACT_DEF_RE_TEMPLATE.format(sym=re.escape(f.symbol)))
    return _in_file(ctx, f.path, pattern, limit=1)


def _chk_barrel(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind not in SYMBOL_KINDS or not ctx.star_reexports:
        return []
    stem = re.escape(n.stem)
    pattern = re.compile(rf"export\s+\*\s+from\s+['\"][^'\"]*\b{stem}(?:\.\w+)?['\"]|from\s+[\w.]*\b{stem}\s+import\s+\*")
    out: list[Evidence] = []
    for ev in ctx.star_reexports:
        rel = ev.where.rsplit(":", 1)[0]
        for lineno, line in enumerate(ctx.lines(rel), start=1):
            if pattern.search(line):
                out.append(Evidence(where=f"{rel}:{lineno}", line=_snippet(line), category="source"))
                break
    return out[:MAX_EVIDENCE]


def _chk_keep_marker(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        lines = ctx.lines(f.path)
        for lineno, line in enumerate(lines, start=1):
            if f.symbol and f.symbol in line and KEEP_MARKER_RE.search(line):
                return [Evidence(where=f"{f.path}:{lineno}", line=_snippet(line), category="source")]
        return []
    if f.symbol:
        return _near_symbol(ctx, f, KEEP_MARKER_RE, radius=2)
    return _in_file(ctx, f.path, KEEP_MARKER_RE, limit=1)


def _chk_deprecation(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        return []
    if f.symbol:
        return _near_symbol(ctx, f, DEPRECATION_RE, radius=4)
    return _in_file(ctx, f.path, DEPRECATION_RE, head=40, limit=2)


def _chk_wip_marker(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        return []
    if f.symbol:
        return _near_symbol(ctx, f, WIP_RE, radius=6)
    return _in_file(ctx, f.path, WIP_RE, limit=2)


def _chk_recent_git(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.path in ctx.recent_files:
        return [Evidence(where=f"{f.path}:0", line=f"added within the last {GIT_RECENT_DAYS} days (git log --diff-filter=A)", category="git")]
    return []


def _chk_shebang(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind != "orphan_file":
        return []
    text = ctx.text(f.path)
    if SHEBANG_RE.match(text):
        return [Evidence(where=f"{f.path}:1", line=_snippet(text.splitlines()[0]), category="source")]
    return []


def _chk_cli_args(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind != "orphan_file":
        return []
    return _in_file(ctx, f.path, CLI_ARGS_IN_FILE_RE, limit=2)


def _chk_test_only(f: "Finding", ctx: Context, n: Needles) -> list[Evidence]:
    if f.kind == "unused_dep":
        return []
    out: list[Evidence] = []
    for word in n.words or ([n.stem] if len(n.stem) >= 4 and n.stem.lower() not in GENERIC_NAMES else []):
        out.extend(ctx.sources.locate(word, exclude=f.path, only_tests=True, limit=2))
    return out[:2]


HYPOTHESES: list[Hypothesis] = [
    Hypothesis("explicit_keep_marker", "strong", 0.70, ALL_KINDS,
               "An `unreach: keep` / `unreach-ignore` marker sits on or next to the target.",
               "Honor the marker: record `keep` with unreach.remember and move on.", _chk_keep_marker),
    Hypothesis("scheduled_job", "strong", 0.50, CODE_KINDS,
               "Named in a scheduler artifact (crontab, celery beat, k8s CronJob, workflow `schedule:`, systemd timer).",
               "Open {where}. If the schedule is active in production this is a live job: remember `keep`. If the schedule is disabled, remove the schedule entry and the code in the same patch.", _chk_scheduled_job),
    Hypothesis("container_or_process_entry", "strong", 0.50, CODE_KINDS,
               "Named by a Dockerfile CMD/ENTRYPOINT, Procfile, compose/k8s command, or a systemd/supervisor unit.",
               "Open {where} and confirm whether that process definition is still deployed.", _chk_container_entry),
    Hypothesis("serverless_handler", "strong", 0.50, CODE_KINDS,
               "Named as a function handler in a serverless/SAM/Azure/Cloud Functions manifest.",
               "Open {where}; the platform invokes this by handler string, not by import.", _chk_serverless),
    Hypothesis("cli_entry_point", "strong", 0.50, CODE_KINDS,
               "Invoked from a shell script, `console_scripts`, package `bin`, or `python -m` in CI/containers.",
               "Open {where} and check whether that script/command is still run anywhere.", _chk_cli_entry),
    Hypothesis("plugin_or_entry_point_group", "strong", 0.50, CODE_KINDS,
               "Registered through an entry-point group or plugin manifest; the host discovers it by name.",
               "Open {where}; if the plugin group is consumed (pkg_resources/importlib.metadata/ServiceLoader), the code is live.", _chk_plugin_entry_point),
    Hypothesis("ci_or_build_invocation", "strong", 0.45, ALL_KINDS,
               "Named in a CI workflow, Makefile, tox/nox, pre-commit, or package.json script.",
               "Open {where}. Build and CI steps run code the import graph never sees.", _chk_ci),
    Hypothesis("infrastructure_manifest", "strong", 0.45, CODE_KINDS,
               "Referenced from Terraform/CloudFormation/Helm/Pulumi/ansible definitions.",
               "Open {where}; infrastructure may package or invoke this path at deploy time.", _chk_infra),
    Hypothesis("dynamic_loading_or_reflection", "medium", 0.35, CODE_KINDS,
               "The name appears next to a reflection/dynamic-import API in another source file.",
               "Read {where}: if the string reaches importlib/getattr/Class.forName/require, the target is loaded at runtime.", _chk_dynamic_loading),
    Hypothesis("side_effect_import", "medium", 0.35, CODE_KINDS,
               "Another file imports this module for its side effects only (no bound names).",
               "Read {where}; a bare `import 'x'` executes the module even though nothing is imported from it.", _chk_side_effect_import),
    Hypothesis("template_reference", "medium", 0.35, CODE_KINDS,
               "Referenced from an HTML/Jinja/ERB/Blade/Razor/XAML template (template tags, filters, event handlers, selectors).",
               "Open {where}; templates call code by name at render time.", _chk_template),
    Hypothesis("scheduler_registration_in_file", "medium", 0.35, CODE_KINDS,
               "The file registers a periodic/scheduled task with a scheduler API.",
               "Check how the scheduler discovers tasks ({where}); autodiscovery loads modules without imports.", _chk_scheduler_registration),
    Hypothesis("event_or_signal_subscriber", "medium", 0.30, CODE_KINDS,
               "The file subscribes handlers to signals, events, queues, or sockets.",
               "Confirm how the subscriber module gets loaded ({where}); registration at import time needs an importer or autodiscovery.", _chk_subscriber),
    Hypothesis("registry_pattern_in_file", "medium", 0.30, CODE_KINDS,
               "The file uses a registry/plugin/DI pattern (`register(...)`, `__init_subclass__`, `@Component`, `ServiceLoader`).",
               "Check the registry consumer ({where}); DI containers and registries resolve by name/class, not import.", _chk_registry_pattern),
    Hypothesis("serverless_handler_signature", "medium", 0.30, CODE_KINDS,
               "The file defines a cloud-function style handler (event, context) or exports `handler`.",
               "Look for a deployment manifest that points here ({where}); handlers are invoked by string.", _chk_handler_signature),
    Hypothesis("ide_or_runner_config", "medium", 0.30, CODE_KINDS,
               "Referenced from an IDE launch/run configuration or devcontainer.",
               "Open {where}; developers may run this directly even though nothing imports it.", _chk_ide),
    Hypothesis("public_library_surface", "medium", 0.30, ("orphan_file", "unused_export"),
               "The repository publishes a package; external consumers the graph cannot see may import this.",
               "Treat as public API: check the changelog/consumers before removal, or deprecate first ({where}).", _chk_public_library),
    Hypothesis("convention_dispatched_name", "medium", 0.30, SYMBOL_KINDS,
               "The name matches a convention a framework or tool resolves at runtime (`clean_<field>`, `getServerSideProps`, `*Command`).",
               "Check whether the framework in this repo dispatches on this name before removing it.", _chk_convention),
    Hypothesis("feature_flag_or_env_gate", "medium", 0.30, CODE_KINDS,
               "The file is gated by a feature flag, kill switch, or environment toggle — dormant is not dead.",
               "Read {where}; if the flag can still be turned on, the code is a live path.", _chk_feature_flag),
    Hypothesis("platform_or_build_conditional", "medium", 0.30, CODE_KINDS,
               "The file is platform-specific or behind conditional compilation (`#[cfg]`, `//go:build`, `sys.platform`).",
               "Confirm the target platform/build tag is still shipped ({where}).", _chk_platform),
    Hypothesis("migration_or_data_script", "medium", 0.30, CODE_KINDS,
               "Path follows a migration/seed/schema convention that tooling loads by directory scan.",
               "Never delete applied migrations; confirm the tool's discovery rule for {where}.", _chk_migration),
    Hypothesis("generated_code", "medium", 0.25, CODE_KINDS,
               "The file is generated; deleting it is undone by the next generation run.",
               "Remove the generator input (proto/schema/template) instead of the output ({where}).", _chk_generated),
    Hypothesis("type_or_contract_definition", "medium", 0.25, SYMBOL_KINDS,
               "The symbol is a type, interface, protocol, trait, or enum — consumed structurally or via type-only imports.",
               "Search for `import type`, structural use, or serialized names before removing ({where}).", _chk_contract),
    Hypothesis("barrel_star_reexport", "medium", 0.25, SYMBOL_KINDS,
               "A barrel file re-exports this module with `export *` / `import *`, hiding named use.",
               "Grep the barrel's consumers for `{symbol}` ({where}).", _chk_barrel),
    Hypothesis("executable_script_shebang", "weak", 0.20, ("orphan_file",),
               "The file starts with a shebang; it is meant to be executed, not imported.",
               "Check scripts/CI/docs for direct invocation of `{path}`.", _chk_shebang),
    Hypothesis("parses_command_line_arguments", "weak", 0.20, ("orphan_file",),
               "The file parses argv; it is likely a tool run by hand or by automation.",
               "Search runbooks, Makefiles, and CI for `{stem}` before removing.", _chk_cli_args),
    Hypothesis("deprecation_window", "weak", 0.15, CODE_KINDS,
               "Marked deprecated/obsolete: kept deliberately for compatibility during a removal window.",
               "Check the announced removal version/date at {where}; remove only when the window has closed.", _chk_deprecation),
    Hypothesis("test_only_reference", "weak", 0.15, CODE_KINDS,
               "Referenced from tests only; not dead in the graph sense but has no production caller.",
               "Decide with the owner: move into test helpers, or delete the tests along with it ({where}).", _chk_test_only),
    Hypothesis("work_in_progress_marker", "info", 0.0, CODE_KINDS,
               "WIP/TODO/placeholder comments suggest not-yet-wired code rather than abandoned code.",
               "Ask the author before removing ({where}).", _chk_wip_marker),
    Hypothesis("recently_added_in_git", "info", 0.0, CODE_KINDS,
               "Added recently; may simply not be wired up yet.",
               "Confirm with the author or the open PR before proposing deletion.", _chk_recent_git),
    Hypothesis("documentation_reference", "info", 0.0, ALL_KINDS,
               "Mentioned in README/docs/notebooks; removal must update the documentation too.",
               "Update {where} in the same patch.", _chk_docs),
]

# --------------------------------------------------------------------------- #
# Identification check: is the finding pointing at the right thing?
# --------------------------------------------------------------------------- #


def _identification(finding: "Finding", ctx: Context, n: Needles) -> list[Objection]:
    out: list[Objection] = []
    name = finding.symbol or n.stem
    name_precision = any(k.endswith(("_name_reference_graph", "_token_match_heuristic")) for k in finding.signals)
    if name and (len(name) <= 3 or name.lower() in GENERIC_NAMES):
        out.append(Objection("generic_name", "medium", 0.15 if name_precision else 0.08,
                             f"`{name}` is short or generic; token/grep evidence for it is unreliable.", []))
    if finding.kind == "orphan_file" and ctx.stems.get(n.stem, 0) > 1:
        out.append(Objection("stem_collision", "weak", 0.10,
                             f"{ctx.stems[n.stem]} source files share the stem `{n.stem}`; references may target a different file.", []))
    if finding.kind in SYMBOL_KINDS and ctx.star_reexports:
        out.append(Objection("star_reexports_present", "weak", 0.10,
                             "The repository uses `export *` / `import *`; named-use tracking is incomplete.", ctx.star_reexports[:2]))
    if ctx.parse_failures:
        out.append(Objection("graph_incomplete_parse_failures", "weak", 0.10,
                             f"{ctx.parse_failures} source file(s) failed to parse; their imports are missing from the graph.", []))
    if ctx.profile.monorepo and _lang_of(finding.path) == "ts":
        out.append(Objection("unresolved_workspace_imports", "weak", 0.10,
                             "Monorepo: `@scope/pkg` workspace imports are not resolved to files by the TS graph.", []))
    if name_precision:
        out.append(Objection("name_precision_graph", "info", 0.0,
                             "This language uses a name-precision reference graph; confidence is already capped below `block`.", []))
    return out


# --------------------------------------------------------------------------- #
# Security lens
# --------------------------------------------------------------------------- #

SECURITY_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("code_execution", re.compile(r"(?<![\w.])eval\(|(?<![\w.])exec\(|new Function\(|Runtime\.getRuntime\(\)\.exec|Process\.Start\(|child_process|os\.system\(|shell\s*=\s*True|(?<![\w.])popen\(|(?<![\w.])system\(|Kernel\.exec|instance_eval|class_eval|\bsend\(\s*params|os\.popen\(|subprocess\.getoutput|ProcessBuilder\(")),
    ("unsafe_deserialization", re.compile(r"pickle\.loads?\(|cPickle|yaml\.load\((?![^)]*Safe)|yaml\.unsafe_load|marshal\.loads?|\bshelve\.|ObjectInputStream|BinaryFormatter|\bunserialize\(|Marshal\.load|YAML\.load\b(?!_file)|jsonpickle|\bdill\.|SoapFormatter|NetDataContractSerializer|XmlDecoder|readObject\(")),
    ("sql_string_building", re.compile(r"(?:execute|executemany|query|raw|cursor\.execute)\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+)|\w+\s*%\s*\()|f['\"](?:SELECT|INSERT|UPDATE|DELETE)\b|['\"](?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*(?:\+|%|\.format)|\.raw\(|RawSQL\(|text\(f['\"]|\$\{[^}]*\}[^`]*(?:FROM|WHERE)|\"\s*\+\s*\w+\s*\+\s*\"\s*(?:FROM|WHERE)|string\.Format\([^)]*SELECT")),
    ("weak_crypto", re.compile(r"\bmd5\b|\bMD5\b|\bsha1\b|\bSHA1\b|\bDES\b|\bRC4\b|/ECB/|Cipher\.getInstance\(\"AES\"\)|hashlib\.(?:md5|sha1)|Math\.random\(\)[^\n]*(?:token|secret|password|key)|random\.(?:random|randint|choice)\([^\n]*(?:token|secret|password)")),
    ("tls_or_verification_disabled", re.compile(r"verify\s*=\s*False|rejectUnauthorized:\s*false|InsecureSkipVerify:\s*true|CURLOPT_SSL_VERIFYPEER[^\n]*(?:false|0)|check_hostname\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED|TrustAllCerts|allowsArbitraryLoads|ServerCertificateValidationCallback\s*=|CERT_NONE|--insecure|\bcurl\s+-k\b|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|badssl|trustAllHosts|HostnameVerifier[^\n]*true")),
    ("debug_or_permissive_config", re.compile(r"\bdebug\s*=\s*True|DEBUG\s*=\s*True|Access-Control-Allow-Origin['\"]?\s*[:=,]\s*['\"]\*|allow_origins\s*=\s*\[\s*['\"]\*|origin:\s*['\"]\*['\"]|cors\(\)|@csrf_exempt|csrf_exempt|permission_classes\s*=\s*\[\s*\]|AllowAny\b|authentication_classes\s*=\s*\[\s*\]|\[AllowAnonymous\]|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+except|chmod\s+(?:-R\s+)?777|0o777|\b0777\b|app\.run\([^)]*host\s*=\s*['\"]0\.0\.0\.0|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|SECURE_SSL_REDIRECT\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False")),
    ("network_exposure", re.compile(r"@\w+\.(?:route|get|post|put|delete|patch|api_route|websocket)\(|@(?:Get|Post|Put|Delete|Patch|Request)Mapping|\[Http(?:Get|Post|Put|Delete|Patch)\]|\brouter\.(?:get|post|put|delete|patch|all)\(|\bapp\.(?:get|post|put|delete|patch|all|use)\(\s*['\"]/|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\b|Route::(?:get|post|put|delete|patch|any)|^\s*(?:get|post|put|delete|patch|resources?)\s+['\"]/|http\.HandleFunc\(|\.(?:GET|POST|PUT|DELETE|PATCH)\(\s*\"/|@(?:app|api|bp|blueprint|router)\.(?:get|post|put|delete|patch)|urlpatterns|path\(\s*['\"]|re_path\(|@socketio\.on|@websocket|listen\(\s*\d+|\.listen\(|HttpServer|ListenAndServe|@WebServlet|@Path\(|@Controller|@RestController|@RestResource")),
    ("dangerous_html", re.compile(r"innerHTML\s*=|dangerouslySetInnerHTML|\|\s*safe\b|mark_safe\(|Markup\(|\.html_safe|\braw\(|\{\{\{|v-html|bypassSecurityTrust|\[innerHTML\]|@Html\.Raw|document\.write\(|autoescape\s+false|\{%\s*autoescape\s+off|Html\.Raw\(|__html")),
    ("memory_unsafe", re.compile(r"\bstrcpy\(|\bstrcat\(|\bsprintf\(|\bgets\(|\bscanf\(\s*\"%s|\bunsafe\s*\{|\bunsafe\.Pointer|\balloca\(|\bmemcpy\([^)]*,\s*\w+\s*\)|std::mem::transmute|from_raw_parts|get_unchecked|Marshal\.Copy|fixed\s*\(|stackalloc")),
    ("path_or_file_exposure", re.compile(r"send_file\(|send_from_directory\(|FileResponse\(|res\.sendFile\(|res\.download\(|readFile\([^)]*req\.|open\([^)]*request\.|os\.path\.join\([^)]*(?:request|params|args)|Path\([^)]*request\.|\.\./\.\./|File\.ReadAllText\([^)]*Request|new File\([^)]*request|send_data\s|X-Sendfile|X-Accel-Redirect")),
    ("secret_like_literal", re.compile(r"$^")),  # handled by SECRET_PATTERNS below
]
SECURITY_NOTES = {
    "code_execution": "shells out or evaluates strings",
    "unsafe_deserialization": "deserializes untrusted formats",
    "sql_string_building": "builds SQL from strings",
    "weak_crypto": "weak hash/cipher",
    "tls_or_verification_disabled": "TLS/cert verification disabled",
    "debug_or_permissive_config": "debug mode or permissive CORS/auth/permissions",
    "network_exposure": "defines a network endpoint (dead endpoint = unmonitored attack surface)",
    "dangerous_html": "renders unescaped HTML",
    "memory_unsafe": "memory-unsafe operations",
    "path_or_file_exposure": "serves or opens files from request data",
    "secret_like_literal": "secret-like literal present (value never shown)",
    "supply_chain_surface": "unused dependency still ships in the lockfile/SBOM and inherits its CVEs",
}


def security_lens(finding: "Finding", ctx: Context) -> dict[str, Any]:
    markers: list[dict[str, Any]] = []
    if finding.kind == "unused_dep":
        markers.append({"marker": "supply_chain_surface", "lines": [], "note": SECURITY_NOTES["supply_chain_surface"]})
    else:
        lines = ctx.lines(finding.path)
        scope = _symbol_scope(lines, finding.symbol) if finding.symbol else range(1, len(lines) + 1)
        for label, pattern in SECURITY_MARKERS:
            hits: list[int] = []
            for lineno in scope:
                line = lines[lineno - 1]
                matched = pattern.search(line) if label != "secret_like_literal" else any(p.search(line) for p in SECRET_PATTERNS)
                if matched:
                    hits.append(lineno)
                    if len(hits) >= 5:
                        break
            if hits:
                markers.append({"marker": label, "lines": hits, "note": SECURITY_NOTES[label]})
    attack_surface = any(m["marker"] in {"network_exposure", "path_or_file_exposure", "debug_or_permissive_config"} for m in markers)
    return {"markers": markers, "attack_surface": attack_surface}


def _symbol_scope(lines: list[str], symbol: str) -> range:
    """Approximate the definition block of ``symbol`` by indentation / braces; fall back to the whole file."""
    def_re = re.compile(rf"^(\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:pub(?:\(crate\))?\s+)?(?:public\s+|private\s+|protected\s+|static\s+|final\s+|abstract\s+|open\s+|internal\s+)*(?:def|class|function|fn|func|struct|enum|trait|interface|type|const|let|var|val|module|object|record|protocol|defmodule|sub)\s+\b{re.escape(symbol)}\b")
    start = None
    indent = 0
    for lineno, line in enumerate(lines, start=1):
        match = def_re.search(line)
        if match:
            start, indent = lineno, len(match.group(1))
            break
    if start is None:
        return range(1, len(lines) + 1)
    end = start
    depth = 0
    for lineno in range(start, len(lines) + 1):
        line = lines[lineno - 1]
        depth += line.count("{") - line.count("}")
        if lineno > start and line.strip() and depth <= 0 and (len(line) - len(line.lstrip())) <= indent and not line.lstrip().startswith(("}", ")", "]", "end", "else", "elif", "except", "finally", "case", "when")):
            break
        end = lineno
    return range(start, min(len(lines), end + 1) + 1)


# --------------------------------------------------------------------------- #
# Effort (developer velocity)
# --------------------------------------------------------------------------- #


def effort_estimate(finding: "Finding", ctx: Context, objections: list[Objection]) -> dict[str, Any]:
    if finding.kind == "unused_dep":
        lines = 1
    else:
        lines = len(ctx.lines(finding.path))
        if finding.symbol:
            scope = _symbol_scope(ctx.lines(finding.path), finding.symbol)
            lines = max(1, len(scope))
    checks = len(objections)
    if lines <= 60 and checks <= 1:
        size = "trivial"
    elif lines <= 400 and checks <= 3:
        size = "small"
    else:
        size = "large"
    minutes = 2 + min(20, lines // 40) + 3 * checks
    return {"lines": lines, "checks": checks, "size": size, "minutes_estimate": minutes}


# --------------------------------------------------------------------------- #
# Judge
# --------------------------------------------------------------------------- #


@dataclass
class Critique:
    finding_id: str
    raw_confidence: float
    confidence: float
    verdict: str
    rationale: str
    next_check: str | None
    hypotheses_checked: int
    objections: list[Objection]
    identification: list[Objection]
    security: dict[str, Any]
    effort: dict[str, Any]
    quick_win: bool
    security_priority: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "raw_confidence": self.raw_confidence,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "rationale": self.rationale,
            "next_check": self.next_check,
            "hypotheses_checked": self.hypotheses_checked,
            "objections": [o.to_dict() for o in self.objections],
            "identification": [o.to_dict() for o in self.identification],
            "security": self.security,
            "security_priority": self.security_priority,
            "effort": self.effort,
            "quick_win": self.quick_win,
        }


def critique(finding: "Finding", ctx: Context) -> Critique:
    n = _needles(finding)
    objections: list[Objection] = []
    checked = 0
    for hyp in HYPOTHESES:
        if finding.kind not in hyp.kinds:
            continue
        checked += 1
        try:
            evidence = hyp.check(finding, ctx, n)
        except (OSError, re.error, ValueError):  # a broken artifact must never break the scan
            evidence = []
        if evidence:
            objections.append(Objection(hyp.name, hyp.strength, _penalty_for(hyp, finding, ctx), hyp.note, evidence[:MAX_EVIDENCE]))
    identification = _identification(finding, ctx, n)
    strength_rank = {"strong": 0, "medium": 1, "weak": 2, "info": 3}
    objections.sort(key=lambda o: (strength_rank[o.strength], -o.penalty, o.hypothesis))

    raw = finding.confidence
    penalty = min(MAX_PENALTY, sum(o.penalty for o in objections) + sum(o.penalty for o in identification))
    adjusted = round(max(0.02, raw - penalty), 2)
    substantive = [o for o in objections if o.penalty > 0]
    if any(o.strength == "strong" for o in objections):
        verdict = "keep"
    elif adjusted >= conf.BLOCK_AT:
        verdict = "remove"
    elif adjusted >= conf.WARN_AT or not substantive:
        verdict = "verify"
    else:
        verdict = "keep"

    security = security_lens(finding, ctx)
    effort = effort_estimate(finding, ctx, substantive)
    if security["markers"] and verdict == "remove":
        security_priority = "remove_first"
    elif security["markers"]:
        security_priority = "review"
    else:
        security_priority = "normal"
    quick_win = verdict == "remove" and effort["size"] == "trivial"

    top = substantive[0] if substantive else None
    hyp_by_name = {h.name: h for h in HYPOTHESES}
    next_check = None
    if top is not None:
        where = top.evidence[0].where if top.evidence else finding.path
        next_check = hyp_by_name[top.hypothesis].next_check.format(where=where, path=finding.path, stem=n.stem, symbol=finding.symbol or n.stem)
    elif verdict == "remove":
        next_check = f"One grep for `{finding.symbol or n.stem}` outside `{finding.path}`, then run the validate steps and propose the patch."
    elif verdict == "verify":
        next_check = f"Weak evidence either way: read the definition in `{finding.path}` and grep `{finding.symbol or n.stem}` once."
    info_flags = [o.hypothesis for o in objections if o.penalty == 0]
    rationale = _rationale(finding, raw, adjusted, verdict, substantive, identification, info_flags, checked)
    return Critique(
        finding_id=finding.id,
        raw_confidence=raw,
        confidence=adjusted,
        verdict=verdict,
        rationale=rationale,
        next_check=next_check,
        hypotheses_checked=checked,
        objections=objections,
        identification=identification,
        security=security,
        effort=effort,
        quick_win=quick_win,
        security_priority=security_priority,
    )


ARTIFACT_HYPOTHESES = {
    "scheduled_job", "container_or_process_entry", "serverless_handler", "cli_entry_point",
    "plugin_or_entry_point_group", "ci_or_build_invocation", "infrastructure_manifest", "ide_or_runner_config",
}
CONFIG_SIGNALS = {"module_named_in_config", "symbol_named_in_config", "dependency_named_in_config_or_scripts", "cli_binary_use"}
STRING_SIGNALS = {"module_named_in_string_literal", "symbol_named_in_string_literal"}


def _penalty_for(hyp: Hypothesis, finding: "Finding", ctx: Context) -> float:
    """Avoid double counting evidence the scanner already priced into the confidence."""
    penalty = hyp.penalty
    names = set(finding.signals)
    if hyp.name in ARTIFACT_HYPOTHESES and names & CONFIG_SIGNALS:
        penalty = round(penalty / 2, 3)
    if hyp.name == "dynamic_loading_or_reflection" and names & STRING_SIGNALS:
        penalty = round(penalty / 2, 3)
    if hyp.name == "convention_dispatched_name" and not ctx.profile.frameworks:
        penalty = 0.15
    return penalty


def _rationale(finding: "Finding", raw: float, adjusted: float, verdict: str, objections: list[Objection], identification: list[Objection], info_flags: list[str], checked: int) -> str:
    prosecution = f"Prosecution: {finding.why.rstrip('.')} (scan confidence {raw:.2f})."
    if objections:
        defense = "Defense: " + "; ".join(
            f"{o.hypothesis} [{o.strength}] at {o.evidence[0].where}" if o.evidence else f"{o.hypothesis} [{o.strength}]" for o in objections[:3]
        ) + (f"; +{len(objections) - 3} more" if len(objections) > 3 else "") + "."
    else:
        defense = f"Defense: none of {checked} counter-hypotheses found supporting evidence."
    ident = ""
    real_ident = [o for o in identification if o.penalty > 0]
    if real_ident:
        ident = " Identification: " + "; ".join(o.hypothesis for o in real_ident) + "."
    flags = f" Flags: {', '.join(info_flags)}." if info_flags else ""
    judge = {
        "remove": f"Judge: remove — confidence {adjusted:.2f} after due diligence; propose the patch after validation.",
        "verify": f"Judge: verify — confidence {adjusted:.2f}; one targeted check settles it.",
        "keep": f"Judge: keep — confidence {adjusted:.2f}; a plausible live path exists. Record the decision if you agree.",
    }[verdict]
    return f"{prosecution} {defense}{ident}{flags} {judge}"


def judge_findings(findings: list["Finding"], ctx: Context) -> list["Finding"]:
    """Attach a critique to each finding and fold the judged confidence into severity/signals."""
    for finding in findings:
        result = critique(finding, ctx)
        finding.critique = result.to_dict()
        finding.confidence = result.confidence
        finding.severity = conf.severity_for(result.confidence)
        for objection in result.objections:
            if objection.penalty:
                finding.signals[f"judge_{objection.hypothesis}"] = -objection.penalty
        for objection in result.identification:
            if objection.penalty:
                finding.signals[f"judge_{objection.hypothesis}"] = -objection.penalty
        if result.objections:
            finding.evidence.append(
                "judge: " + "; ".join(
                    f"{o.hypothesis} ({o.evidence[0].where})" if o.evidence else o.hypothesis for o in result.objections[:4]
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > 2_000_000:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _stem(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".d.ts"):
        return name[: -len(".d.ts")]
    return name.rsplit(".", 1)[0] if "." in name else name


def _module_for(path: str) -> str:
    stem = path.rsplit(".", 1)[0] if "." in path.rsplit("/", 1)[-1] else path
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


def _lang_of(path: str) -> str:
    if path.endswith((".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".vue", ".svelte")):
        return "ts"
    if path.endswith(".py"):
        return "py"
    return "other"
