"""Canned mock findings so `--mock` works with zero API keys."""

from __future__ import annotations

from pathlib import Path

from unreach.scan import Finding, finding_id


def canned_findings() -> list[Finding]:
    return [
        Finding(
            id=finding_id("orphan_file", "pkg/orphan.py"),
            kind="orphan_file",
            severity="block",
            path="pkg/orphan.py",
            symbol=None,
            why="pkg/orphan.py is never imported by another module.",
            evidence=[
                "fixture mock: no importer of pkg.orphan",
                "not an entry file",
            ],
        ),
        Finding(
            id=finding_id("unused_export", "pkg/exports.py", "dead_symbol"),
            kind="unused_export",
            severity="block",
            path="pkg/exports.py",
            symbol="dead_symbol",
            why="Exported symbol `dead_symbol` in pkg/exports.py is never imported.",
            evidence=[
                "defined in pkg/exports.py",
                "pkg.app imports live_symbol only",
            ],
        ),
    ]


def looks_like_deadapp(root: Path) -> bool:
    return (root / "pkg" / "orphan.py").is_file() and (root / "pkg" / "exports.py").is_file()


def default_mock_root() -> Path | None:
    here = Path(__file__).resolve().parents[1] / "fixtures" / "deadapp"
    cwd = Path.cwd() / "fixtures" / "deadapp"
    for candidate in (cwd, here):
        if candidate.is_dir():
            return candidate
    return None


def ensure_mock_findings(root: Path, findings: list[Finding]) -> list[Finding]:
    """Guarantee the fixture demo findings appear when --mock is set."""
    if not looks_like_deadapp(root) and not any(
        f.kind == "unused_export" and f.symbol == "dead_symbol" for f in findings
    ):
        extra = canned_findings()
        ids = {f.id for f in findings}
        for finding in extra:
            if finding.id not in ids:
                findings.append(finding)
        return findings
    ids = {f.id for f in findings}
    for finding in canned_findings():
        if finding.id not in ids and looks_like_deadapp(root):
            findings.append(finding)
    return findings
