"""Long-term memory: ``.unreach/memory.json`` next to the scanned root.

What it stores (never file contents, never secrets):

* ``files`` — content hash → extracted facts, so unchanged files are not
  re-parsed on the next scan (incremental cache).
* ``findings`` — finding id → first/last seen, run count, last confidence.
* ``decisions`` — agent/human decisions per finding id
  (``keep`` | ``false_positive`` | ``resolved``), with an optional note.
* ``llm`` — triage verdicts per finding id, keyed by evidence digest, so the
  model is never asked twice about an unchanged finding.
* ``runs`` — compact run log with token estimates.

Why it saves tokens: an agent that already triaged a finding in a previous
session gets it back as a one-line ``persisting`` entry (or not at all if it
was acknowledged), instead of the full evidence packet every time.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MEMORY_VERSION = 1
MEMORY_DIR_NAME = ".unreach"
MEMORY_FILE = "memory.json"
DECISIONS = ("keep", "false_positive", "resolved")
MAX_RUNS = 50
MAX_FILES = 20_000


@dataclass
class Delta:
    new: list[str] = field(default_factory=list)
    persisting: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": self.new,
            "persisting": self.persisting,
            "resolved": self.resolved,
            "suppressed": self.suppressed,
            "counts": {
                "new": len(self.new),
                "persisting": len(self.persisting),
                "resolved": len(self.resolved),
                "suppressed": len(self.suppressed),
            },
        }


def memory_dir_for(root: Path) -> Path:
    override = os.environ.get("UNREACH_MEMORY_DIR")
    if override:
        return Path(override)
    return Path(root) / MEMORY_DIR_NAME


class Memory:
    """Persistent per-repository memory. Safe to delete at any time."""

    def __init__(self, root: Path, *, enabled: bool = True, directory: Path | None = None) -> None:
        self.root = Path(root)
        self.enabled = enabled
        self.directory = directory or memory_dir_for(self.root)
        self.path = self.directory / MEMORY_FILE
        self.data: dict[str, Any] = self._empty()
        self.cache_hits = 0
        self.cache_misses = 0
        self.dirty = False
        if enabled:
            self._load()

    # ---- persistence -------------------------------------------------- #

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "version": MEMORY_VERSION,
            "files": {},
            "findings": {},
            "decisions": {},
            "llm": {},
            "runs": [],
            "profile": {},
        }

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(loaded, dict) and loaded.get("version") == MEMORY_VERSION:
            base = self._empty()
            base.update(loaded)
            self.data = base

    def save(self) -> None:
        if not self.enabled or not self.dirty:
            return
        files = self.data["files"]
        if len(files) > MAX_FILES:
            for key in list(files)[: len(files) - MAX_FILES]:
                files.pop(key, None)
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
        self.dirty = False

    def clear(self) -> None:
        self.data = self._empty()
        self.dirty = True
        if self.path.is_file():
            self.path.unlink()
        self.dirty = False

    # ---- FactsCache protocol ------------------------------------------ #

    def get(self, rel: str, digest: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        entry = self.data["files"].get(rel)
        if entry and entry.get("sha256") == digest:
            self.cache_hits += 1
            return entry.get("facts")
        self.cache_misses += 1
        return None

    def put(self, rel: str, digest: str, facts: dict[str, Any]) -> None:
        if not self.enabled:
            return
        self.data["files"][rel] = {"sha256": digest, "facts": facts}
        self.dirty = True

    # ---- findings history --------------------------------------------- #

    def seen_count(self, finding_id: str) -> int:
        entry = self.data["findings"].get(finding_id)
        return int(entry.get("seen_count", 0)) if entry else 0

    def decision_for(self, finding_id: str) -> dict[str, Any] | None:
        return self.data["decisions"].get(finding_id)

    def remember(self, finding_id: str, decision: str, note: str = "") -> dict[str, Any]:
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        entry = {"decision": decision, "note": note[:500], "at": _now()}
        self.data["decisions"][finding_id] = entry
        self.dirty = True
        return entry

    def forget(self, finding_id: str) -> bool:
        removed = self.data["decisions"].pop(finding_id, None) is not None
        self.dirty = self.dirty or removed
        return removed

    def record_run(self, findings: list[Any], *, profile: dict[str, Any] | None = None) -> Delta:
        """Update history and return the delta versus the previous run."""
        now = _now()
        current_ids = {f.id for f in findings}
        history = self.data["findings"]
        previous_open = {
            fid for fid, entry in history.items() if entry.get("status", "open") == "open"
        }
        delta = Delta()
        for finding in findings:
            entry = history.get(finding.id)
            decision = self.data["decisions"].get(finding.id)
            if decision and decision.get("decision") in {"keep", "false_positive"}:
                delta.suppressed.append(finding.id)
            elif entry is None or entry.get("status") == "resolved":
                delta.new.append(finding.id)
            else:
                delta.persisting.append(finding.id)
            history[finding.id] = {
                "kind": finding.kind,
                "path": finding.path,
                "symbol": finding.symbol,
                "first_seen": entry.get("first_seen", now) if entry and entry.get("status") != "resolved" else now,
                "last_seen": now,
                "seen_count": (int(entry.get("seen_count", 0)) if entry and entry.get("status") != "resolved" else 0) + 1,
                "confidence": getattr(finding, "confidence", None),
                "severity": finding.severity,
                "status": "open",
            }
        for fid in sorted(previous_open - current_ids):
            history[fid]["status"] = "resolved"
            history[fid]["resolved_at"] = now
            delta.resolved.append(fid)
            decision = self.data["decisions"].get(fid)
            if decision and decision.get("decision") != "resolved":
                # A finding that disappeared no longer needs a suppression.
                self.data["decisions"][fid] = {**decision, "decision": "resolved", "at": now}
        if profile is not None:
            self.data["profile"] = profile
        self.data["runs"].append(
            {
                "at": now,
                "total": len(findings),
                "new": len(delta.new),
                "persisting": len(delta.persisting),
                "resolved": len(delta.resolved),
                "suppressed": len(delta.suppressed),
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
            }
        )
        self.data["runs"] = self.data["runs"][-MAX_RUNS:]
        self.dirty = True
        return delta

    # ---- reporting ---------------------------------------------------- #

    def summary(self) -> dict[str, Any]:
        runs = self.data["runs"]
        open_ids = [fid for fid, e in self.data["findings"].items() if e.get("status", "open") == "open"]
        return {
            "enabled": self.enabled,
            "path": str(self.path),
            "runs": len(runs),
            "last_run": runs[-1] if runs else None,
            "open_findings": len(open_ids),
            "decisions": len(self.data["decisions"]),
            "triage_verdicts": len(self.data.get("llm", {})),
            "cached_files": len(self.data["files"]),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }

    def decisions(self) -> dict[str, Any]:
        return dict(self.data["decisions"])


def estimate_tokens(text: str) -> int:
    """Rough token estimate (≈4 chars per token). Good enough for savings reports."""
    return max(1, len(text) // 4)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
