"""
Core scanning logic for ActionGuard.

Finds every `uses:` line in GitHub Actions workflow files and classifies the
action reference it points to:

- PINNED     -> referenced by a full 40-character commit SHA (safe)
- UNPINNED   -> referenced by a tag or branch name (mutable, can be moved)
- COMPROMISED-> owner/repo matches the known-compromised list, regardless of ref

Deliberately regex-based rather than a full YAML parse: workflow files are
simple enough that this is robust, and it keeps line numbers for free, which
a YAML parse normally throws away.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_USES_LINE = re.compile(r'^\s*-?\s*uses\s*:\s*[\'"]?([^\'"\s#]+)[\'"]?\s*(?:#.*)?$')
_SHA_RE = re.compile(r'^[0-9a-fA-F]{40}$')

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    file: str
    line: int
    raw_ref: str
    owner_repo: str
    ref: str
    status: str      # PINNED | UNPINNED | SKIPPED
    severity: str     # INFO | MEDIUM | HIGH | CRITICAL
    message: str
    incident: dict | None = None

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "line": self.line,
            "action": self.raw_ref,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
        }
        if self.incident:
            d["incident"] = self.incident
        return d


def load_known_compromised(data_path: Path | None = None) -> dict[str, dict]:
    """Returns {owner/repo (lowercase): incident-info-dict}."""
    if data_path is None:
        data_path = Path(__file__).parent / "data" / "known_compromised.json"
    raw = json.loads(data_path.read_text())
    return {entry["repo"].lower(): entry for entry in raw["actions"]}


def _parse_ref(raw: str) -> tuple[str, str] | None:
    """Split 'owner/repo/optional/path@ref' into (owner/repo, ref). None if
    not a remote action reference (local path or docker image)."""
    if raw.startswith("./") or raw.startswith("docker://") or raw.startswith("${{"):
        return None
    if "@" not in raw:
        return None
    path_part, ref = raw.rsplit("@", 1)
    parts = path_part.split("/")
    if len(parts) < 2:
        return None
    owner_repo = "/".join(parts[:2])
    return owner_repo, ref


def find_workflow_files(root: Path) -> list[Path]:
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []
    return sorted(
        p for p in workflows_dir.iterdir()
        if p.is_file() and p.suffix in (".yml", ".yaml")
    )


def scan_file(path: Path, known_bad: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _USES_LINE.match(line)
        if not m:
            continue
        raw_ref = m.group(1)
        parsed = _parse_ref(raw_ref)
        if parsed is None:
            continue
        owner_repo, ref = parsed

        incident = known_bad.get(owner_repo.lower())
        if incident:
            findings.append(Finding(
                file=str(path),
                line=lineno,
                raw_ref=raw_ref,
                owner_repo=owner_repo,
                ref=ref,
                status="UNPINNED" if not _SHA_RE.match(ref) else "PINNED",
                severity="CRITICAL",
                message=(
                    f"{owner_repo} has a documented supply-chain compromise "
                    f"({incident['incident']}, {incident['date']}). Avoid using "
                    f"it, or pin to a commit SHA you have personally audited."
                ),
                incident=incident,
            ))
            continue

        if _SHA_RE.match(ref):
            findings.append(Finding(
                file=str(path), line=lineno, raw_ref=raw_ref,
                owner_repo=owner_repo, ref=ref,
                status="PINNED", severity="INFO",
                message=f"{owner_repo} is pinned to a commit SHA. Good.",
            ))
        else:
            findings.append(Finding(
                file=str(path), line=lineno, raw_ref=raw_ref,
                owner_repo=owner_repo, ref=ref,
                status="UNPINNED", severity="MEDIUM",
                message=(
                    f"{owner_repo}@{ref} is pinned to a mutable tag/branch, "
                    f"not a commit SHA. Whoever controls that ref can change "
                    f"what code runs without this file ever changing."
                ),
            ))
    return findings


def scan_repo(root: Path, known_bad: dict[str, dict] | None = None) -> list[Finding]:
    if known_bad is None:
        known_bad = load_known_compromised()
    findings: list[Finding] = []
    for wf in find_workflow_files(root):
        findings.extend(scan_file(wf, known_bad))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return findings


def summarize(findings: Iterable[Finding]) -> dict:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts
