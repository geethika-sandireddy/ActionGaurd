"""
Output formats beyond the plain console report: a GitHub Job Summary
(markdown shown right on the Actions run page) and SARIF (the format
GitHub's Security/Code Scanning tab consumes).
"""
from __future__ import annotations

import json
from typing import Iterable

from actionguard.scanner import Finding

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "🟢",
}

# SARIF only has 3 result levels; map our 5 severities onto them.
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def to_markdown_summary(findings: Iterable[Finding], summary: dict) -> str:
    findings = list(findings)
    lines = ["## 🛡️ ActionGuard scan results", ""]

    badge = " · ".join(
        f"{SEVERITY_EMOJI[sev]} {sev}: **{count}**"
        for sev, count in summary.items()
        if count
    ) or "No findings"
    lines.append(badge)
    lines.append("")

    if not findings:
        lines.append("No workflow files found under `.github/workflows/`.")
        return "\n".join(lines)

    lines.append("| Severity | File | Action | Note |")
    lines.append("|---|---|---|---|")
    for f in findings:
        short_file = f.file.split(".github/workflows/")[-1]
        lines.append(
            f"| {SEVERITY_EMOJI[f.severity]} {f.severity} "
            f"| `{short_file}:{f.line}` | `{f.raw_ref}` | {f.message} |"
        )
    return "\n".join(lines)


def to_sarif(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    rules = {}
    results = []

    for f in findings:
        rule_id = "known-compromised-action" if f.severity == "CRITICAL" else "unpinned-action-ref"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": (
                    "Action is on ActionGuard's known-compromised list"
                    if rule_id == "known-compromised-action"
                    else "Action is referenced by a mutable tag/branch instead of a commit SHA"
                )
            },
        })
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ActionGuard",
                    "informationUri": "https://github.com/geethika-sandireddy/ActionGaurd",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump(to_sarif(findings), fh, indent=2)
