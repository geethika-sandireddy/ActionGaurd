"""
Command-line interface for ActionGuard.

Usage:
    python -m actionguard.cli [path] [--json] [--fail-on MEDIUM]

If [path] is omitted, scans the current directory.
Exit code is non-zero if any finding meets or exceeds --fail-on (default HIGH),
so this can be dropped straight into a CI pipeline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from actionguard.scanner import SEVERITY_ORDER, scan_repo, summarize

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "INFO": "\033[92m",
}
RESET = "\033[0m"


def _print_human(findings, summary) -> None:
    if not findings:
        print("No workflow files found under .github/workflows/.")
        return

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"{color}[{f.severity}]{RESET} {f.file}:{f.line}  {f.raw_ref}")
        print(f"    {f.message}")

    print()
    print("Summary:", ", ".join(f"{k}={v}" for k, v in summary.items() if v))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="actionguard")
    parser.add_argument("path", nargs="?", default=".", help="repo root to scan")
    parser.add_argument("--json", action="store_true", help="output JSON report")
    parser.add_argument(
        "--fail-on", default="HIGH", choices=SEVERITY_ORDER.keys(),
        help="minimum severity that causes a non-zero exit code (default: HIGH)",
    )
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    findings = scan_repo(root)
    summary = summarize(findings)

    if args.json:
        report = {
            "root": str(root),
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(report, indent=2))
    else:
        _print_human(findings, summary)

    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
