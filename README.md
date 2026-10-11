# ActionGuard

A static scanner for GitHub Actions workflows. It reads your `.github/workflows/*.yml`
files and flags third-party actions that are:

- **Unpinned** — referenced by a mutable tag or branch (e.g. `@v4`, `@main`)
  instead of a commit SHA, so the code behind them can change without your
  workflow file ever changing.
- **Known-compromised** — matched against a small, growing list of actions
  that have had real supply-chain incidents, starting with
  `tj-actions/changed-files` (CVE-2025-30066, March 2025).

This is part of **CI/CD Redzone**. The companion repo
[`ActionGaurd-demo`](https://github.com/geethika-sandireddy/ActionGaurd-demo)
safely reproduces the attack this scanner is built to catch.

## Usage

```bash
pip install pytest   # only needed to run the test suite
python -m actionguard.cli /path/to/repo           # human-readable report
python -m actionguard.cli /path/to/repo --json    # JSON report
python -m actionguard.cli /path/to/repo --fail-on CRITICAL   # for CI
```

### Sample output

Run against the fixture workflows in `tests/fixtures/` (copies of the
vulnerable/fixed workflows from
[`ActionGaurd-demo`](https://github.com/geethika-sandireddy/ActionGaurd-demo),
plus one using the real compromised `tj-actions/changed-files`):

```
[CRITICAL] .github/workflows/vulnerable-demo.yml:12  tj-actions/changed-files@v44
    tj-actions/changed-files has a documented supply-chain compromise
    (CVE-2025-30066, 2025-03-14). Avoid using it, or pin to a commit SHA
    you have personally audited.

[MEDIUM] .github/workflows/vulnerable-demo.yml:10  .../fake-action@v1
    Pinned to a mutable tag/branch, not a commit SHA.

[INFO] .github/workflows/fixed-demo.yml:10  .../fake-action@9a9bab07...
    Pinned to a commit SHA. Good.

Summary: INFO=1, MEDIUM=3, CRITICAL=1
```

Exit code is `1` whenever a finding meets or exceeds `--fail-on` (default
`HIGH`), so this drops straight into a CI pipeline — see `.github/workflows/ci.yml`
for ActionGuard scanning itself on every push.

## How it works

1. Walks `.github/workflows/*.yml` and reads every `uses:` line (regex-based,
   so it keeps line numbers without needing a full YAML parser).
2. Splits each reference into `owner/repo` and `ref`.
3. `owner/repo` matched against `actionguard/data/known_compromised.json` →
   **CRITICAL**, regardless of which ref is used.
4. `ref` is a 40-character commit SHA → **PINNED / INFO**. Anything else
   (a tag or branch name) → **UNPINNED / MEDIUM**.

## Project layout

| Path | Purpose |
|---|---|
| `actionguard/scanner.py` | Core scanning + classification logic |
| `actionguard/cli.py` | Command-line interface, human + JSON output |
| `actionguard/data/known_compromised.json` | List of actions with documented incidents |
| `tests/` | Unit tests + fixture workflows used to verify detection |
| `.github/workflows/ci.yml` | Runs tests and self-scans this repo on every push |

## Relationship to the rest of CI/CD Redzone

This repo is the **scanner** piece only. The companion pieces are:
- **ActionGuard Demo** — safely replays the tag-move attack this scanner
  is built to catch.
- **ActionGuard Dashboard** — a web UI to visualize scan results and
  trigger/replay the attack remotely.

## Status

✅ Scanner, CLI, known-compromised list, tests, and self-scanning CI are all
in place and passing.
