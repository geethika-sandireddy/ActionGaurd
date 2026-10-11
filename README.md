# ActionGuard

[![CI](https://github.com/geethika-sandireddy/ActionGaurd/actions/workflows/ci.yml/badge.svg)](https://github.com/geethika-sandireddy/ActionGaurd/actions/workflows/ci.yml)

A static scanner for GitHub Actions workflows — and a **drop-in GitHub Action
you can use in any repo**, not just a script you have to clone and run. It reads your `.github/workflows/*.yml`
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

## Use it as a GitHub Action (recommended)

Drop this into any repo's `.github/workflows/`:

```yaml
name: ActionGuard
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed if you use the sarif input below
    steps:
      - uses: actions/checkout@v4

      - name: Scan workflows for supply-chain risk
        uses: geethika-sandireddy/ActionGaurd@v1
        with:
          path: '.'
          fail-on: 'HIGH'          # fail the build on HIGH or CRITICAL findings
          sarif: 'actionguard.sarif'   # optional: feed GitHub's Security tab

      - name: Upload results to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: actionguard.sarif
```

That's it — no install step, no Python setup on your side. The action
handles its own dependencies and posts a readable summary straight to the
run page (see screenshot-style example below).

## Use it as a CLI

```bash
pip install pytest   # only needed to run the test suite
python -m actionguard.cli /path/to/repo                       # human-readable report
python -m actionguard.cli /path/to/repo --json                 # JSON report
python -m actionguard.cli /path/to/repo --sarif out.sarif       # SARIF, for Code Scanning
python -m actionguard.cli /path/to/repo --fail-on CRITICAL       # for CI
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

When run inside GitHub Actions, the same scan also posts a markdown table
straight to the **Job Summary** on the run page — no log-scrolling needed —
and `--sarif` output feeds directly into GitHub's **Security → Code Scanning**
tab alongside CodeQL and other scanners.

Exit code is `1` whenever a finding meets or exceeds `--fail-on` (default
`HIGH`), so this drops straight into a CI pipeline. `.github/workflows/ci.yml`
in this repo dogfoods ActionGuard on itself, using the packaged action
(`uses: ./`), on every push.

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
| `action.yml` | Makes this repo usable as `uses: geethika-sandireddy/ActionGaurd@v1` in any workflow |
| `actionguard/scanner.py` | Core scanning + classification logic |
| `actionguard/cli.py` | Command-line interface, human + JSON output |
| `actionguard/reporters.py` | Markdown job-summary and SARIF report generators |
| `actionguard/data/known_compromised.json` | List of actions with documented incidents |
| `tests/` | Unit tests + fixture workflows used to verify detection |
| `.github/workflows/ci.yml` | Dogfoods the packaged action and uploads SARIF to Code Scanning |

## Relationship to the rest of CI/CD Redzone

This repo is the **scanner** piece only. The companion pieces are:
- **ActionGuard Demo** — safely replays the tag-move attack this scanner
  is built to catch.
- **ActionGuard Dashboard** — a web UI to visualize scan results and
  trigger/replay the attack remotely.

## Status

✅ Scanner, CLI, known-compromised list, SARIF + job-summary output, a
packaged reusable GitHub Action, and self-scanning CI are all in place and
passing. Tagged `v1` — usable today via `uses: geethika-sandireddy/ActionGaurd@v1`.
