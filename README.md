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

## Status

🚧 Building in public — see commit history for progress.
