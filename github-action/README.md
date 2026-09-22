# Codex Security GitHub Action

Run Codex Security scans in GitHub Actions. Scan a repository or pull request,
check findings against a severity threshold, and export JSON, coverage, and
SARIF reports.

## Quick start

Use a GitHub-hosted Ubuntu 24.04 x64 runner on GitHub.com and an OpenAI API key
with access to the selected model. For Amazon Bedrock, see the separate
[workflow example](../examples/github-actions/README.md).

Add your API key as a repository secret named `CODEX_SECURITY_API_KEY`, then
save this workflow in `.github/workflows/codex-security.yml`.
Replace `REPLACE_WITH_REVIEWED_COMMIT` with the full SHA of an Action commit.
When using a fork, replace `openai` with the fork owner.

```yaml
name: Codex Security repository
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Scan repository
        id: security
        uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          max-cost: '25'
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

Run it from **Actions → Codex Security repository → Run workflow**.
Findings are report-only by default. Errors and incomplete scans fail the job.
Set `fail-on-severity` to fail on findings at or above a selected severity.

Choose `max-cost` for your budget. It is an estimated USD stop threshold;
in-flight requests can exceed it. Without this input, no cost limit is set.

## Scan pull requests

Use the same API-key secret and Action commit as above. Check out the PR head
with full history so the Action can resolve the diff.

```yaml
name: Codex Security PR
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read

concurrency:
  group: codex-security-pr-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  security:
    name: Codex Security
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false
      - name: Scan PR changes
        id: security
        uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          scope: diff
          max-cost: '5'
          fail-on-severity: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

This job fails on high or critical findings, incomplete scans, and errors.
Make it a required check in repository rules to block merging when it fails.

Use PR scanning for trusted contributors with branches in the calling repository.
Fork and Dependabot PRs, `pull_request_target`, and `workflow_run` are not supported.
PRs that change `SECURITY.md` are also refused; review and merge policy changes
separately before scanning dependent code changes.

## Scan settings

Run the scan immediately after checkout, before builds or other steps modify
files. Repository and diff scans require a clean checkout of the triggering
repository and revision. Keep unrelated credentials and deployment steps in
separate jobs.

- Set `paths` to newline-separated files or folders to scan part of a repository.
- Set `mode: deep` for repeated discovery passes. Deep mode and `paths` require
  repository scope.
- For diff scans outside PR events, set `diff-base`.
- Set `dry-run: 'true'` to check configuration without an API key or model calls.
  Use a separate setup job; dry-run does not assess code or verify model access.

## Reports

The Action writes a job summary and source annotations. Set
`upload-artifacts: 'true'` for downloadable reports, retained for seven days by
default. Reports can contain source code and vulnerability details.

The normal job check is available automatically. For an additional named check,
set `publish-check: 'true'`, pass `github-token: ${{ github.token }}`, and grant
`checks: write`.

### GitHub code scanning

Grant the job `security-events: write` and, for private repositories,
`actions: read`, alongside `contents: read`. Add this step after the scan:

```yaml
- name: Upload security findings
  if: ${{ always() && steps.security.outputs.sarif-upload-ready == 'true' }}
  uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0
  with:
    sarif_file: ${{ steps.security.outputs.sarif-path }}
    sha: ${{ steps.security.outputs.scanned-sha }}
    ref: ${{ steps.security.outputs.analysis-ref }}
    category: codex-security-repository
```

Complete scans remain uploadable when findings exceed the severity threshold.
Incomplete scans, dry runs, and working-tree snapshots are not uploadable.
Use a distinct category for each scan scope, such as repository and PR scans.
See [GitHub's SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for code scanning availability and permissions.

## Runtime

The Action installs a pinned CLI release from npm using a committed dependency
lock. It runs on Linux x64 with Node 24 and Python 3.11 or 3.12; the Ubuntu 24.04
runner supplies these prerequisites. Authentication uses `OPENAI_API_KEY`.
Temporary runtime files are removed after the job; reports remain available to
downstream steps.

## Troubleshooting

- **Checkout or history errors:** use the triggering revision, `fetch-depth: 0`
  for PRs, and `persist-credentials: false`.
- **Authentication errors:** check the repository secret and model access.
- **Missing SARIF uploads:** inspect `scan-status`, `report-status`, and
  `sarif-upload-ready`.
- **Incomplete scans:** inspect the coverage report before adjusting scope or budget.

CLI diagnostics stream by default. Set `verbose: 'false'` for lifecycle and
elapsed-time messages only.

## Development

From the repository root:

```bash
npm --prefix github-action ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run docs
npm --prefix github-action run build
npm --prefix github-action run validate
# Linux x64 with Node 24; no model calls:
node github-action/scripts/linux-smoke.mjs
```

Commit source changes and the generated `dist/*.cjs` bundles together.
Validation checks types, tests, Action metadata, documentation, and bundle
reproducibility. CI also runs the packaged Linux smoke test and audits the Action
and CLI dependency locks. Update the CLI pin and lock together, and verify report
compatibility when adopting a new release.

<!-- action-reference:start -->

## Inputs

Inputs are strings. Quote booleans and use newline-separated literal paths for lists.

| Input | Default | Meaning |
| --- | --- | --- |
| `repository` | `${{ github.workspace }}` | Checkout root. Use paths to select folders within the checkout. |
| `scope` | `repository` | repository, diff, or working-tree. Select diff for PR changes only; repository scans the full checkout. |
| `paths` | Unset | Newline-delimited literal repository-relative files or folders. Only for repository scope; no globs. |
| `diff-base` | Unset | Diff base revision. Defaults to the PR merge base; required outside PRs when scope is diff. |
| `diff-head` | Unset | Diff head revision. Defaults to the PR head or HEAD and must match the checkout. |
| `working-tree-base` | Unset | Base for working-tree changes. Defaults to HEAD; requires working-tree scope. |
| `mode` | `standard` | standard or deep. Deep supports repository and path scans only. |
| `model` | `gpt-5.6-sol` | Model with access through your API key. Cost limits require CLI pricing support for the model. |
| `effort` | `xhigh` | Reasoning effort: minimal, low, medium, high, xhigh, or max (subject to model support). |
| `max-cost` | Unset | Positive estimated USD stop threshold per invocation. In-flight requests can exceed it; unset means no cost limit. |
| `fail-on-severity` | `none` | none, low, medium, high, or critical. Scanner/coverage/report failures fail independently. |
| `knowledge-base` | Unset | Newline-delimited repository-relative .md/.txt/.pdf/.docx context files or directories. No symlinks. |
| `scan-prompt-file` | Unset | Repository-relative file of additional scan instructions (maximum 1 MiB). |
| `validation-prompt-file` | Unset | Repository-relative file replacing final validation. Standard mode only (maximum 1 MiB). |
| `workers` | Unset | Maximum concurrent deep-scan discovery workers (positive integer; deep only). |
| `subagents` | Unset | Subagents per deep discovery worker (nonnegative integer; deep only). |
| `stop-after-no-new` | Unset | Stop after this many discovery runs find no new issues (positive integer; deep only). |
| `max-discovery-runs` | Unset | Maximum discovery runs (positive integer; deep only). |
| `max-time-hours` | Unset | Deep discovery duration, greater than 0 and at most 96 hours. Job timeout still applies. |
| `codex-config` | Unset | Newline-delimited TOML settings. Allowed: analytics.enabled (boolean) and features.multi_agent_v2.max_concurrent_threads_per_session (positive integer). |
| `provider` | `openai` | Only openai is supported in this release. |
| `auth` | `api-key` | Only api-key is supported. Pass the secret via OPENAI_API_KEY. |
| `safety-identifier` | Unset | Stable hashed end-user identifier for model requests (1–64 characters). |
| `verbose` | `true` | Stream bounded, credential-redacted CLI diagnostics to the job log. Set false for lifecycle and elapsed-time messages only. |
| `dry-run` | `false` | Validate local configuration without a scan or API key. Does not verify authentication or model access. Use a separate non-required job; cannot publish a named check. |
| `cli-version` | `0.1.29` | Reviewed CLI version with a shipped integrity lock. Only 0.1.29 is supported. |
| `publish-check` | `false` | Publish a separate named check in addition to the job check. Requires github-token and checks write permission. |
| `check-name` | `Codex Security findings` | Stable name of the optional named check (maximum 100 characters). |
| `github-token` | Unset | GitHub token for optional named check reporting. Never passed to the CLI or installer. |
| `summary` | `true` | Write a human-readable job summary. |
| `annotations` | `true` | Emit up to 50 source finding annotations; complete findings remain in reports. |
| `upload-artifacts` | `false` | Upload an allowlist of validated reports. Reports may contain source and vulnerability details. |
| `artifact-name` | `codex-security` | Report artifact name; choose distinct names for matrix jobs and multiple invocations. |
| `retention-days` | `7` | Artifact retention, 1–90 days (subject to repository limits). |

## Outputs

All outputs are strings. An empty cost or count means unavailable, not zero.

| Output | Meaning |
| --- | --- |
| `sarif-path` | Absolute validated SARIF file path, or empty when unavailable or withheld. |
| `json-path` | Absolute canonical findings JSON path, or empty when unavailable or withheld. |
| `coverage-path` | Absolute coverage JSON path, or empty when unavailable or withheld. |
| `results-directory` | Runner-local reports directory; do not upload it recursively. |
| `scan-status` | completed, incomplete, failed, or skipped. Skipped is reserved for empty diffs or dry-run. |
| `skip-reason` | empty-diff or dry-run when no scan ran; otherwise empty. |
| `policy-status` | passed, failed, or not-evaluated. Incomplete scans never pass the policy. |
| `report-status` | ready, partial, or failed. Reporting failure fails the action. |
| `exit-code` | CLI exit code, or empty if the CLI was not started. |
| `scanned-sha` | Verified checkout commit SHA. Working-tree contents are not represented by this SHA alone. |
| `analysis-ref` | GitHub ref matching the scanned revision. Empty for working-tree scans. |
| `sarif-upload-ready` | true only for complete, validated reports with a publishable immutable revision. Remains true after severity-policy failure. |
| `critical-count` | Available critical findings, or empty before results are available. |
| `high-count` | Available high findings, or empty before results are available. |
| `medium-count` | Available medium findings, or empty before results are available. |
| `low-count` | Available low findings, or empty before results are available. |
| `informational-count` | Available informational findings, or empty before results are available. |
| `estimated-cost` | Estimated USD cost reported by the CLI. Empty means unavailable, not zero. |

<!-- action-reference:end -->
