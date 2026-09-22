# Codex Security GitHub Action

Run the published Codex Security CLI against a repository or pull request,
evaluate findings, and produce JSON, coverage, and SARIF reports.
The root [action.yml](../action.yml) is the public Action entrypoint.

This integration is a preview. It pins the published CLI **0.1.29** runtime
and supports **Linux x64**, **Node 24**, and **OpenAI API-key authentication**.
It installs the published CLI, not the CLI source at the Action's commit.
The CLI's other providers, including Bedrock, are not exposed by this Action;
see the separate [Bedrock workflow example](../examples/github-actions/README.md).

## Scan a repository

Add a `CODEX_SECURITY_API_KEY` secret to the repository that will run the scan.
Save this workflow under its `.github/workflows/` directory. Replace
`REPLACE_WITH_REVIEWED_COMMIT` with a full commit SHA containing the Action.
For fork development, replace `openai` with the fork owner and use your pushed
branch name as the ref. No Marketplace publication or release tag is needed.

```yaml
name: Codex Security repository
on:
  workflow_dispatch:
  # Enable a schedule after testing the workflow.
  # schedule:
  #   - cron: '23 7 * * 1'

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
          scope: repository
          model: gpt-5.6-sol
          effort: high
          max-cost: '25'
          fail-on-severity: none
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

Run it from **Actions → Codex Security repository → Run workflow**.
Findings are report-only in this example; errors and incomplete scans still fail.
The budget is an example, not a price estimate. `max-cost` is an estimated USD
stop threshold; in-flight requests can exceed it. Choose your budget explicitly.

For a setup test without credentials or model calls, set `dry-run: 'true'` and
omit the API-key environment entry. Use a separate, non-required job: dry-run
validates configuration, not authentication, model access, or security coverage.

## Scan pull requests

Use the same secret and replace the Action commit placeholder as above.
Check out the PR **head**, with full history and no persisted Git credentials.

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
          model: gpt-5.6-sol
          effort: high
          max-cost: '5'
          fail-on-severity: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

This fails on high or critical findings, incomplete scans, and errors.
The job can be made a required PR check in repository rules. Fork PRs and
Dependabot PRs are refused; this workflow is for trusted contributors with
branches in the repository. Hosting the Action in a fork does not prevent it
from scanning same-repository PRs in the calling repository.

## Reports and scan settings

- Put the scan immediately after checkout, before build steps modify files.
  Repository and diff scans require a clean checkout of the triggering repository
  and revision. The Action runs against the caller's checkout, not its own source.
- `paths` accepts newline-separated literal files/folders for repository scope.
  It cannot be combined with diff or working-tree scope. Deep mode also requires
  repository scope. Outside PR events, diff scans require `diff-base`.
- `fail-on-severity: none` disables findings enforcement, not scanner health
  checks. Incomplete coverage never passes as a completed assessment.
- Enable `upload-artifacts: 'true'` for downloadable validated reports. Default
  retention is seven days. Reports and diagnostics can include source and findings.
- Optional named checks require `publish-check: 'true'`,
  `github-token: ${{ github.token }}`, and `checks: write`. The normal job check
  already exists without this option.

To upload SARIF, grant the job `security-events: write` and, for private
repositories, `actions: read`, alongside `contents: read`. Add this step after
the scan:

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

Complete scans remain uploadable after a severity-policy failure. Incomplete
scans, dry runs, and working-tree snapshots are not uploadable. Use a distinct,
stable category for each independent scope (for example, repository versus PR).
Code scanning must be available in the destination repository; see
[GitHub's upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

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

## Runtime and trust boundaries

Use a dedicated ephemeral Linux x64 runner with trusted code and contributors.
Ubuntu 24.04 supplies supported system Python 3.12; Python 3.11 or a Python 3.12
installation in GitHub's hosted tool cache is also supported. npm must be in a
system location or GitHub's Node 24 tool cache. The runner supplies the Node 24
Action runtime. macOS, Windows, ARM, and persistent shared runners are unsupported.
This Action supports GitHub.com; GitHub Enterprise Server is not supported.

The CLI is installed with `npm ci --ignore-scripts` from the committed runtime
lock, including the CLI's `smol-toml` 1.8.0 dependency. Installation receives no
scan credentials.
Only the scan receives the model API key; the GitHub reporting token is not
forwarded to it. Each invocation has its own home, state, and temporary runtime.
Cleanup removes that runtime; reports remain available to downstream job steps.

These controls are not operating-system isolation from other processes running
as the same user. Keep unrelated credentials and deployment tasks in separate
jobs. Fork PRs, Dependabot PRs, `pull_request_target`, and `workflow_run` are
refused. Same-repository origin does not establish contributor trust.

PRs changing any `SECURITY.md` file are refused, including policy-only PRs.
Review and merge policy changes through your repository's authorized process,
then update dependent code PRs. Symlinked PR policies are refused as well.
Knowledge-base and custom prompt files affect analysis and require review.

The Action preserves the pinned CLI's approval and sandbox defaults, including
automatic approval review. `codex-config` permits only the keys listed above;
it cannot override permissions, executables, plugins, or authentication.
Analytics default to disabled. Other CLI versions require an updated runtime
lock and result-adapter validation.

## Troubleshooting

Logs show preparation, scan timing, target revision, and final scan/policy/report
status. CLI diagnostics stream by default; `verbose: 'false'` keeps lifecycle
messages while suppressing scan/export diagnostics. A 30-second elapsed-time
message indicates that the process is running, not that coverage is complete.

For PR-history errors, use the head SHA and `fetch-depth: 0`. For credential
errors, check the caller's secret and `persist-credentials: false`. For skipped
SARIF uploads, inspect `scan-status`, `report-status`, and `sarif-upload-ready`.
For incomplete scans, inspect coverage before adjusting the scope or budget.

## Development

From this repository's root:

```bash
npm --prefix github-action ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run docs
npm --prefix github-action run build
npm --prefix github-action run validate
# On Linux x64 with Node 24 and the prerequisites above; no model calls:
node github-action/scripts/linux-smoke.mjs
```

Commit source changes and both `dist/*.cjs` bundles together. Validation checks
types, unit tests, metadata, generated documentation, and bundle reproducibility.
The Linux smoke test resolves the entrypoint from the root `action.yml` and runs
the bundled Action with the locked CLI against a synthetic checkout, including
its post-cleanup entrypoint.
Release metadata and the SBOM are generated into ignored `build/` files and
saved as CI artifacts. Dependencies and CLI locks remain separate from the SDK.

The `dependencies` CI job audits both locks. The pinned CLI has existing
dependency advisories in `extract-zip` ([symlink extraction](https://github.com/advisories/GHSA-jmr9-qjv8-65gv)
and [arbitrary writes](https://github.com/advisories/GHSA-7pqw-9j4j-h8q3)); this
CLI upgrade does not resolve or waive them. Resolve
the audit findings before treating the integration as production-ready. Updating
the CLI requires reviewing the runtime lock, adapter, and completed-scan fixtures
together. The runtime pin is maintained explicitly rather than automatically
following npm releases.

The Action can be tested from a fork branch before an upstream release. A passing
dry-run does not prove live model execution, named-check publication, artifact
upload, or SARIF ingestion; those require separate integration testing.

## Follow-up tasks

- [ ] Decide how to automate update PRs when a new CLI is published to npm,
  including regenerating the runtime lock and validating compatibility before release.
- [ ] Add a minimal GitHub Action quickstart to the repository root README,
  alongside the SDK and CLI documentation, with a basic workflow and a link
  to this detailed guide.
