import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import * as core from '@actions/core';
import { runAction } from '../src/main.js';
import { INPUT_NAMES } from '../src/inputs.js';
import { gitEnvironment } from '../src/targets.js';
import type { Runtime } from '../src/runtime.js';
import type { ProcessResult } from '../src/process.js';

type Scenario = 'schedule' | 'pr' | 'policy-pr';
const inputKey = (name: string): string => `INPUT_${name.toUpperCase()}`;

function outputValues(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const marker = line.indexOf('<<');
    if (marker < 0) continue;
    const name = line.slice(0, marker);
    const delimiter = line.slice(marker + 2);
    const value: string[] = [];
    while (++index < lines.length && lines[index] !== delimiter) value.push(lines[index]);
    values[name] = value.join('\n');
  }
  return values;
}

async function harness(t: TestContext, scenario: Scenario = 'schedule') {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-main-test-')));
  const repository = join(root, 'repo');
  await mkdir(repository);
  const git = (...args: string[]): string => execFileSync('/usr/bin/git', [
    '-c', 'user.name=Offline Test', '-c', 'user.email=offline@example.invalid', '-c', 'core.hooksPath=/dev/null', ...args,
  ], { cwd: repository, env: gitEnvironment(), encoding: 'utf8' }).trim();
  git('init', '-q', '-b', 'main');
  git('remote', 'add', 'origin', 'https://github.com/example/repo.git');
  await writeFile(join(repository, 'app.txt'), 'synthetic source\n');
  git('add', '.'); git('commit', '-qm', 'base');
  const base = git('rev-parse', 'HEAD');
  if (scenario !== 'schedule') {
    await writeFile(join(repository, scenario === 'policy-pr' ? 'SECURITY.md' : 'app.txt'), 'synthetic change\n');
    git('add', '.'); git('commit', '-qm', 'PR change');
  }
  const sha = git('rev-parse', 'HEAD');
  const previousEnv = { ...process.env };
  const previousExitCode = process.exitCode;
  t.after(async () => {
    for (const key of Object.keys(process.env)) if (!(key in previousEnv)) delete process.env[key];
    Object.assign(process.env, previousEnv);
    process.exitCode = previousExitCode;
    await rm(root, { recursive: true, force: true });
  });
  for (const name of INPUT_NAMES) delete process.env[inputKey(name)];
  const eventPath = join(root, 'event.json');
  const outputPath = join(root, 'outputs');
  const statePath = join(root, 'state');
  const payload = scenario === 'schedule' ? {} : { number: 4, pull_request: { number: 4,
    head: { sha, repo: { full_name: 'example/repo' } }, base: { sha: base, repo: { full_name: 'example/repo' } } } };
  await writeFile(eventPath, JSON.stringify(payload));
  await writeFile(outputPath, ''); await writeFile(statePath, '');
  Object.assign(process.env, {
    GITHUB_EVENT_PATH: eventPath, GITHUB_EVENT_NAME: scenario === 'schedule' ? 'schedule' : 'pull_request',
    GITHUB_REPOSITORY: 'example/repo', GITHUB_WORKSPACE: repository, GITHUB_SHA: sha,
    GITHUB_REF: scenario === 'schedule' ? 'refs/heads/main' : 'refs/pull/4/merge',
    GITHUB_ACTOR: 'trusted-maintainer', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_OUTPUT: outputPath, GITHUB_STATE: statePath, RUNNER_TEMP: root,
    OPENAI_API_KEY: 'synthetic-offline-test-key', INPUT_SUMMARY: 'true', INPUT_ANNOTATIONS: 'false',
    INPUT_SCOPE: scenario === 'schedule' ? 'repository' : 'diff',
  });
  delete process.env.CODEX_API_KEY;
  const runtime: Runtime = {
    root: join(root, 'runtime'), home: join(root, 'runtime/home'), codexHome: join(root, 'runtime/codex'),
    stateDirectory: join(root, 'runtime/state'), resultsDirectory: join(root, 'results'),
    nodePath: '/never-executed/node', cliPath: '/never-executed/cli.js', pythonPath: '/never-executed/python',
    env: (key) => ({ OPENAI_API_KEY: key }),
  };
  let setups = 0;
  let processes = 0;
  let cleanups = 0;
  let executionExit: number | undefined;
  let scanOutput = '';
  let cliFailure = false;
  let incomplete = false;
  let omitSarif = false;
  let mutateCheckout = false;
  let exportSucceeds = true;
  let cleanupFails = false;
  let summary = '';
  t.mock.method(core.summary, 'write', async () => {
    summary = core.summary.stringify();
    core.summary.emptyBuffer();
    return core.summary;
  });
  t.after(() => { core.summary.emptyBuffer(); });
  let capturedArgs: readonly string[] = [];
  let capturedEnvironment: NodeJS.ProcessEnv = {};
  async function reports(): Promise<void> {
    await cp(new URL('./fixtures/completed-scan/', import.meta.url), runtime.resultsDirectory, { recursive: true });
    const manifestPath = join(runtime.resultsDirectory, 'scan-manifest.json');
    const coveragePath = join(runtime.resultsDirectory, 'coverage.json');
    const sarifPath = join(runtime.resultsDirectory, 'exports/results.sarif');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const coverage = JSON.parse(await readFile(coveragePath, 'utf8'));
    const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
    manifest.scan.target.revision = sha;
    if (scenario !== 'schedule') {
      Object.assign(manifest.scan.target, { kind: 'git_diff', baseRevision: base, headRevision: sha });
      coverage.mode = 'branch_diff';
      sarif.runs[0].properties.codexSecurityTargetKind = 'git_diff';
    }
    if (process.env.INPUT_SCOPE === 'working-tree') {
      Object.assign(manifest.scan.target, { kind: 'git_diff', baseRevision: sha, headRevision: sha });
      coverage.mode = 'working_tree';
      sarif.runs[0].properties.codexSecurityTargetKind = 'git_diff';
    }
    if (incomplete) {
      coverage.completeness = 'partial';
      coverage.deferred = [{id: 'unreviewed-route', reason: 'Dependency <example> unavailable; validation deferred.'}];
    }
    sarif.runs[0].versionControlProvenance[0].revisionId = sha;
    await writeFile(coveragePath, JSON.stringify(coverage));
    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(sarifPath, JSON.stringify(sarif));
    if (omitSarif) await rm(sarifPath);
    scanOutput = JSON.stringify({manifest, coverage, findings: JSON.parse(await readFile(join(runtime.resultsDirectory, 'findings.json'), 'utf8')),
      scanDir: runtime.resultsDirectory, sarifPath: omitSarif ? null : sarifPath, cost: {estimatedUsd: 0.125}});
  }
  return {
    repository, sha, base, git, runtime,
    setInput: (name: string, value: string) => { process.env[inputKey(name)] = value; },
    configure: (options: { exitCode?: number; partial?: boolean; missingSarif?: boolean; mutateCheckout?: boolean; exportSucceeds?: boolean; cleanupFails?: boolean; cliFailure?: boolean }) => {
      executionExit = options.exitCode ?? executionExit; incomplete = options.partial ?? incomplete;
      omitSarif = options.missingSarif ?? omitSarif; mutateCheckout = options.mutateCheckout ?? mutateCheckout;
      exportSucceeds = options.exportSucceeds ?? exportSucceeds;
      cleanupFails = options.cleanupFails ?? cleanupFails;
      cliFailure = options.cliFailure ?? cliFailure;
    },
    run: async () => {
      const logs: string[] = [];
      const originalWrite = process.stdout.write;
      process.stdout.write = ((chunk: string | Uint8Array, encodingOrCallback?: unknown, callback?: unknown): boolean => {
        logs.push(String(chunk));
        if (typeof encodingOrCallback === 'function') encodingOrCallback();
        else if (typeof callback === 'function') callback();
        return true;
      }) as typeof process.stdout.write;
      let exitCode: typeof process.exitCode;
      try {
        process.exitCode = 0;
        await runAction(root, {
          setupRuntime: async () => { setups++; await reports(); return runtime; },
          cleanupRuntime: async () => { cleanups++; if (cleanupFails) throw new Error('Synthetic cleanup failure'); },
          runProcess: async (_executable, args, options): Promise<ProcessResult> => {
            processes++; capturedArgs = args; capturedEnvironment = options.env;
            options.log?.('[codex-security] Synthetic live CLI progress.');
            if (mutateCheckout) await writeFile(join(repository, 'app.txt'), 'modified while scanning\n');
            if (args[1] === 'export' && exportSucceeds) { omitSarif = false; await reports(); }
            return { exitCode: args[1] === 'export' ? (exportSucceeds ? 0 : 2) : executionExit ?? (process.env['INPUT_FAIL-ON-SEVERITY'] === 'high' ? 1 : 0), signal: null,
              stdout: cliFailure ? JSON.stringify({status: 'failed', code: 'SCAN_FAILED', message: 'Synthetic API authentication failure.'}) : scanOutput, stderr: '', interrupted: false, timedOut: false, truncated: false };
          },
        });
        exitCode = process.exitCode;
      } finally { process.stdout.write = originalWrite; process.exitCode = previousExitCode; }
      return { exitCode, setups, processes, cleanups, summary, args: capturedArgs, environment: capturedEnvironment,
        outputs: outputValues(await readFile(outputPath, 'utf8')), logs: logs.join('') };
    },
  };
}

test('PR severity failure retains complete SARIF outputs for always upload steps', async (t) => {
  const app = await harness(t, 'pr'); app.setInput('fail-on-severity', 'high'); app.configure({ exitCode: 1 });
  app.setInput('model', 'gpt-5.6-luna'); app.setInput('effort', 'medium');
  app.setInput('annotations', ''); // Use the default, as in the README's PR workflow.
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['policy-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'true'); assert.equal(result.outputs['analysis-ref'], 'refs/pull/4/head');
  assert.equal(result.outputs['scanned-sha'], app.sha); assert.equal(result.outputs['high-count'], '1');
  assert.equal(result.outputs['estimated-cost'], '0.125'); assert.ok(result.outputs['sarif-path']);
  assert.equal(result.args[result.args.indexOf('--model') + 1], 'gpt-5.6-luna');
  assert.equal(result.args[result.args.indexOf('--effort') + 1], 'medium');
  assert.ok(!result.args.includes('--max-cost'));
  assert.match(result.logs, /::error::Scan completed\. Findings meet the configured failure threshold\./);
  assert.match(result.summary, /^## Codex Security\n\n\*\*Scan completed\. Findings meet the configured failure threshold\.\*\*/);
  const annotation = /^::warning ([^\r\n]+)::([^\r\n]+)$/m.exec(result.logs);
  assert.ok(annotation, 'PR findings must emit a GitHub warning annotation even when the severity policy fails');
  const properties = Object.fromEntries(annotation[1].split(',').map(property => property.split('=')));
  assert.equal(properties.file, 'src/extract.py');
  assert.equal(properties.line, '41'); assert.equal(properties.endLine, '44');
  assert.match(properties.title, /^HIGH%3A Unsafe archive extraction/);
  assert.match(annotation[2], /filesystem write without containment validation/);
});

test('scheduled complete report-only scan succeeds', async (t) => {
  const app = await harness(t); const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['policy-status'], 'passed'); assert.equal(result.outputs['sarif-upload-ready'], 'true');
  assert.equal(result.outputs['analysis-ref'], 'refs/heads/main');
  assert.ok(result.args.includes('--verbose'));
  assert.match(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /CLI preparation completed in \d+m \d+s/);
  assert.match(result.logs, /Target commit: [a-f0-9]{40}/);
  assert.match(result.logs, /Security scan exited after \d+m \d+s; exit code: 0/);
  assert.match(result.logs, /Scan: completed; findings policy: passed; report: ready/);
  assert.match(result.logs, /Estimated cost: \$0.1250/);
  assert.match(result.logs, /Scan completed\. Findings are reported without failing the job\./);
  assert.match(result.summary, /\*\*Scan completed\. Findings are reported without failing the job\.\*\*/);
});

test('findings below the threshold pass with an explicit outcome', async (t) => {
  const app = await harness(t); app.setInput('fail-on-severity', 'critical');
  const result = await app.run();
  assert.equal(result.exitCode, 0);
  assert.equal(result.outputs['high-count'], '1');
  assert.match(result.logs, /Scan completed\. No findings meet the failure threshold\./);
  assert.match(result.summary, /\*\*Scan completed\. No findings meet the failure threshold\.\*\*/);
});

test('missing API key reports an incomplete scan with the credential diagnostic', async (t) => {
  const app = await harness(t); delete process.env.OPENAI_API_KEY;
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.processes, 0);
  assert.equal(result.outputs['policy-status'], 'not-evaluated');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.logs, /::error::Scan could not complete\./);
  assert.match(result.summary, /\*\*Scan could not complete\.\*\*/);
  assert.match(result.summary, /Set the CODEX_SECURITY_API_KEY repository secret/);
  assert.doesNotMatch(result.logs, /Findings meet the configured failure threshold/);
});

test('cleanup failure fails the job and appears in the summary and final error', async (t) => {
  const app = await harness(t); app.configure({cleanupFails: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.cleanups, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['report-status'], 'failed');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.logs, /::error::Scan completed\..*Runtime cleanup failed\./);
  assert.match(result.summary, /Runtime cleanup failed\.\*\*/);
});

for (const threshold of ['none', 'high']) {
  test(`summary write failure preserves the scan result with severity threshold ${threshold}`, async (t) => {
    const app = await harness(t);
    app.setInput('summary', 'true'); app.setInput('fail-on-severity', threshold);
    t.mock.method(core.summary, 'write', async () => { throw new Error('Synthetic summary write failure'); });
    t.after(() => { core.summary.emptyBuffer(); });
    const result = await app.run();
    assert.equal(result.exitCode, threshold === 'none' ? 0 : 1);
    assert.equal(result.outputs['scan-status'], 'completed');
    assert.equal(result.outputs['policy-status'], threshold === 'none' ? 'passed' : 'failed');
    assert.equal(result.outputs['report-status'], 'ready');
    assert.equal(result.outputs['sarif-upload-ready'], 'true');
    assert.ok(result.outputs['sarif-path']);
    assert.equal(result.cleanups, 1);
    assert.match(result.logs, /::warning::Could not write the job summary\./);
  });
}

test('verbose false suppresses CLI diagnostics but retains lifecycle and results', async (t) => {
  const app = await harness(t); app.setInput('verbose', 'false'); const result = await app.run();
  assert.equal(result.exitCode, 0);
  assert.ok(!result.args.includes('--verbose'));
  assert.doesNotMatch(result.logs, /Synthetic live CLI progress/);
  assert.match(result.logs, /Starting security scan/);
  assert.match(result.logs, /Scan: completed/);
});

test('configuration values in logs are redacted and cannot inject runner commands', async (t) => {
  const app = await harness(t);
  app.setInput('model', 'synthetic-offline-test-key\u2028::error::injected');
  const result = await app.run();
  // The runner mask-registration command contains the key by design.
  const logs = result.logs.split('\n').filter(line => !line.startsWith('::add-mask::')).join('\n');
  assert.doesNotMatch(logs, /synthetic-offline-test-key/);
  assert.doesNotMatch(logs, /^::error::injected/m);
  assert.match(logs, /\[REDACTED\]/);
});

test('partial scan fails with provisional findings and no upload eligibility', async (t) => {
  const app = await harness(t); app.configure({ exitCode: 2, partial: true }); app.setInput('verbose', 'false');
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'incomplete');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], '1'); assert.ok(result.outputs['json-path']);
  assert.match(result.logs, /Provisional findings:/);
  assert.match(result.logs, /::error::Scan could not complete\. Available findings are provisional\./);
  assert.match(result.summary, /\*\*Scan could not complete\. Available findings are provisional\.\*\*/);
  assert.match(result.summary, /Deferred work: Dependency &lt;example&gt; unavailable; validation deferred\./);
  assert.match(result.logs, /Report diagnostic: Deferred work: Dependency <example> unavailable; validation deferred\./);
  assert.doesNotMatch(result.logs, /Synthetic live CLI progress/);
});

test('wrong checkout fails before setup or scanner execution', async (t) => {
  const app = await harness(t); process.env.GITHUB_SHA = '0'.repeat(40); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 0); assert.equal(result.processes, 0);
  assert.equal(result.outputs['scan-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
});

test('PR policy changes are scanned at the checked-out revision', async (t) => {
  const app = await harness(t, 'policy-pr'); const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.setups, 1); assert.equal(result.processes, 1);
  assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['scanned-sha'], app.sha);
  assert.ok(result.args.includes('--diff')); assert.ok(result.args.includes(app.sha));
});

test('dry-run is explicitly skipped with no findings policy pass', async (t) => {
  const app = await harness(t); app.setInput('dry-run', 'true'); delete process.env.OPENAI_API_KEY;
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'skipped'); assert.equal(result.outputs['skip-reason'], 'dry-run');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['high-count'], ''); assert.ok(result.args.includes('--dry-run')); assert.equal(result.environment.OPENAI_API_KEY, undefined);
});

test('scope conflict fails without runtime setup', async (t) => {
  const app = await harness(t, 'pr'); app.setInput('paths', 'app.txt'); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.setups, 0); assert.match(result.logs, /paths cannot be combined/u);
});

test('changed checkout during scan prevents a completed result', async (t) => {
  const app = await harness(t); app.configure({ mutateCheckout: true }); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.ok(result.outputs['json-path']);
  assert.match(result.logs, /Report diagnostic: The source checkout changed/);
});

test('strict export repairs missing best-effort SARIF without model credentials', async (t) => {
  const app = await harness(t); app.configure({ missingSarif: true }); const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.processes, 2); assert.equal(result.args[1], 'export');
  assert.equal(result.environment.OPENAI_API_KEY, undefined); assert.equal(result.outputs['sarif-upload-ready'], 'true');
});

test('failed strict export leaves a failed action with partial report', async (t) => {
  const app = await harness(t); app.configure({ missingSarif: true, exportSucceeds: false }); const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'completed'); assert.equal(result.outputs['report-status'], 'partial');
  assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.match(result.logs, /::error::Scan completed, but required reporting failed\./);
  assert.match(result.summary, /\*\*Scan completed, but required reporting failed\.\*\*/);
});

test('working-tree results retain local reports without code-scanning upload', async (t) => {
  const app = await harness(t); app.setInput('scope', 'working-tree');
  await writeFile(join(app.repository, 'app.txt'), 'local change\n');
  const result = await app.run();
  assert.equal(result.exitCode, 0); assert.equal(result.outputs['scan-status'], 'completed');
  assert.equal(result.outputs['sarif-upload-ready'], 'false'); assert.equal(result.outputs['analysis-ref'], '');
});

test('CLI authentication failure is not reported as a findings threshold failure', async (t) => {
  const app = await harness(t); app.configure({exitCode: 2, cliFailure: true});
  const result = await app.run();
  assert.equal(result.exitCode, 1); assert.equal(result.outputs['scan-status'], 'failed');
  assert.equal(result.outputs['policy-status'], 'not-evaluated'); assert.equal(result.outputs['sarif-upload-ready'], 'false');
  assert.equal(result.outputs['json-path'], '');
  assert.match(result.summary, /Synthetic API authentication failure/);
  assert.doesNotMatch(result.logs, /Findings meet the configured failure threshold/);
});
