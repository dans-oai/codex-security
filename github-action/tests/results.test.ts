import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, writeFile, rm, realpath, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { analyzeResults, readReportFile, type ResultOptions } from '../src/results.js';
import { exportSarifArgs } from '../src/sarif.js';
import { parseInputs } from '../src/inputs.js';

async function fixture(t: { after(fn: () => Promise<void>): void }): Promise<ResultOptions> {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'codex-results-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  await cp(new URL('./fixtures/completed-scan/', import.meta.url), root, { recursive: true });
  return { resultsDirectory: root, cliVersion: '0.1.30', exitCode: 0,
    expected: { scope: 'repository', mode: 'standard', paths: [], scannedSha: 'a'.repeat(40), publishable: true }, failOnSeverity: 'none' };
}
async function change(options: ResultOptions, file: string, update: (value: any) => void, reseal = true): Promise<void> {
  const path = join(options.resultsDirectory, file);
  const value = JSON.parse(await readFile(path, 'utf8'));
  update(value);
  await writeFile(path, JSON.stringify(value));
  if (reseal && ['coverage.json', 'findings.json'].includes(file)) {
    await change(options, 'scan-manifest.json', (manifest) => {
      manifest.scan.artifacts.find((entry: { path: string }) => entry.path === file).sha256 = createHash('sha256').update(JSON.stringify(value)).digest('hex');
    });
  }
}

test('accepts a real pinned CLI exporter fixture as complete and uploadable', async (t) => {
  const result = await analyzeResults(await fixture(t));
  assert.deepEqual(result.errors, []);
  assert.equal(result.scanStatus, 'completed');
  assert.equal(result.policyStatus, 'passed');
  assert.equal(result.reportStatus, 'ready');
  assert.equal(result.sarifUploadReady, true);
  assert.equal(result.counts.high, 1);
  assert.equal(result.estimatedCost, undefined);
});
test('exit 1 preserves completed SARIF after severity policy failure', async (t) => {
  const opts = await fixture(t); opts.exitCode = 1; opts.failOnSeverity = 'high';
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed'); assert.equal(result.policyStatus, 'failed'); assert.equal(result.sarifUploadReady, true);
});
test('exit 2 never passes even with complete artifacts', async (t) => {
  const opts = await fixture(t); opts.exitCode = 2;
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'failed'); assert.equal(result.policyStatus, 'not-evaluated'); assert.equal(result.sarifUploadReady, false);
  assert.equal(result.findings.length, 1);
});
test('partial and unknown coverage remain provisional for exits 0, 1 and 2', async (t) => {
  const opts = await fixture(t);
  for (const completeness of ['partial', 'unknown']) {
    await change(opts, 'coverage.json', (coverage) => { coverage.completeness = completeness; });
    for (const exit of [0, 1, 2]) {
      opts.exitCode = exit;
      const result = await analyzeResults(opts);
      assert.equal(result.scanStatus, 'incomplete'); assert.equal(result.policyStatus, 'not-evaluated'); assert.equal(result.sarifUploadReady, false);
    }
  }
});
test('missing SARIF requests export without invalidating canonical completeness', async (t) => {
  const opts = await fixture(t); await rm(join(opts.resultsDirectory, 'exports/results.sarif'));
  const result = await analyzeResults(opts);
  assert.equal(result.canonicalValid, true); assert.equal(result.scanStatus, 'completed'); assert.equal(result.reportStatus, 'partial'); assert.equal(result.sarifUploadReady, false);
});
test('invalid SARIF does not erase findings', async (t) => {
  const opts = await fixture(t); await change(opts, 'exports/results.sarif', (sarif) => { sarif.runs[0].results = []; });
  const result = await analyzeResults(opts);
  assert.equal(result.findings.length, 1); assert.equal(result.reportStatus, 'partial'); assert.equal(result.paths.sarifPath, '');
});
test('rejects wrong revision, paths and coverage mode', async (t) => {
  const opts = await fixture(t);
  for (const expected of [ { ...opts.expected, scannedSha: 'b'.repeat(40) }, { ...opts.expected, paths: ['src'] }, { ...opts.expected, mode: 'deep' as const } ]) {
    const result = await analyzeResults({ ...opts, expected });
    assert.equal(result.scanStatus, 'failed'); assert.equal(result.canonicalValid, false); assert.equal(result.sarifUploadReady, false);
  }
});
test('equivalent input path spellings accept the completed normalized scope', async (t) => {
  const opts = await fixture(t);
  await change(opts, 'coverage.json', (value) => { value.mode = 'scoped_path'; value.includePaths = ['src']; });
  await change(opts, 'scan-manifest.json', (value) => { value.scan.scope.includePaths = ['src']; });
  for (const mode of ['standard', 'deep'] as const) {
    opts.expected.mode = mode;
    for (const paths of ['src', './src', 'src/', 'src\nsrc', './src/\nsrc']) {
      opts.expected.paths = parseInputs(name => name === 'paths' ? paths : '', '/checkout').paths;
      const result = await analyzeResults(opts);
      assert.deepEqual(result.errors, [], `${mode}: ${paths}`);
      assert.equal(result.scanStatus, 'completed');
      assert.equal(result.sarifUploadReady, true);
    }
  }
  opts.expected.paths = ['lib'];
  const mismatch = await analyzeResults(opts);
  assert.equal(mismatch.scanStatus, 'failed');
  assert.ok(mismatch.errors.includes('Reported scope does not match requested paths.'));
});
test('digest and scan identity mismatches fail closed', async (t) => {
  const opts = await fixture(t); await change(opts, 'findings.json', (value) => { value.scanId = 'other-scan'; }, false);
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'failed'); assert.equal(result.canonicalValid, false);
});
test('complete coverage cannot hide deferred work', async (t) => {
  const opts = await fixture(t); await change(opts, 'coverage.json', (value) => { value.deferred = [{ id: 'x', reason: 'Not reviewed' }]; });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'failed'); assert.match(result.errors.join(' '), /deferred/u);
});
test('exact branch diff identity and coverage modes', async (t) => {
  const opts = await fixture(t);
  opts.expected = { ...opts.expected, scope: 'diff', diffBase: 'b'.repeat(40), diffHead: 'a'.repeat(40) };
  await change(opts, 'scan-manifest.json', (value) => { Object.assign(value.scan.target, { kind: 'git_diff', baseRevision: 'b'.repeat(40), headRevision: 'a'.repeat(40) }); });
  await change(opts, 'coverage.json', (value) => { value.mode = 'branch_diff'; });
  await change(opts, 'exports/results.sarif', (value) => { value.runs[0].properties.codexSecurityTargetKind = 'git_diff'; });
  assert.equal((await analyzeResults(opts)).scanStatus, 'completed');
  opts.expected.diffBase = 'c'.repeat(40);
  assert.equal((await analyzeResults(opts)).scanStatus, 'failed');
});
test('working-tree never becomes SARIF upload ready', async (t) => {
  const opts = await fixture(t);
  opts.expected = { ...opts.expected, scope: 'working-tree', diffBase: 'a'.repeat(40) };
  await change(opts, 'scan-manifest.json', (value) => { Object.assign(value.scan.target, { kind: 'git_diff', baseRevision: 'a'.repeat(40), headRevision: 'a'.repeat(40) }); });
  await change(opts, 'coverage.json', (value) => { value.mode = 'working_tree'; });
  await change(opts, 'exports/results.sarif', (value) => { value.runs[0].properties.codexSecurityTargetKind = 'git_diff'; });
  const result = await analyzeResults(opts);
  assert.equal(result.scanStatus, 'completed'); assert.equal(result.sarifUploadReady, false);
});
test('deep path mode is scoped_path', async (t) => {
  const opts = await fixture(t); opts.expected.mode = 'deep'; opts.expected.paths = ['src'];
  await change(opts, 'coverage.json', (value) => { value.mode = 'scoped_path'; value.includePaths = ['src']; });
  await change(opts, 'scan-manifest.json', (value) => { value.scan.scope.includePaths = ['src']; });
  assert.equal((await analyzeResults(opts)).scanStatus, 'completed');
});
test('malformed finding severity fails instead of counting zero', async (t) => {
  const opts = await fixture(t); await change(opts, 'findings.json', (value) => { value.findings[0].severity.level = 'unknown'; });
  const result = await analyzeResults(opts); assert.equal(result.scanStatus, 'failed'); assert.equal(result.policyStatus, 'not-evaluated');
});
test('remote and encoded traversal SARIF paths rejected', async (t) => {
  const opts = await fixture(t);
  for (const uri of ['https://example.com/source', '%2e%2e/secret', '/etc/passwd', 'a%5cb', '%00file']) {
    await change(opts, 'exports/results.sarif', (value) => { value.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = uri; });
    assert.equal((await analyzeResults(opts)).sarifUploadReady, false);
  }
});
test('safe reader rejects symlinks, hardlinks, FIFO and bounded oversize', async (t) => {
  const opts = await fixture(t); const path = join(opts.resultsDirectory, 'findings.json');
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json', 1));
  await rm(path); await symlink('coverage.json', path);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await rm(path); await link(join(opts.resultsDirectory, 'coverage.json'), path);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await rm(path); execFileSync('mkfifo', [path]);
  await assert.rejects(readReportFile(opts.resultsDirectory, 'findings.json'));
  await assert.rejects(readReportFile(opts.resultsDirectory, '../outside'));
});
test('strict exporter args bind directory and checkout explicitly', () => {
  assert.deepEqual(exportSarifArgs('/tmp/a b', '/repo', '/tmp/a b/exports/results.sarif'),
    ['export', '/tmp/a b', '--export-format', 'sarif', '--source-root', '/repo', '--output', '/tmp/a b/exports/results.sarif']);
});
test('SARIF cannot substitute another target or nested external source', async (t) => {
  const opts = await fixture(t);
  await change(opts, 'exports/results.sarif', (value) => { value.runs[0].versionControlProvenance[0].revisionId = 'b'.repeat(40); });
  assert.equal((await analyzeResults(opts)).sarifUploadReady, false);
  await change(opts, 'exports/results.sarif', (value) => {
    value.runs[0].versionControlProvenance[0].revisionId = 'a'.repeat(40);
    value.runs[0].results[0].relatedLocations = [{ physicalLocation: { artifactLocation: { uri: 'file:///secret' } } }];
  });
  assert.equal((await analyzeResults(opts)).sarifUploadReady, false);
});
