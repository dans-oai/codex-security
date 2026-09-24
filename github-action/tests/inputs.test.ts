import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInputs, scanArguments } from '../src/inputs.js';
const parse = (values: Record<string, string> = {}) => parseInputs(key => values[key] ?? '', '/checkout');

test('defaults are stable across events', () => {
  const input = parse();
  assert.deepEqual(input, {
    repository: '/checkout', scope: 'repository', paths: [], diffBase: undefined,
    model: 'gpt-5.6-sol', effort: 'xhigh', maxCost: undefined, failOnSeverity: 'none',
    verbose: true, dryRun: false, summary: true, annotations: true,
    uploadArtifacts: false, artifactName: 'codex-security', retentionDays: 7,
  });
  const args = scanArguments(input, {repository:'/checkout'}, '/results', '/usr/bin/python3');
  assert.equal(args[args.indexOf('--mode') + 1], 'standard');
  assert.ok(!args.includes('--fail-on-severity'));
});
test('verbose diagnostics default on and can be explicitly disabled', () => {
  const args = (values: Record<string, string>) => scanArguments(parse(values), {repository:'/checkout'}, '/results', '/usr/bin/python3');
  assert.ok(args({}).includes('--verbose'));
  assert.ok(!args({verbose:'false'}).includes('--verbose'));
});
test('only repository and diff scopes are supported, with separate path and diff inputs', () => {
  assert.throws(() => parse({scope:'diff', paths:'src\nlib'}), /cannot be combined/);
  assert.throws(() => parse({scope:'working-tree'}), /scope must be one of: repository, diff/);
  assert.throws(() => parse({'diff-base':'HEAD~1'}), /requires scope: diff/);
});
test('numeric and boolean parsing rejects ambiguous or unbounded input', () => {
  for (const value of ['NaN','Infinity','-1','0','1e99','10 dollars']) assert.throws(() => parse({'max-cost':value}));
  for (const value of ['yes','TRUE','1']) assert.throws(() => parse({verbose:value}));
  for (const value of ['0','1.5','91']) assert.throws(() => parse({'retention-days':value}));
});
test('path lists accept spaces but reject traversal, globs, and option injection', () => {
  assert.deepEqual(parse({paths:'src/my folder\nlib'}).paths, ['src/my folder','lib']);
  for (const paths of ['/etc','../other','src/../../other','src/*','--output-dir','a\\b','C:/other','x\u0000'])
    assert.throws(() => parse({paths}));
});
test('CLI path arguments use normalized, deduplicated repository-relative paths', () => {
  const input = parse({paths:'./src\nsrc/\nsrc\n./lib//./my folder/\n./\n.'});
  assert.deepEqual(input.paths, ['src', 'lib/my folder', '.']);
  const args = scanArguments(input, {repository:'/checkout'}, '/results', '/usr/bin/python3');
  assert.deepEqual(args.flatMap((arg, index) => arg === '--path' ? [args[index + 1]] : []), input.paths);
});
test('model cannot inject a CLI option', () => {
  assert.throws(() => parse({'model':'--plugin-path=evil'}), /not a CLI option/);
});
test('dry-run allows keyless configuration validation', () => {
  const dryArgs=scanArguments(parse({'dry-run':'true'}),{repository:'/checkout'},'/results','/usr/bin/python3');
  assert.equal(dryArgs[dryArgs.indexOf('--auth')+1],'auto'); assert.ok(dryArgs.includes('--dry-run'));
});
test('CLI arguments preserve literal values and enforce CI policy', () => {
  const input = parse({paths:'src/my folder',model:'model; echo never-execute', effort:'medium', 'max-cost':'5', 'fail-on-severity':'high'});
  const args = scanArguments(input, {repository:'/checkout'}, '/private/results', '/usr/bin/python3');
  assert.equal(args[args.indexOf('--provider') + 1], 'openai');
  assert.equal(args[args.indexOf('--auth') + 1], 'api-key');
  assert.ok(args.includes('model; echo never-execute')); assert.ok(args.includes('src/my folder'));
  assert.ok(!args.some(arg => arg.startsWith('approval_policy=')));
  assert.ok(!args.some(arg => arg.startsWith('approvals_reviewer=')));
  assert.ok(args.includes('analytics.enabled=false'));
  assert.equal(args[args.indexOf('--effort') + 1], 'medium');
  assert.equal(args[args.indexOf('--max-cost') + 1], '5');
  assert.equal(args[args.indexOf('--fail-on-severity') + 1], 'high');
  assert.ok(!args.some(value => value.includes('API_KEY')));
});
test('diff arguments use the verified checkout and resolved comparison revisions', () => {
  const input = parse({repository:'component', scope:'diff', 'diff-base':'main'});
  assert.equal(input.repository, 'component');
  assert.equal(input.diffBase, 'main');
  const args = scanArguments(input, {repository:'/checkout/component', diffBase:'base-sha', diffHead:'head-sha'}, '/results', '/usr/bin/python3');
  assert.equal(args[1], '/checkout/component');
  assert.equal(args[args.indexOf('--diff') + 1], 'base-sha');
  assert.equal(args[args.indexOf('--head') + 1], 'head-sha');
});
test('report publication and artifact settings remain configurable', () => {
  const input = parse({summary:'false', annotations:'false', 'upload-artifacts':'true', 'artifact-name':'reports-component', 'retention-days':'14'});
  assert.equal(input.summary, false);
  assert.equal(input.annotations, false);
  assert.equal(input.uploadArtifacts, true);
  assert.equal(input.artifactName, 'reports-component');
  assert.equal(input.retentionDays, 14);
});
