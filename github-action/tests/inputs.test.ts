import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInputs, scanArguments } from '../src/inputs.js';
const parse = (values: Record<string, string> = {}) => parseInputs(key => values[key] ?? '', '/checkout');

test('defaults are stable across events and do not implicitly publish', () => {
  const input = parse();
  assert.equal(input.scope, 'repository'); assert.equal(input.mode, 'standard');
  assert.equal(input.effort, 'xhigh'); assert.equal(input.failOnSeverity, 'none');
  assert.equal(input.publishCheck, false); assert.equal(input.uploadArtifacts, false);
  assert.equal(input.verbose, true);
});
test('verbose diagnostics default on and can be explicitly disabled', () => {
  const args = (values: Record<string, string>) => scanArguments(parse(values), {repository:'/checkout'}, '/results', '/usr/bin/python3');
  assert.ok(args({}).includes('--verbose'));
  assert.ok(!args({verbose:'false'}).includes('--verbose'));
});
test('diff/path conflicts and unsupported deep controls fail before execution', () => {
  for (const scope of ['diff','working-tree']) assert.throws(() => parse({scope, paths:'src\nlib'}), /cannot be combined/);
  for (const scope of ['diff','working-tree']) assert.throws(() => parse({scope, mode:'deep'}), /deep supports/);
  assert.throws(() => parse({workers:'2'}), /require mode: deep/);
  assert.throws(() => parse({'validation-prompt-file':'context.md', mode:'deep'}), /not supported/);
  assert.throws(() => parse({'diff-head':'HEAD'}), /require scope: diff/);
});
test('numeric and boolean parsing rejects ambiguous or unbounded input', () => {
  for (const value of ['NaN','Infinity','-1','0','1e99','10 dollars']) assert.throws(() => parse({'max-cost':value}));
  for (const value of ['yes','TRUE','1']) assert.throws(() => parse({verbose:value}));
  assert.throws(() => parse({mode:'deep', 'max-time-hours':'97'}));
  assert.throws(() => parse({mode:'deep', workers:'1.5'}));
  assert.equal(parse({mode:'deep', subagents:'0'}).subagents, 0);
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
test('config cannot override credentials, executables, approval or supplied model', () => {
  for (const entry of ['approval_policy="never"','approval_policy="on-request"','model="x"','profile="x"','mcp_servers.x.command="evil"','plugins=[]','analytics.enabled="false"','analytics.enabled=false\nanalytics.enabled=true'])
    assert.throws(() => parse({'codex-config':entry}));
  assert.equal(parse({'codex-config':'analytics.enabled=false\nfeatures.multi_agent_v2.max_concurrent_threads_per_session=4'}).codexConfig.length, 2);
  assert.throws(() => parse({'model':'--plugin-path=evil'}), /not a CLI option/);
  assert.throws(() => parse({'safety-identifier':'--patch'}), /hyphen/);
});
test('check publication requires credentials and cannot be a dry-run', () => {
  assert.throws(() => parse({'publish-check':'true'}), /github-token/);
  assert.throws(() => parse({'publish-check':'true','github-token':'test','dry-run':'true'}), /dry-run/);
  const dryArgs=scanArguments(parse({'dry-run':'true'}),{repository:'/checkout'},'/results','/usr/bin/python3');
  assert.equal(dryArgs[dryArgs.indexOf('--auth')+1],'auto'); assert.ok(dryArgs.includes('--dry-run'));
});
test('CLI arguments preserve literal values and enforce CI policy', () => {
  const input = parse({paths:'src/my folder',model:'model; echo never-execute', 'max-cost':'5', 'fail-on-severity':'high'});
  const args = scanArguments(input, {repository:'/checkout'}, '/private/results', '/usr/bin/python3');
  assert.equal(args[args.indexOf('--provider') + 1], 'openai');
  assert.equal(args[args.indexOf('--auth') + 1], 'api-key');
  assert.ok(args.includes('model; echo never-execute')); assert.ok(args.includes('src/my folder'));
  assert.ok(!args.some(arg => arg.startsWith('approval_policy=')));
  assert.ok(!args.some(arg => arg.startsWith('approvals_reviewer=')));
  assert.ok(args.includes('analytics.enabled=false'));
  assert.equal(args[args.indexOf('--fail-on-severity') + 1], 'high');
  assert.ok(!args.some(value => value.includes('API_KEY')));
});
