import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cleanupRuntime, runtimeEnvironment, setupRuntime, trustedNpm, trustedPython, validateRuntimeLock } from '../src/runtime.js';

function pythonFilesystem(files: Record<string, string>, entries: string[] = []) {
  return {
    regularFile: async (path: string) => {
      if (!(path in files)) throw new Error('Missing or unsafe file');
      return files[path];
    },
    readdir: async (path: string) => {
      assert.equal(path, '/opt/hostedtoolcache/Python');
      return entries;
    },
  };
}

test('Python discovery supports Ubuntu 22.04 hosted cache and versioned system Python', async () => {
  const cached = '/opt/hostedtoolcache/Python/3.12.14/x64/bin/python3.12';
  assert.equal(await trustedPython(pythonFilesystem({ [cached]: cached }, ['3.10.12', '3.12.9', '3.12.14'])), cached);
  const system = '/usr/bin/python3.12';
  assert.equal(await trustedPython(pythonFilesystem({ [system]: system })), system);
});

test('Python discovery rejects symlink escapes, unapproved versions, and oversized caches', async () => {
  const candidate = '/opt/hostedtoolcache/Python/3.12.14/x64/bin/python3.12';
  for (const target of ['/home/runner/work/repo/python', '/opt/hostedtoolcache/Python/3.12.9/x64/bin/python3.12']) {
    await assert.rejects(trustedPython(pythonFilesystem({ [candidate]: target }, ['3.12.14', '3.12.14/../../repo', '3.14.0'])), /trusted Python/);
  }
  await assert.rejects(trustedPython(pythonFilesystem({ '/usr/bin/python3.12': '/tmp/python' })), /trusted Python/);
  await assert.rejects(trustedPython(pythonFilesystem({ [candidate]: candidate }, Array(257).fill('3.12.14'))), /trusted Python/);
  await assert.rejects(trustedPython(pythonFilesystem({})), /trusted Python/);
});

function npmFilesystem(files: Record<string, string>, entries: string[] = []) {
  const visited: string[] = [];
  return { visited, regularFile: async (path: string) => {
    visited.push(path);
    if (!(path in files)) throw new Error('Missing or unsafe file');
    return files[path];
  }, readdir: async (path: string) => {
    assert.equal(path, '/opt/hostedtoolcache/node');
    return entries;
  } };
}

test('npm discovery supports hosted Node 24 without a system npm symlink', async () => {
  const npm = '/opt/hostedtoolcache/node/24.20.0/x64/lib/node_modules/npm/bin/npm-cli.js';
  const fs = npmFilesystem({ [npm]: npm }, ['24.9.0', '24.20.0', '22.23.2']);
  assert.equal(await trustedNpm(fs), npm);
  assert.equal(fs.visited.at(-1), npm);
});

test('npm discovery retains fixed system installations and legitimate symlinks', async () => {
  const npm = '/usr/local/lib/node_modules/npm/bin/npm-cli.js';
  assert.equal(await trustedNpm(npmFilesystem({ [npm]: npm })), npm);
  const cached = '/opt/hostedtoolcache/node/24.20.0/x64/lib/node_modules/npm/bin/npm-cli.js';
  assert.equal(await trustedNpm(npmFilesystem({ '/usr/bin/npm': cached })), cached);
});

test('npm discovery rejects malformed cache entries and symlink escapes', async () => {
  const candidate = '/opt/hostedtoolcache/node/24.20.0/x64/lib/node_modules/npm/bin/npm-cli.js';
  for (const escaped of ['/home/runner/work/repo/npm/bin/npm-cli.js', '/usr/evil/npm/bin/npm-cli.js', '/opt/hostedtoolcache/node/24.19.0/x64/lib/node_modules/npm/bin/npm-cli.js']) {
    const fs = npmFilesystem({ [candidate]: escaped }, ['../../repo', '24.20.0/../../repo', '24.20.0', '24.21.0-rc.1', '26.0.0']);
    await assert.rejects(trustedNpm(fs), /trusted npm/);
    assert.equal(fs.visited.filter(path => path.startsWith('/opt/')).length, 1);
  }
  await assert.rejects(trustedNpm(npmFilesystem({ '/usr/bin/npm': '/usr/evil/npm/bin/npm-cli.js' })), /trusted npm/);
});

test('npm discovery bounds cache enumeration and fails clearly when absent', async () => {
  await assert.rejects(trustedNpm(npmFilesystem({}, Array(257).fill('24.20.0'))), /trusted npm/);
  await assert.rejects(trustedNpm({ ...npmFilesystem({}), readdir: async () => { throw new Error('No cache'); } }), /actions\/setup-node/);
});

test('scan environment excludes all inherited credential/config channels', () => {
  const poison = { INPUT_GITHUB_TOKEN: 'secret', GITHUB_TOKEN: 'secret', ACTIONS_RUNTIME_TOKEN: 'secret', GITHUB_OUTPUT: 'file', NODE_OPTIONS: '--require=evil', PYTHONPATH: 'evil', NPM_CONFIG_REGISTRY: 'evil', AWS_SECRET_ACCESS_KEY: 'secret', CODEX_CLI_PATH: 'evil', OPENAI_BASE_URL: 'evil', HTTPS_PROXY: 'evil' };
  const previous = Object.fromEntries(Object.keys(poison).map((key) => [key, process.env[key]]));
  Object.assign(process.env, poison);
  try {
    const paths = { root: '/tmp/owned', home: '/tmp/owned/home', codexHome: '/tmp/owned/codex', stateDirectory: '/tmp/owned/state', pythonPath: '/usr/bin/python3' };
    const installer = runtimeEnvironment(paths);
    const scanner = runtimeEnvironment(paths, 'scan-only-key');
    for (const key of Object.keys(poison)) { assert.equal(installer[key], undefined); assert.equal(scanner[key], undefined); }
    assert.equal(installer.OPENAI_API_KEY, undefined);
    assert.equal(scanner.OPENAI_API_KEY, 'scan-only-key');
    assert.equal(scanner.PYTHONSAFEPATH, '1');
    assert.equal(scanner.GIT_CONFIG_VALUE_0, '');
  } finally { for (const key of Object.keys(poison)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } }
});

test('shipped runtime lock has integrity for all transitive platform artifacts', async () => {
  const lock = JSON.parse(await readFile(new URL('../runtime/0.1.29/package-lock.json', import.meta.url), 'utf8'));
  validateRuntimeLock(lock);
  const manifest = JSON.parse(await readFile(new URL('../runtime/0.1.29/package.json', import.meta.url), 'utf8'));
  assert.equal(manifest.dependencies['@openai/codex-security'], '0.1.29');
  assert.equal(lock.packages['node_modules/smol-toml'].version, '1.8.0');
  const regressed = structuredClone(lock);
  regressed.packages['node_modules/smol-toml'].version = '1.6.1';
  assert.throws(() => validateRuntimeLock(regressed), /security fix/);
  const nested = structuredClone(lock);
  nested.packages['node_modules/@openai/codex-security/node_modules/smol-toml'] = { ...lock.packages['node_modules/smol-toml'], version: '1.6.1' };
  assert.throws(() => validateRuntimeLock(nested), /security fix/);
  for (const mutation of ['url', 'integrity', 'link']) {
    const malicious = structuredClone(lock);
    const pkg = malicious.packages['node_modules/@openai/codex-security'];
    if (mutation === 'url') pkg.resolved = 'https://attacker.invalid/archive.tgz';
    if (mutation === 'integrity') delete pkg.integrity;
    if (mutation === 'link') pkg.link = true;
    assert.throws(() => validateRuntimeLock(malicious), /unapproved/);
  }
});

test('cleanup preserves reports and rejects arbitrary or symlink roots', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'runtime-test-'));
  const base = await import('node:fs/promises').then((fs) => fs.realpath(temp));
  const owned = join(base, 'codex-security-runtime-abc');
  const reports = join(base, 'codex-security-reports-abc');
  try {
    await mkdir(owned); await mkdir(reports);
    await writeFile(join(owned, '.codex-security-action-owned'), 'codex-security-action-v1\n');
    await writeFile(join(reports, 'report.sarif'), '{}');
    const link = join(base, 'codex-security-runtime-link');
    await symlink(owned, link);
    await assert.rejects(cleanupRuntime(link, base), /Refusing/);
    await assert.rejects(cleanupRuntime(reports, base), /Refusing/);
    await cleanupRuntime(owned, base);
    assert.ok((await stat(join(reports, 'report.sarif'))).isFile());
    await cleanupRuntime(owned, base);
  } finally { await rm(base, { recursive: true, force: true }); }
});

test('unreviewed versions fail before platform detection or installation', async () => {
  await assert.rejects(setupRuntime({ actionRoot: '/none', tempRoot: '/none', version: 'latest' }), /reviewed/);
});
