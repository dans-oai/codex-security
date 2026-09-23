import { constants } from 'node:fs';
import { access, chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { runProcess, safeLogLines } from './process.js';
import runtimeManifest from '../runtime/package.json' with { type: 'json' };

export const SUPPORTED_CLI_VERSION = runtimeManifest.dependencies['@openai/codex-security'];
export const PATCHED_TOML_VERSION = '1.8.0';
const MARKER = '.codex-security-action-owned';
const ROOT_PREFIX = 'codex-security-runtime-';
const REGISTRY = 'https://registry.npmjs.org/';

export interface RuntimeOptions {
  actionRoot: string;
  tempRoot: string;
  log?: (line: string) => void;
}
export interface Runtime {
  nodePath: string;
  cliPath: string;
  pythonPath: string;
  root: string;
  home: string;
  codexHome: string;
  stateDirectory: string;
  resultsDirectory: string;
  env: (apiKey: string) => NodeJS.ProcessEnv;
}

export function validateRuntimeLock(lock: unknown): void {
  if (!lock || typeof lock !== 'object') throw new Error('Invalid runtime dependency lock.');
  const data = lock as { lockfileVersion?: number; packages?: Record<string, { resolved?: string; integrity?: string; link?: boolean; version?: string; dependencies?: Record<string, string> }> };
  if (data.lockfileVersion !== 3 || !data.packages || data.packages['']?.dependencies?.['@openai/codex-security'] !== SUPPORTED_CLI_VERSION) throw new Error('Runtime lock does not match the reviewed CLI version.');
  for (const [name, entry] of Object.entries(data.packages)) {
    if (!name) continue;
    if (!name.startsWith('node_modules/') || name.split('/').includes('..') || entry.link || !entry.resolved?.startsWith(REGISTRY) || !/^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity ?? '')) {
      throw new Error(`Runtime lock contains an unapproved dependency record: ${name}`);
    }
    const url = new URL(entry.resolved);
    if (url.origin !== 'https://registry.npmjs.org' || url.username || url.password || url.hash || url.search) throw new Error('Runtime lock contains an unapproved registry URL.');
    if (name.endsWith('/smol-toml') && entry.version !== PATCHED_TOML_VERSION) throw new Error('Runtime lock omits the reviewed smol-toml security fix.');
  }
  if (data.packages['node_modules/@openai/codex-security']?.version !== SUPPORTED_CLI_VERSION) throw new Error('Runtime CLI version mismatch.');
  if (!data.packages['node_modules/@openai/codex-linux-x64']) throw new Error('Runtime lock omits the supported platform binary.');
  if (data.packages['node_modules/smol-toml']?.version !== PATCHED_TOML_VERSION) throw new Error('Runtime lock omits the reviewed smol-toml security fix.');
}

/** Deliberately construct a new environment: never copy process.env. */
export function runtimeEnvironment(paths: Pick<Runtime, 'root' | 'home' | 'codexHome' | 'stateDirectory' | 'pythonPath'>, apiKey?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: `${join(paths.root, 'bin')}:/usr/bin:/bin`,
    HOME: paths.home, CODEX_HOME: paths.codexHome,
    CODEX_SECURITY_STATE_DIR: paths.stateDirectory,
    TMPDIR: join(paths.root, 'tmp'), TMP: join(paths.root, 'tmp'), TEMP: join(paths.root, 'tmp'),
    XDG_CONFIG_HOME: join(paths.home, '.config'), XDG_CACHE_HOME: join(paths.home, '.cache'),
    CI: 'true', NO_COLOR: '1', TERM: 'dumb', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    CODEX_SECURITY_NO_UPDATE_NOTICE: '1', NO_UPDATE_NOTIFIER: '1',
    PYTHON: paths.pythonPath, PYTHONNOUSERSITE: '1', PYTHONSAFEPATH: '1', PYTHONUTF8: '1',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_COUNT: '4',
    GIT_CONFIG_KEY_0: 'credential.helper', GIT_CONFIG_VALUE_0: '',
    GIT_CONFIG_KEY_1: 'core.hooksPath', GIT_CONFIG_VALUE_1: '/dev/null',
    GIT_CONFIG_KEY_2: 'core.fsmonitor', GIT_CONFIG_VALUE_2: 'false',
    GIT_CONFIG_KEY_3: 'core.askPass', GIT_CONFIG_VALUE_3: '/bin/false',
  };
  if (apiKey !== undefined) {
    if (!apiKey || /[\r\n\u0000]/.test(apiKey)) throw new Error('OPENAI_API_KEY must be a nonempty single-line value.');
    env.OPENAI_API_KEY = apiKey;
  }
  return env;
}

async function regularFile(path: string, executable = false, runnerProvided = false): Promise<string> {
  const target = await realpath(path);
  const info = await lstat(target);
  // Hosted images deliberately expose writable Node/npm tools. That exception is
  // limited to approved npm locations and the Node executable already running us;
  // downloaded CLI files and action manifests retain the stricter mode check.
  if (!info.isFile() || (!runnerProvided && (info.mode & 0o022) !== 0)) throw new Error('Runtime prerequisite must be a regular file without group/world write access.');
  if (executable) await access(target, constants.X_OK);
  return target;
}

export async function trustedPython(fs: {
  regularFile: (path: string) => Promise<string>;
  readdir: (path: string) => Promise<string[]>;
} = { regularFile: path => regularFile(path, true), readdir }): Promise<string> {
  // Ubuntu 22.04 has Python 3.10 at /usr/bin/python3. Use only fixed,
  // versioned system paths or GitHub's canonical Python 3.12 cache.
  for (const candidate of ['/usr/bin/python3.12', '/usr/bin/python3.11']) {
    try {
      const target = await fs.regularFile(candidate);
      if (target === candidate) return target;
    } catch { /* Try the next approved location. */ }
  }
  const cache = '/opt/hostedtoolcache/Python';
  const entries = await fs.readdir(cache).catch(() => []);
  if (entries.length <= 256) {
    const versions = entries.filter(version => /^3\.12\.\d{1,5}$/.test(version))
      .sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
    for (const version of versions) {
      const candidate = join(cache, version, 'x64/bin/python3.12');
      try {
        const target = await fs.regularFile(candidate);
        if (target === candidate) return target;
      } catch { /* Try the next approved installation. */ }
    }
  }
  throw new Error('A trusted Python 3.11/3.12 installation is required. Use a GitHub-hosted Ubuntu runner with Python 3.12 in /opt/hostedtoolcache/Python; Python from PATH or the checkout is not accepted.');
}

export async function trustedNpm(fs: {
  regularFile: (path: string) => Promise<string>;
  readdir: (path: string) => Promise<string[]>;
} = { regularFile: path => regularFile(path, false, true), readdir }): Promise<string> {
  // GitHub's Node action runtime does not itself promise npm. Resolve only the
  // hosted Ubuntu/system tool locations, never PATH, RUNNER_TOOL_CACHE, or npm_execpath.
  const systemTargets = ['/usr/local/lib/node_modules/npm/bin/npm-cli.js', '/usr/share/nodejs/npm/bin/npm-cli.js'];
  const cache = '/opt/hostedtoolcache/node';
  const cacheTarget = /^\/opt\/hostedtoolcache\/node\/24\.\d{1,5}\.\d{1,5}\/x64\/lib\/node_modules\/npm\/bin\/npm-cli\.js$/;
  for (const candidate of ['/usr/local/lib/node_modules/npm/bin/npm-cli.js', '/usr/share/nodejs/npm/bin/npm-cli.js', '/usr/local/bin/npm', '/usr/bin/npm']) {
    try {
      const target = await fs.regularFile(candidate);
      if (systemTargets.includes(target) || cacheTarget.test(target)) return target;
    } catch { /* Try the next fixed prerequisite location. */ }
  }
  const entries = await fs.readdir(cache).catch(() => []);
  if (entries.length <= 256) {
    const versions = entries.filter(version => /^24\.\d{1,5}\.\d{1,5}$/.test(version)).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
    for (const version of versions) {
      const candidate = join(cache, version, 'x64/lib/node_modules/npm/bin/npm-cli.js');
      try {
        const target = await fs.regularFile(candidate);
        // Reject cache-directory symlinks to a checkout, alternate cache, or version.
        if (target === candidate) return target;
      } catch { /* Try the next installed Node 24 version. */ }
    }
  }
  throw new Error('A trusted npm installation is required. Use an Ubuntu GitHub-hosted runner with Node 24 in /opt/hostedtoolcache/node (actions/setup-node can prepare it); npm from the checkout or PATH is not accepted.');
}

export async function setupRuntime(options: RuntimeOptions): Promise<Runtime> {
  if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Codex Security Action currently supports Linux x64 runners only.');
  if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error('Codex Security Action requires the Node 24 GitHub Actions runtime.');
  if (!isAbsolute(options.actionRoot) || !isAbsolute(options.tempRoot)) throw new Error('Action and temporary roots must be absolute.');
  const tempRoot = await realpath(options.tempRoot);
  const actionRoot = await realpath(options.actionRoot);
  const npmCli = await trustedNpm();
  const pythonPath = await trustedPython();
  const nodePath = await regularFile(process.execPath, true, true);
  const root = await mkdtemp(join(tempRoot, ROOT_PREFIX));
  await chmod(root, 0o700);
  await writeFile(join(root, MARKER), 'codex-security-action-v1\n', { mode: 0o600, flag: 'wx' });
  const home = join(root, 'home');
  const codexHome = join(root, 'codex-home');
  const stateDirectory = join(root, 'state');
  const paths = { root, home, codexHome, stateDirectory, pythonPath };
  try {
    for (const dir of [home, codexHome, stateDirectory, join(root, 'tmp'), join(root, 'bin'), join(root, 'install')]) await mkdir(dir, { mode: 0o700 });
    await symlink(nodePath, join(root, 'bin', 'node'));
    const env = runtimeEnvironment(paths);
    const pythonCheck = await runProcess(pythonPath, ['-I', '-c', 'import sys, sqlite3, tomllib; assert sys.version_info >= (3, 11)'], { cwd: root, env, timeoutMs: 10_000 });
    if (pythonCheck.exitCode !== 0 || pythonCheck.timedOut || pythonCheck.interrupted) throw new Error('Trusted Python 3.11 or later with sqlite3 and tomllib is required.');
    const source = join(actionRoot, 'runtime');
    const lockPath = await regularFile(join(source, 'package-lock.json'));
    const packagePath = await regularFile(join(source, 'package.json'));
    if (!lockPath.startsWith(source + sep) || !packagePath.startsWith(source + sep)) throw new Error('Runtime manifests must remain within the action package.');
    const lockBytes = await readFile(lockPath, 'utf8');
    validateRuntimeLock(JSON.parse(lockBytes));
    const destination = join(root, 'install');
    await copyFile(packagePath, join(destination, 'package.json'));
    await writeFile(join(destination, 'package-lock.json'), lockBytes, { mode: 0o600, flag: 'wx' });
    const userConfig = join(root, 'npm-user.conf');
    const globalConfig = join(root, 'npm-global.conf');
    await writeFile(userConfig, '', { mode: 0o600, flag: 'wx' });
    await writeFile(globalConfig, '', { mode: 0o600, flag: 'wx' });
    const install = await runProcess(nodePath, [npmCli, 'ci', '--ignore-scripts', '--include=optional', `--registry=${REGISTRY}`, `--userconfig=${userConfig}`, `--globalconfig=${globalConfig}`, `--cache=${join(root, 'npm-cache')}`, '--no-audit', '--no-fund', '--loglevel=error'], { cwd: destination, env, timeoutMs: 10 * 60 * 1000, log: options.log });
    if (install.exitCode !== 0 || install.timedOut || install.interrupted) {
      // npm sometimes writes lock/usage diagnostics to stdout. This process had
      // no credentials and every physical line is still treated as untrusted.
      for (const line of safeLogLines(install.stdout)) options.log?.(line);
      throw new Error(`Integrity-locked CLI installation failed (exit ${install.exitCode}${install.timedOut ? ', timed out' : ''}${install.interrupted ? ', interrupted' : ''}). Check the prefixed npm diagnostics, registry access, and runner prerequisites.`);
    }
    const cliPath = await regularFile(join(destination, 'node_modules', '@openai', 'codex-security', 'bin', 'codex-security.mjs'));
    const binary = join(destination, 'node_modules', '@openai', 'codex-linux-x64', 'vendor', 'x86_64-unknown-linux-musl', 'bin', 'codex');
    await regularFile(binary, true);
    // Private reports deliberately live outside the disposable credentials/runtime
    // root so downstream upload-sarif remains usable after the post action.
    const resultsDirectory = await mkdtemp(join(tempRoot, 'codex-security-reports-'));
    await chmod(resultsDirectory, 0o700);
    return { ...paths, nodePath, cliPath, resultsDirectory, env: (apiKey) => runtimeEnvironment(paths, apiKey) };
  } catch (error) {
    await cleanupRuntime(root, tempRoot);
    throw error;
  }
}

export async function cleanupRuntime(root: string, tempRoot: string): Promise<void> {
  if (!isAbsolute(root) || !isAbsolute(tempRoot)) throw new Error('Cleanup requires absolute owned paths.');
  const base = await realpath(tempRoot);
  const info = await lstat(root).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (!info) return;
  const canonical = await realpath(root);
  const child = relative(base, canonical);
  if (!info.isDirectory() || info.isSymbolicLink() || dirname(canonical) !== base || !child.startsWith(ROOT_PREFIX) || child.includes(sep) || resolve(root) !== canonical) throw new Error('Refusing to clean a path outside the owned runtime root.');
  const marker = join(canonical, MARKER);
  if (!(await lstat(marker)).isFile() || (await lstat(marker)).isSymbolicLink() || await readFile(marker, 'utf8') !== 'codex-security-action-v1\n') throw new Error('Refusing to clean a directory without the ownership marker.');
  await rm(canonical, { recursive: true, force: false });
}
