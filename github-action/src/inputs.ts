export const INPUT_NAMES = [
  'repository', 'scope', 'paths', 'diff-base', 'diff-head', 'working-tree-base',
  'mode', 'model', 'effort', 'max-cost', 'fail-on-severity', 'knowledge-base',
  'scan-prompt-file', 'validation-prompt-file', 'workers', 'subagents',
  'stop-after-no-new', 'max-discovery-runs', 'max-time-hours', 'codex-config',
  'safety-identifier', 'verbose', 'dry-run',
  'publish-check', 'check-name', 'github-token', 'summary', 'annotations',
  'upload-artifacts', 'artifact-name', 'retention-days',
] as const;

export type Scope = 'repository' | 'diff' | 'working-tree';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export type Threshold = 'none' | 'critical' | 'high' | 'medium' | 'low';
export interface Inputs {
  repository: string;
  scope: Scope;
  paths: string[];
  diffBase?: string;
  diffHead?: string;
  workingTreeBase?: string;
  mode: 'standard' | 'deep';
  model: string;
  effort: string;
  maxCost?: number;
  failOnSeverity: Threshold;
  knowledgeBase: string[];
  scanPromptFile?: string;
  validationPromptFile?: string;
  workers?: number;
  subagents?: number;
  stopAfterNoNew?: number;
  maxDiscoveryRuns?: number;
  maxTimeHours?: number;
  codexConfig: string[];
  safetyIdentifier?: string;
  verbose: boolean;
  dryRun: boolean;
  publishCheck: boolean;
  checkName: string;
  githubToken: string;
  summary: boolean;
  annotations: boolean;
  uploadArtifacts: boolean;
  artifactName: string;
  retentionDays: number;
}

export function parseInputs(read: (name: string) => string, workspace: string): Inputs {
  const str = (name: string, fallback = '') => {
    const value = read(name).trim() || fallback;
    if (value.length > 8192 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value))
      throw new Error(`Invalid ${name}: contains control characters or is too long.`);
    return value;
  };
  const single = (name: string, fallback = '') => {
    const value = str(name, fallback);
    if (/[\r\n]/.test(value)) throw new Error(`${name} must be a single value.`);
    return value;
  };
  const choice = <T extends string>(name: string, values: readonly T[], fallback: T): T => {
    const value = single(name, fallback);
    if (!values.includes(value as T)) throw new Error(`${name} must be one of: ${values.join(', ')}.`);
    return value as T;
  };
  const bool = (name: string, fallback: boolean) => choice(name, ['true', 'false'], String(fallback) as 'true' | 'false') === 'true';
  const num = (name: string, integer: boolean, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    const value = single(name);
    if (!value) return undefined;
    if (!/^\d+(?:\.\d+)?$/.test(value)) throw new Error(`${name} must be a finite ${integer ? 'integer' : 'number'}.`);
    const n = Number(value);
    if (!Number.isFinite(n) || (integer && !Number.isSafeInteger(n)) || n < min || n > max)
      throw new Error(`${name} must be ${integer ? 'an integer' : 'a number'} between ${min} and ${max}.`);
    return n;
  };
  const list = (name: string) => str(name).split(/\r?\n/).map(v => v.trim()).filter(Boolean);
  const safeRelative = (name: string, value: string) => {
    if (value.startsWith('-') || value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.includes('\\') || value.split('/').includes('..') || /[*?\[\]\x00-\x1f\x7f]/.test(value))
      throw new Error(`${name} must contain literal repository-relative paths, without globs or '..'.`);
    return value;
  };
  // Match the CLI's scope spelling before constructing arguments or checking reports.
  const paths = [...new Set(list('paths').map(v =>
    safeRelative('paths', v).split('/').filter(part => part && part !== '.').join('/') || '.'))];
  const scope = choice('scope', ['repository', 'diff', 'working-tree'], 'repository');
  if (scope !== 'repository' && paths.length)
    throw new Error(`paths cannot be combined with scope: ${scope}. Remove paths to scan changes, or use scope: repository to scan selected paths.`);
  const mode = choice('mode', ['standard', 'deep'], 'standard');
  if (mode === 'deep' && scope !== 'repository') throw new Error('mode: deep supports repository and path scans only. Use mode: standard for changes.');
  const diffBase = single('diff-base') || undefined;
  const diffHead = single('diff-head') || undefined;
  const workingTreeBase = single('working-tree-base') || undefined;
  if ((diffBase || diffHead) && scope !== 'diff') throw new Error('diff-base and diff-head require scope: diff.');
  if (workingTreeBase && scope !== 'working-tree') throw new Error('working-tree-base requires scope: working-tree.');
  const validationPromptFile = single('validation-prompt-file') || undefined;
  if (validationPromptFile && mode === 'deep') throw new Error('validation-prompt-file is not supported in deep mode.');
  const deep = {
    workers: num('workers', true, 1), subagents: num('subagents', true),
    stopAfterNoNew: num('stop-after-no-new', true, 1), maxDiscoveryRuns: num('max-discovery-runs', true, 1),
    maxTimeHours: num('max-time-hours', false, Number.MIN_VALUE, 96),
  };
  if (mode !== 'deep' && Object.values(deep).some(v => v !== undefined)) throw new Error('workers, subagents, and discovery limits require mode: deep.');
  const codexConfig = list('codex-config');
  const keys = new Set<string>();
  for (const entry of codexConfig) {
    const match = /^(analytics\.enabled|features\.multi_agent_v2\.max_concurrent_threads_per_session)\s*=\s*(true|false|\d+)$/.exec(entry);
    if (!match) throw new Error('codex-config supports only analytics.enabled (boolean) and features.multi_agent_v2.max_concurrent_threads_per_session (positive integer). Use model and effort inputs for reasoning settings.');
    const [, key, value] = match;
    if (keys.has(key)) throw new Error(`Duplicate codex-config key: ${key}.`);
    keys.add(key);
    if (key === 'analytics.enabled' ? !['true', 'false'].includes(value) : !/^\d+$/.test(value) || Number(value) < 1 || !Number.isSafeInteger(Number(value)))
      throw new Error(`Invalid value for codex-config key: ${key}.`);
  }
  const publishCheck = bool('publish-check', false);
  const dryRun = bool('dry-run', false);
  if (dryRun && publishCheck) throw new Error('dry-run cannot publish a production security check. Use a separate configuration-validation job.');
  const githubToken = read('github-token').trim();
  if (publishCheck && !githubToken) throw new Error('publish-check requires github-token and checks: write permission.');
  const checkName = single('check-name', 'Codex Security findings');
  if (checkName.length > 100) throw new Error('check-name must be at most 100 characters.');
  const artifactName = single('artifact-name', 'codex-security');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(artifactName)) throw new Error('artifact-name must be 1–128 letters, numbers, dots, underscores, or hyphens.');
  const safetyIdentifier = single('safety-identifier') || undefined;
  if (safetyIdentifier && safetyIdentifier.length > 64) throw new Error('safety-identifier must be at most 64 characters.');
  if (safetyIdentifier?.startsWith('-')) throw new Error('safety-identifier cannot begin with a hyphen.');
  const model = single('model', 'gpt-5.6-sol');
  if (model.startsWith('-')) throw new Error('model must be a model name, not a CLI option.');
  return {
    repository: single('repository', workspace), scope, paths, diffBase, diffHead, workingTreeBase, mode,
    model, effort: choice('effort', ['minimal','low','medium','high','xhigh','max'], 'xhigh'),
    maxCost: num('max-cost', false, Number.MIN_VALUE), failOnSeverity: choice('fail-on-severity', ['none','low','medium','high','critical'], 'none'),
    knowledgeBase: list('knowledge-base').map(v => safeRelative('knowledge-base', v)),
    scanPromptFile: single('scan-prompt-file') ? safeRelative('scan-prompt-file', single('scan-prompt-file')) : undefined,
    validationPromptFile: validationPromptFile ? safeRelative('validation-prompt-file', validationPromptFile) : undefined,
    ...deep, codexConfig, safetyIdentifier, verbose: bool('verbose', true), dryRun,
    publishCheck, checkName, githubToken, summary: bool('summary', true), annotations: bool('annotations', true),
    uploadArtifacts: bool('upload-artifacts', false), artifactName, retentionDays: num('retention-days', true, 1, 90) ?? 7,
  };
}

export function scanArguments(inputs: Inputs, target: {repository: string; diffBase?: string; diffHead?: string; workingTreeBase?: string}, resultsDirectory: string, python: string): string[] {
  // The pinned CLI checks API-key presence even during local preflight. Its
  // dry-run branch never starts a model session; auto allows keyless preflight
  // with our empty private credential home. Real scans always use api-key.
  const args = ['scan', target.repository, '--auth', inputs.dryRun ? 'auto' : 'api-key', '--provider', 'openai', '--mode', inputs.mode,
    '--model', inputs.model, '--effort', inputs.effort, '--headless', '--python', python,
    '--output-dir', resultsDirectory, '--format', 'json'];
  // Preserve the pinned CLI's sandbox and automatic approval-review defaults.
  // Forcing approval_policy="never" prevents recovery from hosted Linux sandbox errors.
  // No ambient telemetry configuration. Users may explicitly enable built-in analytics.
  if (!inputs.codexConfig.some(v => v.startsWith('analytics.enabled'))) args.push('--codex', 'analytics.enabled=false');
  for (const path of inputs.paths) args.push('--path', path);
  for (const path of inputs.knowledgeBase) args.push('--knowledge-base', path);
  for (const entry of inputs.codexConfig) args.push('--codex', entry);
  const options: Array<[string, string | number | undefined]> = [
    ['--diff', target.diffBase], ['--head', target.diffHead], ['--base', target.workingTreeBase],
    ['--max-cost', inputs.maxCost], ['--workers', inputs.workers], ['--subagents', inputs.subagents],
    ['--stop-after-no-new', inputs.stopAfterNoNew], ['--max-discovery-runs', inputs.maxDiscoveryRuns],
    ['--max-time-hours', inputs.maxTimeHours], ['--scan-prompt-file', inputs.scanPromptFile],
    ['--validation-prompt-file', inputs.validationPromptFile], ['--safety-identifier', inputs.safetyIdentifier],
  ];
  for (const [name, value] of options) if (value !== undefined) args.push(name, String(value));
  if (inputs.scope === 'working-tree') args.push('--working-tree');
  if (inputs.failOnSeverity !== 'none') args.push('--fail-on-severity', inputs.failOnSeverity);
  if (inputs.verbose) args.push('--verbose');
  if (inputs.dryRun) args.push('--dry-run');
  return args;
}
