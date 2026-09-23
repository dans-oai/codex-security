import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { isRecord, safeSourcePath, validateSarif, type SarifFindingIdentity } from './sarif.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ScanStatus = 'completed' | 'incomplete' | 'failed' | 'skipped';
export type PolicyStatus = 'passed' | 'failed' | 'not-evaluated';
export type ReportStatus = 'ready' | 'partial' | 'failed';
export interface Finding extends SarifFindingIdentity {
  severity: Severity;
  title: string;
  summary: string;
  path?: string;
  startLine?: number;
  endLine?: number;
}
export interface ExpectedScan {
  scope: 'repository' | 'diff' | 'working-tree';
  mode: 'standard' | 'deep';
  paths: readonly string[];
  scannedSha: string;
  diffBase?: string;
  diffHead?: string;
  publishable: boolean;
}
export interface ResultOptions {
  resultsDirectory: string;
  exitCode: number | null;
  expected: ExpectedScan;
  failOnSeverity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  estimatedCost?: number;
}
export interface ResultPaths {
  resultsDirectory: string;
  manifestPath: string;
  jsonPath: string;
  coveragePath: string;
  sarifPath: string;
}
export interface ScanResults {
  scanStatus: ScanStatus;
  policyStatus: PolicyStatus;
  reportStatus: ReportStatus;
  findings: Finding[];
  counts: Record<Severity, number>;
  estimatedCost?: number;
  paths: ResultPaths;
  errors: string[];
  sarifUploadReady: boolean;
  /** True only after manifest, canonical digests, scope, revision and reporting fields validate. */
  canonicalValid: boolean;
  scanId: string;
}

const MAX_REPORT_BYTES = 16 * 1024 * 1024;
const REPORT_FILES = new Set(['scan-manifest.json', 'findings.json', 'coverage.json', 'exports/results.sarif']);
const LEVELS: readonly Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];

/** Bounded reads only. Call after stopping the scanner; this is not isolation against a same-UID attacker. */
export async function readReportFile(root: string, name: string, maxBytes = MAX_REPORT_BYTES): Promise<Buffer> {
  if (!REPORT_FILES.has(name)) throw new Error('Unsupported report filename.');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_REPORT_BYTES) throw new Error('Invalid report byte limit.');
  const absoluteRoot = resolve(root);
  if (await realpath(absoluteRoot) !== absoluteRoot) throw new Error('Report root must be canonical and cannot contain symlinks.');
  const rootInfo = await lstat(absoluteRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('Report root is not a directory.');
  const components = name.split('/');
  let directory = absoluteRoot;
  for (const part of components.slice(0, -1)) {
    directory = join(directory, part);
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(directory) !== directory) throw new Error('Report directory contains a symlink or non-directory.');
  }
  const path = join(absoluteRoot, name);
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maxBytes) throw new Error('Report must be a bounded regular file without links.');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await file.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > maxBytes) throw new Error('Report changed while opening.');
    const bytes = Buffer.alloc(Math.min(opened.size + 1, maxBytes + 1));
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await file.read(bytes, used, bytes.length - used, null);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    const after = await file.stat();
    if (used > opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        await realpath(path) !== path) throw new Error('Report changed while reading.');
    return bytes.subarray(0, used);
  } finally { await file.close(); }
}

function document(value: unknown, type: string): Record<string, unknown> {
  if (!isRecord(value) || value.documentType !== `codex-security.${type}` || value.schemaVersion !== '1.0') throw new Error(`Invalid ${type} document or schema version.`);
  return value;
}
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.length <= 25000 && value.every((item) => typeof item === 'string' && item.length <= 4096); }
function samePaths(a: unknown, b: unknown): boolean {
  return strings(a) && strings(b) && JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
}
function requiredText(value: unknown): value is string { return typeof value === 'string' && value.length > 0 && value.length <= 100000; }
function parseFindings(value: unknown): { scanId: string; findings: Finding[] } {
  const doc = document(value, 'findings');
  if (!requiredText(doc.scanId) || !Array.isArray(doc.findings) || doc.findings.length > 25000) throw new Error('Invalid findings identity or count.');
  const seen = new Set<string>();
  const findings = doc.findings.map((item): Finding => {
    if (!isRecord(item) || typeof item.findingId !== 'string' || !/^csf_[a-f0-9]{24}$/u.test(item.findingId) ||
        typeof item.occurrenceId !== 'string' || !/^occ_[a-f0-9]{24}$/u.test(item.occurrenceId) || seen.has(item.occurrenceId) ||
        typeof item.ruleId !== 'string' || !/^[a-z0-9][a-z0-9._/-]*$/u.test(item.ruleId) ||
        !requiredText(item.title) || !requiredText(item.summary) || !isRecord(item.severity) || !LEVELS.includes(item.severity.level as Severity) ||
        !isRecord(item.fingerprints) || item.fingerprints.algorithm !== 'codex-security/v1' || typeof item.fingerprints.primary !== 'string' ||
        !/^codex-security\/v1:sha256:[a-f0-9]{64}$/u.test(item.fingerprints.primary) ||
        !Array.isArray(item.locations) || item.locations.length < 1 || item.locations.length > 100) throw new Error('Invalid canonical finding fields.');
    seen.add(item.occurrenceId);
    for (const location of item.locations) {
      if (!isRecord(location) || !safeSourcePath(location.path) || !Number.isSafeInteger(location.startLine) || Number(location.startLine) < 1 ||
          (location.endLine !== undefined && (!Number.isSafeInteger(location.endLine) || Number(location.endLine) < Number(location.startLine)))) throw new Error('Invalid canonical finding location.');
    }
    const primary = item.locations[0] as Record<string, unknown>;
    return { id: item.findingId, occurrenceId: item.occurrenceId, ruleId: item.ruleId, fingerprint: item.fingerprints.primary,
      title: item.title, summary: item.summary, severity: item.severity.level as Severity, path: primary.path as string,
      startLine: primary.startLine as number, endLine: (primary.endLine ?? primary.startLine) as number };
  });
  return { scanId: doc.scanId, findings };
}

function validateCanonical(manifestValue: unknown, coverageValue: unknown, scanId: string, bytes: Map<string, Buffer>, expected: ExpectedScan): { status: string; completeness: string; targetKind: string } {
  const manifest = document(manifestValue, 'scan-manifest');
  const coverage = document(coverageValue, 'coverage');
  const scan = manifest.scan;
  if (!isRecord(scan) || scan.id !== scanId || coverage.scanId !== scanId || !requiredText(scanId) ||
      !['completed', 'failed', 'canceled', 'interrupted'].includes(String(scan.status)) ||
      !isRecord(scan.producer) || !requiredText(scan.producer.name) || !requiredText(scan.producer.version) ||
      !['startedAt', 'completedAt', 'sealedAt'].every((field) => typeof scan[field] === 'string' && Number.isFinite(Date.parse(scan[field] as string)))) throw new Error('Invalid manifest identity, producer, status or seal.');
  if (scan.findingsRef !== 'findings.json' || scan.coverageRef !== 'coverage.json' || !Array.isArray(scan.artifacts) || scan.artifacts.length > 100000) throw new Error('Invalid canonical artifact references.');
  for (const name of ['findings.json', 'coverage.json']) {
    const entries = scan.artifacts.filter((entry) => isRecord(entry) && entry.path === name);
    const entry = entries[0];
    if (entries.length !== 1 || !isRecord(entry) || entry.mediaType !== 'application/json' || entry.sha256 !== createHash('sha256').update(bytes.get(name)!).digest('hex')) throw new Error(`Canonical digest mismatch: ${name}.`);
  }
  const scope = scan.scope;
  const paths = expected.paths.length ? expected.paths : ['.'];
  if (!isRecord(scope) || !samePaths(scope.includePaths, coverage.includePaths) || !samePaths(scope.excludePaths, coverage.excludePaths) ||
      !samePaths(scope.includePaths, paths) || !samePaths(scope.excludePaths, [])) throw new Error('Reported scope does not match requested paths.');
  const mode = expected.scope === 'diff' ? 'branch_diff' : expected.scope === 'working-tree' ? 'working_tree' :
    expected.paths.length ? 'scoped_path' : expected.mode === 'deep' ? 'deep_repository' : 'repository';
  if (coverage.mode !== mode) throw new Error('Reported coverage mode does not match requested scope/mode.');
  if (!['complete', 'partial', 'unknown'].includes(String(coverage.completeness)) || !['repository', 'scoped_path', 'diff', 'directory', 'custom'].includes(String(coverage.inventoryStrategy)) ||
      !Array.isArray(coverage.surfaces) || !Array.isArray(coverage.deferred) || !Array.isArray(coverage.explicitExclusions)) throw new Error('Invalid coverage fields.');
  if (!coverage.surfaces.every((surface) => isRecord(surface) && requiredText(surface.id) && requiredText(surface.label) &&
      ['reported', 'no_issue_found', 'rejected', 'not_applicable', 'needs_follow_up'].includes(String(surface.disposition)) && strings(surface.receiptRefs))) throw new Error('Invalid coverage surface.');
  if (coverage.completeness === 'complete' && (coverage.deferred.length > 0 || coverage.surfaces.some((surface) => isRecord(surface) && surface.disposition === 'needs_follow_up'))) throw new Error('Complete coverage contains deferred work.');
  const target = scan.target;
  if (!isRecord(target) || !requiredText(target.targetId) || !requiredText(target.displayName)) throw new Error('Invalid scan target.');
  if (expected.scope === 'repository') {
    if (!['git_revision', 'git_worktree'].includes(String(target.kind)) || target.revision !== expected.scannedSha) throw new Error('Reported target revision does not match the checkout.');
  } else if (target.kind !== 'git_diff' || target.baseRevision !== expected.diffBase || target.headRevision !== (expected.diffHead ?? expected.scannedSha) || !expected.diffBase) {
    throw new Error('Reported diff revisions do not match the requested change set.');
  }
  if (target.kind !== 'git_revision' && (typeof target.snapshotDigest !== 'string' || !/^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u.test(target.snapshotDigest))) throw new Error('Missing or invalid snapshot identity.');
  return { status: String(scan.status), completeness: String(coverage.completeness), targetKind: String(target.kind) };
}

export async function analyzeResults(options: ResultOptions): Promise<ScanResults> {
  const result: ScanResults = { scanStatus: 'failed', policyStatus: 'not-evaluated', reportStatus: 'failed', findings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    paths: { resultsDirectory: '', manifestPath: '', jsonPath: '', coveragePath: '', sarifPath: '' }, errors: [],
    sarifUploadReady: false, canonicalValid: false, scanId: '' };
  if (typeof options.estimatedCost === 'number' && Number.isFinite(options.estimatedCost) && options.estimatedCost >= 0) result.estimatedCost = options.estimatedCost;
  const bytes = new Map<string, Buffer>();
  const values = new Map<string, unknown>();
  for (const name of ['scan-manifest.json', 'findings.json', 'coverage.json', 'exports/results.sarif']) {
    try {
      const data = await readReportFile(options.resultsDirectory, name);
      bytes.set(name, data);
      values.set(name, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)) as unknown);
    } catch { result.errors.push(`Missing, unsafe, oversized or invalid report: ${name}.`); }
  }
  try {
    const parsed = parseFindings(values.get('findings.json'));
    result.findings = parsed.findings;
    result.scanId = parsed.scanId;
    result.paths.jsonPath = join(options.resultsDirectory, 'findings.json');
    result.paths.resultsDirectory = options.resultsDirectory;
    for (const finding of result.findings) result.counts[finding.severity] += 1;
  } catch (error) { result.errors.push((error as Error).message); }
  let canonical: ReturnType<typeof validateCanonical> | undefined;
  try {
    // A malformed findings document may carry an empty list; scan identity must also validate.
    if (!result.scanId) throw new Error('No validated findings identity.');
    canonical = validateCanonical(values.get('scan-manifest.json'), values.get('coverage.json'), result.scanId, bytes, options.expected);
    result.canonicalValid = true;
    result.paths.manifestPath = join(options.resultsDirectory, 'scan-manifest.json');
    result.paths.coveragePath = join(options.resultsDirectory, 'coverage.json');
    if (canonical.completeness !== 'complete') result.scanStatus = 'incomplete';
    else if (canonical.status === 'completed' && (options.exitCode === 0 || options.exitCode === 1)) result.scanStatus = 'completed';
    else result.errors.push('Scanner did not exit successfully with a completed scan.');
  } catch (error) { result.errors.push((error as Error).message); }
  if (result.scanStatus === 'completed') {
    const threshold = options.failOnSeverity;
    const policyFailed = threshold !== 'none' && result.findings.some((finding) => LEVELS.indexOf(finding.severity) >= LEVELS.indexOf(threshold));
    result.policyStatus = policyFailed ? 'failed' : 'passed';
    if (options.exitCode === 1 && !policyFailed) {
      result.scanStatus = 'failed'; result.policyStatus = 'not-evaluated'; result.errors.push('CLI policy exit does not match the configured severity policy.');
    }
  }
  if (values.has('exports/results.sarif') && result.scanId) {
    const sarifErrors = validateSarif(values.get('exports/results.sarif'), result.scanId, result.findings,
      canonical ? { kind: canonical.targetKind, revision: options.expected.scannedSha } : undefined);
    result.errors.push(...sarifErrors);
    if (!sarifErrors.length) result.paths.sarifPath = join(options.resultsDirectory, 'exports/results.sarif');
  }
  result.reportStatus = result.canonicalValid && result.paths.sarifPath ? 'ready' : result.paths.jsonPath ? 'partial' : 'failed';
  result.sarifUploadReady = result.scanStatus === 'completed' && result.reportStatus === 'ready' && options.expected.publishable &&
    options.expected.scope !== 'working-tree' && (options.expected.scope === 'diff' || canonical?.targetKind === 'git_revision');
  return result;
}
