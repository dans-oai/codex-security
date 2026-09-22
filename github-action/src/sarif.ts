/** Validation of the SARIF subset emitted by the pinned CLI. Never follows URI references. */
export interface SarifFindingIdentity {
  id: string;
  occurrenceId: string;
  ruleId: string;
  severity: string;
  fingerprint: string;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function safeSourcePath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    !/[\\\x00-\x1f\x7f]/u.test(value) && !value.startsWith('/') &&
    !/^[a-z][a-z0-9+.-]*:/iu.test(value) &&
    value.split('/').every((part) => part !== '..' && part !== '' && part !== '.');
}

export function exportSarifArgs(scanDirectory: string, sourceRoot: string, outputPath: string): string[] {
  // Each item is an argv entry, not shell text. The caller supplies verified absolute paths.
  return ['export', scanDirectory, '--export-format', 'sarif', '--source-root', sourceRoot, '--output', outputPath];
}

export interface SarifTarget { kind: string; revision?: string }

export function validateSarif(value: unknown, scanId: string, findings: readonly SarifFindingIdentity[], target?: SarifTarget): string[] {
  const errors: string[] = [];
  const fail = (message: string): void => { if (errors.length < 20) errors.push(`SARIF: ${message}`); };
  if (!isRecord(value) || value.version !== '2.1.0' || !Array.isArray(value.runs) || value.runs.length !== 1) {
    return ['SARIF: expected version 2.1.0 with exactly one CLI run.'];
  }
  const run = value.runs[0];
  if (!isRecord(run) || !isRecord(run.tool) || !isRecord(run.tool.driver) || run.tool.driver.name !== 'Codex Security') {
    return ['SARIF: expected Codex Security driver.'];
  }
  if (!isRecord(run.automationDetails) || run.automationDetails.id !== scanId) fail('scan identity does not match the manifest.');
  if (target && (!isRecord(run.properties) || run.properties.codexSecurityTargetKind !== target.kind)) fail('target kind differs from the canonical manifest.');
  if (run.versionControlProvenance !== undefined && (!Array.isArray(run.versionControlProvenance) || run.versionControlProvenance.length !== 1 ||
      !isRecord(run.versionControlProvenance[0]) || (target?.revision !== undefined && run.versionControlProvenance[0].revisionId !== target.revision))) fail('revision provenance differs from the canonical manifest.');
  if (run.externalPropertyFileReferences !== undefined || run.originalUriBaseIds !== undefined) fail('external properties and URI bases are unsupported.');
  // Optional SARIF fields can also contain source locations. Validate those without dereferencing them.
  const pending: unknown[] = [run];
  let nodes = 0;
  while (pending.length) {
    const item = pending.pop();
    if (++nodes > 1000000) { fail('structure exceeds the supported bound.'); break; }
    if (Array.isArray(item)) { for (const child of item) pending.push(child); }
    else if (isRecord(item)) {
      for (const [key, child] of Object.entries(item)) {
        if (key === 'externalPropertyFileReferences' || key === 'originalUriBaseIds') fail('external property references and URI bases are unsupported.');
        if (key === 'artifactLocation') {
          let decoded: unknown;
          try { decoded = isRecord(child) && typeof child.uri === 'string' ? decodeURIComponent(child.uri) : undefined; } catch { decoded = undefined; }
          if (!isRecord(child) || child.uriBaseId !== undefined || child.index !== undefined || !safeSourcePath(decoded)) fail('unsafe artifact location.');
        }
        if (typeof child === 'object' && child !== null) pending.push(child);
      }
    }
  }
  const rules = run.tool.driver.rules;
  if (!Array.isArray(rules) || rules.length > 25000 || !rules.every((rule) => isRecord(rule) && typeof rule.id === 'string')) {
    return [...errors, 'SARIF: invalid rules.'];
  }
  if (!Array.isArray(run.results) || run.results.length !== findings.length || run.results.length > 25000) {
    return [...errors, 'SARIF: result count does not match canonical findings.'];
  }
  const byOccurrence = new Map(findings.map((finding) => [finding.occurrenceId, finding]));
  const seen = new Set<string>();
  for (const result of run.results) {
    if (!isRecord(result) || !isRecord(result.properties) || !isRecord(result.message) || typeof result.message.text !== 'string') {
      fail('invalid result shape.'); continue;
    }
    const occurrence = result.properties.occurrenceId;
    const finding = typeof occurrence === 'string' ? byOccurrence.get(occurrence) : undefined;
    if (!finding || seen.has(finding.occurrenceId)) { fail('unknown or duplicate finding identity.'); continue; }
    seen.add(finding.occurrenceId);
    if (result.properties.findingId !== finding.id || result.ruleId !== finding.ruleId || result.properties.severity !== finding.severity ||
        !isRecord(result.partialFingerprints) || result.partialFingerprints['codexSecurity/v1'] !== finding.fingerprint) fail('finding identity differs from canonical JSON.');
    const index = result.ruleIndex;
    if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || !isRecord(rules[index]) || rules[index].id !== finding.ruleId) fail('invalid rule reference.');
    if (!['error', 'warning', 'note', 'none'].includes(String(result.level))) fail('invalid result level.');
    if (!Array.isArray(result.locations) || result.locations.length < 1 || result.locations.length > 100) { fail('invalid locations.'); continue; }
    for (const location of result.locations) {
      if (!isRecord(location) || !isRecord(location.physicalLocation)) { fail('invalid physical location.'); continue; }
      const physical = location.physicalLocation;
      const artifact = physical.artifactLocation;
      let decoded: unknown;
      try { decoded = isRecord(artifact) && typeof artifact.uri === 'string' ? decodeURIComponent(artifact.uri) : undefined; } catch { decoded = undefined; }
      if (!isRecord(artifact) || artifact.uriBaseId !== undefined || artifact.index !== undefined || !safeSourcePath(decoded)) fail('source location must be a repository-relative path.');
      const region = physical.region;
      if (!isRecord(region) || !Number.isSafeInteger(region.startLine) || Number(region.startLine) < 1 ||
          (region.endLine !== undefined && (!Number.isSafeInteger(region.endLine) || Number(region.endLine) < Number(region.startLine)))) fail('invalid source line range.');
    }
  }
  return errors;
}
