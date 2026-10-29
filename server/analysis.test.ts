import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync, parseSqlSchemaFile, ttlUnitFromComment } from './analyzer/astAnalyzer.js';
import { INITIAL_REPO_FILES } from './analyzer/repoBaseline.js';
import { runTreeSitterQueries, treeSitterQueriesFor } from './analyzer/treeSitter.js';
import { compileLegalProseToFormalPolicy, getInitialClauses, mergeLlmBounds, extractDeonticBoundsFromProse } from './compiler/legalCompiler.js';
import { executeByocCustomScan } from './enterprise/enterpriseSuite.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { applyEdits, synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';
import type { TargetRepoFile } from '../shared/types.js';

const fixture = (overrides: Record<string, (c: string) => string> = {}): TargetRepoFile[] =>
  Object.entries(INITIAL_REPO_FILES).map(([path, spec]) => ({
    path,
    language: spec.language,
    description: spec.description,
    content: overrides[path] ? overrides[path](spec.content) : spec.content,
    lastModified: '',
  }));

const hours = (text: string) =>
  compileLegalProseToFormalPolicy(text, 'RETENTION_AND_TENANT_KMS', 'X', 'X').deontic.extractedParameters.maxRetentionHours;

describe('legal compiler', () => {
  it('takes the strictest duration and parses number words', () => {
    expect(hours('Backups may be kept 90 days, but PII must be purged within 3 days.')).toBe(72);
    expect(hours('PII must be purged within seventy-two hours.')).toBe(72);
    expect(hours('PII must be purged within one week.')).toBe(168);
    expect(hours('Purge within 30 minutes.')).toBe(0.5);
  });

  it('honours negation and permissions', () => {
    const kms = compileLegalProseToFormalPolicy('PII need not use tenant-isolated keys and must be deleted within 72 hours.', 'RETENTION_AND_TENANT_KMS', 'X', 'X');
    expect(kms.deontic.extractedParameters.requiresTenantIsolatedKeys).toBe(false);
    const log = compileLegalProseToFormalPolicy('Logging of email addresses is permitted.', 'PII_LOGGING_BAN', 'X', 'X');
    expect(log.deontic.extractedParameters.forbidPlaintextLogging).toBe(false);
  });

  it('only lets a validated LLM answer fill a missing numeric bound', () => {
    const base = extractDeonticBoundsFromProse('Gate low-confidence AI decisions for human review.', 'AI_HUMAN_IN_THE_LOOP');
    expect(mergeLlmBounds(base, { minAiConfidenceThreshold: 85 }, 'm', 1).minAiConfidenceThreshold).toBe(0.85);
    expect(mergeLlmBounds(base, { minAiConfidenceThreshold: 900 }, 'm', 1).provenance.method).not.toBe('LLM_JSON_FALLBACK');
    const withBound = extractDeonticBoundsFromProse('Purge within 72 hours.', 'RETENTION_AND_TENANT_KMS');
    expect(mergeLlmBounds(withBound, { maxRetentionHours: 5000 }, 'm', 1).maxRetentionHours).toBe(72);
  });
});

describe('analyzer', () => {
  it('folds constant expressions and converts TTL units', async () => {
    const files = fixture({
      'workers/redis_cache_worker.py': (c) =>
        c.replace('PII_CACHE_TTL_HOURS = 720', 'PII_CACHE_TTL_HOURS = 24 * 30\nSESSION_TTL_SECONDS = 3600'),
    });
    const { astFindings } = await analyzeFullRepositoryAsync(files);
    const ttl = (name: string) => astFindings.find((f) => f.metadata.retentionSource?.startsWith(name))?.metadata.retentionTtlHours;
    expect(ttl('PII_CACHE_TTL_HOURS')).toBe(720);
    expect(ttl('SESSION_TTL_SECONDS')).toBe(1);
  });

  it('analyzes Python with non-ASCII text (stdin is read as UTF-8, not the Windows code page)', async () => {
    const files = fixture({
      'workers/redis_cache_worker.py': (c) => `# Résumé cache — ব্যাংক নীতিমালা ✓\n${c.replace('"""Caches session PII', '"""Caches session PII 🔒')}`,
    });
    const { astFindings } = await analyzeFullRepositoryAsync(files);
    const ttl = astFindings.find((f) => f.metadata.retentionSource?.startsWith('PII_CACHE_TTL_HOURS'));
    expect(ttl?.metadata.retentionTtlHours).toBe(720);
  });

  it('takes a unitless TTL unit from its comment and ignores caches in modules without PII', async () => {
    expect(ttlUnitFromComment(' 5 minutes', 300)).toEqual({ hoursPerUnit: 1 / 3600, unit: 'seconds' });
    expect(ttlUnitFromComment(' 30 days', 30)).toEqual({ hoursPerUnit: 24, unit: 'days' });
    expect(ttlUnitFromComment(' seconds', 900)).toEqual({ hoursPerUnit: 1 / 3600, unit: 'seconds' });
    expect(ttlUnitFromComment(' Increased for slow servers', 30)).toBeNull();

    const schemaCache = { path: 'mcp/client.py', language: 'python' as const, description: '', lastModified: '', content: '_cache_ttl = 300  # 5 minutes\n_schema_cache = {}\n\ndef get_schema(url):\n    return _schema_cache.get(url)\n' };
    const piiCache = { ...schemaCache, path: 'workers/session.py', content: 'SESSION_TTL = 7200  # 2 hours\n\ndef store(redis, email):\n    redis.setex(email, SESSION_TTL, "1")\n' };
    const { astFindings } = await analyzeFullRepositoryAsync([schemaCache, piiCache]);
    const retention = astFindings.filter((f) => f.metadata.retentionTtlHours != null);
    expect(retention.map((f) => f.filePath)).toEqual(['workers/session.py']);
    expect(retention[0].metadata).toMatchObject({ retentionTtlHours: 2, retentionUnitAssumed: false });
  });

  it('scopes taint to the function: a same-named variable elsewhere in the module is not tainted', async () => {
    const content = [
      'import logging',
      'logger = logging.getLogger(__name__)',
      '',
      'def notify(user_email, http):',
      '    message = f"alert for {user_email}".strip()',
      '    response = http.post("/hook", json={"to": user_email})',
      '    logger.info("sent %s", message)',
      '    logger.info("hook answered %s", response.status_code)',
      '',
      'def health(http):',
      '    message = "ok"',
      '    logger.info("health %s", message)',
      '',
    ].join('\n');
    const { astFindings } = await analyzeFullRepositoryAsync([{ path: 'svc/alerts.py', language: 'python', description: '', lastModified: '', content }]);
    const leaks = astFindings.filter((f) => f.constructType === 'LOGGER_CALL');
    // Only the e-mail-derived message leaks: not the other function's "message", and not the
    // response of an HTTP call that was merely sent the e-mail.
    expect(leaks.map((f) => f.line)).toEqual([7]);
    expect(leaks[0].metadata.leakedFields).toEqual(['user_email']);
  });

  it('tracks PII through assignments and ignores PII-looking text', async () => {
    const files = fixture({
      'api/fastapi_intake.py': (c) =>
        c.replace(/logger\.info\([\s\S]*?\)\n/, 'x = payload.ssn\n    logger.info(f"rec {x}")\n    logger.info(f"email_count={len(rows)}")\n'),
    });
    const { astFindings } = await analyzeFullRepositoryAsync(files);
    const leaks = astFindings.filter((f) => f.constructType === 'LOGGER_CALL');
    expect(leaks).toHaveLength(1);
    expect(leaks[0].metadata.leakedFields).toEqual(['ssn']);
  });

  it('parses multi-line SQL, table constraints, and ALTER TABLE', () => {
    const { tables, syntaxError } = parseSqlSchemaFile({
      path: 's.sql',
      language: 'sql',
      description: '',
      lastModified: '',
      content: `CREATE TABLE "customers" (
  id UUID,
  email
    VARCHAR(255) NOT NULL,
  retention_days INT DEFAULT 7,
  PRIMARY KEY (id)
);
CREATE TABLE orders (
  id UUID PRIMARY KEY,
  customer_id UUID,
  CONSTRAINT fk_c FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE RESTRICT
);
ALTER TABLE customers ADD COLUMN ssn_encrypted BYTEA;`,
    });
    expect(syntaxError).toBeUndefined();
    const customers = tables.find((t) => t.tableName === 'customers')!;
    expect(customers.retentionHoursConfigured).toBe(168);
    expect(customers.unencryptedPiiColumns).toEqual(['email']);
    expect(customers.columns.find((c) => c.name === 'id')?.isPrimaryKey).toBe(true);
    expect(customers.columns.find((c) => c.name === 'ssn_encrypted')?.encryptedAtRest).toBe(true);
    expect(customers.dependentForeignKeys).toEqual([
      expect.objectContaining({ childTable: 'orders', childColumn: 'customer_id', onDeleteCascade: false }),
    ]);
  });
});

describe('prover', () => {
  it('reports every violating instance and treats missing constructs as not applicable', async () => {
    const files = fixture({
      'workers/redis_cache_worker.py': (c) => c.replace('PII_CACHE_TTL_HOURS = 720', 'PII_CACHE_TTL_HOURS = 720\nAUDIT_RETENTION_HOURS = 900'),
    });
    const { sqlTables, astFindings } = await analyzeFullRepositoryAsync(files);
    const [proof] = (await verifyRepositoryAgainstClauses([getInitialClauses()[0]], sqlTables, astFindings)).proofs;
    expect(proof.status).toBe('UNSAT_VIOLATION');
    expect(proof.offendingLocations.filter((l) => l.nodeId === 'node-redis-worker')).toHaveLength(2);
    expect(proof.unsatCoreAssertions.length).toBeGreaterThan(0);
    expect(proof.smtLib2Executed).toContain('check-sat-assuming');

    const empty = (await verifyRepositoryAgainstClauses(getInitialClauses(), [], [])).proofs;
    expect(empty.every((p) => p.status === 'SAT_COMPLIANT')).toBe(true);
    expect(empty.find((p) => p.category === 'RETENTION_AND_TENANT_KMS')?.reviewReasons?.join(' ')).toMatch(/vacuously/);
  });

  it('BYOC scans of a clean single file are compliant', async () => {
    const res = await executeByocCustomScan({
      contractClauseText: 'Data must be purged within 48 hours.',
      citationLabel: 'X',
      language: 'python',
      fileName: 'a.py',
      sourceCode: 'import redis\nCACHE_TTL_HOURS = 24\n\ndef cache(r, k, v):\n    r.setex(k, CACHE_TTL_HOURS * 3600, v)\n',
    });
    expect(res.verdict).toBe('SAT_COMPLIANT');
  });
});

describe('remediation', () => {
  it('applies edits back to front without overlap', () => {
    const { content } = applyEdits('abc\ndef', [
      { line: 1, column: 0, endLine: 1, endColumn: 1, text: 'X', note: '' },
      { line: 2, column: 1, endLine: 2, endColumn: 2, text: 'YY', note: '' },
    ]);
    expect(content).toBe('Xbc\ndYYf');
  });

  it('keeps user code and never emits a plaintext-leaking helper', async () => {
    const files = fixture({ 'api/fastapi_intake.py': (c) => `${c}\n\ndef my_custom_helper():\n    return 42\n` });
    const clauses = getInitialClauses();
    const a = await analyzeFullRepositoryAsync(files);
    const v = await verifyRepositoryAgainstClauses(clauses, a.sqlTables, a.astFindings);
    const pr = await synthesizeRemediationPullRequest(clauses, a.enrichedFiles, v.proofs);
    const api = pr!.filePatches.find((p) => p.filePath === 'api/fastapi_intake.py')!;
    expect(api.patchedContent).toContain('my_custom_helper');
    // The fixture's own encrypt_shared_aes256 contains plaintext[:4]; the inserted helper must not add another.
    const count = (t: string) => t.split('plaintext[:4]').length - 1;
    expect(count(api.patchedContent)).toBe(count(api.originalContent));
    expect(api.patchedContent).toContain('TENANT_KMS_CLIENT is not configured');
    expect(api.syntaxCheck?.passed).toBe(true);
    expect(pr!.status).toBe('READY_TO_MERGE');
  });
});

describe('tree-sitter structural queries', () => {
  it('compile to real queries and locate the constrained constructs', async () => {
    const [retention, logging, ai, egress] = getInitialClauses();
    const files = fixture();
    const ttl = await runTreeSitterQueries(retention.compiled.astPatternQuery, files);
    expect(ttl).toContainEqual(expect.objectContaining({ filePath: 'workers/redis_cache_worker.py', captures: expect.objectContaining({ name: 'PII_CACHE_TTL_HOURS', value: '720' }) }));
    expect((await runTreeSitterQueries(logging.compiled.astPatternQuery, files)).some((m) => m.captures.method === 'info')).toBe(true);
    expect((await runTreeSitterQueries(ai.compiled.astPatternQuery, files)).map((m) => m.captures.name)).toContain('MIN_CONFIDENCE_FOR_AUTO_APPROVAL');
    expect((await runTreeSitterQueries(egress.compiled.astPatternQuery, files))[0].captures.value).toBe('"us-east-1"');
  });

  it('runs SQL DDL queries with the SQL grammar', async () => {
    const clauses = getInitialClauses();
    const files = fixture();
    const sqlOnly = (m: { language: string }) => m.language === 'sql';
    const retention = (await runTreeSitterQueries(clauses[0].compiled.astPatternQuery, files)).filter(sqlOnly);
    expect(retention).toEqual([expect.objectContaining({ filePath: 'schema/postgres_pii.sql', captures: { name: 'retention_ttl_hours', value: '720' } })]);
    const fks = (await runTreeSitterQueries(treeSitterQueriesFor('RIGHT_TO_ERASURE_CASCADE'), files)).filter(sqlOnly);
    expect(fks[0].captures).toMatchObject({ column: 'patient_id', parent: 'patient_records', action: 'CASCADE' });
    const cols = (await runTreeSitterQueries(treeSitterQueriesFor('ENCRYPTION_AT_REST'), files)).filter(sqlOnly).map((m) => m.captures.name);
    expect(cols).toEqual(expect.arrayContaining(['full_name', 'email', 'ssn', 'diagnosis_code']));
  });
});
