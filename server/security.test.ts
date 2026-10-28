import fs from 'node:fs';
import path from 'node:path';
import type { NextFunction, Request, Response } from 'express';
import { describe, expect, it } from 'vitest';
import { analyzeFullRepository } from './analyzer/astAnalyzer.js';
import {
  INITIAL_REPO_FILES,
  TARGET_REPO_ROOT,
  TargetRepoPathError,
  resetTargetRepoToBaseline,
  readTargetRepoFiles,
  writeTargetRepoFile,
} from './analyzer/repoBaseline.js';
import {
  compileLegalProseToFormalPolicy,
  fetchLiveRegulatoryFeed,
  getBanglaInitialClauses,
  getInitialClauses,
} from './compiler/legalCompiler.js';
import { generateSignedConformityCertificate } from './enterprise/enterpriseSuite.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';
import {
  assertSafeBindConfig,
  createApiGuard,
  resolveServerSecurityConfig,
} from './security.js';
import type { FullComplianceScanReport, LegalClause } from '../shared/types.js';

function runGuard(
  env: NodeJS.ProcessEnv,
  req: { path?: string; method?: string; headers?: Record<string, string> }
): { status: number | null; passed: boolean } {
  const guard = createApiGuard(resolveServerSecurityConfig(env));
  let status: number | null = null;
  let passed = false;
  const res = {
    locals: {},
    status(code: number) {
      status = code;
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;
  const next: NextFunction = () => {
    passed = true;
  };
  guard(
    {
      path: req.path ?? '/state',
      method: req.method ?? 'GET',
      headers: { host: '127.0.0.1:3001', ...req.headers },
    } as unknown as Request,
    res,
    next
  );
  return { status, passed };
}

describe('API guard', () => {
  const client = { 'x-lexcompiler-client': 'test' };

  it('allows loopback requests that carry the client header', () => {
    expect(runGuard({}, { headers: client }).passed).toBe(true);
    expect(runGuard({}, { headers: { ...client, origin: 'http://localhost:5173' } }).passed).toBe(true);
  });

  it('rejects requests without the client header (e.g. <img>/form GETs from other pages)', () => {
    expect(runGuard({}, {})).toEqual({ status: 403, passed: false });
  });

  it('rejects disallowed origins and non-loopback Host headers (DNS rebinding)', () => {
    expect(runGuard({}, { headers: { ...client, origin: 'https://evil.example' } }).status).toBe(403);
    expect(runGuard({}, { headers: { ...client, host: 'evil.example:3001' } }).status).toBe(403);
    expect(
      runGuard({ LEXCOMPILER_ALLOWED_HOSTS: 'lexcompiler.internal' }, {
        headers: { ...client, host: 'lexcompiler.internal:3001' },
      }).passed
    ).toBe(true);
  });

  it('requires the bearer token when LEXCOMPILER_API_TOKEN is set', () => {
    const env = { LEXCOMPILER_API_TOKEN: 's3cret' };
    expect(runGuard(env, { headers: client }).status).toBe(401);
    expect(runGuard(env, { headers: { authorization: 'Bearer wrong' } }).status).toBe(401);
    expect(
      runGuard(env, { headers: { authorization: 'Bearer s3cret', host: '10.0.0.5:3001' } }).passed
    ).toBe(true);
  });

  it('always lets the health check through', () => {
    expect(runGuard({ LEXCOMPILER_API_TOKEN: 's3cret' }, { path: '/health' }).passed).toBe(true);
  });

  it('refuses to bind beyond loopback without a token', () => {
    expect(() => assertSafeBindConfig(resolveServerSecurityConfig({ HOST: '0.0.0.0' }))).toThrow(
      /LEXCOMPILER_API_TOKEN/
    );
    expect(() =>
      assertSafeBindConfig(resolveServerSecurityConfig({ HOST: '0.0.0.0', LEXCOMPILER_API_TOKEN: 't' }))
    ).not.toThrow();
    expect(() => assertSafeBindConfig(resolveServerSecurityConfig({}))).not.toThrow();
  });

  it('keeps the runtime sandbox disabled unless explicitly enabled', () => {
    expect(resolveServerSecurityConfig({}).runtimeSandboxEnabled).toBe(false);
    expect(
      resolveServerSecurityConfig({ LEXCOMPILER_ENABLE_RUNTIME_SANDBOX: '1' }).runtimeSandboxEnabled
    ).toBe(true);
  });
});

describe('writeTargetRepoFile', () => {
  it('rejects path traversal and untracked files', () => {
    for (const bad of ['../server/index.ts', 'api/../../package.json', '/etc/passwd', 'api/new_file.py']) {
      expect(() => writeTargetRepoFile(bad, 'x')).toThrow(TargetRepoPathError);
    }
    expect(fs.existsSync(path.join(TARGET_REPO_ROOT, 'api', 'new_file.py'))).toBe(false);
  });

  it('still writes tracked files', () => {
    resetTargetRepoToBaseline();
    const relPath = Object.keys(INITIAL_REPO_FILES)[0];
    writeTargetRepoFile(`/${relPath}`, INITIAL_REPO_FILES[relPath].content);
    expect(readTargetRepoFiles().find((f) => f.path === relPath)?.content).toBe(
      INITIAL_REPO_FILES[relPath].content
    );
  });
});

describe('pre-PR Z3 sandbox gate', () => {
  it('marks a PR READY_TO_MERGE only when every clause is SAT after patching', async () => {
    resetTargetRepoToBaseline();
    const clauses = getInitialClauses();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(readTargetRepoFiles());
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const pr = await synthesizeRemediationPullRequest(clauses, enrichedFiles, verification.proofs);

    expect(pr?.postPatchZ3Status).toBe('SAT_COMPLIANT');
    expect(pr?.status).toBe('READY_TO_MERGE');
    expect(pr?.unresolvedClauseIds).toEqual([]);
  });

  it('blocks the PR and names the unresolved clauses when patches cannot satisfy Z3', async () => {
    resetTargetRepoToBaseline();
    // Two residency clauses that each allow only one (different) region cannot both be satisfied.
    const base = getInitialClauses().find((c) => c.category === 'CROSS_BORDER_TRANSFER')!;
    const onlyRegion = (id: string, region: string): LegalClause => ({
      ...base,
      id,
      deontic: {
        ...base.deontic,
        extractedParameters: { ...base.deontic.extractedParameters, allowedDataRegions: [region] },
      },
    });
    const clauses = [onlyRegion('CLAUSE-ONLY-WEST', 'eu-west-1'), onlyRegion('CLAUSE-ONLY-CENTRAL', 'eu-central-1')];
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(readTargetRepoFiles());
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const pr = await synthesizeRemediationPullRequest(clauses, enrichedFiles, verification.proofs);

    expect(pr).not.toBeNull();
    expect(pr?.postPatchZ3Status).toBe('UNSAT_VIOLATION');
    expect(pr?.status).toBe('BLOCKED_UNRESOLVED');
    expect(pr?.unresolvedClauseIds?.length).toBeGreaterThan(0);
    expect(pr?.executiveSummary).toMatch(/blocked/i);
    expect(pr?.executiveSummary).not.toMatch(/UNSAT → SAT/);
  });
});

describe('illustrative demo content', () => {
  it('tags every built-in clause as illustrative', () => {
    for (const clause of [...getInitialClauses(), ...getBanglaInitialClauses()]) {
      expect(clause.illustrative).toBe(true);
    }
  });

  it('tags curated and offline feed items and never invents Federal Register abstracts', async () => {
    const items = await fetchLiveRegulatoryFeed();
    const curated = items.filter((i) => i.source === 'EUR_LEX');
    expect(curated.length).toBeGreaterThan(0);
    for (const item of curated) {
      expect(item.illustrative).toBe(true);
      expect(item.title).toMatch(/^\[Illustrative\]/);
    }
    for (const item of items.filter((i) => i.source === 'FEDERAL_REGISTER' && !i.illustrative)) {
      expect(item.excerpt).not.toMatch(/tenant-isolated keys and purged within 72 hours/);
    }
    expect(items.some((i) => i.documentNumber === '89 FR 104210')).toBe(false);

    // The labelled excerpt still compiles to the same demo parameter.
    const aiAct = curated.find((i) => i.suggestedFramework === 'EU_AI_ACT')!;
    const compiled = compileLegalProseToFormalPolicy(aiAct.excerpt, 'AI_HUMAN_IN_THE_LOOP', 'X', 'X');
    expect(compiled.deontic.extractedParameters.minAiConfidenceThreshold).toBe(0.88);
  }, 10000);

  it('does not label a self-signed attestation as a certification', async () => {
    const report = {
      repositoryName: 'demo',
      commitHash: 'abc12345',
      merkleAuditRoot: 'root',
      totalClausesEvaluated: 0,
      compliantClausesCount: 0,
      violatedClausesCount: 0,
      overallComplianceScore: 100,
      z3EngineVersion: 'z3',
      proofs: [],
    } as unknown as FullComplianceScanReport;
    const cert = await generateSignedConformityCertificate(report);
    expect(cert.overallVerdict).toBe('SAT_COMPLIANT_ATTESTED');
    expect(cert.issuer).not.toMatch(/hardware/i);
    expect(cert.standard).toMatch(/not an EU AI Act Art\. 43/);
  });
});
