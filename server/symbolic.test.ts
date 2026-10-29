import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { INITIAL_REPO_FILES } from './analyzer/repoBaseline.js';
import { summarizeTypeScriptFunction } from './analyzer/symbolicTs.js';
import { compileLegalProseToFormalPolicy, getInitialClauses } from './compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';
import type { LegalClause, RuleCategory, TargetRepoFile } from '../shared/types.js';

const fixture = (overrides: Record<string, (c: string) => string> = {}): TargetRepoFile[] =>
  Object.entries(INITIAL_REPO_FILES).map(([path, spec]) => ({
    path,
    language: spec.language,
    description: spec.description,
    content: overrides[path] ? overrides[path](spec.content) : spec.content,
    lastModified: '',
  }));

const byCategory = (c: RuleCategory) => getInitialClauses().find((x) => x.category === c)!;

function clause(category: RuleCategory, text: string): LegalClause {
  const base = getInitialClauses()[0];
  return { ...base, id: `CLAUSE-${category}`, category, citation: category, rawLegalText: text, illustrative: false, ...compileLegalProseToFormalPolicy(text, category, `CLAUSE-${category}`, category) };
}

async function prove(c: LegalClause, files: TargetRepoFile[]) {
  const a = await analyzeFullRepositoryAsync(files);
  return (await verifyRepositoryAgainstClauses([c], a.sqlTables, a.astFindings)).proofs[0];
}

const AI = 'services/ai_credit_triage.ts';

describe('symbolic execution', () => {
  it('summarises TypeScript paths with folded constants and free inputs', () => {
    const s = summarizeTypeScriptFunction(INITIAL_REPO_FILES[AI].content, AI, 'evaluateClinicalAndCreditRisk')!;
    expect(s.paths).toHaveLength(1);
    expect(JSON.stringify(s.paths[0].returns.approved)).toContain('"v":0.68');
    expect(s.approximations).toEqual([]);
  });

  it('AI gate: Z3 finds a low-confidence input that is auto-approved, with a witness', async () => {
    const proof = await prove(byCategory('AI_HUMAN_IN_THE_LOOP'), fixture());
    const behaviour = proof.offendingLocations.find((l) => /Symbolic execution/.test(l.explanation))!;
    const conf = Number(/input\.modelConfidenceScore = (\d+(?:\.\d+)?)/.exec(behaviour.explanation)![1]);
    expect(conf).toBeGreaterThanOrEqual(0.68);
    expect(conf).toBeLessThan(0.85);
  });

  it('AI gate: compliant constants do not hide hard-coded autonomous behaviour', async () => {
    const files = fixture({
      [AI]: (c) =>
        c
          .replace('MIN_CONFIDENCE_FOR_AUTO_APPROVAL = 0.68', 'MIN_CONFIDENCE_FOR_AUTO_APPROVAL = 0.9')
          .replace('ENFORCE_HUMAN_OVERSIGHT_GATE = false', 'ENFORCE_HUMAN_OVERSIGHT_GATE = true')
          .replace('WRITE_IMMUTABLE_AUDIT_LOG = false', 'WRITE_IMMUTABLE_AUDIT_LOG = true')
          .replace("executionMode: canAutoApprove ? 'AUTONOMOUS_AI' : 'HUMAN_OVERSIGHT_REQUIRED'", "executionMode: input.requestedCreditLimit < 1000 ? 'AUTONOMOUS_AI' : 'HUMAN_OVERSIGHT_REQUIRED'"),
    });
    const proof = await prove(byCategory('AI_HUMAN_IN_THE_LOOP'), files);
    expect(proof.status).toBe('UNSAT_VIOLATION');
    expect(proof.unsatCoreAssertions.some((n) => n.includes('behaviour'))).toBe(true);
    expect(proof.offendingLocations.map((l) => l.explanation).join(' ')).toMatch(/requestedCreditLimit = /);

    const fixed = fixture({
      [AI]: (c) =>
        c
          .replace('MIN_CONFIDENCE_FOR_AUTO_APPROVAL = 0.68', 'MIN_CONFIDENCE_FOR_AUTO_APPROVAL = 0.9')
          .replace('ENFORCE_HUMAN_OVERSIGHT_GATE = false', 'ENFORCE_HUMAN_OVERSIGHT_GATE = true')
          .replace('WRITE_IMMUTABLE_AUDIT_LOG = false', 'WRITE_IMMUTABLE_AUDIT_LOG = true'),
    });
    expect((await prove(byCategory('AI_HUMAN_IN_THE_LOOP'), fixed)).status).toBe('SAT_COMPLIANT');
  });

  it('egress: a data-dependent region is refuted with the input that selects it', async () => {
    const files = fixture({
      'services/cross_border_sync.ts': (c) =>
        c.replace('const REPLICA_TARGET_REGION = "us-east-1";', 'const REPLICA_TARGET_REGION = "eu-central-1";').replace(
          'destinationRegion: REPLICA_TARGET_REGION,',
          'destinationRegion: event.tenantId === "tenant-us-01" ? "us-east-1" : REPLICA_TARGET_REGION,'
        ),
    });
    const proof = await prove(byCategory('CROSS_BORDER_TRANSFER'), files);
    expect(proof.status).toBe('UNSAT_VIOLATION');
    expect(proof.offendingLocations.map((l) => l.explanation).join(' ')).toContain('event.tenantId = "tenant-us-01"');
  });

  it('logging: a leak on an unreachable branch is not a violation; a reachable one is', async () => {
    const guarded = (debug: string) =>
      fixture({
        'api/fastapi_intake.py': (c) =>
          c
            .replace('ENCRYPTION_CIPHER = "AES-256-GCM-SHARED-KEY"', `ENCRYPTION_CIPHER = "AES-256-GCM-SHARED-KEY"\nDEBUG_PII = ${debug}`)
            .replace('    logger.info(\n', '    if DEBUG_PII:\n        logger.info(\n'),
      });
    expect((await prove(byCategory('PII_LOGGING_BAN'), guarded('False'))).status).toBe('SAT_COMPLIANT');
    expect((await prove(byCategory('PII_LOGGING_BAN'), guarded('True'))).status).toBe('UNSAT_VIOLATION');
  });

  it('consent: a check on only some paths is refuted with the path condition', async () => {
    const c = clause('CONSENT_LAWFUL_BASIS', 'Processing requires consent or another lawful basis.');
    const conditional = fixture({
      'api/fastapi_intake.py': (s) =>
        s.replace('    # VIOLATION RISK: Logs plaintext SSN', '    if x_tenant_id != "internal":\n        require_consent(payload)\n    # VIOLATION RISK: Logs plaintext SSN'),
    });
    const proof = await prove(c, conditional);
    expect(proof.status).toBe('UNSAT_VIOLATION');
    expect(proof.offendingLocations[0].explanation).toContain('x_tenant_id = "internal"');
    const always = fixture({ 'api/fastapi_intake.py': (s) => s.replace('    # VIOLATION RISK: Logs plaintext SSN', '    require_consent(payload)\n    # VIOLATION RISK: Logs plaintext SSN') });
    expect((await prove(c, always)).status).toBe('SAT_COMPLIANT');
  });

  it('inter-procedural taint: PII passed into a logging helper is caught and redacted at the call site', async () => {
    const files = fixture({
      'workers/redis_cache_worker.py': (c) =>
        `${c}\n\nimport logging\n_audit_logger = logging.getLogger("audit")\n\n\ndef audit(message):\n    text = message\n    _audit_logger.info(text)\n\n\ndef record_access(payload):\n    audit(payload.email)\n    audit("static")\n`,
    });
    const c = byCategory('PII_LOGGING_BAN');
    const a = await analyzeFullRepositoryAsync(files);
    const viaHelper = a.astFindings.filter((f) => f.constructType === 'LOGGER_CALL' && f.filePath === 'workers/redis_cache_worker.py');
    expect(viaHelper.map((f) => f.metadata.leakedFields)).toEqual([['email']]);
    const { proofs } = await verifyRepositoryAgainstClauses([c], a.sqlTables, a.astFindings);
    expect(proofs[0].offendingLocations.some((l) => l.filePath === 'workers/redis_cache_worker.py')).toBe(true);
    const pr = await synthesizeRemediationPullRequest([c], a.enrichedFiles, proofs);
    expect(pr?.status).toBe('READY_TO_MERGE');
    expect(pr!.filePatches.find((p) => p.filePath === 'workers/redis_cache_worker.py')!.patchedContent).toContain('audit(redact_pii(payload.email))');
  });
});
