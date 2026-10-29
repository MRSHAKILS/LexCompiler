import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { INITIAL_REPO_FILES } from './analyzer/repoBaseline.js';
import { compileLegalProseToFormalPolicy, extractPurposes, getInitialClauses, inferRuleCategoryFromProse } from './compiler/legalCompiler.js';
import { buildRegoInput } from './policy/opaEvaluator.js';
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

function clause(category: RuleCategory, text: string): LegalClause {
  const base = getInitialClauses()[0];
  const id = `CLAUSE-${category}`;
  return { ...base, id, category, citation: category, title: category, rawLegalText: text, illustrative: false, ...compileLegalProseToFormalPolicy(text, category, id, category) };
}

const TEXTS: Record<string, string> = {
  CONSENT_LAWFUL_BASIS: 'Personal data shall be processed only where the data subject has given consent or another lawful basis applies (Art. 6).',
  BREACH_NOTIFICATION: 'In the case of a personal data breach, the controller shall notify the supervisory authority within 48 hours.',
  DPIA_REQUIRED: 'Automated decision-making requires a data protection impact assessment before processing (Art. 35).',
  DATA_MINIMISATION: 'Personal data shall be adequate, relevant and limited to what is necessary (data minimisation).',
  PURPOSE_LIMITATION: 'Patient data shall be processed only for the purposes of "patient_intake".',
};

async function prove(c: LegalClause, files: TargetRepoFile[]) {
  const a = await analyzeFullRepositoryAsync(files);
  const [proof] = (await verifyRepositoryAgainstClauses([c], a.sqlTables, a.astFindings)).proofs;
  return { a, proof };
}

describe('governance categories', () => {
  it('infers each category from its prose and extracts its bounds', () => {
    for (const [cat, text] of Object.entries(TEXTS)) expect(inferRuleCategoryFromProse(text)).toBe(cat);
    expect(clause('BREACH_NOTIFICATION', TEXTS.BREACH_NOTIFICATION).deontic.extractedParameters.maxBreachNotificationHours).toBe(48);
    expect(extractPurposes('Use it only for the purposes of clinical care and billing.')).toEqual(['clinical_care', 'billing']);
    expect(clause('PURPOSE_LIMITATION', TEXTS.PURPOSE_LIMITATION).compiled.opaRegoRule).toContain('"patient_intake"');
    // A condition ("may … only with consent") is an obligation; only an explicit waiver negates it.
    expect(clause('CONSENT_LAWFUL_BASIS', 'Personal data may be processed only with consent or another lawful basis.').deontic.extractedParameters.requireConsentCheck).toBe(true);
    expect(clause('CONSENT_LAWFUL_BASIS', 'For anonymised statistics, consent is not required.').deontic.extractedParameters.requireConsentCheck).toBe(false);
  });

  it('extracts governance facts from the fixture', async () => {
    const { astFindings } = await analyzeFullRepositoryAsync(fixture());
    const entry = astFindings.find((f) => f.constructType === 'PII_ENTRYPOINT');
    expect(entry).toMatchObject({ functionName: 'ingest_patient_pii', metadata: { hasConsentCheck: false, declaredPurpose: null } });
    const model = astFindings.find((f) => f.constructType === 'PII_COLLECTION_MODEL');
    // full_name is collected by PatientIntakePayload but never read.
    expect(model?.metadata.unusedPiiFields).toEqual(['full_name']);
    expect(astFindings.find((f) => f.constructType === 'BREACH_NOTIFICATION_POLICY')?.metadata.breachNotificationHours).toBeNull();
    const input = buildRegoInput([], astFindings);
    expect(input.entrypoints[0].has_consent_check).toBe(false);
    expect(input.models[0].unused_pii_fields).toEqual(['full_name']);
  });

  it.each(['CONSENT_LAWFUL_BASIS', 'BREACH_NOTIFICATION', 'DATA_MINIMISATION', 'PURPOSE_LIMITATION'] as const)(
    '%s: refutes the fixture, remediates it, and the patch passes the Z3 gate',
    async (category) => {
      const c = clause(category, TEXTS[category]);
      const { a, proof } = await prove(c, fixture());
      expect(proof.status).toBe('UNSAT_VIOLATION');
      expect(proof.unsatCoreAssertions.length).toBeGreaterThan(0);
      const pr = await synthesizeRemediationPullRequest([c], a.enrichedFiles, [proof]);
      expect(pr?.status).toBe('READY_TO_MERGE');
      expect(pr?.postPatchZ3Status).toBe('SAT_COMPLIANT');
      expect(pr?.filePatches.every((p) => p.syntaxCheck?.passed)).toBe(true);
    }
  );

  it('breach deadline: an explicit constant is tightened to the legal limit', async () => {
    const c = clause('BREACH_NOTIFICATION', TEXTS.BREACH_NOTIFICATION);
    const files = fixture({ 'workers/redis_cache_worker.py': (s) => s.replace('PII_CACHE_TTL_HOURS = 720', 'PII_CACHE_TTL_HOURS = 720\nBREACH_NOTIFICATION_WINDOW_DAYS = 7') });
    const { a, proof } = await prove(c, files);
    expect(proof.offendingLocations[0].explanation).toMatch(/168h/);
    const pr = await synthesizeRemediationPullRequest([c], a.enrichedFiles, [proof]);
    const patch = pr!.filePatches.find((p) => p.filePath === 'workers/redis_cache_worker.py')!;
    expect(patch.patchedContent).toContain('BREACH_NOTIFICATION_WINDOW_DAYS = 2');
  });

  it('consent: the inserted check fails closed', async () => {
    const c = clause('CONSENT_LAWFUL_BASIS', TEXTS.CONSENT_LAWFUL_BASIS);
    const { a, proof } = await prove(c, fixture());
    const pr = await synthesizeRemediationPullRequest([c], a.enrichedFiles, [proof]);
    const api = pr!.filePatches.find((p) => p.filePath === 'api/fastapi_intake.py')!.patchedContent;
    expect(api).toMatch(/\n {4}require_consent\(payload\)\n/);
    expect(api).toContain('CONSENT_REGISTRY is not configured');
    expect(api.match(/def require_consent\(/g)).toHaveLength(1);
  });

  it('DPIA: missing assessments are reported but never auto-generated; a referenced file satisfies it', async () => {
    const c = clause('DPIA_REQUIRED', TEXTS.DPIA_REQUIRED);
    const { a, proof } = await prove(c, fixture());
    expect(proof.status).toBe('UNSAT_VIOLATION');
    expect(proof.repairTargets || []).toHaveLength(0);
    const pr = await synthesizeRemediationPullRequest([c], a.enrichedFiles, [proof]);
    expect(pr?.status).not.toBe('READY_TO_MERGE');

    const withDpia = [
      ...fixture({ 'services/ai_credit_triage.ts': (s) => `export const DPIA_REFERENCE = 'docs/dpia/ai_credit_triage.md';\n${s}` }),
      { path: 'docs/dpia/ai_credit_triage.md', language: 'markdown', description: '', content: '# DPIA', lastModified: '' } as unknown as TargetRepoFile,
    ];
    expect((await prove(c, withDpia)).proof.status).toBe('SAT_COMPLIANT');
  });
});
