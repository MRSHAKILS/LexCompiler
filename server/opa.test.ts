import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles, resetTargetRepoToBaseline, writeTargetRepoFile } from './analyzer/repoBaseline.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { findOpaBinary } from './policy/opaEvaluator.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';

const opaAvailable = Boolean(await findOpaBinary());

describe('generated Rego policies', () => {
  it('use Rego v1 syntax with one deny rule per check', () => {
    for (const clause of getInitialClauses()) {
      expect(clause.compiled.opaRegoRule).toMatch(/^package lexcompiler\./);
      expect(clause.compiled.opaRegoRule).toContain('import rego.v1');
      expect(clause.compiled.opaRegoRule).toMatch(/deny contains msg if \{/);
      expect(clause.compiled.opaRegoRule).not.toMatch(/deny\[msg\]/);
    }
  });

  it.skipIf(!opaAvailable)('are evaluated by OPA and agree with Z3 before and after remediation', async () => {
    resetTargetRepoToBaseline();
    const clauses = getInitialClauses();
    const pre = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const preV = await verifyRepositoryAgainstClauses(clauses, pre.sqlTables, pre.astFindings);
    for (const proof of preV.proofs) {
      expect(proof.policyDenialSource).toBe('opa');
      expect(proof.opaError).toBeUndefined();
      expect(proof.opaRegoTriggeredDenials.length).toBeGreaterThan(0);
    }
    const pr = await synthesizeRemediationPullRequest(clauses, pre.enrichedFiles, preV.proofs);
    for (const patch of pr!.filePatches) writeTargetRepoFile(patch.filePath, patch.patchedContent);
    const post = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const postV = await verifyRepositoryAgainstClauses(clauses, post.sqlTables, post.astFindings);
    for (const proof of postV.proofs) {
      expect(proof.status).toBe('SAT_COMPLIANT');
      expect(proof.opaRegoTriggeredDenials).toEqual([]);
    }
  }, 60000);
});
