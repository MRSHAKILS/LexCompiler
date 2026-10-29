import crypto from 'node:crypto';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles } from './analyzer/repoBaseline.js';
import { runTreeSitterQueries } from './analyzer/treeSitter.js';
import { getMutationPresets, sha256Hex } from './compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';
import { resolveRepositoryIdentity } from './sandbox/realWorldSandbox.js';
import { recordScanToPersistentSqlite } from './services/realAiServiceMesh.js';
import type { FullComplianceScanReport, LegalClause } from '../shared/types.js';
import { z3EngineLabel } from './util/versions.js';

/**
 * Scans the target repository against `clauses`: AST analysis, Z3 proofs, the remediation PR,
 * repository identity and Tree-sitter structural matches. Only state-changing requests pass
 * `recordToLedger`, so reads stay side-effect free.
 */
export async function buildComplianceReport(
  clauses: LegalClause[],
  activeAmendmentLabel: string | null,
  options: { recordToLedger?: boolean } = {}
): Promise<FullComplianceScanReport> {
  const rawFiles = readTargetRepoFiles();
  const { sqlTables, astFindings, enrichedFiles } = await analyzeFullRepositoryAsync(rawFiles);
  const { proofs, architectureGraph, totalZ3ExecutionMs, merkleAuditRoot } =
    await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);

  const remediationPR = await synthesizeRemediationPullRequest(
    clauses,
    enrichedFiles,
    proofs
  );

  const compliantClausesCount = proofs.filter((p) => p.status === 'SAT_COMPLIANT').length;
  const violatedClausesCount = proofs.filter((p) => p.status === 'UNSAT_VIOLATION').length;
  const overallComplianceScore = Math.round(
    (compliantClausesCount / Math.max(1, proofs.length)) * 100
  );

  const identity = await resolveRepositoryIdentity(
    sha256Hex(enrichedFiles.map((f) => `${f.path}\n${f.content}`).join('\n'))
  );
  const commitHash = `${identity.commitHash}${identity.dirty ? '-dirty' : ''}`;
  const scanId = `SCAN-${crypto.randomUUID()}`;

  if (options.recordToLedger) {
    recordScanToPersistentSqlite({
      scanId,
      commitHash,
      compliantCount: compliantClausesCount,
      violatedCount: violatedClausesCount,
      z3SolveMs: totalZ3ExecutionMs,
      merkleRoot: merkleAuditRoot,
    });
  }

  const structuralQueryMatches: FullComplianceScanReport['structuralQueryMatches'] = {};
  for (const clause of clauses) {
    try {
      structuralQueryMatches[clause.id] = await runTreeSitterQueries(clause.compiled.astPatternQuery, enrichedFiles);
    } catch {
      structuralQueryMatches[clause.id] = [];
    }
  }

  return {
    scanId,
    timestamp: new Date().toISOString(),
    repositoryName: identity.name,
    repositoryBranch: identity.branch,
    commitHash,
    z3EngineVersion: z3EngineLabel(),
    activeAmendmentLabel,
    totalClausesEvaluated: clauses.length,
    compliantClausesCount,
    violatedClausesCount,
    overallComplianceScore,
    totalZ3ExecutionMs,
    merkleAuditRoot,
    clauses,
    sqlTables,
    astFindings,
    architectureGraph,
    proofs,
    remediationPR,
    mutationPresets: getMutationPresets(),
    structuralQueryMatches,
    files: enrichedFiles,
  };
}
