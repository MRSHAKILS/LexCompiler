import { enterScratchFixtureCopy } from './cli/scratchFixture.js';

/**
 * Compliance gate.
 *
 * - With LEXCOMPILER_TARGET_REPO set (a real repository): proves every clause against it
 *   and exits 1 if any clause is UNSAT or UNKNOWN. Nothing in the repository is modified.
 * - Otherwise (demo fixture, scratch copy): checks that the intentionally non-compliant
 *   fixture is detected and that the synthesized remediation passes the Z3 gate.
 *
 * Exit codes: 0 = gate passed, 1 = gate failed, 2 = internal error.
 */
async function main() {
  const realRepo = Boolean(process.env.LEXCOMPILER_TARGET_REPO) && process.env.LEXCOMPILER_TARGET_REPO_IS_FIXTURE !== '1';
  if (!realRepo) enterScratchFixtureCopy('verify');

  const { analyzeFullRepository } = await import('./analyzer/astAnalyzer.js');
  const { readTargetRepoFiles, resetTargetRepoToBaseline, TARGET_REPO_ROOT } = await import('./analyzer/repoBaseline.js');
  const { getInitialClauses } = await import('./compiler/legalCompiler.js');
  const { verifyRepositoryAgainstClauses } = await import('./prover/z3Engine.js');
  const { synthesizeRemediationPullRequest } = await import('./remediation/prSynthesizer.js');

  console.log('=== LexCompiler Verification Gate ===');
  console.log(`Repository: ${TARGET_REPO_ROOT}${realRepo ? '' : ' (scratch copy of the demo fixture)'}`);
  if (!realRepo) resetTargetRepoToBaseline();

  const clauses = getInitialClauses();
  const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(readTargetRepoFiles());
  console.log(`Parsed ${enrichedFiles.length} files (${sqlTables.length} SQL tables, ${astFindings.length} findings).`);

  const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
  for (const proof of verification.proofs) {
    console.log(
      `[${proof.z3SolverStatus.toUpperCase()}] ${proof.citation} -> ${proof.status} (${proof.applicableInstanceCount ?? 0} constructs) | nodes: ${
        proof.affectedGraphNodeIds.join(', ') || 'none'
      }`
    );
    for (const loc of proof.offendingLocations) console.log(`    ${loc.filePath}:${loc.line} ${loc.explanation}`);
    for (const reason of proof.reviewReasons || []) console.log(`    review: ${reason}`);
  }

  const pr = await synthesizeRemediationPullRequest(clauses, enrichedFiles, verification.proofs);
  if (pr) {
    console.log(`\nRemediation ${pr.prId}: "${pr.title}" — ${pr.filePatches.length} file(s), status ${pr.status}`);
    console.log(`Post-patch Z3: ${pr.postPatchZ3Status}${pr.unresolvedClauseIds?.length ? ` (unresolved: ${pr.unresolvedClauseIds.join(', ')})` : ''}`);
  }

  const failing = verification.proofs.filter((p) => p.status !== 'SAT_COMPLIANT');
  if (realRepo) {
    if (failing.length > 0) {
      console.error(`\nGATE FAILED: ${failing.length} clause(s) not proven compliant.`);
      process.exit(1);
    }
    console.log('\nGATE PASSED: every clause is SAT_COMPLIANT.');
    return;
  }

  const detected = failing.length === clauses.length;
  const remediated = pr?.status === 'READY_TO_MERGE';
  if (!detected || !remediated) {
    console.error(`\nGATE FAILED: detected all fixture violations=${detected}, remediation passes Z3 gate=${remediated}.`);
    process.exit(1);
  }
  console.log('\nGATE PASSED: all fixture violations detected and the remediation passes the Z3 gate.');
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
