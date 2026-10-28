import { analyzeFullRepository } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles, resetTargetRepoToBaseline } from './analyzer/repoBaseline.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';

async function main() {
  console.log('=== LexCompiler Neuro-Symbolic Verification CLI ===');
  resetTargetRepoToBaseline();
  const clauses = getInitialClauses();
  const files = readTargetRepoFiles();
  const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(files);

  console.log(`Parsed ${enrichedFiles.length} polyglot source files (${sqlTables.length} SQL tables, ${astFindings.length} AST nodes).`);

  const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
  for (const proof of verification.proofs) {
    console.log(
      `[${proof.z3SolverStatus.toUpperCase()}] ${proof.citation} (${proof.title}) -> ${proof.status} in ${proof.z3SolveTimeMs}ms | Affected Nodes: ${proof.affectedGraphNodeIds.join(', ') || 'none'}`
    );
  }

  const pr = await synthesizeRemediationPullRequest(clauses, enrichedFiles, verification.proofs);
  if (pr) {
    console.log(
      `\nSynthesized Auto-Remediation PR #${pr.prNumber}: "${pr.title}" with ${pr.filePatches.length} verified file patches.`
    );
    console.log(
      `Pre-Patch Z3: ${pr.prePatchZ3Status} -> Post-Patch Z3: ${pr.postPatchZ3Status} (Verified in ${pr.postPatchVerifyTimeMs}ms)`
    );
    console.log(`Cryptographic Attestation Root: ${pr.cryptographicAttestationHash}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
