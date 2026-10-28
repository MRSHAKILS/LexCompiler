import fs from 'node:fs';
import path from 'node:path';
import { loadClausesForCli } from './cli/clauses.js';
import { enterScratchFixtureCopy } from './cli/scratchFixture.js';

/**
 * Writes a SARIF 2.1.0 report for the target repository (LEXCOMPILER_TARGET_REPO, or a
 * scratch copy of the demo fixture) to the path given as the first argument.
 */
async function main() {
  const out = path.resolve(process.argv[2] || 'lexcompiler.sarif');
  const realRepo = Boolean(process.env.LEXCOMPILER_TARGET_REPO) && process.env.LEXCOMPILER_TARGET_REPO_IS_FIXTURE !== '1';
  if (!realRepo) enterScratchFixtureCopy('sarif');

  const { analyzeFullRepositoryAsync } = await import('./analyzer/astAnalyzer.js');
  const { readTargetRepoFiles, resetTargetRepoToBaseline } = await import('./analyzer/repoBaseline.js');
  const { generateSarifReport } = await import('./enterprise/enterpriseSuite.js');
  const { verifyRepositoryAgainstClauses } = await import('./prover/z3Engine.js');
  const { resolveRepositoryIdentity } = await import('./sandbox/realWorldSandbox.js');

  if (!realRepo) resetTargetRepoToBaseline();
  const clauses = await loadClausesForCli();
  const { sqlTables, astFindings } = await analyzeFullRepositoryAsync(readTargetRepoFiles());
  const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
  const identity = resolveRepositoryIdentity(verification.merkleAuditRoot);
  const sarif = generateSarifReport(
    clauses,
    verification.proofs,
    { commitHash: identity.commitHash, branch: identity.branch, remoteUrl: identity.remoteUrl },
    process.env.LEXCOMPILER_SARIF_PATH_PREFIX ?? (realRepo ? '' : 'target-repo/')
  );
  fs.writeFileSync(out, JSON.stringify(sarif, null, 2));
  const results = (sarif.runs as Array<{ results: unknown[] }>)[0].results.length;
  console.log(`Wrote ${out} (${results} results)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
