import { spawnSync } from 'node:child_process';
import { useScratchFixtureCopy } from './cli/scratchFixture.js';

/**
 * End-to-end demo on the bundled fixture: run the target app, prove violations in Z3,
 * talk to the stdio MCP server, synthesize and apply the remediation, then re-run and
 * re-prove. Every stage is asserted; the process exits 1 on the first failed check.
 * Works on a scratch copy of target-repo/ unless --in-place is passed.
 */
async function runRealWorldScenario() {
  const inPlace = process.argv.includes('--in-place');
  const repo = inPlace ? 'target-repo/' : useScratchFixtureCopy('realworld');

  const { analyzeFullRepository } = await import('./analyzer/astAnalyzer.js');
  const { readTargetRepoFiles, resetTargetRepoToBaseline, writeTargetRepoFile } = await import(
    './analyzer/repoBaseline.js'
  );
  const { getInitialClauses } = await import('./compiler/legalCompiler.js');
  const { verifyRepositoryAgainstClauses } = await import('./prover/z3Engine.js');
  const { executeHybridRagQuery } = await import('./rag/hybridRagEngine.js');
  const { synthesizeRemediationPullRequest } = await import('./remediation/prSynthesizer.js');
  const { commitTargetRepoChanges, executeRealWorldSandboxVerification, resetTargetRepoGitHistory } = await import(
    './sandbox/realWorldSandbox.js'
  );

  const failures: string[] = [];
  const check = (ok: boolean, label: string) => {
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
    if (!ok) failures.push(label);
  };

  console.log('================================================================================');
  console.log(' LEXCOMPILER — END-TO-END VERIFICATION ON THE DEMO FIXTURE');
  console.log(`  repository: ${repo}`);
  console.log('================================================================================\n');

  resetTargetRepoToBaseline();
  resetTargetRepoGitHistory();
  const clauses = getInitialClauses();

  console.log('--- [1] Runtime sandbox (pre-remediation) ---');
  const pre = executeRealWorldSandboxVerification();
  console.log(`  git ${pre.git.branch} @ ${pre.git.headCommit}`);
  console.log(`  SQL: ${pre.sqlDatabaseExecution.engine}, retention default ${pre.sqlDatabaseExecution.actualDefaultRetentionHours}h`);
  console.log(`  FastAPI log: ${pre.pythonFastApiExecution.capturedLoggerOutput}`);
  console.log(`  Redis SETEX TTL: ${pre.pythonRedisWorkerExecution.capturedSetexTtlHours}h`);
  check(pre.pythonFastApiExecution.leakedPlaintextSsnInLogs, 'baseline app leaks plaintext PII to logs (expected)');

  console.log('\n--- [2] AST extraction & Z3 proof (pre-patch) ---');
  const preAst = analyzeFullRepository(readTargetRepoFiles());
  const preZ3 = await verifyRepositoryAgainstClauses(clauses, preAst.sqlTables, preAst.astFindings);
  for (const proof of preZ3.proofs) {
    console.log(`  [${proof.z3SolverStatus}] ${proof.citation} -> ${proof.status} | core: ${proof.unsatCoreAssertions.join(', ') || '—'}`);
  }
  check(preZ3.proofs.every((p) => p.status === 'UNSAT_VIOLATION'), 'Z3 refutes every clause on the baseline');
  check(preZ3.proofs.every((p) => p.unsatCoreAssertions.length > 0), 'every refutation has a Z3 unsat core');

  console.log('\n--- [3] stdio MCP server (JSON-RPC 2.0) ---');
  const stdioInput = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'cli', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'prove_repository_compliance_z3', arguments: {} } },
  ]
    .map((m) => JSON.stringify(m))
    .join('\n');
  const mcpProc = spawnSync(process.execPath, ['--import', 'tsx', 'server/mcp/stdio-server.ts', 'lex-z3-prover-mcp'], {
    input: `${stdioInput}\n`,
    encoding: 'utf8',
    timeout: 30000,
    env: process.env,
  });
  const responses = (mcpProc.stdout || '')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { id?: number; result?: { tools?: unknown[]; isError?: boolean } });
  console.log(`  ${responses.length} responses: ids ${responses.map((r) => r.id).join(', ')}`);
  check(responses.find((r) => r.id === 1)?.result !== undefined, 'MCP initialize answered');
  check((responses.find((r) => r.id === 2)?.result?.tools?.length ?? 0) > 0, 'MCP tools/list returns tools');
  check(responses.find((r) => r.id === 3)?.result?.isError === false, 'MCP tools/call succeeds');

  console.log('\n--- [4] Hybrid retrieval ---');
  const rag = executeHybridRagQuery(
    'Which SQL tables and Python endpoints violate the 72-hour retention and tenant-isolated KMS requirement?',
    clauses,
    preAst.sqlTables,
    preAst.astFindings,
    preZ3.proofs,
    4
  );
  console.log(`  top chunk: ${rag.retrievedChunks[0]?.chunk.citationOrPath} (score ${rag.retrievedChunks[0]?.rrfHybridScore})`);
  check(rag.retrievedChunks.length > 0, 'retrieval returns chunks');

  console.log('\n--- [5] Remediation (pre-PR Z3 gate) ---');
  const pr = await synthesizeRemediationPullRequest(clauses, preAst.enrichedFiles, preZ3.proofs);
  check(pr !== null, 'a remediation bundle is synthesized');
  if (pr) {
    console.log(`  ${pr.prId}: "${pr.title}" — ${pr.filePatches.length} file(s), ${pr.cegisIterations} round(s)`);
    check(pr.status === 'READY_TO_MERGE' && pr.postPatchZ3Status === 'SAT_COMPLIANT', 'post-patch Z3 gate passes');
    check(pr.filePatches.every((fp) => fp.syntaxCheck?.passed), 'every patched file re-parses');
    if (pr.status === 'READY_TO_MERGE') {
      for (const patch of pr.filePatches) writeTargetRepoFile(patch.filePath, patch.patchedContent);
      const commit = commitTargetRepoChanges(`fix(compliance): apply ${pr.prId} (${pr.filePatches.length} files)`);
      console.log(`  committed to sandbox git @ ${commit}`);
    }
  }

  console.log('\n--- [6] Runtime sandbox & Z3 proof (post-patch) ---');
  const post = executeRealWorldSandboxVerification();
  console.log(`  git log: ${post.git.commitLog.join(' | ')}`);
  console.log(`  FastAPI log: ${post.pythonFastApiExecution.capturedLoggerOutput}`);
  console.log(`  Redis SETEX TTL: ${post.pythonRedisWorkerExecution.capturedSetexTtlHours}h`);
  check(!post.pythonFastApiExecution.leakedPlaintextSsnInLogs, 'patched app no longer logs plaintext PII');
  check(post.pythonRedisWorkerExecution.capturedSetexTtlHours <= 72, 'patched cache TTL is within 72h');
  check(post.sqlDatabaseExecution.hasTenantKmsKeyColumn, 'patched schema has tenant_kms_key_id');
  const postAst = analyzeFullRepository(readTargetRepoFiles());
  const postZ3 = await verifyRepositoryAgainstClauses(clauses, postAst.sqlTables, postAst.astFindings);
  for (const proof of postZ3.proofs) {
    console.log(`  [${proof.z3SolverStatus}] ${proof.citation} -> ${proof.status}`);
  }
  check(postZ3.proofs.every((p) => p.status === 'SAT_COMPLIANT'), 'Z3 proves every clause after remediation');

  console.log('\n================================================================================');
  if (failures.length > 0) {
    console.log(` ${failures.length} CHECK(S) FAILED:`);
    for (const f of failures) console.log(`  - ${f}`);
    console.log('================================================================================');
    process.exit(1);
  }
  console.log(' ALL END-TO-END CHECKS PASSED');
  console.log('================================================================================');
}

runRealWorldScenario().catch((err) => {
  console.error(err);
  process.exit(1);
});
