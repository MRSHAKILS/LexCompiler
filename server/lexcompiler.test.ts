import { describe, expect, it } from 'vitest';
import { buildMultiAgentExecutionReport } from './agents/multiAgentOrchestrator.js';
import { analyzeFullRepository } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles, resetTargetRepoToBaseline } from './analyzer/repoBaseline.js';
import {
  compileLegalProseToFormalPolicy,
  getInitialClauses,
} from './compiler/legalCompiler.js';
import { getMcpServersCatalog, invokeMcpTool } from './mcp/mcpSuite.js';
import { runTokenOptimizationBenchmark } from './optimization/tokenOptimizer.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { executeHybridRagQuery } from './rag/hybridRagEngine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';

describe('LexCompiler Neuro-Symbolic Law-to-AST Engine & AI-Heavy Suite', () => {
  it('compiles natural-language 72-hour + tenant KMS prose into SMT-LIB2 and OPA Rego', () => {
    const prose =
      'Personal identifiable information (PII) must be encrypted at rest with tenant-isolated keys and purged within 72 hours.';
    const res = compileLegalProseToFormalPolicy(
      prose,
      'RETENTION_AND_TENANT_KMS',
      'CLAUSE-DPA-4.2',
      'GDPR Art. 17 / DPA §4.2'
    );
    expect(res.deontic.extractedParameters.maxRetentionHours).toBe(72);
    expect(res.deontic.extractedParameters.requiresTenantIsolatedKeys).toBe(true);
    expect(res.compiled.smtLib2Snippet).toContain('statutory_max_ttl_hours 72');
    expect(res.compiled.opaRegoRule).toContain('statutory_max_hours := 72');
  });

  it('parses polyglot SQL, Python, and TypeScript ASTs and proves UNSAT violations in Z3, then verifies SAT after remediation patch', async () => {
    resetTargetRepoToBaseline();
    const clauses = getInitialClauses();
    const files = readTargetRepoFiles();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(files);

    expect(sqlTables.length).toBeGreaterThanOrEqual(2);
    expect(astFindings.length).toBeGreaterThanOrEqual(5);

    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const dpaProof = verification.proofs.find((p) => p.clauseId === 'CLAUSE-DPA-4.2');
    expect(dpaProof?.status).toBe('UNSAT_VIOLATION');
    expect(dpaProof?.affectedGraphNodeIds).toEqual(
      expect.arrayContaining([
        'node-postgres-schema',
        'node-fastapi-endpoint',
        'node-redis-worker',
      ])
    );

    const pr = await synthesizeRemediationPullRequest(
      clauses,
      enrichedFiles,
      verification.proofs
    );
    expect(pr).not.toBeNull();
    expect(pr?.postPatchZ3Status).toBe('SAT_COMPLIANT');
    expect(pr?.filePatches.length).toBe(5);
  });

  it('exposes 6 custom MCP servers and executes JSON-RPC 2.0 tool calls', async () => {
    const servers = getMcpServersCatalog();
    expect(servers.length).toBe(6);

    const rpcRes = await invokeMcpTool(
      'lex-z3-prover-mcp',
      'prove_repository_compliance_z3',
      { extractUnsatCore: true }
    );
    expect(rpcRes.jsonRpcResponse.result.isError).toBe(false);
    expect(rpcRes.serverId).toBe('lex-z3-prover-mcp');
  });

  it('executes Hybrid Contextual + Graph RAG queries and 5-Stage Token Optimization', async () => {
    const clauses = getInitialClauses();
    const files = readTargetRepoFiles();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(files);
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);

    const ragReport = executeHybridRagQuery(
      'Which SQL tables and Python endpoints violate 72-hour retention and tenant KMS?',
      clauses,
      sqlTables,
      astFindings,
      verification.proofs,
      4
    );
    expect(ragReport.retrievedChunks.length).toBe(4);
    expect(ragReport.ragasMetrics.faithfulness).toBeGreaterThan(0.95);

    const tokBench = runTokenOptimizationBenchmark(
      clauses,
      enrichedFiles,
      sqlTables,
      astFindings
    );
    expect(tokBench.totalReductionPercent).toBeGreaterThan(75);
    expect(tokBench.stages.length).toBe(5);

    const agentReport = buildMultiAgentExecutionReport(
      clauses,
      enrichedFiles,
      sqlTables,
      astFindings,
      verification.proofs,
      null
    );
    expect(agentReport.steps.length).toBe(6);
  });
});
