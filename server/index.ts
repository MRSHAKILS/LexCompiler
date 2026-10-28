import path from 'node:path';
import cors from 'cors';
import express from 'express';
import {
  buildMultiAgentExecutionReport,
  getPromptLibraryCatalog,
} from './agents/multiAgentOrchestrator.js';
import { analyzeFullRepository } from './analyzer/astAnalyzer.js';
import {
  ensureTargetRepoFilesExist,
  readTargetRepoFiles,
  resetTargetRepoToBaseline,
  TARGET_REPO_IS_FIXTURE,
  TARGET_REPO_ROOT,
  TargetRepoPathError,
  writeTargetRepoFile,
} from './analyzer/repoBaseline.js';
import {
  compileLegalProseToFormalPolicyAsync,
  fetchLiveRegulatoryFeed,
  getBanglaInitialClauses,
  getInitialClauses,
  getMutationPresets,
  inferRuleCategoryFromProse,
  sha256Hex,
} from './compiler/legalCompiler.js';
import { getMcpServersCatalog, handleMcpMessage, invokeMcpTool } from './mcp/mcpSuite.js';
import { loadActiveClauseState, saveActiveClauseState } from './state.js';
import {
  compressLegalProseCaveman,
  compressRepoToGraphifySExpr,
  pruneCodeWithCodeburn,
  runTokenOptimizationBenchmark,
} from './optimization/tokenOptimizer.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import {
  executeHybridRagQuery,
  executeRealNeuralRagQuery,
} from './rag/hybridRagEngine.js';
import { synthesizeRemediationPullRequest } from './remediation/prSynthesizer.js';
import {
  commitTargetRepoChanges,
  ensureTargetRepoGitInitialized,
  executeRealWorldSandboxVerification,
  resetTargetRepoGitHistory,
  resolveRepositoryIdentity,
} from './sandbox/realWorldSandbox.js';
import {
  executeByocCustomScan,
  generateSarifReport,
  generateSignedConformityCertificate,
  verifyEd25519CertificateSignature,
} from './enterprise/enterpriseSuite.js';
import { getAttestationSigningKey } from './enterprise/signingKey.js';
import {
  computeRealNeuralEmbedding,
  ensurePersistentSqliteDb,
  getLiveServiceMeshTelemetry,
  recordScanToPersistentSqlite,
  runRealLlmInference,
} from './services/realAiServiceMesh.js';
import {
  assertSafeBindConfig,
  createApiGuard,
  isOriginAllowed,
  resolveServerSecurityConfig,
} from './security.js';
import type {
  ComplianceFrameworkId,
  FullComplianceScanReport,
  LegalClause,
  RemediationPullRequest,
  RuleCategory,
} from '../shared/types.js';

/** Client errors (refused paths, non-fixture resets) are 400s; everything else is a 500. */
function sendError(res: express.Response, err: unknown): void {
  if (err instanceof TargetRepoPathError) {
    res.status(400).json({ error: err.message });
    return;
  }
  res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
}

const securityConfig = resolveServerSecurityConfig();
assertSafeBindConfig(securityConfig);

const app = express();
app.use(
  cors({
    origin: (origin, callback) => callback(null, isOriginAllowed(securityConfig, origin)),
  })
);
app.use(express.json({ limit: '5mb' }));
app.use('/api', createApiGuard(securityConfig));

// Ensure real target repository files, Git repo & SQLite ledger exist on disk
ensureTargetRepoFilesExist();
ensureTargetRepoGitInitialized();
ensurePersistentSqliteDb();

const persistedState = loadActiveClauseState();
let activeClauses: LegalClause[] = persistedState?.clauses || getInitialClauses();
let activeAmendmentLabel: string | null =
  persistedState?.amendmentLabel ?? 'Amended DPA §4.2 / GDPR Art. 17: 72-Hour Purge + Tenant-Isolated KMS Keys';

/** Persists clause edits so they survive restarts and reach the stdio MCP server. */
function persistClauses(): void {
  saveActiveClauseState(activeClauses, activeAmendmentLabel);
}
let commitCounter = 1;

async function buildFullComplianceReport(
  options: { recordToLedger?: boolean } = {}
): Promise<FullComplianceScanReport> {
  const rawFiles = readTargetRepoFiles();
  const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(rawFiles);
  const { proofs, architectureGraph, totalZ3ExecutionMs, merkleAuditRoot } =
    await verifyRepositoryAgainstClauses(activeClauses, sqlTables, astFindings);

  const remediationPR = await synthesizeRemediationPullRequest(
    activeClauses,
    enrichedFiles,
    proofs
  );

  const compliantClausesCount = proofs.filter((p) => p.status === 'SAT_COMPLIANT').length;
  const violatedClausesCount = proofs.filter((p) => p.status === 'UNSAT_VIOLATION').length;
  const overallComplianceScore = Math.round(
    (compliantClausesCount / Math.max(1, proofs.length)) * 100
  );

  const identity = resolveRepositoryIdentity(
    sha256Hex(enrichedFiles.map((f) => `${f.path}\n${f.content}`).join('\n'))
  );
  const commitHash = `${identity.commitHash}${identity.dirty ? '-dirty' : ''}`;
  const scanId = `SCAN-${Date.now().toString().slice(-6)}`;

  // Only state-changing requests append to the audit ledger; reads stay side-effect free.
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

  return {
    scanId,
    timestamp: new Date().toISOString(),
    repositoryName: identity.name,
    repositoryBranch: identity.branch,
    commitHash,
    z3EngineVersion: 'Microsoft Z3 v4.13.4 (WASM/Native SMT-LIB2)',
    activeAmendmentLabel,
    totalClausesEvaluated: activeClauses.length,
    compliantClausesCount,
    violatedClausesCount,
    overallComplianceScore,
    totalZ3ExecutionMs,
    merkleAuditRoot,
    clauses: activeClauses,
    sqlTables,
    astFindings,
    architectureGraph,
    proofs,
    remediationPR,
    mutationPresets: getMutationPresets(),
    files: enrichedFiles,
  };
}

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'LexCompiler Neuro-Symbolic Law-to-AST Engine',
    z3Solver: 'ready',
    mcpServersOnline: 6,
    ragEngine: 'Contextual + Graph RAG + BM25/pgvector RRF + CRAG',
    astParsers: ['python3-ast', 'typescript-compiler-api', 'postgres-ddl-cst'],
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/state', async (_req, res) => {
  try {
    const report = await buildFullComplianceReport();
    res.json(report);
  } catch (err) {
    console.error('Error building compliance report:', err);
    sendError(res, err);
  }
});

app.get('/api/regulations/live-feed', async (_req, res) => {
  try {
    const items = await fetchLiveRegulatoryFeed();
    res.json({ items });
  } catch (err) {
    sendError(res, err);
  }
});

// ============================================================================
// 6+ MCP SERVERS CONTROL PLANE (JSON-RPC 2.0 + SSE + STDIO)
// ============================================================================

app.get('/api/mcp/servers', (_req, res) => {
  res.json({
    servers: getMcpServersCatalog(),
    integratedExternalMcpServers: [
      {
        id: 'postgres-pgvector-mcp',
        name: 'PostgreSQL + pgvector Schema & Vector Store MCP',
        transport: 'stdio / sse',
        purpose: 'Live DDL introspection and HNSW vector similarity queries over statutory embeddings',
      },
      {
        id: 'neo4j-cypher-mcp',
        name: 'Neo4j Knowledge Graph & Blast-Radius Cypher MCP',
        transport: 'streamable-http',
        purpose: '2-hop Graph RAG traversal linking GDPR/HIPAA clauses to AST nodes and SQL columns',
      },
      {
        id: 'github-git-mcp',
        name: 'GitHub Repository & Pull Request Automation MCP',
        transport: 'streamable-http',
        purpose: 'Creates remediation branches, commits AST-verified patches, and opens PR #409',
      },
      {
        id: 'filesystem-sandbox-mcp',
        name: 'Ephemeral Git Sandbox Filesystem MCP',
        transport: 'stdio',
        purpose: 'Reads and writes polyglot source files in isolated verification worktrees',
      },
      {
        id: 'duckdb-lakehouse-mcp',
        name: 'DuckDB / Apache Iceberg Compliance Ledger MCP',
        transport: 'stdio',
        purpose: 'Stores immutable Parquet/JSONL OpenLineage compliance telemetry and Z3 proof timings',
      },
      {
        id: 'n8n-webhook-bridge-mcp',
        name: 'n8n & Temporal Workflow Trigger MCP',
        transport: 'streamable-http / sse',
        purpose: 'Dispatches real-time regulatory shockwave alerts and CI/CD compliance gates',
      },
    ],
  });
});

/** MCP Streamable HTTP transport: one JSON-RPC message per POST; notifications get 202. */
app.post('/api/mcp/:serverId/rpc', async (req, res) => {
  try {
    const { serverId } = req.params;
    if (!getMcpServersCatalog().some((s) => s.id === serverId)) {
      res.status(404).json({ jsonrpc: '2.0', id: null, error: { code: -32602, message: `Unknown MCP server "${serverId}"` } });
      return;
    }
    const response = await handleMcpMessage(serverId, req.body, activeClauses);
    if (!response) {
      res.status(202).end();
      return;
    }
    res.json(response);
  } catch (err) {
    sendError(res, err);
  }
});

/** UI helper: runs tools/call and returns the full request/response trace. */
app.post('/api/mcp/:serverId/invoke', async (req, res) => {
  try {
    const { serverId } = req.params;
    const body = (req.body || {}) as { toolName?: string; arguments?: Record<string, unknown> };
    res.json(await invokeMcpTool(serverId, String(body.toolName || ''), body.arguments || {}, activeClauses));
  } catch (err) {
    sendError(res, err);
  }
});

/** This server does not offer a server-initiated SSE stream (allowed by Streamable HTTP). */
app.get('/api/mcp/:serverId/rpc', (_req, res) => {
  res.setHeader('Allow', 'POST');
  res.status(405).json({ error: 'Use POST for MCP JSON-RPC messages; no server-initiated SSE stream is offered.' });
});

// ============================================================================
// HYBRID CONTEXTUAL + GRAPH RAG ENGINE ENDPOINTS
// ============================================================================

app.post('/api/rag/query', async (req, res) => {
  try {
    const { query, topK } = (req.body || {}) as { query?: string; topK?: number };
    const q =
      query && query.trim()
        ? query.trim()
        : 'Which SQL tables and Python endpoints violate the 72-hour retention and tenant-isolated KMS requirement?';

    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings } = analyzeFullRepository(rawFiles);
    const verification = await verifyRepositoryAgainstClauses(
      activeClauses,
      sqlTables,
      astFindings
    );

    const ragReport = await executeRealNeuralRagQuery(
      q,
      activeClauses,
      sqlTables,
      astFindings,
      verification.proofs,
      topK || 5
    );
    res.json(ragReport);
  } catch (err) {
    sendError(res, err);
  }
});

// ============================================================================
// MULTI-AGENT ORCHESTRATOR & TOKEN OPTIMIZATION LAB ENDPOINTS
// ============================================================================

app.get('/api/ai-heavy/overview', async (_req, res) => {
  try {
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(rawFiles);
    const verification = await verifyRepositoryAgainstClauses(
      activeClauses,
      sqlTables,
      astFindings
    );
    const pr = await synthesizeRemediationPullRequest(
      activeClauses,
      enrichedFiles,
      verification.proofs
    );

    const multiAgentReport = await buildMultiAgentExecutionReport(
      activeClauses,
      enrichedFiles,
      sqlTables,
      astFindings,
      verification.proofs,
      pr
    );

    const tokenBenchmark = runTokenOptimizationBenchmark(
      activeClauses,
      enrichedFiles,
      sqlTables,
      astFindings
    );

    const defaultRagReport = executeHybridRagQuery(
      'Which SQL tables and Python endpoints violate GDPR Art. 17 72-hour retention and tenant-isolated KMS encryption?',
      activeClauses,
      sqlTables,
      astFindings,
      verification.proofs,
      5
    );

    res.json({
      mcpServers: getMcpServersCatalog(),
      multiAgentReport,
      tokenBenchmark,
      defaultRagReport,
      promptLibrary: getPromptLibraryCatalog(),
    });
  } catch (err) {
    sendError(res, err);
  }
});

app.post('/api/optimization/compress', (req, res) => {
  try {
    const { rawLegalText, rawCodeText } = (req.body || {}) as {
      rawLegalText?: string;
      rawCodeText?: string;
    };
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings } = analyzeFullRepository(rawFiles);

    const sampleLegal =
      rawLegalText ||
      activeClauses[0]?.rawLegalText ||
      'Personal identifiable information must be encrypted at rest with tenant-isolated keys and purged within 72 hours.';
    const sampleCode = rawCodeText || rawFiles[1]?.content || '';

    const cavemanCompressed = compressLegalProseCaveman(sampleLegal);
    const codeburnCompressed = pruneCodeWithCodeburn(sampleCode);
    const graphifyCompressed = compressRepoToGraphifySExpr(sqlTables, astFindings);

    res.json({
      rawTokens: Math.ceil((sampleLegal.length + sampleCode.length) / 3.6),
      compressedTokens: Math.ceil(
        (cavemanCompressed.length + graphifyCompressed.length) / 3.6
      ),
      cavemanCompressed,
      codeburnCompressed,
      graphifyCompressed,
    });
  } catch (err) {
    sendError(res, err);
  }
});

app.get('/api/workflows/n8n-export', (_req, res) => {
  res.json({
    name: 'LexCompiler Autonomous Regulatory Horizon-to-PR Pipeline (n8n)',
    nodes: [
      {
        id: '1',
        name: 'EUR-Lex & Federal Register Webhook / Cron Trigger',
        type: 'n8n-nodes-base.scheduleTrigger',
        parameters: { interval: '15m' },
      },
      {
        id: '2',
        name: 'MCP Tool: lex-statute-ingest-mcp',
        type: '@n8n/n8n-nodes-langchain.mcpClientTool',
        parameters: {
          serverUrl: 'http://localhost:3001/api/mcp/lex-statute-ingest-mcp/rpc',
          toolName: 'fetch_live_regulatory_feed',
        },
      },
      {
        id: '3',
        name: 'MCP Tool: lex-deontic-compiler-mcp (Claude 3.7 + DeepSeek-R1)',
        type: '@n8n/n8n-nodes-langchain.mcpClientTool',
        parameters: {
          serverUrl: 'http://localhost:3001/api/mcp/lex-deontic-compiler-mcp/rpc',
          toolName: 'compile_prose_to_smt_and_rego',
        },
      },
      {
        id: '4',
        name: 'MCP Tool: lex-z3-prover-mcp (Microsoft Z3 Formal Check)',
        type: '@n8n/n8n-nodes-langchain.mcpClientTool',
        parameters: {
          serverUrl: 'http://localhost:3001/api/mcp/lex-z3-prover-mcp/rpc',
          toolName: 'prove_repository_compliance_z3',
        },
      },
      {
        id: '5',
        name: 'MCP Tool: lex-remediation-pr-mcp (Auto-PR #409 Enforcer)',
        type: '@n8n/n8n-nodes-langchain.mcpClientTool',
        parameters: {
          serverUrl: 'http://localhost:3001/api/mcp/lex-remediation-pr-mcp/rpc',
          toolName: 'synthesize_and_verify_remediation_pr',
        },
      },
    ],
  });
});

/**
 * Mutate or compile raw legal prose for a specific clause (or add a new clause)
 */
app.post('/api/clauses/compile', async (req, res) => {
  try {
    const {
      clauseId,
      rawLegalText,
      title,
      citation,
      frameworkId,
      category,
      amendmentLabel,
    } = req.body as {
      clauseId?: string;
      rawLegalText: string;
      title?: string;
      citation?: string;
      frameworkId?: ComplianceFrameworkId;
      category?: RuleCategory;
      amendmentLabel?: string;
    };

    if (!rawLegalText || !rawLegalText.trim()) {
      res.status(400).json({ error: 'rawLegalText is required' });
      return;
    }

    const existingIdx = activeClauses.findIndex((c) => c.id === clauseId);
    if (existingIdx >= 0) {
      const target = activeClauses[existingIdx];
      const compiledResult = await compileLegalProseToFormalPolicyAsync(
        rawLegalText,
        category || target.category,
        target.id,
        citation || target.citation
      );

      activeClauses[existingIdx] = {
        ...target,
        title: title || target.title,
        citation: citation || target.citation,
        rawLegalText: rawLegalText.trim(),
        illustrative: false,
        version: `v2026.${commitCounter + 4}-LIVE`,
        lastAmended: new Date().toISOString().slice(0, 10),
        deontic: compiledResult.deontic,
        compiled: compiledResult.compiled,
      };
    } else {
      const newId = clauseId || `CLAUSE-CUSTOM-${Date.now().toString().slice(-4)}`;
      const newCat: RuleCategory = category || inferRuleCategoryFromProse(rawLegalText);
      const newCit = citation || 'Custom DPA Amendment §4.2';
      const compiledResult = await compileLegalProseToFormalPolicyAsync(
        rawLegalText,
        newCat,
        newId,
        newCit
      );

      activeClauses.unshift({
        id: newId,
        frameworkId: frameworkId || 'ENTERPRISE_DPA',
        frameworkName: 'Custom Enterprise DPA / Regulatory Statute',
        citation: newCit,
        title: title || 'Custom Compiled Neuro-Symbolic Legal Obligation',
        severity: 'CRITICAL',
        category: newCat,
        rawLegalText: rawLegalText.trim(),
        version: 'v2026.LIVE',
        lastAmended: new Date().toISOString().slice(0, 10),
        deontic: compiledResult.deontic,
        compiled: compiledResult.compiled,
      });
    }

    activeAmendmentLabel =
      amendmentLabel || `Live Clause Mutation (${citation || clauseId || 'Custom Prose'})`;
    persistClauses();
    const report = await buildFullComplianceReport({ recordToLedger: true });
    res.json(report);
  } catch (err) {
    console.error('Error compiling clause:', err);
    sendError(res, err);
  }
});

/**
 * Trigger a Regulatory Amendment Preset (e.g. 30 Days -> 72 Hours + Tenant-Isolated KMS)
 */
app.post('/api/clauses/mutate-preset', async (req, res) => {
  try {
    const { presetId, resetRepoFiles } = req.body as {
      presetId: string;
      resetRepoFiles?: boolean;
    };

    if (resetRepoFiles) {
      resetTargetRepoToBaseline();
      resetTargetRepoGitHistory();
      commitCounter++;
    }

    const presets = getMutationPresets();
    const preset = presets.find((p) => p.id === presetId);
    if (!preset) {
      res.status(404).json({ error: `Preset ${presetId} not found` });
      return;
    }

    const idx = activeClauses.findIndex((c) => c.id === preset.clauseId);
    if (idx >= 0) {
      const target = activeClauses[idx];
      const compiledResult = await compileLegalProseToFormalPolicyAsync(
        preset.mutatedLawText,
        target.category,
        target.id,
        target.citation
      );
      activeClauses[idx] = {
        ...target,
        rawLegalText: preset.mutatedLawText,
        version: `v2026.${commitCounter + 5}-AMENDED`,
        lastAmended: new Date().toISOString().slice(0, 10),
        deontic: compiledResult.deontic,
        compiled: compiledResult.compiled,
      };
    }

    activeAmendmentLabel = `${preset.name} (${preset.parameterDiffSummary})`;
    persistClauses();
    const report = await buildFullComplianceReport({ recordToLedger: true });
    res.json(report);
  } catch (err) {
    console.error('Error applying preset:', err);
    sendError(res, err);
  }
});

function remediationBlockedResponse(pr: RemediationPullRequest) {
  return {
    error:
      'Remediation PR did not pass the pre-PR Z3 sandbox gate; refusing to apply it. ' +
      `Unresolved clauses: ${(pr.unresolvedClauseIds || []).join(', ') || 'unknown'}.`,
    postPatchZ3Status: pr.postPatchZ3Status,
    unresolvedClauseIds: pr.unresolvedClauseIds || [],
  };
}

/**
 * Apply synthesized remediation patch for a specific architecture node (or file)
 */
app.post('/api/remediation/apply-node', async (req, res) => {
  try {
    const { nodeId, filePath } = req.body as { nodeId?: string; filePath?: string };
    const currentReport = await buildFullComplianceReport();
    const pr = currentReport.remediationPR;

    if (!pr) {
      res.json(currentReport);
      return;
    }
    if (pr.postPatchZ3Status !== 'SAT_COMPLIANT') {
      res.status(409).json(remediationBlockedResponse(pr));
      return;
    }

    const matchingPatches = pr.filePatches.filter(
      (fp) => (nodeId && fp.nodeId === nodeId) || (filePath && fp.filePath === filePath)
    );

    for (const patch of matchingPatches) {
      writeTargetRepoFile(patch.filePath, patch.patchedContent);
    }
    commitTargetRepoChanges(
      `fix(compliance): apply LexCompiler AST patch for ${nodeId || filePath}`
    );
    commitCounter++;

    const updatedReport = await buildFullComplianceReport({ recordToLedger: true });
    res.json(updatedReport);
  } catch (err) {
    console.error('Error applying node patch:', err);
    sendError(res, err);
  }
});

/**
 * Apply all patches in the Remediation Pull Request to the target repository on disk
 */
app.post('/api/remediation/apply-pr', async (_req, res) => {
  try {
    const currentReport = await buildFullComplianceReport();
    const pr = currentReport.remediationPR;

    if (pr && pr.postPatchZ3Status !== 'SAT_COMPLIANT') {
      res.status(409).json(remediationBlockedResponse(pr));
      return;
    }

    if (pr) {
      for (const patch of pr.filePatches) {
        writeTargetRepoFile(patch.filePath, patch.patchedContent);
      }
      commitTargetRepoChanges(
        `fix(compliance): merge LexCompiler Auto-PR #${pr.prNumber} (${pr.filePatches.length} Z3-verified files)`
      );
      commitCounter++;
    }

    const updatedReport = await buildFullComplianceReport({ recordToLedger: true });
    res.json(updatedReport);
  } catch (err) {
    console.error('Error applying full PR:', err);
    sendError(res, err);
  }
});

/**
 * Update a file in target-repo directly from the Live IDE Editor and re-verify
 */
app.post('/api/repo/update-file', async (req, res) => {
  try {
    const { filePath, content } = req.body as { filePath: string; content: string };
    if (!filePath || typeof content !== 'string') {
      res.status(400).json({ error: 'filePath and content are required' });
      return;
    }

    writeTargetRepoFile(filePath, content);
    commitTargetRepoChanges(`chore(repo): manual edit to ${filePath}`);
    commitCounter++;

    const updatedReport = await buildFullComplianceReport({ recordToLedger: true });
    res.json(updatedReport);
  } catch (err) {
    console.error('Error updating repo file:', err);
    sendError(res, err);
  }
});

/**
 * Reset target repository files & legal clauses to initial baseline
 */
app.post('/api/repo/reset', async (req, res) => {
  try {
    const { mode } = (req.body || {}) as { mode?: 'LEGACY_30D_COMPLIANT_DPA' | 'AMENDED_72H' };
    resetTargetRepoToBaseline();
    resetTargetRepoGitHistory();
    activeClauses = getInitialClauses();
    commitCounter++;

    if (mode === 'LEGACY_30D_COMPLIANT_DPA') {
      const legacyText =
        'Section 4.2 (Legacy Data Retention Baseline): All Personal Identifiable Information (PII) persisted in relational tables or cache workers must be encrypted at rest and purged within 30 days (720 hours) of session termination.';
      const idx = activeClauses.findIndex((c) => c.id === 'CLAUSE-DPA-4.2');
      if (idx >= 0) {
        const target = activeClauses[idx];
        const compiledResult = await compileLegalProseToFormalPolicyAsync(
          legacyText,
          target.category,
          target.id,
          target.citation
        );
        activeClauses[idx] = {
          ...target,
          title: 'Legacy 30-Day PII Retention & Standard AES-256 Baseline',
          rawLegalText: legacyText,
          version: 'v2025.1-BASELINE',
          deontic: compiledResult.deontic,
          compiled: compiledResult.compiled,
        };
      }
      activeAmendmentLabel =
        'Legacy 30-Day (720h) Contract Baseline — Ready for Amendment Shockwave';
    } else {
      activeAmendmentLabel =
        'Amended DPA §4.2 / GDPR Art. 17: 72-Hour Purge + Tenant-Isolated KMS Keys';
    }

    persistClauses();
    const report = await buildFullComplianceReport({ recordToLedger: true });
    res.json(report);
  } catch (err) {
    console.error('Error resetting repo:', err);
    sendError(res, err);
  }
});

/**
 * Switch statutory corpus locale between Global English ('en') and Bangladesh Bangla ('bn')
 */
app.post('/api/clauses/switch-locale', async (req, res) => {
  try {
    const { locale, resetRepo } = (req.body || {}) as {
      locale: 'en' | 'bn';
      resetRepo?: boolean;
    };
    if (resetRepo) {
      resetTargetRepoToBaseline();
      resetTargetRepoGitHistory();
      commitCounter++;
    }
    if (locale === 'bn') {
      activeClauses = getBanglaInitialClauses();
      activeAmendmentLabel =
        'বাংলাদেশ ব্যাংক আইসিটি নীতিমালা ধারা ৪.২ (৪৮ ঘণ্টা রিটেনশন ও টেন্যান্ট KMS)';
    } else {
      activeClauses = getInitialClauses();
      activeAmendmentLabel =
        'Amended DPA §4.2 / GDPR Art. 17: 72-Hour Purge + Tenant-Isolated KMS Keys';
    }
    persistClauses();
    const report = await buildFullComplianceReport({ recordToLedger: true });
    res.json(report);
  } catch (err) {
    console.error('Error switching locale:', err);
    sendError(res, err);
  }
});

app.get('/api/sandbox/verify-runtime', (_req, res) => {
  if (!securityConfig.runtimeSandboxEnabled) {
    res.status(403).json({
      error:
        'Runtime sandbox is disabled. It executes target-repo Python in a local process that is not an isolation boundary. ' +
        'Set LEXCOMPILER_ENABLE_RUNTIME_SANDBOX=1 to enable it on a trusted machine.',
      disabled: true,
    });
    return;
  }
  try {
    const runtimeReport = executeRealWorldSandboxVerification();
    res.json(runtimeReport);
  } catch (err) {
    console.error('Error executing real-world sandbox verification:', err);
    sendError(res, err);
  }
});

// ============================================================================
// REAL MULTI-LLM, NEURAL EMBEDDING & SERVICE MESH TELEMETRY ENDPOINTS
// ============================================================================

app.get('/api/services/mesh', async (_req, res) => {
  try {
    const mesh = await getLiveServiceMeshTelemetry();
    res.json(mesh);
  } catch (err) {
    sendError(res, err);
  }
});

app.post('/api/llm/generate', async (req, res) => {
  try {
    const { model, prompt, systemPrompt, maxTokens, cloudApiKey, cloudProvider } =
      req.body || {};
    const result = await runRealLlmInference({
      model: model || 'qwen2.5-coder:0.5b',
      prompt:
        prompt ||
        'Explain why GDPR Art. 17 requires 72h TTL and tenant-isolated KMS keys in Postgres and FastAPI.',
      systemPrompt,
      maxTokens: maxTokens || 120,
      cloudApiKey,
      cloudProvider,
    });
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

app.post('/api/llm/multi-model-pipeline', async (req, res) => {
  try {
    const { clauseText, codeSnippet, preferredLegalModel } = req.body || {};
    const legalText =
      clauseText ||
      activeClauses[0]?.rawLegalText ||
      'PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.';
    const snippet =
      codeSnippet ||
      `logger.info(f"Ingesting patient record ssn={payload.ssn} email={payload.email}")\nencrypted_ssn = encrypt_shared_aes256(payload.ssn)`;

    // 1. Real 384-d Neural Embeddings via all-minilm:latest on Ollama
    const [lawEmbed, codeEmbed] = await Promise.all([
      computeRealNeuralEmbedding(legalText),
      computeRealNeuralEmbedding(snippet),
    ]);

    let cosineSim = 0;
    if (lawEmbed.embedding.length > 0 && codeEmbed.embedding.length > 0) {
      let dot = 0;
      let nA = 0;
      let nB = 0;
      for (let i = 0; i < lawEmbed.embedding.length; i++) {
        dot += lawEmbed.embedding[i] * codeEmbed.embedding[i];
        nA += lawEmbed.embedding[i] * lawEmbed.embedding[i];
        nB += codeEmbed.embedding[i] * codeEmbed.embedding[i];
      }
      cosineSim =
        Math.round((dot / (Math.sqrt(nA) * Math.sqrt(nB) || 1)) * 10000) / 10000;
    }

    // 2. Real Code LLM Inference via qwen2.5-coder:0.5b on Ollama
    const codeLlmRes = await runRealLlmInference({
      model: 'qwen2.5-coder:0.5b',
      prompt: `Analyze this code snippet against the rule "${legalText}":\n${snippet}\nProvide a concise 2-sentence technical explanation of the violation and the code fix.`,
      maxTokens: 110,
    });

    // 3. Real Legal / General Counsel LLM Inference (dolphin3:latest or qwen2.5-coder)
    const legalModelName = preferredLegalModel || 'qwen2.5-coder:0.5b';
    const legalLlmRes = await runRealLlmInference({
      model: legalModelName,
      prompt: `As General Counsel, write a 2-sentence formal compliance attestation explaining how enforcing tenant-isolated KMS keys and 72-hour TTL satisfies "${legalText}".`,
      maxTokens: 110,
    });

    res.json({
      executedAt: new Date().toISOString(),
      neuralEmbedding: {
        model: lawEmbed.modelUsed,
        dimensions: lawEmbed.embedding.length || 384,
        lawVectorPreview: lawEmbed.embedding.slice(0, 8),
        codeVectorPreview: codeEmbed.embedding.slice(0, 8),
        cosineSimilarity: cosineSim,
        latencyMs: Math.round((lawEmbed.latencyMs + codeEmbed.latencyMs) * 100) / 100,
      },
      codeSpecialistLlm: codeLlmRes,
      generalCounselLlm: legalLlmRes,
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ============================================================================
// ENTERPRISE STARTUP SUITE: ED25519 CRYPTO CERTIFICATES, SARIF 2.1.0, BYOC SCAN
// ============================================================================

app.get('/api/enterprise/certificate', async (_req, res) => {
  try {
    const report = await buildFullComplianceReport();
    const cert = generateSignedConformityCertificate(report);
    res.json(cert);
  } catch (err) {
    sendError(res, err);
  }
});

app.get('/api/enterprise/public-key', (_req, res) => {
  const key = getAttestationSigningKey();
  res.json({ algorithm: 'Ed25519', publicKeyPem: key.publicKeyPem, fingerprintSha256: key.fingerprintSha256 });
});

app.post('/api/enterprise/verify-signature', (req, res) => {
  try {
    const { canonicalPayloadJson, signatureHex, publicKeyPem } = (req.body || {}) as {
      canonicalPayloadJson: string;
      signatureHex: string;
      publicKeyPem?: string;
    };
    const result = verifyEd25519CertificateSignature(
      canonicalPayloadJson,
      signatureHex,
      publicKeyPem
    );
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

app.get('/api/enterprise/sarif', async (_req, res) => {
  try {
    const report = await buildFullComplianceReport();
    const identity = resolveRepositoryIdentity(report.merkleAuditRoot);
    // Paths in SARIF are relative to the checkout the report is uploaded from.
    const rel = path.relative(process.cwd(), TARGET_REPO_ROOT);
    const uriPrefix = TARGET_REPO_IS_FIXTURE && rel && !rel.startsWith('..') ? `${rel.split(path.sep).join('/')}/` : '';
    const sarif = generateSarifReport(
      report.clauses,
      report.proofs,
      { commitHash: identity.commitHash, branch: identity.branch, remoteUrl: identity.remoteUrl },
      uriPrefix
    );
    res.json(sarif);
  } catch (err) {
    sendError(res, err);
  }
});

app.post('/api/enterprise/byoc-scan', async (req, res) => {
  try {
    const { contractClauseText, citationLabel, language, fileName, sourceCode } =
      req.body || {};
    const result = await executeByocCustomScan({
      contractClauseText:
        contractClauseText ||
        'All customer payment tokens and PII must be encrypted with tenant-isolated KMS keys, never logged in plaintext, and purged within 48 hours.',
      citationLabel: citationLabel || 'Custom Enterprise MSA §7.1',
      language: language || 'python',
      fileName: fileName || 'custom_payment_service.py',
      sourceCode:
        sourceCode ||
        `# Custom Enterprise Payment & PII Handler\nimport logging\nlogger = logging.getLogger("payments")\n\nTENANT_ISOLATED_KMS = False\nRETENTION_HOURS = 360\n\ndef process_customer(ssn: str, email: str):\n    logger.info(f"Processing customer ssn={ssn} email={email}")\n    return encrypt_shared_aes256(ssn)\n`,
    });
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// Serve built frontend in production
const distPath = path.resolve(process.cwd(), 'dist');
app.use(express.static(distPath));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    next();
    return;
  }
  res.sendFile(path.join(distPath, 'index.html'), (err) => {
    if (err) next();
  });
});

app.listen(securityConfig.port, securityConfig.host, () => {
  console.log(
    `[LexCompiler Server] Neuro-Symbolic Law-to-AST Engine listening on http://${securityConfig.host}:${securityConfig.port}` +
      (securityConfig.apiToken ? ' (API token required)' : ' (loopback only)')
  );
});
