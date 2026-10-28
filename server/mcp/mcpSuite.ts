import { performance } from 'node:perf_hooks';
import { analyzeFullRepository } from '../analyzer/astAnalyzer.js';
import { readTargetRepoFiles } from '../analyzer/repoBaseline.js';
import {
  compileLegalProseToFormalPolicy,
  fetchLiveRegulatoryFeed,
  getInitialClauses,
  sha256Hex,
} from '../compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from '../prover/z3Engine.js';
import { executeHybridRagQuery } from '../rag/hybridRagEngine.js';
import { synthesizeRemediationPullRequest } from '../remediation/prSynthesizer.js';
import type {
  LegalClause,
  McpServerDescriptor,
  McpToolInvocationResult,
  RuleCategory,
} from '../../shared/types.js';

export function getMcpServersCatalog(): McpServerDescriptor[] {
  return [
    {
      id: 'lex-statute-ingest-mcp',
      name: 'LexStatute Ingest & Horizon Scanner MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-statute-ingest-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-statute-ingest-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-statute-ingest-mcp',
      status: 'ONLINE',
      description:
        'Custom MCP server for scraping EUR-Lex CELEX statutes, querying the live U.S. Federal Register REST API, parsing enterprise DPA PDFs/XML/JSON, and normalizing legal clauses.',
      toolsCount: 4,
      resourcesCount: 6,
      promptsCount: 3,
      tools: [
        {
          name: 'fetch_live_regulatory_feed',
          description: 'Fetches real-time statutory updates from EUR-Lex and the U.S. Federal Register API.',
          inputSchema: {
            type: 'object',
            properties: {
              jurisdiction: { type: 'string', enum: ['ALL', 'EU', 'US'] },
            },
          },
          sampleArgs: { jurisdiction: 'ALL' },
        },
        {
          name: 'parse_dpa_contract_clause',
          description: 'Extracts normative obligations and temporal bounds from raw contractual prose.',
          inputSchema: {
            type: 'object',
            properties: {
              clauseText: { type: 'string' },
              framework: { type: 'string' },
            },
            required: ['clauseText'],
          },
          sampleArgs: {
            clauseText:
              'PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.',
            framework: 'ENTERPRISE_DPA',
          },
        },
      ],
    },
    {
      id: 'lex-deontic-compiler-mcp',
      name: 'LexDeontic Neuro-Symbolic Compiler MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-deontic-compiler-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-deontic-compiler-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-deontic-compiler-mcp',
      status: 'ONLINE',
      description:
        'Compiles natural-language legal obligations O(φ), prohibitions F(φ), and permissions P(φ) into First-Order Logic, Microsoft Z3 SMT-LIB2 scripts, and OPA Rego policies.',
      toolsCount: 4,
      resourcesCount: 4,
      promptsCount: 4,
      tools: [
        {
          name: 'compile_prose_to_smt_and_rego',
          description: 'Compiles legal prose directly into SMT-LIB2 assertions, OPA Rego rules, and AST queries.',
          inputSchema: {
            type: 'object',
            properties: {
              rawLegalText: { type: 'string' },
              category: { type: 'string' },
              citation: { type: 'string' },
            },
            required: ['rawLegalText'],
          },
          sampleArgs: {
            rawLegalText:
              'All PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.',
            category: 'RETENTION_AND_TENANT_KMS',
            citation: 'GDPR Art. 17 & 32 / DPA §4.2',
          },
        },
      ],
    },
    {
      id: 'lex-polyglot-ast-mcp',
      name: 'LexAST Polyglot Code & SQL Schema Mapper MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-polyglot-ast-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-polyglot-ast-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-polyglot-ast-mcp',
      status: 'ONLINE',
      description:
        'Parses live Python 3 ASTs, TypeScript Compiler ASTs, and PostgreSQL DDL schemas into a unified Compliance Intermediate Representation & Data-Flow Knowledge Graph.',
      toolsCount: 5,
      resourcesCount: 5,
      promptsCount: 2,
      tools: [
        {
          name: 'scan_polyglot_repository_ast',
          description: 'Parses SQL DDL, Python 3 AST, and TypeScript AST files in target-repo/ and extracts PII data-flow facts.',
          inputSchema: {
            type: 'object',
            properties: {
              includeMetrics: { type: 'boolean' },
            },
          },
          sampleArgs: { includeMetrics: true },
        },
      ],
    },
    {
      id: 'lex-z3-prover-mcp',
      name: 'LexZ3 Formal Theorem Prover & Attestation MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-z3-prover-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-z3-prover-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-z3-prover-mcp',
      status: 'ONLINE',
      description:
        'Executes the Microsoft Z3 SMT Solver over compiled statutory axioms and AST facts, extracting minimal UNSAT Cores, Counterexample Witnesses, and SHA-256 Merkle Provenance proofs.',
      toolsCount: 4,
      resourcesCount: 4,
      promptsCount: 2,
      tools: [
        {
          name: 'prove_repository_compliance_z3',
          description: 'Runs Microsoft Z3 SMT check-sat across all active statutory clauses and returns formal proofs.',
          inputSchema: {
            type: 'object',
            properties: {
              extractUnsatCore: { type: 'boolean' },
            },
          },
          sampleArgs: { extractUnsatCore: true },
        },
      ],
    },
    {
      id: 'lex-hybrid-rag-mcp',
      name: 'LexRAG Contextual + Graph RAG & CRAG MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-hybrid-rag-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-hybrid-rag-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-hybrid-rag-mcp',
      status: 'ONLINE',
      description:
        'Exposes Anthropic-style Contextual RAG, Semantic/Late Chunking, pgvector + BM25 RRF Hybrid Search, Neo4j Knowledge Graph traversal, HyDE query expansion, and RAGAS telemetry.',
      toolsCount: 4,
      resourcesCount: 8,
      promptsCount: 3,
      tools: [
        {
          name: 'hybrid_contextual_graph_rag_query',
          description: 'Executes HyDE + Contextual RAG + BM25/Vector RRF + 2-Hop Knowledge Graph retrieval with RAGAS scoring.',
          inputSchema: {
            type: 'object',
            properties: {
              query: { type: 'string' },
              topK: { type: 'number' },
            },
            required: ['query'],
          },
          sampleArgs: {
            query:
              'Which SQL tables and Python endpoints violate the 72-hour retention and tenant-isolated KMS requirement?',
            topK: 4,
          },
        },
      ],
    },
    {
      id: 'lex-remediation-pr-mcp',
      name: 'LexPR Autonomous Patch Synthesizer & n8n Enforcer MCP',
      role: 'BUILT_CUSTOM',
      version: '2.4.0',
      transports: ['stdio', 'sse', 'streamable-http'],
      endpointUrl: '/api/mcp/lex-remediation-pr-mcp/rpc',
      sseEndpointUrl: '/api/mcp/lex-remediation-pr-mcp/sse',
      stdioCommand: 'npx tsx server/mcp/stdio-server.ts lex-remediation-pr-mcp',
      status: 'ONLINE',
      description:
        'Synthesizes drop-in AST/SQL diffs for UNSAT violations, executes a Pre-PR Z3 Sandbox Verification Gate, opens automated remediation PRs, and triggers n8n/Slack compliance webhooks.',
      toolsCount: 4,
      resourcesCount: 3,
      promptsCount: 2,
      tools: [
        {
          name: 'synthesize_and_verify_remediation_pr',
          description: 'Generates multi-file unified diffs and verifies post-patch SAT compliance in Z3 sandbox.',
          inputSchema: {
            type: 'object',
            properties: {
              branchPrefix: { type: 'string' },
            },
          },
          sampleArgs: { branchPrefix: 'lexcompiler/auto-remediate' },
        },
      ],
    },
  ];
}

export async function invokeMcpTool(
  serverId: string,
  toolName: string,
  args: Record<string, unknown>,
  activeClauses?: LegalClause[]
): Promise<McpToolInvocationResult> {
  const t0 = performance.now();
  const clauses = activeClauses || getInitialClauses();
  const rpcId = `rpc-${Date.now().toString().slice(-6)}`;

  let structuredOutput: unknown = {};

  if (serverId === 'lex-statute-ingest-mcp') {
    if (toolName === 'fetch_live_regulatory_feed') {
      const feed = await fetchLiveRegulatoryFeed();
      structuredOutput = {
        totalStatutesFetched: feed.length,
        sources: ['EUR_LEX_SPARQL_REST', 'US_FEDERAL_REGISTER_API'],
        items: feed,
      };
    } else {
      const text = String(
        args.clauseText ||
          'PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.'
      );
      const compiled = compileLegalProseToFormalPolicy(
        text,
        'RETENTION_AND_TENANT_KMS',
        'CLAUSE-MCP-INGEST',
        'GDPR Art. 17 / DPA §4.2'
      );
      structuredOutput = {
        extractedDeontic: compiled.deontic,
        statuteSha256: sha256Hex(text),
      };
    }
  } else if (serverId === 'lex-deontic-compiler-mcp') {
    const rawText = String(
      args.rawLegalText ||
        'All PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.'
    );
    const category = (args.category as RuleCategory) || 'RETENTION_AND_TENANT_KMS';
    const citation = String(args.citation || 'GDPR Art. 17 & 32 / DPA §4.2');
    const compiled = compileLegalProseToFormalPolicy(
      rawText,
      category,
      'CLAUSE-MCP-COMPILE',
      citation
    );
    structuredOutput = compiled;
  } else if (serverId === 'lex-polyglot-ast-mcp') {
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(rawFiles);
    structuredOutput = {
      filesScanned: enrichedFiles.length,
      totalAstNodes: enrichedFiles.reduce((acc, f) => acc + (f.astNodeCount || 0), 0),
      sqlTables,
      astFindings,
    };
  } else if (serverId === 'lex-z3-prover-mcp') {
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings } = analyzeFullRepository(rawFiles);
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    structuredOutput = {
      z3Engine: 'Microsoft Z3 v4.13.4',
      totalSolveTimeMs: verification.totalZ3ExecutionMs,
      merkleAuditRoot: verification.merkleAuditRoot,
      verdicts: verification.proofs.map((p) => ({
        clauseId: p.clauseId,
        citation: p.citation,
        status: p.status,
        unsatCore: p.unsatCoreAssertions,
        solveTimeMs: p.z3SolveTimeMs,
      })),
    };
  } else if (serverId === 'lex-hybrid-rag-mcp') {
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings } = analyzeFullRepository(rawFiles);
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const query = String(
      args.query ||
        'Which SQL tables and Python endpoints violate the 72-hour retention and tenant-isolated KMS requirement?'
    );
    const topK = typeof args.topK === 'number' ? args.topK : 4;
    structuredOutput = executeHybridRagQuery(
      query,
      clauses,
      sqlTables,
      astFindings,
      verification.proofs,
      topK
    );
  } else if (serverId === 'lex-remediation-pr-mcp') {
    const rawFiles = readTargetRepoFiles();
    const { sqlTables, astFindings, enrichedFiles } = analyzeFullRepository(rawFiles);
    const verification = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const pr = await synthesizeRemediationPullRequest(
      clauses,
      enrichedFiles,
      verification.proofs
    );
    structuredOutput = pr || {
      status: 'ALL_COMPLIANT_NO_PR_NEEDED',
      merkleAuditRoot: verification.merkleAuditRoot,
    };
  }

  const latencyMs = Math.max(0.8, Math.round((performance.now() - t0) * 100) / 100);

  return {
    invocationId: `MCP-CALL-${Date.now().toString().slice(-5)}`,
    serverId,
    toolName,
    transportUsed: 'streamable-http',
    latencyMs,
    jsonRpcRequest: {
      jsonrpc: '2.0',
      id: rpcId,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: args,
      },
    },
    jsonRpcResponse: {
      jsonrpc: '2.0',
      id: rpcId,
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify(structuredOutput, null, 2),
          },
        ],
        structuredOutput,
        isError: false,
      },
    },
    timestamp: new Date().toISOString(),
  };
}
