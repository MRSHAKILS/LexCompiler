export type DeonticModality = 'OBLIGATION' | 'PROHIBITION' | 'PERMISSION';

export type ComplianceFrameworkId =
  | 'ENTERPRISE_DPA'
  | 'GDPR'
  | 'EU_AI_ACT'
  | 'HIPAA'
  | 'CCPA_CPRA';

export type RuleCategory =
  | 'RETENTION_AND_TENANT_KMS'
  | 'ENCRYPTION_AT_REST'
  | 'PII_LOGGING_BAN'
  | 'RIGHT_TO_ERASURE_CASCADE'
  | 'AI_HUMAN_IN_THE_LOOP'
  | 'CROSS_BORDER_TRANSFER';

export interface DeonticExtraction {
  modality: DeonticModality; // O (Obligation), F (Prohibition), P (Permission)
  deonticOperatorSymbol: 'O(φ)' | 'F(φ)' | 'P(φ)';
  actor: string;
  regulatedAction: string;
  targetDataScope: string[];
  normativeCondition: string;
  formalPredicateSummary: string;
  extractedParameters: {
    maxRetentionHours?: number;
    maxRetentionDays?: number;
    requiresTenantIsolatedKeys?: boolean;
    requiredEncryptionAlgorithms?: string[];
    forbidPlaintextLogging?: boolean;
    requireCascadeErasure?: boolean;
    minAiConfidenceThreshold?: number;
    requireHumanOversightGate?: boolean;
    allowedDataRegions?: string[];
    requireImmutableAuditLog?: boolean;
  };
}

export interface CompiledPolicyArtifacts {
  deonticFormula: string;
  firstOrderLogic: string;
  smtLib2Snippet: string;
  opaRegoRule: string;
  astPatternQuery: string;
}

export interface LegalClause {
  id: string;
  frameworkId: ComplianceFrameworkId;
  frameworkName: string;
  citation: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  category: RuleCategory;
  rawLegalText: string;
  version: string;
  lastAmended: string;
  sourceUrl?: string;
  deontic: DeonticExtraction;
  compiled: CompiledPolicyArtifacts;
}

export interface SQLColumnNode {
  name: string;
  dataType: string;
  isPrimaryKey: boolean;
  isNullable: boolean;
  isPII: boolean;
  piiClassification?:
    | 'DIRECT_IDENTIFIER'
    | 'HEALTH_PHI'
    | 'FINANCIAL_PCI'
    | 'BIOMETRIC'
    | 'BEHAVIORAL'
    | 'NONE';
  encryptedAtRest: boolean;
  encryptionAlgorithm?: string;
  hasTenantKeyIsolation?: boolean;
  foreignKeyReference?: {
    table: string;
    column: string;
    onDeleteCascade: boolean;
  };
  line: number;
}

export interface SQLTableSchema {
  tableName: string;
  filePath: string;
  startLine: number;
  endLine: number;
  containsPII: boolean;
  retentionHoursConfigured: number | null;
  retentionDaysConfigured: number | null;
  hasTenantKeyIsolation: boolean;
  hasErasureCascade: boolean;
  encryptedColumnsCount: number;
  unencryptedPiiColumns: string[];
  columns: SQLColumnNode[];
}

export interface ASTFindingNode {
  id: string;
  filePath: string;
  line: number;
  endLine: number;
  column: number;
  language: 'python' | 'typescript' | 'sql';
  astNodeKind: string;
  constructType:
    | 'FASTAPI_ENDPOINT'
    | 'REDIS_CACHE_WORKER'
    | 'POSTGRES_DDL_TABLE'
    | 'LOGGER_CALL'
    | 'LLM_INFERENCE_CALL'
    | 'CROSS_BORDER_EGRESS'
    | 'ERASURE_HANDLER';
  functionName: string;
  codeSnippet: string;
  metadata: {
    usesTenantIsolatedKms?: boolean;
    encryptionCipher?: string;
    retentionTtlHours?: number | null;
    logsPlaintextPii?: boolean;
    leakedFields?: string[];
    hasHumanOversightGate?: boolean;
    aiConfidenceThreshold?: number | null;
    writesAuditLog?: boolean;
    egressRegion?: string;
    hasCascadeDelete?: boolean;
  };
}

export interface ArchitectureGraphNode {
  id: string;
  label: string;
  sublabel: string;
  nodeRole:
    | 'POSTGRES_SCHEMA'
    | 'FASTAPI_ENDPOINT'
    | 'REDIS_WORKER'
    | 'AI_DECISION_ENGINE'
    | 'CROSS_BORDER_SYNC'
    | 'ERASURE_CONTROLLER';
  layer: 'INGRESS_API' | 'SERVICE_LOGIC' | 'CACHE_AND_WORKERS' | 'DATA_STORAGE' | 'EXTERNAL_EGRESS';
  language: 'python' | 'typescript' | 'sql';
  filePath: string;
  line: number;
  endLine: number;
  status: 'COMPLIANT' | 'VIOLATION' | 'WARNING';
  violatedClauseIds: string[];
  dataClassifications: string[];
  astSummary: string;
  metrics: Record<string, string | number | boolean>;
}

export interface ArchitectureGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  dataPayload: string[];
  isEncrypted: boolean;
  isTenantIsolated: boolean;
  isCrossBorder?: boolean;
  targetRegion?: string;
  violatedClauseIds: string[];
}

export interface TargetRepoFile {
  path: string;
  language: 'python' | 'typescript' | 'sql';
  description: string;
  content: string;
  lastModified: string;
  astNodeCount?: number;
}

export interface Z3FormalProofStep {
  stepNumber: number;
  ruleName: string;
  formula: string;
  justification: string;
}

export interface ClauseVerificationProof {
  clauseId: string;
  citation: string;
  title: string;
  frameworkId: ComplianceFrameworkId;
  category: RuleCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  status: 'SAT_COMPLIANT' | 'UNSAT_VIOLATION';
  z3SolverStatus: 'sat' | 'unsat';
  z3SolveTimeMs: number;
  smtLib2Executed: string;
  unsatCoreAssertions: string[];
  counterexampleWitness: Record<string, string | number | boolean>;
  formalProofSteps: Z3FormalProofStep[];
  opaRegoTriggeredDenials: string[];
  affectedGraphNodeIds: string[];
  offendingLocations: Array<{
    nodeId: string;
    filePath: string;
    language: 'python' | 'typescript' | 'sql';
    line: number;
    endLine: number;
    codeSnippet: string;
    explanation: string;
    astNodeType: string;
    remediationPreview: string;
  }>;
  cryptographicProvenance: {
    statuteSha256: string;
    deonticIrSha256: string;
    smtFormulaSha256: string;
    astSnapshotSha256: string;
    merkleProofHash: string;
    timestampIso: string;
  };
}

export interface FilePatchDiff {
  nodeId: string;
  filePath: string;
  language: 'python' | 'typescript' | 'sql';
  summary: string;
  offendingLineStart: number;
  offendingLineEnd: number;
  originalContent: string;
  patchedContent: string;
  unifiedDiff: string;
  linesAdded: number;
  linesRemoved: number;
  addressedClauseIds: string[];
}

export interface RemediationPullRequest {
  prId: string;
  prNumber: number;
  title: string;
  branchName: string;
  baseBranch: string;
  status: 'READY_TO_MERGE' | 'APPLIED_TO_REPO';
  createdAt: string;
  triggeredBy: string;
  addressedViolationsCount: number;
  addressedClauses: Array<{
    clauseId: string;
    citation: string;
    title: string;
  }>;
  prePatchZ3Status: 'UNSAT_VIOLATION';
  postPatchZ3Status: 'SAT_COMPLIANT';
  postPatchVerifyTimeMs: number;
  cryptographicAttestationHash: string;
  executiveSummary: string;
  filePatches: FilePatchDiff[];
}

export interface RegulatoryMutationPreset {
  id: string;
  name: string;
  badge: string;
  frameworkId: ComplianceFrameworkId;
  clauseId: string;
  description: string;
  previousLawExcerpt: string;
  mutatedLawText: string;
  parameterDiffSummary: string;
  blastRadiusNodeIds: string[];
}

export interface LiveRegulatoryFeedItem {
  id: string;
  source: 'EUR_LEX' | 'FEDERAL_REGISTER';
  documentNumber: string;
  title: string;
  publicationDate: string;
  agencyOrBody: string;
  excerpt: string;
  url: string;
  suggestedFramework: ComplianceFrameworkId;
}

// ============================================================================
// AI-HEAVY EXTENSIONS: 6+ MCP SERVERS, HYBRID CONTEXTUAL+GRAPH RAG,
// 6-AGENT ORCHESTRATOR, TOKEN OPTIMIZATION LAB, AND DATA LIFECYCLE
// ============================================================================

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  sampleArgs: Record<string, unknown>;
}

export interface McpServerDescriptor {
  id: string;
  name: string;
  role: 'BUILT_CUSTOM' | 'INTEGRATED_EXTERNAL';
  version: string;
  transports: Array<'stdio' | 'sse' | 'streamable-http'>;
  endpointUrl: string;
  sseEndpointUrl: string;
  stdioCommand: string;
  status: 'ONLINE' | 'READY';
  description: string;
  toolsCount: number;
  resourcesCount: number;
  promptsCount: number;
  tools: McpToolDefinition[];
}

export interface McpToolInvocationResult {
  invocationId: string;
  serverId: string;
  toolName: string;
  transportUsed: 'streamable-http' | 'sse' | 'stdio';
  latencyMs: number;
  jsonRpcRequest: {
    jsonrpc: '2.0';
    id: string;
    method: 'tools/call';
    params: {
      name: string;
      arguments: Record<string, unknown>;
    };
  };
  jsonRpcResponse: {
    jsonrpc: '2.0';
    id: string;
    result: {
      content: Array<{ type: 'text'; text: string }>;
      structuredOutput: unknown;
      isError: boolean;
    };
  };
  timestamp: string;
}

export interface ContextualRagChunk {
  chunkId: string;
  sourceType: 'LEGAL_STATUTE' | 'POLYGLOT_AST_NODE' | 'SQL_DDL_SCHEMA' | 'FORMAL_SMT_AXIOM';
  sourceId: string;
  citationOrPath: string;
  chunkStrategy: 'SEMANTIC_PROPOSITION' | 'LATE_CHUNKING' | 'AST_SUBTREE';
  rawChunkText: string;
  anthropicContextualPrefix: string;
  contextualizedText: string;
  tokenCount: number;
  embeddingDimension: number;
  embeddingPreview: number[];
  linkedGraphEntities: string[];
}

export interface KnowledgeGraphTriple {
  id: string;
  subject: string;
  subjectType: 'STATUTE' | 'DEONTIC_RULE' | 'SMT_ASSERTION' | 'AST_NODE' | 'SQL_COLUMN';
  predicate:
    | 'IMPOSES_OBLIGATION'
    | 'COMPILES_TO_SMT'
    | 'CONSTRAINS_AST_NODE'
    | 'PERSISTS_IN_COLUMN'
    | 'VIOLATES_INVARIANT'
    | 'REMEDIATED_BY_PATCH';
  object: string;
  objectType: 'DEONTIC_RULE' | 'SMT_ASSERTION' | 'AST_NODE' | 'SQL_COLUMN' | 'PR_PATCH';
  cypherQuerySnippet: string;
}

export interface RagRetrievedItem {
  chunk: ContextualRagChunk;
  denseVectorScore: number;
  bm25KeywordScore: number;
  graphTraversalBoost: number;
  rrfHybridScore: number;
  crossEncoderRerankScore: number;
  cragVerdict: 'CORRECT_HIGH_CONFIDENCE' | 'AMBIGUOUS_REFINED';
}

export interface RagasEvaluationMetrics {
  contextPrecision: number;
  contextRecall: number;
  faithfulness: number;
  answerRelevance: number;
  deonticAlignmentScore: number;
  overallRagasScore: number;
}

export interface RagQueryExecutionReport {
  queryId: string;
  originalQuery: string;
  hydeHypotheticalFormalQuery: string;
  rewrittenDeonticQuery: string;
  techniquesExecuted: string[];
  latencyMs: number;
  retrievedChunks: RagRetrievedItem[];
  matchedGraphTriples: KnowledgeGraphTriple[];
  synthesizedNeuroSymbolicAnswer: string;
  ragasMetrics: RagasEvaluationMetrics;
  vectorDbBackend: string;
  graphDbBackend: string;
}

export interface AgentExecutionStep {
  stepNumber: number;
  agentId: string;
  agentName: string;
  frameworkUsed: 'LangGraph' | 'CrewAI' | 'DSPy' | 'Pydantic-AI' | 'Hermes-ToolCall' | 'OpenAI-Swarm';
  llmModel: string;
  runtime: 'Cloud-Frontier' | 'Ollama-Local-GGUF';
  mcpServerCalled: string;
  mcpToolCalled: string;
  inputTokensRaw: number;
  inputTokensOptimized: number;
  outputTokens: number;
  latencyMs: number;
  status: 'COMPLETED';
  reasoningSummary: string;
  structuredArtifactPreview: string;
}

export interface MultiAgentPipelineReport {
  runId: string;
  triggeredAt: string;
  orchestrationPattern: string;
  activeFrameworks: string[];
  activeLlms: Array<{
    model: string;
    provider: string;
    role: string;
    quantizationOrTier: string;
    isLocalRuntime: boolean;
  }>;
  totalLatencyMs: number;
  totalRawTokens: number;
  totalOptimizedTokens: number;
  tokenSavingsPercent: number;
  steps: AgentExecutionStep[];
}

export interface TokenOptimizationStageMetric {
  techniqueId: string;
  techniqueName: string;
  category:
    | 'Graphify (AST & Legal Graph Compression)'
    | 'Codeburn (Dead-Branch AST Pruning)'
    | 'LLMLingua-2 / Caveman (Perplexity Token Slimming)'
    | 'Anthropic / DeepSeek / Gemini Context Caching'
    | 'Semantic Chunk Dedup & Sliding Window'
    | 'Cheap-Model Routing & Speculative Decoding';
  tokensBefore: number;
  tokensAfter: number;
  reductionPercent: number;
  latencySavedMs: number;
  description: string;
  beforeSnippet: string;
  afterSnippet: string;
}

export interface TokenOptimizationBenchmarkReport {
  benchmarkId: string;
  rawContextTokens: number;
  finalCompressedTokens: number;
  totalReductionPercent: number;
  cachedPrefixHitRatePercent: number;
  estimatedCostPer1kScansRawUsd: number;
  estimatedCostPer1kScansOptimizedUsd: number;
  stages: TokenOptimizationStageMetric[];
}

export interface PromptLibraryEntry {
  id: string;
  title: string;
  agentRole: string;
  version: string;
  patternType: string;
  targetModels: string[];
  tokenOptimizationApplied: string[];
  systemPromptXml: string;
  fewShotExample: string;
  outputSchemaZodSummary: string;
}

export interface FullComplianceScanReport {
  scanId: string;
  timestamp: string;
  repositoryName: string;
  repositoryBranch: string;
  commitHash: string;
  z3EngineVersion: string;
  activeAmendmentLabel: string | null;
  totalClausesEvaluated: number;
  compliantClausesCount: number;
  violatedClausesCount: number;
  overallComplianceScore: number;
  totalZ3ExecutionMs: number;
  merkleAuditRoot: string;
  clauses: LegalClause[];
  sqlTables: SQLTableSchema[];
  astFindings: ASTFindingNode[];
  architectureGraph: {
    nodes: ArchitectureGraphNode[];
    edges: ArchitectureGraphEdge[];
  };
  proofs: ClauseVerificationProof[];
  remediationPR: RemediationPullRequest | null;
  mutationPresets: RegulatoryMutationPreset[];
  files: TargetRepoFile[];
}
