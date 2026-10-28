import crypto from 'node:crypto';
import type {
  CompiledPolicyArtifacts,
  ComplianceFrameworkId,
  DeonticExtraction,
  DeonticExtractionProvenance,
  LegalClause,
  LiveRegulatoryFeedItem,
  RegulatoryMutationPreset,
  RuleCategory,
} from '../../shared/types.js';
import { runRealLlmInference } from '../services/realAiServiceMesh.js';

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

const BANGLA_DIGIT_MAP: Record<string, string> = {
  '০': '0',
  '১': '1',
  '২': '2',
  '৩': '3',
  '৪': '4',
  '৫': '5',
  '৬': '6',
  '৭': '7',
  '৮': '8',
  '৯': '9',
};

export function normalizeLegalProse(rawText: string): { normalized: string; lower: string } {
  const normalized = rawText.trim().replace(/[০-৯]/g, (d) => BANGLA_DIGIT_MAP[d] || d);
  return { normalized, lower: normalized.toLowerCase() };
}

export interface ExtractedDeonticBounds {
  maxRetentionHours: number;
  maxRetentionDays: number;
  temporalHit: boolean;
  temporalEvidence: string[];
  requiresTenantIsolatedKeys: boolean;
  requiredEncryptionAlgorithms: string[];
  forbidPlaintextLogging: boolean;
  requireCascadeErasure: boolean;
  minAiConfidenceThreshold: number;
  confidenceHit: boolean;
  requireHumanOversightGate: boolean;
  allowedDataRegions: string[];
  requireEncryptionAtRest: boolean;
  provenance: DeonticExtractionProvenance;
}

const LLM_DEONTIC_SCHEMA: Record<string, unknown> = {
  type: 'object',
  properties: {
    maxRetentionHours: { type: 'number' },
    requiresTenantIsolatedKeys: { type: 'boolean' },
    forbidPlaintextLogging: { type: 'boolean' },
    requireCascadeErasure: { type: 'boolean' },
    minAiConfidenceThreshold: { type: 'number' },
    requireHumanOversightGate: { type: 'boolean' },
    allowedDataRegions: { type: 'array', items: { type: 'string' } },
    requireEncryptionAtRest: { type: 'boolean' },
  },
};

/**
 * Parses minutes, hours, days, weeks, months, and years (English + Bangla) into hours.
 * Hours/Bangla ঘণ্টা win over coarser units when both are present (legacy 72 hours vs 30 days).
 */
export function extractTemporalHoursFromProse(lower: string): {
  hours: number;
  hit: boolean;
  evidence: string[];
} {
  const evidence: string[] = [];
  const tryMatch = (
    re: RegExp,
    toHours: (n: number) => number,
    label: string
  ): number | null => {
    const m = lower.match(re);
    if (!m) return null;
    const n = parseFloat(m[1]);
    if (!Number.isFinite(n) || n < 0) return null;
    evidence.push(`${label}:${m[0].trim()}`);
    return toHours(n);
  };

  const hours =
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:hours|hour|hrs|hr|h)\b/, (n) => n, 'hours') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:ঘণ্টা|ঘন্টা)/, (n) => n, 'hours_bn') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:minutes|minute|mins|min)\b/, (n) => n / 60, 'minutes') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:days|day)\b/, (n) => n * 24, 'days') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:দিন)/, (n) => n * 24, 'days_bn') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:weeks|week|wks|wk)\b/, (n) => n * 24 * 7, 'weeks') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:months|month|mos|mo)\b/, (n) => n * 24 * 30, 'months') ??
    tryMatch(/(\d+(?:\.\d+)?)\s*(?:years|year|yrs|yr)\b/, (n) => n * 24 * 365, 'years');

  if (hours != null) {
    return { hours, hit: true, evidence };
  }
  return { hours: 720, hit: false, evidence };
}

export function inferRuleCategoryFromProse(
  rawText: string,
  fallback: RuleCategory = 'RETENTION_AND_TENANT_KMS'
): RuleCategory {
  const { lower } = normalizeLegalProse(rawText);
  if (
    /prohibit|shall not log|never log|plaintext.*log|unredacted|pii.?log|লগ.*নিষিদ্ধ/.test(lower)
  ) {
    return 'PII_LOGGING_BAN';
  }
  if (
    /human[- ]in[- ]the[- ]loop|human oversight|confidence|article 14|মানব তদারকি/.test(lower)
  ) {
    return 'AI_HUMAN_IN_THE_LOOP';
  }
  if (
    /cross[- ]border|transfer|us-east|sovereign|article 44|দেশের বাইরে|স্থানান্তর/.test(lower)
  ) {
    return 'CROSS_BORDER_TRANSFER';
  }
  if (
    /right to (be )?forgotten|erasure|cascade|article 17|মুছে ফেলতে হবে/.test(lower) &&
    !/purged within|retention/.test(lower)
  ) {
    return 'RIGHT_TO_ERASURE_CASCADE';
  }
  if (
    /encrypt(?:ed|ion)? at rest|aes-256|column.?encrypt/.test(lower) &&
    !/purged within|retention|ttl|tenant[- ]isolated/.test(lower)
  ) {
    return 'ENCRYPTION_AT_REST';
  }
  return fallback;
}

export function extractDeonticBoundsFromProse(
  rawText: string,
  category: RuleCategory
): ExtractedDeonticBounds {
  const { normalized, lower } = normalizeLegalProse(rawText);
  const temporal = extractTemporalHoursFromProse(lower);
  const maxRetentionHours = temporal.hours;
  const maxRetentionDays = Math.max(1, Math.round((maxRetentionHours / 24) * 10) / 10);

  const requiresTenantIsolatedKeys =
    /tenant[- ]isolated|tenant[- ]specific|per[- ]tenant|customer[- ]managed\s+key|tenant_kms|টেন্যান্ট|পৃথক\s*কী|আইসোলেটেড\s*কী|কেএমএস/i.test(
      normalized
    );

  const requiredEncryptionAlgorithms: string[] = ['AES-256-GCM'];
  if (requiresTenantIsolatedKeys) {
    requiredEncryptionAlgorithms.push('TENANT-ISOLATED-KMS-ENVELOPE');
  }

  const forbidPlaintextLogging =
    /prohibit|shall not log|never log|forbid|unredacted|plaintext.*log|mask|redact|লগ.*নিষিদ্ধ|লগিং.*নিষিদ্ধ|অরক্ষিত.*লগ|প্রকাশ করা যাবে না|রিড্যাক্ট/i.test(
      normalized
    ) || category === 'PII_LOGGING_BAN';

  const requireCascadeErasure =
    /cascade|erasure|right to be forgotten|delete all linked|article 17|মুছে ফেলতে হবে|সম্পূর্ণরূপে মুছে/i.test(
      normalized
    ) || category === 'RIGHT_TO_ERASURE_CASCADE';

  const requireEncryptionAtRest =
    /encrypt(?:ed|ion)? at rest|encrypted at rest|aes-256|@encrypted/i.test(normalized) ||
    category === 'ENCRYPTION_AT_REST' ||
    category === 'RETENTION_AND_TENANT_KMS';

  let minAiConfidenceThreshold = 0.7;
  let confidenceHit = false;
  const decimalMatch = lower.match(
    /(?:threshold|confidence|score|below|minimum|at least|আত্মবিশ্বাস|স্কোর|কমপক্ষে)[^0-9]*?(0\.\d+)/
  );
  const percentMatch = lower.match(/(\d{2,3})\s*(?:%|শতাংশ)/);
  if (decimalMatch) {
    minAiConfidenceThreshold = parseFloat(decimalMatch[1]);
    confidenceHit = true;
  } else if (percentMatch) {
    const pct = parseInt(percentMatch[1], 10);
    if (pct > 0 && pct <= 100) {
      minAiConfidenceThreshold = pct / 100;
      confidenceHit = true;
    }
  }

  const requireHumanOversightGate =
    /human[- ]in[- ]the[- ]loop|human oversight|human review|manual approval|article 14|মানব তদারকি|মানুষের অনুমোদন|হিউম্যান/i.test(
      normalized
    ) || category === 'AI_HUMAN_IN_THE_LOOP';

  const allowedDataRegions: string[] = ['eu-central-1', 'eu-west-1'];
  if (
    !/strict eu|eea only|prohibit.*us-east|non-adequate|sovereign eu|দেশের বাইরে|স্থানান্তর নিষিদ্ধ|সার্বভৌম/i.test(
      normalized
    ) &&
    category === 'CROSS_BORDER_TRANSFER'
  ) {
    if (/allow.*us-east-1|standard contractual clauses|অনুমোদিত.*us-east-1/i.test(normalized)) {
      allowedDataRegions.push('us-east-1');
    }
  }

  const needsNumeric =
    category === 'RETENTION_AND_TENANT_KMS' || category === 'AI_HUMAN_IN_THE_LOOP';
  const missingNumeric =
    (category === 'RETENTION_AND_TENANT_KMS' && !temporal.hit) ||
    (category === 'AI_HUMAN_IN_THE_LOOP' && !confidenceHit);

  return {
    maxRetentionHours,
    maxRetentionDays,
    temporalHit: temporal.hit,
    temporalEvidence: temporal.evidence,
    requiresTenantIsolatedKeys,
    requiredEncryptionAlgorithms,
    forbidPlaintextLogging,
    requireCascadeErasure,
    minAiConfidenceThreshold,
    confidenceHit,
    requireHumanOversightGate,
    allowedDataRegions,
    requireEncryptionAtRest,
    provenance: {
      method: needsNumeric && missingNumeric ? 'DETERMINISTIC_DEFAULT' : 'DETERMINISTIC_PARSER',
      evidence: [...temporal.evidence, ...(confidenceHit ? [`confidence:${minAiConfidenceThreshold}`] : [])],
    },
  };
}

function mergeLlmBounds(
  base: ExtractedDeonticBounds,
  parsed: Record<string, unknown>,
  model: string,
  latencyMs: number
): ExtractedDeonticBounds {
  const next = { ...base };
  if (typeof parsed.maxRetentionHours === 'number' && parsed.maxRetentionHours > 0) {
    next.maxRetentionHours = parsed.maxRetentionHours;
    next.maxRetentionDays = Math.max(1, Math.round((parsed.maxRetentionHours / 24) * 10) / 10);
    next.temporalHit = true;
  }
  if (typeof parsed.requiresTenantIsolatedKeys === 'boolean') {
    next.requiresTenantIsolatedKeys = parsed.requiresTenantIsolatedKeys;
  }
  if (typeof parsed.forbidPlaintextLogging === 'boolean') {
    next.forbidPlaintextLogging = parsed.forbidPlaintextLogging;
  }
  if (typeof parsed.requireCascadeErasure === 'boolean') {
    next.requireCascadeErasure = parsed.requireCascadeErasure;
  }
  if (typeof parsed.minAiConfidenceThreshold === 'number') {
    next.minAiConfidenceThreshold = parsed.minAiConfidenceThreshold;
    next.confidenceHit = true;
  }
  if (typeof parsed.requireHumanOversightGate === 'boolean') {
    next.requireHumanOversightGate = parsed.requireHumanOversightGate;
  }
  if (Array.isArray(parsed.allowedDataRegions)) {
    next.allowedDataRegions = parsed.allowedDataRegions.filter((r) => typeof r === 'string');
  }
  if (typeof parsed.requireEncryptionAtRest === 'boolean') {
    next.requireEncryptionAtRest = parsed.requireEncryptionAtRest;
  }
  next.provenance = {
    method: 'LLM_JSON_FALLBACK',
    evidence: [...base.provenance.evidence, 'llm_json_schema'],
    llmModel: model,
    llmLatencyMs: latencyMs,
  };
  return next;
}

export async function extractDeonticBoundsWithLlmFallback(
  rawText: string,
  category: RuleCategory
): Promise<ExtractedDeonticBounds> {
  const deterministic = extractDeonticBoundsFromProse(rawText, category);
  const needsFallback =
    (category === 'RETENTION_AND_TENANT_KMS' && !deterministic.temporalHit) ||
    (category === 'AI_HUMAN_IN_THE_LOOP' && !deterministic.confidenceHit);
  if (!needsFallback) {
    return deterministic;
  }

  try {
    const llm = await runRealLlmInference({
      prompt: `Extract deontic compliance bounds as JSON from this legal clause.\nCategory: ${category}\nClause:\n${rawText}\n\nReturn only JSON with maxRetentionHours (hours, converting minutes/days/weeks/months/years), requiresTenantIsolatedKeys, forbidPlaintextLogging, requireCascadeErasure, minAiConfidenceThreshold (0-1), requireHumanOversightGate, allowedDataRegions, requireEncryptionAtRest.`,
      systemPrompt:
        'You are LexCompiler deontic extractor. Output a single JSON object matching the schema. Convert any time unit to hours.',
      jsonSchema: LLM_DEONTIC_SCHEMA,
      maxTokens: 220,
      temperature: 0,
      timeoutMs: 8000,
    });
    const jsonMatch = llm.responseText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        ...deterministic,
        provenance: {
          ...deterministic.provenance,
          llmModel: llm.model,
          llmLatencyMs: llm.totalDurationMs,
          llmRejectedReason: 'no_json_object',
        },
      };
    }
    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
    return mergeLlmBounds(deterministic, parsed, llm.model, llm.totalDurationMs);
  } catch (err) {
    return {
      ...deterministic,
      provenance: {
        ...deterministic.provenance,
        llmRejectedReason: err instanceof Error ? err.message : 'llm_unavailable',
      },
    };
  }
}

/**
 * Neuro-Symbolic Deontic Legal Deconstruction & Policy Synthesis Compiler.
 * Dynamically parses natural-language legal clauses or contract amendments into:
 * 1. Deontic Intermediate Representation (Obligations O, Prohibitions F, Permissions P)
 * 2. First-Order Predicate Logic
 * 3. Executable SMT-LIB2 scripts for Microsoft Z3
 * 4. Open Policy Agent (OPA / Rego) rules
 * 5. Tree-sitter / AST structural query patterns
 */
function compileFromBounds(
  bounds: ExtractedDeonticBounds,
  category: RuleCategory,
  clauseId: string,
  citation: string
): { deontic: DeonticExtraction; compiled: CompiledPolicyArtifacts } {
  const {
    maxRetentionHours,
    maxRetentionDays,
    requiresTenantIsolatedKeys,
    requiredEncryptionAlgorithms,
    forbidPlaintextLogging,
    requireCascadeErasure,
    minAiConfidenceThreshold,
    requireHumanOversightGate,
    allowedDataRegions,
    requireEncryptionAtRest,
    provenance,
  } = bounds;

  if (category === 'RETENTION_AND_TENANT_KMS') {
    const deontic: DeonticExtraction = {
      modality: 'OBLIGATION',
      deonticOperatorSymbol: 'O(φ)',
      actor: 'Data Controller / Ingestion & Storage Pipeline',
      regulatedAction: `Encrypt PII at rest${
        requiresTenantIsolatedKeys ? ' with Tenant-Isolated KMS Keys' : ''
      } & purge within ${maxRetentionHours} hours (${maxRetentionDays}d)`,
      targetDataScope: ['postgres_pii_schema', 'fastapi_patient_endpoint', 'redis_cache_worker'],
      normativeCondition: `∀ entity ∈ PII_Store: EncryptedAtRest(entity) = true ∧ ${
        requiresTenantIsolatedKeys ? 'TenantKeyIsolated(entity) = true ∧ ' : ''
      }RetentionTTL_Hours(entity) ≤ ${maxRetentionHours}`,
      formalPredicateSummary: `O(EncryptedAtRest ∧ ${
        requiresTenantIsolatedKeys ? 'TenantIsolatedKMS ∧ ' : ''
      }TTL_Hours ≤ ${maxRetentionHours})`,
      extractedParameters: {
        maxRetentionHours,
        maxRetentionDays,
        requiresTenantIsolatedKeys,
        requiredEncryptionAlgorithms,
        requireCascadeErasure,
        requireEncryptionAtRest,
      },
      extractionProvenance: provenance,
    };

    const compiled: CompiledPolicyArtifacts = {
      deonticFormula: `O(∀x ∈ PII_Pipeline : Encrypted(x) ∧ ${
        requiresTenantIsolatedKeys ? 'TenantKMS(x) ∧ ' : ''
      }PurgeTTL_Hours(x) ≤ ${maxRetentionHours})`,
      firstOrderLogic: `∀node ∈ {PostgresSchema, FastAPIEndpoint, RedisWorker} : StoresPII(node) → (IsEncrypted(node) ∧ (${
        requiresTenantIsolatedKeys ? 'HasTenantKeyIsolation(node)' : 'True'
      }) ∧ (RetentionHours(node) ≤ ${maxRetentionHours}))`,
      smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_LIA)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const statutory_max_ttl_hours Int)
(declare-const statutory_requires_tenant_kms Bool)
(declare-const postgres_encrypted_at_rest Bool)
(declare-const postgres_tenant_kms_isolated Bool)
(declare-const postgres_retention_hours Int)
(declare-const fastapi_uses_tenant_kms Bool)
(declare-const redis_worker_ttl_hours Int)

; Statutory Normative Axioms (${citation})
(assert (! (= statutory_max_ttl_hours ${maxRetentionHours}) :named law_max_retention_${maxRetentionHours}h))
(assert (! (= statutory_requires_tenant_kms ${requiresTenantIsolatedKeys}) :named law_requires_tenant_kms))

; Universal Compliance Invariants
(assert (! (= postgres_encrypted_at_rest true) :named inv_postgres_encrypted_at_rest))
(assert (! (=> statutory_requires_tenant_kms (= postgres_tenant_kms_isolated true)) :named inv_postgres_tenant_key_isolation))
(assert (! (<= postgres_retention_hours statutory_max_ttl_hours) :named inv_postgres_retention_bound))
(assert (! (=> statutory_requires_tenant_kms (= fastapi_uses_tenant_kms true)) :named inv_fastapi_tenant_kms_envelope))
(assert (! (<= redis_worker_ttl_hours statutory_max_ttl_hours) :named inv_redis_ttl_within_${maxRetentionHours}h))`,
      opaRegoRule: `package lexcompiler.dpa.retention_and_kms

default compliant = false

statutory_max_hours := ${maxRetentionHours}
requires_tenant_kms := ${requiresTenantIsolatedKeys}

deny[msg] {
  input.postgres_schema.retention_hours > statutory_max_hours
  msg := sprintf("VIOLATION [${citation}]: Postgres PII retention (%dh) exceeds statutory limit (%dh)", [input.postgres_schema.retention_hours, statutory_max_hours])
}

deny[msg] {
  requires_tenant_kms
  not input.postgres_schema.has_tenant_key_isolation
  msg := "VIOLATION [${citation}]: Postgres table 'patient_records' lacks tenant-isolated KMS key column (tenant_kms_key_id)"
}

deny[msg] {
  requires_tenant_kms
  not input.fastapi_endpoint.uses_tenant_isolated_kms
  msg := "VIOLATION [${citation}]: FastAPI endpoint '/api/v1/patients/intake' persists PII without tenant-isolated KMS encryption envelope"
}

deny[msg] {
  input.redis_worker.ttl_hours > statutory_max_hours
  msg := sprintf("VIOLATION [${citation}]: Redis cache worker TTL (%dh) exceeds statutory purge window (%dh)", [input.redis_worker.ttl_hours, statutory_max_hours])
}`,
      astPatternQuery: `; Tree-sitter / Polyglot AST Query (${citation})
(sql_create_table
  table_name: (identifier) @table (#match? @table "patient_records")
  column_def: (column_definition name: (identifier) @kms_col (#eq? @kms_col "tenant_kms_key_id"))?)
(python_function_definition
  name: (identifier) @fn (#eq? @fn "ingest_patient_pii")
  body: (block (call function: (attribute attribute: (identifier) @crypto_call))))
(python_assignment
  left: (identifier) @const (#eq? @const "PII_CACHE_TTL_HOURS")
  right: (integer) @ttl_val (#le? @ttl_val ${maxRetentionHours}))`,
    };

    return { deontic, compiled };
  }

  if (category === 'PII_LOGGING_BAN') {
    const deontic: DeonticExtraction = {
      modality: 'PROHIBITION',
      deonticOperatorSymbol: 'F(φ)',
      actor: 'Application Telemetry & API Logging Middleware',
      regulatedAction: 'Emit unredacted PII/PHI fields (ssn, email, diagnosis) to stdout or telemetry log sinks',
      targetDataScope: ['ssn', 'diagnosis_code', 'email', 'full_name'],
      normativeCondition: `∀ call ∈ AST_LoggerCalls : ¬ContainsPlaintextPII(call.arguments)`,
      formalPredicateSummary: `F(PlaintextPIILogging) ≡ O(RedactPIIBeforeLogSink)`,
      extractedParameters: {
        forbidPlaintextLogging,
      },
      extractionProvenance: provenance,
    };

    const compiled: CompiledPolicyArtifacts = {
      deonticFormula: `F(∃sink ∈ LogSinks, ∃field ∈ PII_Fields : WritesUnredacted(sink, field))`,
      firstOrderLogic: `∀call ∈ AST(LoggerCall) : ForbidPlaintextLog → (LogsPlaintextPII(call) = false)`,
      smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_UF)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const law_forbids_plaintext_pii_logs Bool)
(declare-const fastapi_logs_plaintext_pii Bool)

(assert (! (= law_forbids_plaintext_pii_logs ${forbidPlaintextLogging}) :named law_hipaa_gdpr_no_pii_logs))
(assert (! (=> law_forbids_plaintext_pii_logs (= fastapi_logs_plaintext_pii false)) :named inv_zero_plaintext_pii_in_logs))`,
      opaRegoRule: `package lexcompiler.hipaa.pii_logging

deny[msg] {
  ${forbidPlaintextLogging}
  finding := input.ast_findings[_]
  finding.metadata.logsPlaintextPii == true
  msg := sprintf("VIOLATION [${citation}]: Unredacted PII/PHI logged in %s:%d (%v)", [finding.filePath, finding.line, finding.metadata.leakedFields])
}`,
      astPatternQuery: `(call
  function: (attribute object: (identifier) @log_obj (#match? @log_obj "^(logger|logging|console)$")
                       attribute: (identifier) @method (#match? @method "^(info|warn|error|debug)$"))
  arguments: (argument_list (string) @interpolated_pii (#match? @interpolated_pii "(ssn|diagnosis|patient_email)")))`,
    };

    return { deontic, compiled };
  }

  if (category === 'AI_HUMAN_IN_THE_LOOP') {
    const scaledThreshold = Math.round(minAiConfidenceThreshold * 100);
    const deontic: DeonticExtraction = {
      modality: 'OBLIGATION',
      deonticOperatorSymbol: 'O(φ)',
      actor: 'High-Risk AI Automated Decision Engine',
      regulatedAction: `Enforce Human-in-the-Loop review gate when model confidence < ${minAiConfidenceThreshold.toFixed(
        2
      )} (${scaledThreshold}%) & write immutable audit log`,
      targetDataScope: ['services/ai_credit_triage.ts', 'evaluatePatientRiskAndCredit'],
      normativeCondition: `∀ decision ∈ HighRiskAI : HumanOversightGate(decision) = true ∧ ConfidenceThreshold(decision) ≥ ${scaledThreshold}% ∧ ImmutableAudit(decision) = true`,
      formalPredicateSummary: `O(HumanOversightGate ∧ ConfidenceGate ≥ ${scaledThreshold}% ∧ AuditLog)`,
      extractedParameters: {
        minAiConfidenceThreshold,
        requireHumanOversightGate,
        requireImmutableAuditLog: true,
      },
      extractionProvenance: provenance,
    };

    const compiled: CompiledPolicyArtifacts = {
      deonticFormula: `O(∀d ∈ HighRiskAIDecisions : (Confidence(d) < ${minAiConfidenceThreshold.toFixed(
        2
      )} → RequireHumanApproval(d)) ∧ ImmutableAuditLog(d))`,
      firstOrderLogic: `∀fn ∈ AIInferenceNodes : HasHumanGate(fn) ∧ (ConfiguredConfidencePct(fn) ≥ ${scaledThreshold}) ∧ WritesAuditLog(fn)`,
      smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_LIA)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const statutory_min_confidence_pct Int)
(declare-const ai_engine_confidence_gate_pct Int)
(declare-const ai_engine_has_human_oversight Bool)
(declare-const ai_engine_writes_audit_log Bool)

(assert (! (= statutory_min_confidence_pct ${scaledThreshold}) :named law_eu_ai_act_min_confidence_${scaledThreshold}pct))
(assert (! (= ai_engine_has_human_oversight true) :named inv_eu_ai_act_human_oversight_gate))
(assert (! (>= ai_engine_confidence_gate_pct statutory_min_confidence_pct) :named inv_eu_ai_act_confidence_threshold))
(assert (! (= ai_engine_writes_audit_log true) :named inv_eu_ai_act_article12_audit_log))`,
      opaRegoRule: `package lexcompiler.eu_ai_act.article14

statutory_min_confidence := ${minAiConfidenceThreshold}

deny[msg] {
  node := input.ai_nodes[_]
  node.aiConfidenceThreshold < statutory_min_confidence
  msg := sprintf("VIOLATION [${citation}]: AI triage confidence gate (%.2f) is below statutory threshold (%.2f)", [node.aiConfidenceThreshold, statutory_min_confidence])
}

deny[msg] {
  node := input.ai_nodes[_]
  not node.hasHumanOversightGate
  msg := "VIOLATION [${citation}]: High-risk AI inference executes autonomously without mandatory Human-in-the-Loop escalation gate"
}`,
      astPatternQuery: `(function_declaration
  name: (identifier) @fn (#eq? @fn "evaluateClinicalAndCreditRisk")
  body: (statement_block
    (variable_declarator name: (identifier) @gate (#eq? @gate "MIN_CONFIDENCE_FOR_AUTO_APPROVAL")
                         value: (number) @val)))`,
    };

    return { deontic, compiled };
  }

  if (category === 'ENCRYPTION_AT_REST') {
    const deontic: DeonticExtraction = {
      modality: 'OBLIGATION',
      deonticOperatorSymbol: 'O(φ)',
      actor: 'Data Controller / Persistent Storage Pipeline',
      regulatedAction: `Encrypt all PII/PHI columns at rest${
        requiresTenantIsolatedKeys ? ' with tenant-isolated KMS envelopes' : ' with AES-256-GCM'
      }`,
      targetDataScope: ['sql_pii_columns', 'object_storage_blobs'],
      normativeCondition: `∀ col ∈ PII_Columns : EncryptedAtRest(col) = true${
        requiresTenantIsolatedKeys ? ' ∧ TenantKeyIsolated(col) = true' : ''
      }`,
      formalPredicateSummary: `O(EncryptedAtRest${
        requiresTenantIsolatedKeys ? ' ∧ TenantIsolatedKMS' : ''
      })`,
      extractedParameters: {
        requiresTenantIsolatedKeys,
        requiredEncryptionAlgorithms,
        requireEncryptionAtRest: true,
      },
      extractionProvenance: provenance,
    };
    const compiled: CompiledPolicyArtifacts = {
      deonticFormula: `O(∀x ∈ PII_Store : EncryptedAtRest(x) = true)`,
      firstOrderLogic: `∀table ∈ SQLSchema : ContainsPII(table) → UnencryptedPiiColumns(table) = ∅`,
      smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_UF)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const statutory_requires_encryption_at_rest Bool)
(declare-const postgres_encrypted_at_rest Bool)
(declare-const postgres_tenant_kms_isolated Bool)
(declare-const statutory_requires_tenant_kms Bool)

(assert (! (= statutory_requires_encryption_at_rest true) :named law_encryption_at_rest))
(assert (! (= statutory_requires_tenant_kms ${requiresTenantIsolatedKeys}) :named law_requires_tenant_kms))
(assert (! (=> statutory_requires_encryption_at_rest (= postgres_encrypted_at_rest true)) :named inv_all_pii_columns_encrypted))
(assert (! (=> statutory_requires_tenant_kms (= postgres_tenant_kms_isolated true)) :named inv_tenant_kms_for_encrypted_store))`,
      opaRegoRule: `package lexcompiler.crypto.encryption_at_rest

deny[msg] {
  table := input.sql_tables[_]
  table.containsPII
  count(table.unencryptedPiiColumns) > 0
  msg := sprintf("VIOLATION [${citation}]: Table '%s' stores unencrypted PII columns %v", [table.tableName, table.unencryptedPiiColumns])
}`,
      astPatternQuery: `(sql_column_definition
  name: (identifier) @col (#match? @col "ssn|email|phone|patient_|biometric_")
  annotation: (comment) @enc (#match? @enc "@encrypted"))`,
    };
    return { deontic, compiled };
  }

  if (category === 'RIGHT_TO_ERASURE_CASCADE') {
    const deontic: DeonticExtraction = {
      modality: 'OBLIGATION',
      deonticOperatorSymbol: 'O(φ)',
      actor: 'Data Controller / Relational Persistence Layer',
      regulatedAction:
        'Cascade delete all linked PII/PHI child records when a data subject erasure request is executed (GDPR Art. 17)',
      targetDataScope: ['sql_foreign_keys', 'erasure_handlers'],
      normativeCondition: `∀ fk ∈ ForeignKeys(PII_Parent) : OnDeleteCascade(fk) = true`,
      formalPredicateSummary: `O(ErasureCascade)`,
      extractedParameters: {
        requireCascadeErasure: true,
      },
      extractionProvenance: provenance,
    };
    const compiled: CompiledPolicyArtifacts = {
      deonticFormula: `O(∀child ∈ DependentPII : ON_DELETE_CASCADE(child, parent))`,
      firstOrderLogic: `∀t ∈ SQLTables : StoresPII(t) → HasErasureCascade(t)`,
      smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_UF)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const statutory_requires_cascade_erasure Bool)
(declare-const postgres_has_cascade_erasure Bool)

(assert (! (= statutory_requires_cascade_erasure true) :named law_gdpr_art17_cascade_erasure))
(assert (! (=> statutory_requires_cascade_erasure (= postgres_has_cascade_erasure true)) :named inv_fk_on_delete_cascade))`,
      opaRegoRule: `package lexcompiler.gdpr.erasure_cascade

deny[msg] {
  table := input.sql_tables[_]
  table.containsPII
  not table.hasErasureCascade
  msg := sprintf("VIOLATION [${citation}]: PII table '%s' lacks ON DELETE CASCADE erasure edges", [table.tableName])
}`,
      astPatternQuery: `(sql_foreign_key
  references: (identifier) @parent
  on_delete: (keyword) @action (#eq? @action "CASCADE"))`,
    };
    return { deontic, compiled };
  }

  // CROSS_BORDER_TRANSFER (explicit branch; never a silent fallthrough for other categories)
  const allowsUsEast = allowedDataRegions.includes('us-east-1');
  const deontic: DeonticExtraction = {
    modality: 'PROHIBITION',
    deonticOperatorSymbol: 'F(φ)',
    actor: 'Cross-Border Telemetry & Replication Service',
    regulatedAction: `Prohibit outbound PII replication outside approved jurisdictions (${allowedDataRegions.join(
      ', '
    )})`,
    targetDataScope: ['services/cross_border_sync.ts', 'replicatePatientTelemetry'],
    normativeCondition: `∀ egress ∈ DataEgressEdges : TargetRegion(egress) ∈ {${allowedDataRegions.join(
      ', '
    )}}`,
    formalPredicateSummary: `F(TargetRegion ∉ {${allowedDataRegions.join(', ')}})`,
    extractedParameters: {
      allowedDataRegions,
    },
    extractionProvenance: provenance,
  };

  const compiled: CompiledPolicyArtifacts = {
    deonticFormula: `F(∃e ∈ EgressStreams : ContainsPII(e) ∧ Region(e) ∉ {${allowedDataRegions.join(
      ', '
    )}})`,
    firstOrderLogic: `∀egress ∈ OutboundSync : IsApprovedEUJurisdiction(TargetRegion(egress))`,
    smtLib2Snippet: `; LexCompiler SMT-LIB2 Synthesis for ${citation} (${clauseId})
(set-logic QF_UF)
(set-option :produce-models true)
(set-option :produce-unsat-cores true)

(declare-const statutory_allows_non_eu_egress Bool)
(declare-const egress_targets_non_eu_region Bool)

(assert (! (= statutory_allows_non_eu_egress ${allowsUsEast}) :named law_gdpr_ch5_sovereign_residency))
(assert (! (=> (not statutory_allows_non_eu_egress) (= egress_targets_non_eu_region false)) :named inv_gdpr_art44_no_unapproved_egress))`,
    opaRegoRule: `package lexcompiler.gdpr.cross_border

allowed_regions := ${JSON.stringify(allowedDataRegions)}

deny[msg] {
  egress := input.egress_nodes[_]
  not region_allowed(egress.egressRegion)
  msg := sprintf("VIOLATION [${citation}]: Cross-border PII transfer to unapproved region '%s' (allowed: %v)", [egress.egressRegion, allowed_regions])
}

region_allowed(r) {
  r == allowed_regions[_]
}`,
    astPatternQuery: `(variable_declarator
  name: (identifier) @region_const (#eq? @region_const "REPLICA_TARGET_REGION")
  value: (string) @region_val (#match? @region_val "^(eu-central-1|eu-west-1)$"))`,
  };

  return { deontic, compiled };
}

export function compileLegalProseToFormalPolicy(
  rawText: string,
  category: RuleCategory,
  clauseId: string,
  citation: string
): { deontic: DeonticExtraction; compiled: CompiledPolicyArtifacts } {
  return compileFromBounds(
    extractDeonticBoundsFromProse(rawText, category),
    category,
    clauseId,
    citation
  );
}

export async function compileLegalProseToFormalPolicyAsync(
  rawText: string,
  category: RuleCategory,
  clauseId: string,
  citation: string
): Promise<{ deontic: DeonticExtraction; compiled: CompiledPolicyArtifacts }> {
  const bounds = await extractDeonticBoundsWithLlmFallback(rawText, category);
  return compileFromBounds(bounds, category, clauseId, citation);
}

/**
 * Default Baseline Statutory & Contractual Clauses
 * Note: Notice how CLAUSE-DPA-4.2 starts at the baseline "30 days (720 hours) with standard AES-256 encryption",
 * OR can be mutated in 1 click to "encrypted at rest with tenant-isolated keys and purged within 72 hours"!
 * Wait: Let's make sure on initial load we already have a rich mix of BOTH:
 * - Active live violations in the repo AND the flagship clause ready to either inspect or mutate!
 * Even better: let's have CLAUSE-DPA-4.2 already compiled with the active regulatory text, and provide
 * both a "Reset to Legacy 30-Day Baseline (Compliant)" and "Simulate Regulatory Amendment (72h + Tenant KMS)"!
 */
export function getInitialClauses(): LegalClause[] {
  const rawDpaText =
    'Section 4.2 (Data Retention & Cryptographic Isolation — GDPR Art. 17 & Art. 32 / CCPA §1798.105): All Personal Identifiable Information (PII) and Protected Health Information (PHI) ingested via API endpoints, cached in memory workers, or persisted in relational tables must be encrypted at rest with tenant-isolated keys (per-tenant KMS envelope) and purged within 72 hours across all storage tiers.';
  const dpaCompiled = compileLegalProseToFormalPolicy(
    rawDpaText,
    'RETENTION_AND_TENANT_KMS',
    'CLAUSE-DPA-4.2',
    'GDPR Art. 17 & 32 / DPA §4.2'
  );

  const rawHipaaLogText =
    'HIPAA §164.312(b) & GDPR Art. 5(1)(f) (Integrity & Confidentiality — Zero Plaintext PII in Telemetry): Application endpoints and background workers are strictly prohibited from logging unredacted PII or PHI (including SSN, patient email, or clinical diagnosis codes) into application stdout or observability log sinks.';
  const hipaaCompiled = compileLegalProseToFormalPolicy(
    rawHipaaLogText,
    'PII_LOGGING_BAN',
    'CLAUSE-HIPAA-312B',
    'HIPAA §164.312(b) / GDPR Art. 5(1)(f)'
  );

  const rawEuAiActText =
    'EU AI Act Article 14 & Article 12 (Human Oversight & Record-Keeping for High-Risk AI Systems): High-risk AI credit and clinical triage models shall not execute autonomous rejections or approvals when model confidence score falls below 0.85 (85%), and must enforce a mandatory Human-in-the-Loop escalation gate with immutable audit logging.';
  const euAiCompiled = compileLegalProseToFormalPolicy(
    rawEuAiActText,
    'AI_HUMAN_IN_THE_LOOP',
    'CLAUSE-EU-AI-14',
    'EU AI Act Art. 14 & Art. 12'
  );

  const rawCrossBorderText =
    'GDPR Chapter V — Article 44 (General Principle for Transfers & Sovereign EU Residency): Personal data undergoing processing shall not be replicated or transferred to third-country cloud regions outside approved EEA sovereign zones (eu-central-1, eu-west-1); transfer to us-east-1 is strictly prohibited.';
  const crossBorderCompiled = compileLegalProseToFormalPolicy(
    rawCrossBorderText,
    'CROSS_BORDER_TRANSFER',
    'CLAUSE-GDPR-44',
    'GDPR Art. 44 (Chapter V)'
  );

  return [
    {
      id: 'CLAUSE-DPA-4.2',
      frameworkId: 'ENTERPRISE_DPA',
      frameworkName: 'GDPR Art. 17 / Enterprise DPA',
      citation: 'GDPR Art. 17 & 32 / DPA §4.2',
      title: 'Tenant-Isolated KMS Encryption & 72-Hour PII Purge Mandate',
      severity: 'CRITICAL',
      category: 'RETENTION_AND_TENANT_KMS',
      rawLegalText: rawDpaText,
      version: 'v2026.4-AMENDED',
      lastAmended: '2026-10-28',
      sourceUrl: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679',
      illustrative: true,
      deontic: dpaCompiled.deontic,
      compiled: dpaCompiled.compiled,
    },
    {
      id: 'CLAUSE-HIPAA-312B',
      frameworkId: 'HIPAA',
      frameworkName: 'HIPAA Security Rule',
      citation: 'HIPAA §164.312(b) / GDPR Art. 5(1)(f)',
      title: 'Prohibition on Unredacted PII/PHI in Application Logs',
      severity: 'HIGH',
      category: 'PII_LOGGING_BAN',
      rawLegalText: rawHipaaLogText,
      version: '45 CFR §164.312',
      lastAmended: '2026-09-15',
      sourceUrl: 'https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312',
      illustrative: true,
      deontic: hipaaCompiled.deontic,
      compiled: hipaaCompiled.compiled,
    },
    {
      id: 'CLAUSE-EU-AI-14',
      frameworkId: 'EU_AI_ACT',
      frameworkName: 'EU Artificial Intelligence Act',
      citation: 'EU AI Act Art. 14 & Art. 12',
      title: 'High-Risk AI Human-in-the-Loop Gate (≥85% Confidence) & Audit Trail',
      severity: 'CRITICAL',
      category: 'AI_HUMAN_IN_THE_LOOP',
      rawLegalText: rawEuAiActText,
      version: 'Regulation (EU) 2024/1689',
      lastAmended: '2026-08-02',
      sourceUrl: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
      illustrative: true,
      deontic: euAiCompiled.deontic,
      compiled: euAiCompiled.compiled,
    },
    {
      id: 'CLAUSE-GDPR-44',
      frameworkId: 'GDPR',
      frameworkName: 'EU General Data Protection Regulation',
      citation: 'GDPR Art. 44 (Chapter V)',
      title: 'Cross-Border Data Residency & Third-Country Transfer Prohibition',
      severity: 'HIGH',
      category: 'CROSS_BORDER_TRANSFER',
      rawLegalText: rawCrossBorderText,
      version: 'Regulation (EU) 2016/679',
      lastAmended: '2026-07-19',
      sourceUrl: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679',
      illustrative: true,
      deontic: crossBorderCompiled.deontic,
      compiled: crossBorderCompiled.compiled,
    },
  ];
}

export function getBanglaInitialClauses(): LegalClause[] {
  const rawBdBankDpa =
    'ধারা ৪.২ (বাংলাদেশ ব্যাংক আইসিটি নিরাপত্তা নীতিমালা ৪.০ ও উপাত্ত সুরক্ষা আইন): গ্রাহকের সকল ব্যক্তিগত ও আর্থিক সংবেদনশীল তথ্য (PII/PHI) অবশ্যই টেন্যান্ট আইসোলেটেড কেএমএস কী দ্বারা এনক্রিপ্টেড থাকতে হবে এবং ৪৮ ঘণ্টার মধ্যে ডাটাবেস ও ক্যাশ মেমোরি থেকে সম্পূর্ণরূপে মুছে ফেলতে হবে।';
  const bdDpaCompiled = compileLegalProseToFormalPolicy(
    rawBdBankDpa,
    'RETENTION_AND_TENANT_KMS',
    'CLAUSE-DPA-4.2',
    'বাংলাদেশ ব্যাংক নীতিমালা ধারা ৪.২ / GDPR Art. 17'
  );

  const rawBdLogBan =
    'ধারা ২৬ (সাইবার নিরাপত্তা ও ডিজিটাল স্বাস্থ্য উপাত্ত গোপনীয়তা বিধিমালা): অ্যাপ্লিকেশন এন্ডপয়েন্ট বা সার্ভার লগে গ্রাহকের জাতীয় পরিচয়পত্র, এসএসএন, ইমেইল কিংবা চিকিৎসা সংক্রান্ত তথ্য অরক্ষিত অবস্থায় লগিং সম্পূর্ণ নিষিদ্ধ এবং প্রকাশ করা যাবে না; লগে লেখার পূর্বে অবশ্যই ক্রিপ্টোগ্রাফিক হ্যাশ দ্বারা রিড্যাক্ট করতে হবে।';
  const bdLogCompiled = compileLegalProseToFormalPolicy(
    rawBdLogBan,
    'PII_LOGGING_BAN',
    'CLAUSE-HIPAA-312B',
    'সাইবার নিরাপত্তা বিধিমালা ধারা ২৬ / HIPAA §164.312(b)'
  );

  const rawBdAiAct =
    'অনুচ্ছেদ ১৪ (উচ্চ-ঝুঁকিপূর্ণ কৃত্রিম বুদ্ধিমত্তা ও ঋণ ঝুঁকি মূল্যায়ন নীতিমালা): এআই মডেলের আত্মবিশ্বাস স্কোর কমপক্ষে ৮৫% (০.৮৫)-এর নিচে হলে কোনো স্বয়ংক্রিয় সিদ্ধান্ত কার্যকর করা যাবে না; এক্ষেত্রে বাধ্যতামূলক মানব তদারকি (হিউম্যান গেট) এবং অপরিবর্তনীয় অডিট লগ নিশ্চিত করতে হবে।';
  const bdAiCompiled = compileLegalProseToFormalPolicy(
    rawBdAiAct,
    'AI_HUMAN_IN_THE_LOOP',
    'CLAUSE-EU-AI-14',
    'এআই তদারকি নীতিমালা অনুচ্ছেদ ১৪ / EU AI Act Art. 14'
  );

  const rawBdResidency =
    'অধ্যায় ৫ — ধারা ৪৪ (সার্বভৌম ডাটা রেসিডেন্সি ও আন্তঃসীমান্ত স্থানান্তর নিষেধাজ্ঞা): গ্রাহকের সংবেদনশীল ব্যক্তিগত উপাত্ত অনুমোদিত সার্বভৌম অঞ্চলের বাইরে (যেমন অনুমোদনহীন তৃতীয় দেশের ক্লাউড রিজিয়নে) রেপ্লিকেশন বা দেশের বাইরে স্থানান্তর নিষিদ্ধ।';
  const bdResidencyCompiled = compileLegalProseToFormalPolicy(
    rawBdResidency,
    'CROSS_BORDER_TRANSFER',
    'CLAUSE-GDPR-44',
    'সার্বভৌম ডাটা রেসিডেন্সি ধারা ৪৪ / GDPR Art. 44'
  );

  return [
    {
      id: 'CLAUSE-DPA-4.2',
      frameworkId: 'ENTERPRISE_DPA',
      frameworkName: 'বাংলাদেশ ব্যাংক আইসিটি নীতিমালা / DPA',
      citation: 'বাংলাদেশ ব্যাংক ধারা ৪.২ / DPA §4.2',
      title: 'টেন্যান্ট-আইসোলেটেড KMS এনক্রিপশন ও ৪৮ ঘণ্টা উপাত্ত অপসারণ বাধ্যবাধকতা',
      severity: 'CRITICAL',
      category: 'RETENTION_AND_TENANT_KMS',
      rawLegalText: rawBdBankDpa,
      version: 'BD-ICT-v4.0-বাংলা',
      lastAmended: '2026-10-28',
      sourceUrl: 'https://www.bb.org.bd/',
      illustrative: true,
      deontic: bdDpaCompiled.deontic,
      compiled: bdDpaCompiled.compiled,
    },
    {
      id: 'CLAUSE-HIPAA-312B',
      frameworkId: 'HIPAA',
      frameworkName: 'সাইবার নিরাপত্তা ও স্বাস্থ্য উপাত্ত বিধিমালা',
      citation: 'সাইবার নিরাপত্তা ধারা ২৬ / HIPAA §164.312(b)',
      title: 'অ্যাপ্লিকেশন লগে অরক্ষিত ব্যক্তিগত তথ্য (PII/PHI) সংরক্ষণ নিষেধাজ্ঞা',
      severity: 'HIGH',
      category: 'PII_LOGGING_BAN',
      rawLegalText: rawBdLogBan,
      version: 'BD-CSA-2026-বাংলা',
      lastAmended: '2026-09-15',
      sourceUrl: 'https://www.cirt.gov.bd/',
      illustrative: true,
      deontic: bdLogCompiled.deontic,
      compiled: bdLogCompiled.compiled,
    },
    {
      id: 'CLAUSE-EU-AI-14',
      frameworkId: 'EU_AI_ACT',
      frameworkName: 'উচ্চ-ঝুঁকিপূর্ণ এআই তদারকি নীতিমালা',
      citation: 'এআই নীতিমালা অনুচ্ছেদ ১৪ / EU AI Act Art. 14',
      title: 'উচ্চ-ঝুঁকিপূর্ণ এআই মানব তদারকি গেট (≥৮৫% আত্মবিশ্বাস) ও অডিট ট্রেইল',
      severity: 'CRITICAL',
      category: 'AI_HUMAN_IN_THE_LOOP',
      rawLegalText: rawBdAiAct,
      version: 'AI-GOV-2026-বাংলা',
      lastAmended: '2026-08-02',
      sourceUrl: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
      illustrative: true,
      deontic: bdAiCompiled.deontic,
      compiled: bdAiCompiled.compiled,
    },
    {
      id: 'CLAUSE-GDPR-44',
      frameworkId: 'GDPR',
      frameworkName: 'সার্বভৌম ডাটা রেসিডেন্সি বিধিমালা',
      citation: 'ডাটা রেসিডেন্সি ধারা ৪৪ / GDPR Art. 44',
      title: 'সার্বভৌম ডাটা রেসিডেন্সি ও অননুমোদিত আন্তঃসীমান্ত স্থানান্তর নিষেধাজ্ঞা',
      severity: 'HIGH',
      category: 'CROSS_BORDER_TRANSFER',
      rawLegalText: rawBdResidency,
      version: 'BD-DPA-2026-বাংলা',
      lastAmended: '2026-07-19',
      sourceUrl: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679',
      illustrative: true,
      deontic: bdResidencyCompiled.deontic,
      compiled: bdResidencyCompiled.compiled,
    },
  ];
}

export function getMutationPresets(): RegulatoryMutationPreset[] {
  return [
    {
      id: 'PRESET-72H-TENANT-KMS',
      name: 'Amend DPA §4.2 / GDPR Art. 17: 30 Days → 72 Hours + Tenant-Isolated KMS Keys',
      badge: 'FLAGSHIP DEMO SHOCKWAVE',
      frameworkId: 'ENTERPRISE_DPA',
      clauseId: 'CLAUSE-DPA-4.2',
      description:
        'Mutates the retention clause from "purged within 30 days" to "encrypted at rest with tenant-isolated keys and purged within 72 hours", sending a shockwave that turns Postgres Schema, FastAPI Endpoint, and Redis Worker crimson.',
      previousLawExcerpt:
        'PII must be encrypted at rest using standard AES-256 encryption and purged within 30 days (720 hours).',
      mutatedLawText:
        'Section 4.2 (Data Retention & Cryptographic Isolation — GDPR Art. 17 & Art. 32 / CCPA §1798.105): All Personal Identifiable Information (PII) and Protected Health Information (PHI) ingested via API endpoints, cached in memory workers, or persisted in relational tables must be encrypted at rest with tenant-isolated keys (per-tenant KMS envelope) and purged within 72 hours across all storage tiers.',
      parameterDiffSummary: 'max_ttl_hours: 720h → 72h | requires_tenant_kms: false → true',
      blastRadiusNodeIds: ['node-postgres-schema', 'node-fastapi-endpoint', 'node-redis-worker'],
    },
    {
      id: 'PRESET-LEGACY-30D-BASELINE',
      name: 'Restore Legacy Contract Baseline (30-Day Retention / No Tenant KMS)',
      badge: 'BASELINE REGIME',
      frameworkId: 'ENTERPRISE_DPA',
      clauseId: 'CLAUSE-DPA-4.2',
      description:
        'Reverts Section 4.2 back to the legacy 30-day (720 hours) retention window without tenant-isolated KMS key requirements so you can observe the live before/after shockwave transition.',
      previousLawExcerpt:
        'PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.',
      mutatedLawText:
        'Section 4.2 (Legacy Data Retention Baseline): All Personal Identifiable Information (PII) persisted in relational tables or cache workers must be encrypted at rest and purged within 30 days (720 hours) of session termination.',
      parameterDiffSummary: 'max_ttl_hours: 72h → 720h | requires_tenant_kms: true → false',
      blastRadiusNodeIds: ['node-postgres-schema', 'node-fastapi-endpoint', 'node-redis-worker'],
    },
    {
      id: 'PRESET-EU-AI-ACT-92PCT',
      name: 'EU AI Act Art. 14 Emergency Tightening: Raise Confidence Threshold to 92%',
      badge: 'EU AI ACT AMENDMENT',
      frameworkId: 'EU_AI_ACT',
      clauseId: 'CLAUSE-EU-AI-14',
      description:
        'Tightens EU AI Act Article 14 human oversight threshold from 85% to 92% (0.92) minimum model confidence for automated clinical & credit triage.',
      previousLawExcerpt:
        'High-risk AI models shall not execute autonomous decisions when confidence falls below 0.85 (85%).',
      mutatedLawText:
        'EU AI Act Article 14 (Amended High-Risk Threshold): High-risk AI credit and clinical triage models shall not execute autonomous rejections or approvals when model confidence score falls below 0.92 (92%), and must enforce a mandatory Human-in-the-Loop escalation gate with immutable audit logging.',
      parameterDiffSummary: 'statutory_min_confidence_pct: 85% → 92%',
      blastRadiusNodeIds: ['node-ai-engine'],
    },
    {
      id: 'PRESET-24H-ULTRA-STRICT',
      name: 'Zero-Retention HIPAA/GDPR Emergency Mandate: 24-Hour Purge Window',
      badge: '24H ULTRA-STRICT',
      frameworkId: 'ENTERPRISE_DPA',
      clauseId: 'CLAUSE-DPA-4.2',
      description:
        'Tightens ephemeral PII retention window even further to 24 hours with mandatory tenant-isolated KMS envelopes.',
      previousLawExcerpt:
        'PII must be encrypted at rest with tenant-isolated keys and purged within 72 hours.',
      mutatedLawText:
        'Section 4.2 (Ultra-Strict Ephemeral Mandate): All Personal Identifiable Information (PII) and PHI must be encrypted at rest with tenant-isolated keys (per-tenant KMS envelope) and purged within 24 hours across all storage tiers and Redis caches.',
      parameterDiffSummary: 'max_ttl_hours: 72h → 24h | requires_tenant_kms: true',
      blastRadiusNodeIds: ['node-postgres-schema', 'node-fastapi-endpoint', 'node-redis-worker'],
    },
    {
      id: 'PRESET-BANGLADESH-BANK-48H',
      name: 'Bangladesh Bank ICT Guideline v4.0 (বাংলাদেশ ব্যাংক নীতিমালা): ৪৮ ঘণ্টা রিটেনশন ও টেন্যান্ট KMS',
      badge: 'BANGLA / BD FINTECH',
      frameworkId: 'ENTERPRISE_DPA',
      clauseId: 'CLAUSE-DPA-4.2',
      description:
        'Compiles bilingual Bangla + English regulatory prose from Bangladesh Bank ICT Security Guideline & Cyber Security Act (৪৮ ঘণ্টা / 48 hours purge + টেন্যান্ট KMS key isolation) directly into Z3 SMT-LIB2.',
      previousLawExcerpt:
        'PII must be purged within 72 hours.',
      mutatedLawText:
        'ধারা ৪.২ (বাংলাদেশ ব্যাংক আইসিটি নিরাপত্তা নীতিমালা ও সাইবার নিরাপত্তা আইন / Bangladesh Bank ICT Guideline §4.2): গ্রাহকের সকল ব্যক্তিগত ও আর্থিক তথ্য (PII/PHI) অবশ্যই টেন্যান্ট-আইসোলেটেড KMS কী (tenant-isolated keys) দ্বারা এনক্রিপ্টেড থাকতে হবে এবং ৪৮ ঘণ্টা (48 hours)-এর মধ্যে ডাটাবেস ও ক্যাশ থেকে সম্পূর্ণরূপে মুছে ফেলতে হবে।',
      parameterDiffSummary: 'lang: বাংলা+EN | max_ttl_hours: 48h (৪৮ ঘণ্টা) | tenant_kms: true',
      blastRadiusNodeIds: ['node-postgres-schema', 'node-fastapi-endpoint', 'node-redis-worker'],
    },
  ];
}

/**
 * Fetches live regulatory updates from the official US Federal Register API
 * plus curated EUR-Lex Official Journal statutes.
 */
export async function fetchLiveRegulatoryFeed(): Promise<LiveRegulatoryFeedItem[]> {
  const curatedEurLex: LiveRegulatoryFeedItem[] = [
    {
      id: 'EURLEX-32024R1689-ART14',
      source: 'EUR_LEX',
      documentNumber: 'CELEX:32024R1689',
      title: '[Illustrative] Regulation (EU) 2024/1689 (EU AI Act) — Art. 14 Human Oversight & Art. 12 Record-Keeping',
      publicationDate: '2024-07-12',
      agencyOrBody: 'European Parliament & Council of the European Union (excerpt + LexCompiler demo parameter)',
      excerpt:
        'High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which they are in use. [Illustrative demo parameter — not in Regulation (EU) 2024/1689: minimum confidence gate 0.88 (88%) for automated clinical/credit decisions.]',
      illustrative: true,
      url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
      suggestedFramework: 'EU_AI_ACT',
    },
    {
      id: 'EURLEX-32016R0679-ART17',
      source: 'EUR_LEX',
      documentNumber: 'CELEX:32016R0679',
      title: '[Illustrative] Demo DPA obligation referencing GDPR Art. 17 (Erasure) & Art. 32 (Security of Processing)',
      publicationDate: '2026-05-25',
      agencyOrBody: 'LexCompiler demo scenario — not EDPB or EUR-Lex text',
      excerpt:
        '[Illustrative demo obligation — GDPR itself sets no such retention period:] Personal identifiable information (PII) must be encrypted at rest with tenant-isolated keys and purged within 72 hours of session or retention expiration across relational databases and memory caches.',
      illustrative: true,
      url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679',
      suggestedFramework: 'ENTERPRISE_DPA',
    },
  ];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const url =
      'https://www.federalregister.gov/api/v1/documents.json?per_page=3&order=newest&conditions%5Bterm%5D=privacy+cybersecurity+encryption';
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (resp.ok) {
      const data = (await resp.json()) as {
        results?: Array<{
          document_number?: string;
          title?: string;
          publication_date?: string;
          abstract?: string;
          html_url?: string;
          agencies?: Array<{ name?: string }>;
        }>;
      };
      const liveFedItems: LiveRegulatoryFeedItem[] = (data.results || []).map((doc, idx) => ({
        id: `FEDREG-${doc.document_number || idx}`,
        source: 'FEDERAL_REGISTER',
        documentNumber: doc.document_number || 'FR-2026',
        title: doc.title || 'Federal Register Cybersecurity & Privacy Rulemaking',
        publicationDate: doc.publication_date || '2026-10-01',
        agencyOrBody: doc.agencies?.[0]?.name || 'U.S. Federal Register',
        excerpt: doc.abstract || '(No abstract was published for this Federal Register document.)',
        url: doc.html_url || 'https://www.federalregister.gov',
        suggestedFramework: 'HIPAA',
      }));
      return [...curatedEurLex, ...liveFedItems];
    }
  } catch {
    // Fallback cleanly if offline or firewall blocks outbound fetch
  }

  return [
    ...curatedEurLex,
    {
      id: 'ILLUSTRATIVE-HIPAA-OFFLINE',
      source: 'FEDERAL_REGISTER',
      documentNumber: 'ILLUSTRATIVE (offline fallback)',
      title: '[Illustrative] HIPAA-style encryption & cache-purge scenario — not a Federal Register document',
      publicationDate: '2026-09-18',
      agencyOrBody: 'LexCompiler demo data (shown because the Federal Register API was unreachable)',
      excerpt:
        '[Illustrative demo obligation:] Covered entities and business associates must encrypt all ePHI at rest with tenant-isolated keys, purge ephemeral cache workers within 72 hours, and strictly prohibit unredacted PHI in application log sinks.',
      illustrative: true,
      url: 'https://www.federalregister.gov/',
      suggestedFramework: 'HIPAA',
    },
  ];
}
