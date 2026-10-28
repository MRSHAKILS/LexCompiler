import { performance } from 'node:perf_hooks';
import { init as initZ3 } from 'z3-solver';
import { sha256Hex } from '../util/hash.js';
import type {
  ArchitectureGraphEdge,
  ArchitectureGraphNode,
  ASTFindingNode,
  ClauseVerificationProof,
  LegalClause,
  SQLDependentForeignKey,
  SQLTableSchema,
  Z3FormalProofStep,
  Z3RepairAction,
  Z3RepairTarget,
} from '../../shared/types.js';

// The z3-solver typings are generic over the context name; the prover uses them dynamically.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Z3Any = any;

const SOLVER_TIMEOUT_MS = 10_000;

let z3ContextPromise: Promise<Z3Any> | null = null;

/** One shared Z3 context for the process; solvers are created and released per clause. */
async function getZ3Context(): Promise<Z3Any> {
  if (!z3ContextPromise) {
    z3ContextPromise = initZ3().then(({ Context }) => new Context('lexcompiler_prover'));
  }
  return z3ContextPromise;
}

/** Binary SHA-256 Merkle root (last node duplicated on odd levels). */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256Hex('');
  let level = leaves.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256Hex(`${level[i]}${level[i + 1] ?? level[i]}`));
    }
    level = next;
  }
  return level[0];
}

function sanitize(id: string): string {
  return id.replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'x';
}

type NodeRole =
  | 'node-fastapi-endpoint'
  | 'node-postgres-schema'
  | 'node-redis-worker'
  | 'node-ai-engine'
  | 'node-cross-border';

interface Instance {
  key: string;
  nodeId: NodeRole;
  label: string;
  finding?: ASTFindingNode;
  filePath: string;
  language: 'python' | 'typescript' | 'sql';
  line: number;
  endLine: number;
  codeSnippet: string;
  astNodeType: string;
}

interface Invariant {
  name: string;
  expr: Z3Any;
  explanation: string;
  remediation: string;
  repair: Pick<Z3RepairTarget, 'z3Variable' | 'repairAction' | 'anchorSymbol' | 'currentValue' | 'requiredValue'> | null;
}

interface InstanceCheck {
  instance: Instance;
  facts: Array<{ name: string; expr: Z3Any; display: string }>;
  invariants: Invariant[];
}

interface ClausePlan {
  laws: Array<{ name: string; expr: Z3Any; display: string }>;
  checks: InstanceCheck[];
  /** Explains the result when no construct applies (e.g. "no PII tables"). */
  emptyMeaning: string;
  /** Whether an empty instance set needs a human to confirm it. */
  emptyNeedsReview: boolean;
  /** Variables reported from the model when the clause is satisfiable. */
  watch: Array<{ name: string; expr: Z3Any }>;
}

function tableInstance(table: SQLTableSchema, finding: ASTFindingNode | undefined): Instance {
  return {
    key: `tbl_${sanitize(table.tableName)}`,
    nodeId: 'node-postgres-schema',
    label: `table ${table.tableName}`,
    finding,
    filePath: table.filePath,
    language: 'sql',
    line: table.startLine,
    endLine: table.endLine,
    codeSnippet: finding?.codeSnippet || '',
    astNodeType: `SQL::CreateTableStatement(${table.tableName})`,
  };
}

function findingInstance(prefix: string, nodeId: NodeRole, f: ASTFindingNode): Instance {
  const lang = f.language === 'sql' ? 'SQL' : f.language === 'python' ? 'Python' : 'TypeScript';
  return {
    key: `${prefix}_${sanitize(`${f.filePath}_${f.functionName}_${f.line}`)}`,
    nodeId,
    label: `${f.functionName} (${f.filePath}:${f.line})`,
    finding: f,
    filePath: f.filePath,
    language: f.language,
    line: f.line,
    endLine: f.endLine,
    codeSnippet: f.codeSnippet,
    astNodeType: `${lang}::${f.astNodeKind}`,
  };
}

/** Durations are compared in whole minutes so sub-hour TTLs stay exact in integer arithmetic. */
function minutes(hours: number): number {
  return Math.round(hours * 60);
}

function fmtHours(h: number): string {
  return Number.isInteger(h) ? `${h}h` : `${Math.round(h * 1000) / 1000}h`;
}

function dependentLabel(dep: SQLDependentForeignKey): string {
  return dep.implicit ? 'no ON DELETE action' : 'ON DELETE is not CASCADE';
}

/**
 * Builds the Z3 assertions for one clause over every applicable construct instance:
 * law axioms, extracted code facts, and per-instance invariants.
 */
function planClause(
  Z3: Z3Any,
  clause: LegalClause,
  sqlTables: SQLTableSchema[],
  astFindings: ASTFindingNode[]
): ClausePlan {
  const p = clause.deontic.extractedParameters;
  const laws: ClausePlan['laws'] = [];
  const checks: InstanceCheck[] = [];
  const watch: ClausePlan['watch'] = [];
  const piiTables = sqlTables.filter((t) => t.containsPII);
  const tableFinding = (t: SQLTableSchema) =>
    astFindings.find(
      (f) =>
        f.constructType === 'POSTGRES_DDL_TABLE' &&
        f.filePath === t.filePath &&
        f.functionName === `CREATE TABLE ${t.tableName}`
    );
  const byType = (...types: ASTFindingNode['constructType'][]) =>
    astFindings.filter((f) => types.includes(f.constructType));
  const law = (name: string, expr: Z3Any, display: string) => laws.push({ name, expr, display });

  if (clause.category === 'RETENTION_AND_TENANT_KMS' || clause.category === 'ENCRYPTION_AT_REST') {
    const retention = clause.category === 'RETENTION_AND_TENANT_KMS';
    const maxHours = p.maxRetentionHours ?? 72;
    const reqKms = p.requiresTenantIsolatedKeys ?? retention;
    const reqEnc = p.requireEncryptionAtRest ?? true;
    const sMax = Z3.Int.const('law_max_retention_minutes');
    const sKms = Z3.Bool.const('law_requires_tenant_kms');
    const sEnc = Z3.Bool.const('law_requires_encryption_at_rest');
    if (retention) {
      law(`law_max_retention_${sanitize(fmtHours(maxHours))}`, sMax.eq(minutes(maxHours)), `max retention = ${fmtHours(maxHours)}`);
    }
    law('law_requires_tenant_kms', sKms.eq(reqKms), `tenant-isolated KMS required = ${reqKms}`);
    law('law_requires_encryption_at_rest', sEnc.eq(reqEnc), `encryption at rest required = ${reqEnc}`);

    for (const t of piiTables) {
      const inst = tableInstance(t, tableFinding(t));
      const k = inst.key;
      const check: InstanceCheck = { instance: inst, facts: [], invariants: [] };
      const enc = Z3.Int.const(`${k}__unencrypted_pii_columns`);
      const kms = Z3.Bool.const(`${k}__tenant_kms`);
      const unenc = t.unencryptedPiiColumns;
      check.facts.push({
        name: `ast_${k}_unencrypted_${unenc.length}`,
        expr: enc.eq(unenc.length),
        display: `${t.tableName}.unencrypted_pii_columns = ${unenc.length}`,
      });
      check.facts.push({
        name: `ast_${k}_tenant_kms_${t.hasTenantKeyIsolation}`,
        expr: kms.eq(t.hasTenantKeyIsolation),
        display: `${t.tableName}.tenant_kms = ${t.hasTenantKeyIsolation}`,
      });
      check.invariants.push({
        name: `inv_${k}_encrypted_at_rest`,
        expr: Z3.Implies(sEnc, enc.eq(0)),
        explanation: `Table '${t.tableName}' stores PII columns without encryption at rest: ${unenc.join(', ')}.`,
        remediation: `Encrypt ${unenc.join(', ')} and mark them -- @encrypted(AES-256-GCM)`,
        repair: {
          z3Variable: `${k}__unencrypted_pii_columns`,
          repairAction: 'ENCRYPT_COLUMN',
          currentValue: unenc.length,
          requiredValue: 0,
        },
      });
      check.invariants.push({
        name: `inv_${k}_tenant_kms`,
        expr: Z3.Implies(sKms, kms.eq(true)),
        explanation: `Table '${t.tableName}' has no tenant-isolated KMS key column (tenant_kms_key_id).`,
        remediation: 'Add tenant_kms_key_id VARCHAR(128) NOT NULL -- @tenant_isolated_kms',
        repair: {
          z3Variable: `${k}__tenant_kms`,
          repairAction: 'ADD_TENANT_KMS_COLUMN',
          anchorSymbol: 'tenant_kms_key_id',
          currentValue: false,
          requiredValue: true,
        },
      });
      if (retention) {
        const hasRet = Z3.Bool.const(`${k}__has_retention_policy`);
        const ret = Z3.Int.const(`${k}__retention_minutes`);
        const configured = t.retentionHoursConfigured;
        check.facts.push({
          name: `ast_${k}_has_retention_${configured != null}`,
          expr: hasRet.eq(configured != null),
          display: `${t.tableName}.has_retention_policy = ${configured != null}`,
        });
        if (configured != null) {
          check.facts.push({
            name: `ast_${k}_retention_${sanitize(fmtHours(configured))}`,
            expr: ret.eq(minutes(configured)),
            display: `${t.tableName}.retention = ${fmtHours(configured)}`,
          });
        }
        check.invariants.push({
          name: `inv_${k}_retention_policy_present`,
          expr: hasRet.eq(true),
          explanation: `Table '${t.tableName}' stores PII but declares no retention period.`,
          remediation: `Add retention_ttl_hours INT DEFAULT ${maxHours} -- @retention_hours(${maxHours})`,
          repair: {
            z3Variable: `${k}__has_retention_policy`,
            repairAction: 'ADD_RETENTION_COLUMN',
            currentValue: false,
            requiredValue: maxHours,
          },
        });
        check.invariants.push({
          name: `inv_${k}_retention_bound`,
          expr: Z3.Implies(hasRet, ret.le(sMax)),
          explanation: `Table '${t.tableName}' retains PII for ${
            configured != null ? fmtHours(configured) : 'an unbounded period'
          }, exceeding ${fmtHours(maxHours)}.`,
          remediation: `Set the retention default to ${maxHours} hours`,
          repair: {
            z3Variable: `${k}__retention_minutes`,
            repairAction: 'SET_RETENTION_BOUND',
            currentValue: configured,
            requiredValue: maxHours,
          },
        });
        watch.push({ name: `${k}__retention_minutes`, expr: ret });
      }
      checks.push(check);
    }

    if (retention) {
      for (const f of byType('FASTAPI_ENDPOINT', 'PII_PROCESSING_FUNCTION')) {
        const inst = findingInstance('api', 'node-fastapi-endpoint', f);
        const kms = Z3.Bool.const(`${inst.key}__tenant_kms`);
        const val = f.metadata.usesTenantIsolatedKms === true;
        checks.push({
          instance: inst,
          facts: [{ name: `ast_${inst.key}_tenant_kms_${val}`, expr: kms.eq(val), display: `${f.functionName}.tenant_kms = ${val}` }],
          invariants: [
            {
              name: `inv_${inst.key}_tenant_kms_envelope`,
              expr: Z3.Implies(sKms, kms.eq(true)),
              explanation: `'${f.functionName}' encrypts PII with a shared key instead of a tenant-isolated KMS envelope.`,
              remediation: 'Call encrypt_with_tenant_kms(..., tenant_id=...) and enable the tenant KMS flag',
              repair: {
                z3Variable: `${inst.key}__tenant_kms`,
                repairAction: 'ENABLE_TENANT_KMS',
                currentValue: false,
                requiredValue: true,
              },
            },
          ],
        });
      }
      for (const f of byType('REDIS_CACHE_WORKER', 'DATA_RETENTION_POLICY')) {
        const hours = f.metadata.retentionTtlHours;
        if (typeof hours !== 'number') continue;
        const inst = findingInstance('cache', 'node-redis-worker', f);
        const ttl = Z3.Int.const(`${inst.key}__ttl_minutes`);
        const source = f.metadata.retentionSource || 'Cache TTL';
        const check: InstanceCheck = {
          instance: inst,
          facts: [
            {
              name: `ast_${inst.key}_ttl_${sanitize(fmtHours(hours))}`,
              expr: ttl.eq(minutes(hours)),
              display: `${source} = ${fmtHours(hours)}`,
            },
          ],
          invariants: [
            {
              name: `inv_${inst.key}_ttl_bound`,
              expr: ttl.le(sMax),
              explanation: `${source} keeps PII for ${fmtHours(hours)}, exceeding ${fmtHours(maxHours)}.`,
              remediation: `Lower the TTL to ${maxHours} hours`,
              repair: {
                z3Variable: `${inst.key}__ttl_minutes`,
                repairAction: 'SET_RETENTION_BOUND',
                currentValue: hours,
                requiredValue: maxHours,
              },
            },
          ],
        };
        if (typeof f.metadata.usesTenantIsolatedKms === 'boolean') {
          const kms = Z3.Bool.const(`${inst.key}__tenant_kms`);
          const val = f.metadata.usesTenantIsolatedKms;
          check.facts.push({
            name: `ast_${inst.key}_tenant_kms_${val}`,
            expr: kms.eq(val),
            display: `${f.functionName}.tenant_kms_envelope = ${val}`,
          });
          check.invariants.push({
            name: `inv_${inst.key}_tenant_kms_envelope`,
            expr: Z3.Implies(sKms, kms.eq(true)),
            explanation: `Cache '${f.functionName}' stores PII without a tenant KMS envelope.`,
            remediation: 'Enable the tenant KMS envelope flag',
            repair: {
              z3Variable: `${inst.key}__tenant_kms`,
              repairAction: 'ENABLE_TENANT_KMS',
              currentValue: false,
              requiredValue: true,
            },
          });
        }
        watch.push({ name: `${inst.key}__ttl_minutes`, expr: ttl });
        checks.push(check);
      }
    }
    return {
      laws,
      checks,
      watch,
      emptyMeaning: retention
        ? 'No PII tables, PII endpoints, or retention/cache constants were found.'
        : 'No tables with PII columns were found.',
      emptyNeedsReview: true,
    };
  }

  if (clause.category === 'PII_LOGGING_BAN') {
    const forbid = p.forbidPlaintextLogging ?? true;
    const sForbid = Z3.Bool.const('law_forbids_plaintext_pii_logs');
    law('law_forbids_plaintext_pii_logs', sForbid.eq(forbid), `plaintext PII in logs forbidden = ${forbid}`);
    for (const f of byType('LOGGER_CALL').filter((x) => x.metadata.logsPlaintextPii)) {
      const inst = findingInstance('log', 'node-fastapi-endpoint', f);
      const leaks = Z3.Bool.const(`${inst.key}__logs_plaintext_pii`);
      const fields = (f.metadata.leakedFields || []).join(', ');
      checks.push({
        instance: inst,
        facts: [{ name: `ast_${inst.key}_logs_pii_true`, expr: leaks.eq(true), display: `${f.functionName} logs tainted PII (${fields})` }],
        invariants: [
          {
            name: `inv_${inst.key}_no_plaintext_pii`,
            expr: Z3.Implies(sForbid, leaks.eq(false)),
            explanation: `${f.functionName} at ${f.filePath}:${f.line} writes PII (${fields}) to a log sink without redaction.`,
            remediation: 'Wrap the PII arguments in redact_pii(...)',
            repair: {
              z3Variable: `${inst.key}__logs_plaintext_pii`,
              repairAction: 'REDACT_LOG_ARGUMENTS',
              currentValue: true,
              requiredValue: false,
            },
          },
        ],
      });
    }
    return {
      laws,
      checks,
      watch,
      emptyMeaning: 'Taint analysis found no logging sink that receives PII.',
      emptyNeedsReview: false,
    };
  }

  if (clause.category === 'AI_HUMAN_IN_THE_LOOP') {
    const minConf = Math.round((p.minAiConfidenceThreshold ?? 0.85) * 100);
    const reqHuman = p.requireHumanOversightGate ?? true;
    const reqAudit = p.requireImmutableAuditLog ?? true;
    const sConf = Z3.Int.const('law_min_confidence_pct');
    const sHuman = Z3.Bool.const('law_requires_human_oversight');
    const sAudit = Z3.Bool.const('law_requires_audit_log');
    law(`law_min_confidence_${minConf}pct`, sConf.eq(minConf), `minimum confidence gate = ${minConf}%`);
    law('law_requires_human_oversight', sHuman.eq(reqHuman), `human oversight required = ${reqHuman}`);
    law('law_requires_audit_log', sAudit.eq(reqAudit), `immutable audit log required = ${reqAudit}`);
    for (const f of byType('LLM_INFERENCE_CALL')) {
      const inst = findingInstance('ai', 'node-ai-engine', f);
      const k = inst.key;
      const threshold = f.metadata.aiConfidenceThreshold;
      const hasGate = Z3.Bool.const(`${k}__has_confidence_gate`);
      const conf = Z3.Int.const(`${k}__confidence_pct`);
      const human = Z3.Bool.const(`${k}__human_oversight`);
      const audit = Z3.Bool.const(`${k}__audit_log`);
      const humanVal = f.metadata.hasHumanOversightGate === true;
      const auditVal = f.metadata.writesAuditLog === true;
      const facts: InstanceCheck['facts'] = [
        {
          name: `ast_${k}_has_confidence_gate_${threshold != null}`,
          expr: hasGate.eq(threshold != null),
          display: `confidence gate present = ${threshold != null}`,
        },
        { name: `ast_${k}_human_gate_${humanVal}`, expr: human.eq(humanVal), display: `human oversight = ${humanVal}` },
        { name: `ast_${k}_audit_log_${auditVal}`, expr: audit.eq(auditVal), display: `audit log = ${auditVal}` },
      ];
      if (threshold != null) {
        const pct = Math.round(threshold * 100);
        facts.push({ name: `ast_${k}_confidence_${pct}pct`, expr: conf.eq(pct), display: `confidence gate = ${pct}%` });
      }
      checks.push({
        instance: inst,
        facts,
        invariants: [
          {
            name: `inv_${k}_confidence_gate`,
            expr: Z3.And(hasGate.eq(true), Z3.Implies(hasGate, conf.ge(sConf))),
            explanation: `'${f.functionName}' auto-decides at ${
              threshold != null ? `${Math.round(threshold * 100)}%` : 'an unbounded'
            } confidence (< ${minConf}%).`,
            remediation: `Raise the confidence gate to ${(minConf / 100).toFixed(2)}`,
            repair: {
              z3Variable: `${k}__confidence_pct`,
              repairAction: 'RAISE_CONFIDENCE_GATE',
              currentValue: threshold ?? null,
              requiredValue: minConf / 100,
            },
          },
          {
            name: `inv_${k}_human_oversight`,
            expr: Z3.Implies(sHuman, human.eq(true)),
            explanation: `'${f.functionName}' has no human-in-the-loop escalation gate.`,
            remediation: 'Enable the human oversight gate',
            repair: {
              z3Variable: `${k}__human_oversight`,
              repairAction: 'ENABLE_HUMAN_OVERSIGHT',
              currentValue: false,
              requiredValue: true,
            },
          },
          {
            name: `inv_${k}_audit_log`,
            expr: Z3.Implies(sAudit, audit.eq(true)),
            explanation: `'${f.functionName}' does not write an immutable audit log.`,
            remediation: 'Enable immutable audit logging',
            repair: { z3Variable: `${k}__audit_log`, repairAction: 'ENABLE_AUDIT_LOG', currentValue: false, requiredValue: true },
          },
        ],
      });
      watch.push({ name: `${k}__confidence_pct`, expr: conf });
    }
    return {
      laws,
      checks,
      watch,
      emptyMeaning: 'No AI decision constants (confidence gate, human oversight, audit log) were found.',
      emptyNeedsReview: true,
    };
  }

  if (clause.category === 'RIGHT_TO_ERASURE_CASCADE') {
    const req = p.requireCascadeErasure ?? true;
    const sReq = Z3.Bool.const('law_requires_cascade_erasure');
    law('law_requires_cascade_erasure', sReq.eq(req), `cascade erasure required = ${req}`);
    for (const t of piiTables) {
      const finding = tableFinding(t);
      for (const dep of t.dependentForeignKeys || []) {
        const inst: Instance = {
          ...tableInstance(t, finding),
          key: `fk_${sanitize(`${dep.childTable}_${dep.childColumn}`)}`,
          label: `${dep.childTable}.${dep.childColumn} → ${t.tableName}`,
          line: dep.line,
          endLine: dep.line,
          astNodeType: 'SQL::ForeignKeyConstraint',
        };
        const cascade = Z3.Bool.const(`${inst.key}__on_delete_cascade`);
        checks.push({
          instance: inst,
          facts: [
            {
              name: `ast_${inst.key}_cascade_${dep.onDeleteCascade}`,
              expr: cascade.eq(dep.onDeleteCascade),
              display: `${inst.label} ON DELETE CASCADE = ${dep.onDeleteCascade}`,
            },
          ],
          invariants: [
            {
              name: `inv_${inst.key}_on_delete_cascade`,
              expr: Z3.Implies(sReq, cascade.eq(true)),
              explanation: `Foreign key ${inst.label} does not cascade erasure (${dependentLabel(dep)}).`,
              remediation: 'Add ON DELETE CASCADE to the foreign key',
              repair: {
                z3Variable: `${inst.key}__on_delete_cascade`,
                repairAction: 'CASCADE_FOREIGN_KEY',
                anchorSymbol: `${dep.childTable}.${dep.childColumn}`,
                currentValue: false,
                requiredValue: true,
              },
            },
          ],
        });
      }
    }
    return {
      laws,
      checks,
      watch,
      emptyMeaning: 'No tables reference a PII table, so there are no dependent rows to cascade.',
      emptyNeedsReview: false,
    };
  }

  // CROSS_BORDER_TRANSFER: region membership is decided by Z3 over an enumerated universe.
  const allowed =
    p.allowedDataRegions && p.allowedDataRegions.length > 0 ? p.allowedDataRegions.slice() : ['eu-central-1', 'eu-west-1'];
  const egress = byType('CROSS_BORDER_EGRESS').filter((f) => typeof f.metadata.egressRegion === 'string');
  const universe = [...new Set([...allowed, ...egress.map((f) => f.metadata.egressRegion as string)])].sort();
  const regionAllowed = universe.map((r) => Z3.Bool.const(`law_region_allowed__${sanitize(r)}`));
  law(
    'law_allowed_regions',
    Z3.And(...universe.map((r, i) => regionAllowed[i].eq(allowed.includes(r)))),
    `allowed regions = {${allowed.join(', ')}}`
  );
  for (const f of egress) {
    const inst = findingInstance('egress', 'node-cross-border', f);
    const region = Z3.Int.const(`${inst.key}__region_index`);
    const observed = f.metadata.egressRegion as string;
    checks.push({
      instance: inst,
      facts: [
        {
          name: `ast_${inst.key}_region_${sanitize(observed)}`,
          expr: region.eq(universe.indexOf(observed)),
          display: `${f.functionName} region = ${observed}`,
        },
      ],
      invariants: [
        {
          name: `inv_${inst.key}_region_allowed`,
          expr: Z3.Or(...universe.map((_, i) => Z3.And(region.eq(i), regionAllowed[i]))),
          explanation: `'${f.functionName}' sends data to '${observed}', outside the allowed regions (${allowed.join(', ')}).`,
          remediation: `Pin the region to "${allowed[0]}"`,
          repair: {
            z3Variable: `${inst.key}__region_index`,
            repairAction: 'PIN_EGRESS_REGION',
            currentValue: observed,
            requiredValue: allowed[0],
          },
        },
      ],
    });
  }
  return { laws, checks, watch, emptyMeaning: 'No cloud-region egress constants were found.', emptyNeedsReview: true };
}

function reviewReasonsFor(clause: LegalClause): string[] {
  const reasons: string[] = [];
  const prov = clause.deontic.extractionProvenance;
  if (prov?.method === 'DETERMINISTIC_DEFAULT') {
    reasons.push('A bound was not found in the clause text and a default was used; confirm the clause before relying on this result.');
  }
  if (prov?.method === 'LLM_JSON_FALLBACK') {
    reasons.push(`Bounds were extracted by an LLM (${prov.llmModel || 'unknown model'}); confirm them before relying on this result.`);
  }
  for (const note of prov?.reviewNotes || []) reasons.push(note);
  if (clause.illustrative) {
    reasons.push('Illustrative demo clause: thresholds are scenario parameters, not text of the cited law.');
  }
  return reasons;
}

/**
 * Verifies every clause against every applicable construct with Microsoft Z3.
 *
 * Per clause, one solver holds all law axioms, extracted code facts, and invariants as
 * implications guarded by assumption literals. The full assumption set decides the
 * verdict (sat / unsat / unknown) and its unsat core comes from Z3. Each invariant of
 * each instance is then re-checked under its own assumption subset, so every violating
 * construct is reported (a single core may omit some). A construct type that is absent
 * contributes no facts: absence is "not applicable", never a default violation.
 */
export async function verifyRepositoryAgainstClauses(
  clauses: LegalClause[],
  sqlTables: SQLTableSchema[],
  astFindings: ASTFindingNode[]
): Promise<{
  proofs: ClauseVerificationProof[];
  architectureGraph: {
    nodes: ArchitectureGraphNode[];
    edges: ArchitectureGraphEdge[];
  };
  totalZ3ExecutionMs: number;
  merkleAuditRoot: string;
}> {
  const Z3 = await getZ3Context();
  const proofs: ClauseVerificationProof[] = [];
  let totalZ3ExecutionMs = 0;

  for (const clause of clauses) {
    const t0 = performance.now();
    const plan = planClause(Z3, clause, sqlTables, astFindings);
    const solver = new Z3.Solver();
    solver.set('timeout', SOLVER_TIMEOUT_MS);

    const trackers = new Map<string, Z3Any>();
    const track = (name: string, expr: Z3Any) => {
      let tracker = trackers.get(name);
      if (!tracker) {
        tracker = Z3.Bool.const(name);
        trackers.set(name, tracker);
      }
      solver.add(Z3.Implies(tracker, expr));
      return tracker;
    };
    const lawTrackers = plan.laws.map((l) => track(l.name, l.expr));
    const perInstance = plan.checks.map((c) => ({
      check: c,
      facts: c.facts.map((f) => track(f.name, f.expr)),
      invariants: c.invariants.map((inv) => ({ inv, tracker: track(inv.name, inv.expr) })),
    }));
    const allAssumptions = [
      ...lawTrackers,
      ...perInstance.flatMap((pi) => [...pi.facts, ...pi.invariants.map((i) => i.tracker)]),
    ];

    const z3Result = (await solver.check(...allAssumptions)) as 'sat' | 'unsat' | 'unknown';
    const unknownReason = z3Result === 'unknown' ? String(solver.reasonUnknown?.() || 'timeout or resource limit') : '';
    const unsatCoreAssertions =
      z3Result === 'unsat' ? [...solver.unsatCore()].map((b: Z3Any) => String(b)) : [];
    const z3ModelAssignments: Record<string, string | number | boolean> = {};
    if (z3Result === 'sat') {
      const model = solver.model();
      for (const w of plan.watch) {
        const v = String(model.eval(w.expr, true));
        z3ModelAssignments[w.name] = /^-?\d+$/.test(v) ? parseInt(v, 10) : v;
      }
    }

    const offendingLocations: ClauseVerificationProof['offendingLocations'] = [];
    const opaRegoTriggeredDenials: string[] = [];
    const repairTargets: Z3RepairTarget[] = [];
    const affected = new Set<string>();
    const witness: Record<string, string | number | boolean> = {};

    if (z3Result === 'unsat') {
      for (const pi of perInstance) {
        const failing: Invariant[] = [];
        for (const { inv, tracker } of pi.invariants) {
          if ((await solver.check(...lawTrackers, ...pi.facts, tracker)) === 'unsat') failing.push(inv);
        }
        if (failing.length === 0) continue;
        const inst = pi.check.instance;
        affected.add(inst.nodeId);
        for (const f of pi.check.facts) witness[f.name] = f.display;
        offendingLocations.push({
          nodeId: inst.nodeId,
          filePath: inst.filePath,
          language: inst.language,
          line: inst.line,
          endLine: inst.endLine,
          codeSnippet: inst.codeSnippet,
          explanation: failing.map((f) => f.explanation).join(' '),
          astNodeType: inst.astNodeType,
          remediationPreview: failing.map((f) => f.remediation).join('; '),
        });
        for (const inv of failing) {
          opaRegoTriggeredDenials.push(`VIOLATION [${clause.citation}]: ${inv.explanation}`);
          if (inv.repair && inst.finding) {
            repairTargets.push({
              ...inv.repair,
              factLabel: inv.name,
              findingId: inst.finding.id,
              nodeId: inst.nodeId,
              filePath: inst.filePath,
              language: inst.language,
              repairAction: inv.repair.repairAction as Z3RepairAction,
            });
          }
        }
      }
    }

    const solveMs = Math.max(0.1, Math.round((performance.now() - t0) * 100) / 100);
    totalZ3ExecutionMs += solveMs;

    const assertionsSmt = solver.toString().trim();
    const smtLib2Executed = `; LexCompiler — exact assertions passed to Z3 for ${clause.citation} (${clause.id})
; Every assertion is guarded by a named assumption literal; the verdict uses all of them.
${assertionsSmt}
(check-sat-assuming (${[...trackers.keys()].join(' ')}))
; result: ${z3Result}${unknownReason ? ` (${unknownReason})` : ''}${
      z3Result === 'unsat' ? `\n; unsat core: (${unsatCoreAssertions.join(' ')})` : ''
    }`;
    solver.release?.();

    const reviewReasons = reviewReasonsFor(clause);
    if (plan.checks.length === 0 && plan.emptyNeedsReview) {
      reviewReasons.push(`${plan.emptyMeaning} The clause holds vacuously; confirm the repository is in scope.`);
    }
    if (z3Result === 'unknown') {
      reviewReasons.push(`Z3 returned unknown (${unknownReason}); the clause is not proven either way.`);
    }

    const formalProofSteps: Z3FormalProofStep[] = [
      {
        stepNumber: 1,
        ruleName: 'Normative premises (law)',
        formula: plan.laws.map((l) => l.display).join(' ∧ ') || '—',
        justification: `Compiled from ${clause.citation} (${clause.deontic.extractionProvenance?.method || 'DETERMINISTIC_PARSER'})`,
      },
      {
        stepNumber: 2,
        ruleName: `Extracted code facts (${plan.checks.length} construct${plan.checks.length === 1 ? '' : 's'})`,
        formula:
          plan.checks.length > 0
            ? plan.checks.map((c) => c.facts.map((f) => f.display).join(', ')).join(' ∧ ')
            : plan.emptyMeaning,
        justification: 'SQL tokenizer/parser, Python ast with taint propagation, and TypeScript Compiler API',
      },
    ];
    if (z3Result === 'unsat') {
      formalProofSteps.push({
        stepNumber: 3,
        ruleName: 'Q.E.D. — UNSAT (violation)',
        formula: `unsat core = { ${unsatCoreAssertions.join(', ')} }`,
        justification: `Z3 refuted the conjunction in ${solveMs} ms; ${offendingLocations.length} construct(s) violate at least one invariant.`,
      });
    } else if (z3Result === 'sat') {
      formalProofSteps.push({
        stepNumber: 3,
        ruleName: plan.checks.length > 0 ? 'Q.E.D. — SAT (compliant)' : 'SAT (vacuous: no applicable constructs)',
        formula: plan.checks.length > 0 ? 'All invariants hold for every extracted construct.' : plan.emptyMeaning,
        justification: `Z3 found a model in ${solveMs} ms.`,
      });
    } else {
      formalProofSteps.push({
        stepNumber: 3,
        ruleName: 'UNKNOWN — needs review',
        formula: 'Z3 returned unknown',
        justification: unknownReason,
      });
    }

    const statuteSha256 = sha256Hex(clause.rawLegalText);
    const deonticIrSha256 = sha256Hex(JSON.stringify(clause.deontic));
    const smtFormulaSha256 = sha256Hex(assertionsSmt);
    const astSnapshotSha256 = sha256Hex(JSON.stringify(plan.checks.map((c) => c.facts.map((f) => f.name))));
    proofs.push({
      clauseId: clause.id,
      citation: clause.citation,
      title: clause.title,
      frameworkId: clause.frameworkId,
      category: clause.category,
      severity: clause.severity,
      status: z3Result === 'sat' ? 'SAT_COMPLIANT' : z3Result === 'unsat' ? 'UNSAT_VIOLATION' : 'UNKNOWN_NEEDS_REVIEW',
      z3SolverStatus: z3Result,
      z3SolveTimeMs: solveMs,
      smtLib2Executed,
      unsatCoreAssertions,
      z3ModelAssignments,
      repairTargets,
      counterexampleWitness: witness,
      formalProofSteps,
      opaRegoTriggeredDenials,
      affectedGraphNodeIds: [...affected],
      offendingLocations,
      applicableInstanceCount: plan.checks.length,
      reviewReasons,
      cryptographicProvenance: {
        statuteSha256,
        deonticIrSha256,
        smtFormulaSha256,
        astSnapshotSha256,
        merkleProofHash: merkleRoot([statuteSha256, deonticIrSha256, smtFormulaSha256, astSnapshotSha256]),
        timestampIso: new Date().toISOString(),
      },
    });
  }

  return {
    proofs,
    architectureGraph: buildArchitectureGraph(proofs, sqlTables, astFindings),
    totalZ3ExecutionMs: Math.round(totalZ3ExecutionMs * 100) / 100,
    merkleAuditRoot: merkleRoot(proofs.map((p) => p.cryptographicProvenance.merkleProofHash)),
  };
}

/** Aggregates construct instances into the five role nodes of the blast-radius graph. */
function buildArchitectureGraph(
  proofs: ClauseVerificationProof[],
  sqlTables: SQLTableSchema[],
  astFindings: ASTFindingNode[]
): { nodes: ArchitectureGraphNode[]; edges: ArchitectureGraphEdge[] } {
  const violationsFor = (nodeId: string) =>
    proofs
      .filter((p) => p.status === 'UNSAT_VIOLATION' && p.affectedGraphNodeIds.includes(nodeId))
      .map((p) => p.clauseId);
  const offending = (nodeId: string) => proofs.flatMap((p) => p.offendingLocations).find((l) => l.nodeId === nodeId);
  const byType = (...types: ASTFindingNode['constructType'][]) =>
    astFindings.filter((f) => types.includes(f.constructType));

  const piiTables = sqlTables.filter((t) => t.containsPII);
  const endpoints = byType('FASTAPI_ENDPOINT', 'PII_PROCESSING_FUNCTION');
  const loggers = byType('LOGGER_CALL');
  const caches = byType('REDIS_CACHE_WORKER', 'DATA_RETENTION_POLICY');
  const ais = byType('LLM_INFERENCE_CALL');
  const egress = byType('CROSS_BORDER_EGRESS');

  const location = (nodeId: string, fallback: { filePath: string; line: number; endLine: number } | undefined) => {
    const off = offending(nodeId);
    if (off) return { filePath: off.filePath, line: off.line, endLine: off.endLine };
    if (fallback) return { filePath: fallback.filePath, line: fallback.line, endLine: fallback.endLine };
    return { filePath: '(not found in repository)', line: 1, endLine: 1 };
  };
  const status = (ids: string[]): ArchitectureGraphNode['status'] => (ids.length > 0 ? 'VIOLATION' : 'COMPLIANT');

  const apiV = violationsFor('node-fastapi-endpoint');
  const pgV = violationsFor('node-postgres-schema');
  const cacheV = violationsFor('node-redis-worker');
  const aiV = violationsFor('node-ai-engine');
  const egV = violationsFor('node-cross-border');

  const firstTable = piiTables[0];
  const apiKms = endpoints.length > 0 && endpoints.every((e) => e.metadata.usesTenantIsolatedKms === true);
  const tablesKms = piiTables.length > 0 && piiTables.every((t) => t.hasTenantKeyIsolation);
  const maxTableRet = Math.max(0, ...piiTables.map((t) => t.retentionHoursConfigured ?? 0));
  const cacheTtls = caches.map((c) => c.metadata.retentionTtlHours).filter((h): h is number => typeof h === 'number');
  const maxCacheTtl = cacheTtls.length ? Math.max(...cacheTtls) : 0;
  const cacheKms = caches.length > 0 && caches.every((c) => c.metadata.usesTenantIsolatedKms !== false);
  const confs = ais.map((a) => a.metadata.aiConfidenceThreshold).filter((v): v is number => typeof v === 'number');
  const gate = confs.length ? `${Math.round(Math.min(...confs) * 100)}%` : 'none';
  const regions = [...new Set(egress.map((e) => e.metadata.egressRegion).filter((r): r is string => !!r))];
  const nonEu = regions.filter((r) => !r.startsWith('eu-'));

  const apiLoc = location('node-fastapi-endpoint', endpoints[0] || loggers[0]);
  const pgLoc = location(
    'node-postgres-schema',
    firstTable ? { filePath: firstTable.filePath, line: firstTable.startLine, endLine: firstTable.endLine } : undefined
  );
  const cacheLoc = location('node-redis-worker', caches[0]);
  const aiLoc = location('node-ai-engine', ais[0]);
  const egLoc = location('node-cross-border', egress[0]);

  const nodes: ArchitectureGraphNode[] = [
    {
      id: 'node-fastapi-endpoint',
      label: 'API / PII Endpoints',
      sublabel: `${apiLoc.filePath} · ${endpoints.length} endpoint(s), ${loggers.length} leaking log call(s)`,
      nodeRole: 'FASTAPI_ENDPOINT',
      layer: 'INGRESS_API',
      language: 'python',
      ...apiLoc,
      status: status(apiV),
      violatedClauseIds: apiV,
      dataClassifications: ['DIRECT_IDENTIFIER', 'HEALTH_PHI'],
      astSummary: endpoints.map((e) => `${e.astNodeKind}(${e.functionName})`).join(', ') || 'none found',
      metrics: {
        instances: endpoints.length,
        tenant_kms_isolated: apiKms,
        logs_plaintext_pii: loggers.some((l) => l.metadata.logsPlaintextPii),
      },
    },
    {
      id: 'node-postgres-schema',
      label: 'PII Tables',
      sublabel: `${pgLoc.filePath} · ${piiTables.map((t) => t.tableName).join(', ') || 'no PII tables'}`,
      nodeRole: 'POSTGRES_SCHEMA',
      layer: 'DATA_STORAGE',
      language: 'sql',
      ...pgLoc,
      status: status(pgV),
      violatedClauseIds: pgV,
      dataClassifications: ['DIRECT_IDENTIFIER', 'HEALTH_PHI'],
      astSummary:
        piiTables.map((t) => `CreateTable(${t.tableName} · ${t.columns.length} cols)`).join(', ') || 'none found',
      metrics: {
        instances: piiTables.length,
        retention_ttl_hours: `${maxTableRet}h`,
        tenant_kms_column: tablesKms,
        cascade_erasure: piiTables.every((t) => t.hasErasureCascade || (t.dependentForeignKeys || []).length === 0),
      },
    },
    {
      id: 'node-redis-worker',
      label: 'Caches & Retention Policies',
      sublabel: `${cacheLoc.filePath} · ${caches.length} TTL constant(s)`,
      nodeRole: 'REDIS_WORKER',
      layer: 'CACHE_AND_WORKERS',
      language: 'python',
      ...cacheLoc,
      status: status(cacheV),
      violatedClauseIds: cacheV,
      dataClassifications: ['EPHEMERAL_SESSION_PII'],
      astSummary: caches.map((c) => c.metadata.retentionSource || c.functionName).join(', ') || 'none found',
      metrics: {
        instances: caches.length,
        cache_ttl_hours: `${maxCacheTtl}h (${Math.round((maxCacheTtl / 24) * 10) / 10}d)`,
        tenant_kms_envelope: cacheKms,
      },
    },
    {
      id: 'node-ai-engine',
      label: 'AI Decision Engines',
      sublabel: `${aiLoc.filePath} · ${ais.map((a) => a.functionName).join(', ') || 'none found'}`,
      nodeRole: 'AI_DECISION_ENGINE',
      layer: 'SERVICE_LOGIC',
      language: 'typescript',
      ...aiLoc,
      status: status(aiV),
      violatedClauseIds: aiV,
      dataClassifications: ['HIGH_RISK_AI_SCORING'],
      astSummary: ais.map((a) => a.astNodeKind).join(', ') || 'none found',
      metrics: {
        instances: ais.length,
        confidence_gate: gate,
        human_oversight_gate: ais.length > 0 && ais.every((a) => a.metadata.hasHumanOversightGate === true),
        immutable_audit_log: ais.length > 0 && ais.every((a) => a.metadata.writesAuditLog === true),
      },
    },
    {
      id: 'node-cross-border',
      label: 'Cross-Border Egress',
      sublabel: `${egLoc.filePath} · ${regions.join(', ') || 'no egress regions'}`,
      nodeRole: 'CROSS_BORDER_SYNC',
      layer: 'EXTERNAL_EGRESS',
      language: 'typescript',
      ...egLoc,
      status: status(egV),
      violatedClauseIds: egV,
      dataClassifications: ['REPLICATED_TELEMETRY'],
      astSummary: egress.map((e) => `${e.functionName} → ${e.metadata.egressRegion}`).join(', ') || 'none found',
      metrics: {
        instances: egress.length,
        replica_region: regions.join(', ') || 'none',
        eu_sovereign: nonEu.length === 0,
      },
    },
  ];

  const edges: ArchitectureGraphEdge[] = [
    {
      id: 'edge-fastapi-to-postgres',
      source: 'node-fastapi-endpoint',
      target: 'node-postgres-schema',
      label: 'persist PII records',
      dataPayload: [...new Set(piiTables.flatMap((t) => t.columns.filter((c) => c.isPII).map((c) => c.name)))],
      isEncrypted: piiTables.every((t) => t.unencryptedPiiColumns.length === 0),
      isTenantIsolated: apiKms && tablesKms,
      violatedClauseIds: [...new Set([...apiV, ...pgV])],
    },
    {
      id: 'edge-fastapi-to-redis',
      source: 'node-fastapi-endpoint',
      target: 'node-redis-worker',
      label: `cache PII (max TTL=${maxCacheTtl}h)`,
      dataPayload: ['session_pii_blob'],
      isEncrypted: cacheKms,
      isTenantIsolated: cacheKms,
      violatedClauseIds: cacheV,
    },
    {
      id: 'edge-fastapi-to-ai',
      source: 'node-fastapi-endpoint',
      target: 'node-ai-engine',
      label: `high-risk scoring (gate=${gate})`,
      dataPayload: ['features'],
      isEncrypted: true,
      isTenantIsolated: true,
      violatedClauseIds: aiV,
    },
    {
      id: 'edge-postgres-to-crossborder',
      source: 'node-postgres-schema',
      target: 'node-cross-border',
      label: `replicate → ${regions.join(', ') || 'none'}`,
      dataPayload: ['replicated_records'],
      isEncrypted: true,
      isTenantIsolated: tablesKms,
      isCrossBorder: nonEu.length > 0,
      targetRegion: regions[0],
      violatedClauseIds: egV,
    },
  ];
  return { nodes, edges };
}
