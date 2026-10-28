import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { ASTFindingNode, RuleCategory, SQLTableSchema } from '../../shared/types.js';
import { REGO_PACKAGES } from './regoPolicies.js';

const execFileAsync = promisify(execFile);

/** Input document the generated Rego policies evaluate (one entry per construct instance). */
export function buildRegoInput(sqlTables: SQLTableSchema[], astFindings: ASTFindingNode[]) {
  const of = (...types: ASTFindingNode['constructType'][]) => astFindings.filter((f) => types.includes(f.constructType));
  return {
    sql_tables: sqlTables.map((t) => ({
      tableName: t.tableName,
      filePath: t.filePath,
      containsPII: t.containsPII,
      retentionHoursConfigured: t.retentionHoursConfigured,
      hasTenantKeyIsolation: t.hasTenantKeyIsolation,
      unencryptedPiiColumns: t.unencryptedPiiColumns,
      dependentForeignKeys: (t.dependentForeignKeys || []).map((d) => ({
        childTable: d.childTable,
        childColumn: d.childColumn,
        onDeleteCascade: d.onDeleteCascade,
      })),
    })),
    endpoints: of('FASTAPI_ENDPOINT', 'PII_PROCESSING_FUNCTION').map((f) => ({
      name: f.functionName,
      filePath: f.filePath,
      line: f.line,
      uses_tenant_isolated_kms: f.metadata.usesTenantIsolatedKms === true,
    })),
    caches: of('REDIS_CACHE_WORKER', 'DATA_RETENTION_POLICY')
      .filter((f) => typeof f.metadata.retentionTtlHours === 'number')
      .map((f) => ({
        name: f.metadata.retentionSource || f.functionName,
        filePath: f.filePath,
        line: f.line,
        ttl_hours: f.metadata.retentionTtlHours,
        ...(typeof f.metadata.usesTenantIsolatedKms === 'boolean' ? { uses_tenant_isolated_kms: f.metadata.usesTenantIsolatedKms } : {}),
      })),
    log_sinks: of('LOGGER_CALL').map((f) => ({
      name: f.functionName,
      filePath: f.filePath,
      line: f.line,
      leaked_fields: f.metadata.leakedFields || [],
    })),
    ai_nodes: of('LLM_INFERENCE_CALL').map((f) => ({
      name: f.functionName,
      filePath: f.filePath,
      line: f.line,
      confidence_threshold: f.metadata.aiConfidenceThreshold ?? null,
      has_human_oversight_gate: f.metadata.hasHumanOversightGate === true,
      writes_audit_log: f.metadata.writesAuditLog === true,
    })),
    egress_nodes: of('CROSS_BORDER_EGRESS').map((f) => ({
      name: f.functionName,
      filePath: f.filePath,
      line: f.line,
      region: f.metadata.egressRegion,
    })),
  };
}

let opaBinary: Promise<string | null> | null = null;

/** Locates an `opa` binary (LEXCOMPILER_OPA_BIN or PATH); null when OPA is not installed. */
export function findOpaBinary(): Promise<string | null> {
  opaBinary ??= (async () => {
    const candidate = process.env.LEXCOMPILER_OPA_BIN || 'opa';
    try {
      await execFileAsync(candidate, ['version'], { timeout: 5000 });
      return candidate;
    } catch {
      return null;
    }
  })();
  return opaBinary;
}

export interface OpaEvaluation {
  evaluated: boolean;
  denials: string[];
  error?: string;
}

/** Evaluates `data.<package>.deny` of a generated policy with `opa eval`. */
export async function evaluateRegoPolicy(
  category: RuleCategory,
  policy: string,
  input: unknown
): Promise<OpaEvaluation> {
  const opa = await findOpaBinary();
  if (!opa) return { evaluated: false, denials: [], error: 'opa binary not found (set LEXCOMPILER_OPA_BIN or install OPA)' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lexcompiler-opa-'));
  try {
    fs.writeFileSync(path.join(dir, 'policy.rego'), policy);
    fs.writeFileSync(path.join(dir, 'input.json'), JSON.stringify(input));
    const { stdout } = await execFileAsync(
      opa,
      ['eval', '--format', 'json', '--data', 'policy.rego', '--input', 'input.json', `data.${REGO_PACKAGES[category]}.deny`],
      { cwd: dir, timeout: 15000, maxBuffer: 4 * 1024 * 1024 }
    );
    const parsed = JSON.parse(stdout) as { result?: Array<{ expressions?: Array<{ value?: unknown }> }> };
    const value = parsed.result?.[0]?.expressions?.[0]?.value;
    const denials = Array.isArray(value) ? value.map(String).sort() : [];
    return { evaluated: true, denials };
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    return { evaluated: false, denials: [], error: (e.stderr || e.message || String(err)).slice(0, 500) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
