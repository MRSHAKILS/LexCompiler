import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import ts from 'typescript';
import type {
  ASTFindingNode,
  SourceEditAnchor,
  SQLColumnNode,
  SQLDependentForeignKey,
  SQLTableSchema,
  TargetRepoFile,
} from '../../shared/types.js';

const PII_EXACT_COLUMNS =
  /^(ssn|email|phone|dob|date_of_birth|passport|national_id|tax_id|credit_card|full_name|diagnosis_code|patient_email|patient_ssn)$/i;
const PII_PREFIX_COLUMNS = /^(patient_|biometric_)/i;
const LOGGING_SINKS = /^(logger|logging|log|console)\.(info|warn|error|debug|warning|exception|log)$/i;
const PRINT_SINKS = /^(print|pprint)$/i;
const CACHE_TTL_CALLS = /(setex|expire|pexpire|set_ex|set_expire)$/i;
const TTL_ASSIGN_NAMES = /(ttl|retention|expire|expiry|purge).*(hour|hr|day|sec|second)?|(hour|hr|day).*ttl/i;
const KMS_ASSIGN_NAMES = /(tenant.*kms|kms.*envelope|using_tenant_isolated_kms|use_tenant_kms)/i;
const CIPHER_ASSIGN_NAMES = /(encryption_cipher|cipher|kms_cipher)/i;
const CONFIDENCE_NAMES = /(confidence|threshold|auto_approval|min_score|min_conf)/i;
const HUMAN_GATE_NAMES = /(human_oversight|human_in_the_loop|hitl|manual_approval|human_review|enforce_human)/i;
const AUDIT_LOG_NAMES = /(audit_log|immutable_audit|write_audit|audit_trail)/i;
const REGION_NAMES = /(region|replica_target|egress_region|data_residency|destination_region)/i;
const PII_IDENT_RE =
  /\b(ssn|email|phone|dob|passport|national_id|tax_id|credit_card|full_name|diagnosis_code|patient_\w+|biometric_\w+)\b/i;

interface ParsedPythonAst {
  node_count: number;
  assignments: Record<
    string,
    { value: unknown; lineno: number; end_lineno: number; col_offset: number }
  >;
  functions: Array<{
    name: string;
    kind: string;
    lineno: number;
    end_lineno: number;
    col_offset: number;
    args: string[];
    decorators: string[];
  }>;
  classes: Array<{ name: string; lineno: number; end_lineno: number }>;
  calls: Array<{
    func: string;
    lineno: number;
    end_lineno: number;
    col_offset: number;
    unparsed: string;
    args: string[];
  }>;
}

const pythonAstCache = new Map<string, ParsedPythonAst>();

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function snippet(lines: string[], startLine: number, endLine: number): string {
  return lines.slice(Math.max(0, startLine - 1), Math.max(startLine, endLine)).join('\n');
}

function isInferredPiiColumn(colName: string): boolean {
  if (/_id$/i.test(colName) && !/^(national_id|tax_id)$/i.test(colName)) {
    return false;
  }
  return PII_EXACT_COLUMNS.test(colName) || PII_PREFIX_COLUMNS.test(colName);
}

function parseSqlAnnotations(text: string): {
  piiClass?: SQLColumnNode['piiClassification'];
  encryptedAlg?: string;
  tenantIsolated: boolean;
  retentionHours?: number;
} {
  const piiMatch = text.match(/@pii\(([A-Z_]+)\)/i);
  const encMatch = text.match(/@encrypted\(([A-Za-z0-9_-]+)\)/i);
  const retMatch = text.match(/@retention_hours\((\d+)\)/i);
  return {
    piiClass: piiMatch?.[1] as SQLColumnNode['piiClassification'] | undefined,
    encryptedAlg: encMatch?.[1],
    tenantIsolated: /@tenant_isolated_kms/i.test(text),
    retentionHours: retMatch ? parseInt(retMatch[1], 10) : undefined,
  };
}

/**
 * Parses SQL DDL files into structured SQLTableSchema & ASTFindingNode representations.
 * Analyzes every CREATE TABLE (not a hardcoded table name) and infers PII columns from
 * explicit `-- @pii(...)` / `-- @encrypted(...)` annotations or zero-tag name patterns.
 */
export function parseSqlSchemaFile(file: TargetRepoFile): {
  tables: SQLTableSchema[];
  findings: ASTFindingNode[];
  astNodeCount: number;
} {
  const lines = file.content.split('\n');
  const tables: SQLTableSchema[] = [];
  const findings: ASTFindingNode[] = [];
  let astNodeCount = 0;
  const pendingFk: Array<SQLDependentForeignKey & { parentTable: string }> = [];

  let currentTable: SQLTableSchema | null = null;
  let pendingCommentAnnotations = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const createMatch = line.match(
      /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)/i
    );
    if (createMatch) {
      astNodeCount += 4;
      pendingCommentAnnotations = '';
      currentTable = {
        tableName: createMatch[1],
        filePath: file.path,
        startLine: lineNum,
        endLine: lineNum,
        containsPII: false,
        retentionHoursConfigured: null,
        retentionDaysConfigured: null,
        hasTenantKeyIsolation: false,
        hasErasureCascade: false,
        encryptedColumnsCount: 0,
        unencryptedPiiColumns: [],
        columns: [],
        dependentForeignKeys: [],
      };
      continue;
    }

    if (currentTable) {
      if (line.trim().startsWith(');') || line.trim() === ')') {
        currentTable.endLine = lineNum;
        tables.push(currentTable);

        const snippetLines = lines.slice(currentTable.startLine - 1, currentTable.endLine);
        const retentionAnchor = currentTable.columns.find((c) =>
          /retention_ttl_hours|retention_hours/i.test(c.name)
        );
        const editAnchors: SourceEditAnchor[] = [];
        if (retentionAnchor && currentTable.retentionHoursConfigured != null) {
          const retLine = lines[retentionAnchor.line - 1] || '';
          const num = String(currentTable.retentionHoursConfigured);
          const col = retLine.indexOf(num);
          editAnchors.push({
            role: 'RETENTION_TTL_LITERAL',
            symbol: retentionAnchor.name,
            line: retentionAnchor.line,
            column: Math.max(0, col),
            endLine: retentionAnchor.line,
            endColumn: Math.max(0, col) + num.length,
            sourceText: num,
            numericValue: currentTable.retentionHoursConfigured,
          });
          const ann = retLine.match(/@retention_hours\((\d+)\)/i);
          if (ann && ann.index != null) {
            editAnchors.push({
              role: 'RETENTION_ANNOTATION_LITERAL',
              symbol: '@retention_hours',
              line: retentionAnchor.line,
              column: ann.index,
              endLine: retentionAnchor.line,
              endColumn: ann.index + ann[0].length,
              sourceText: ann[0],
              numericValue: parseInt(ann[1], 10),
            });
          }
        }
        if (!currentTable.hasTenantKeyIsolation) {
          const insertAfter =
            currentTable.columns.find((c) => /tenant_id/i.test(c.name)) ||
            currentTable.columns[0];
          if (insertAfter) {
            editAnchors.push({
              role: 'SQL_COLUMN_INSERTION_POINT',
              symbol: 'tenant_kms_key_id',
              line: insertAfter.line,
              column: 0,
              endLine: insertAfter.line,
              endColumn: (lines[insertAfter.line - 1] || '').length,
              sourceText: lines[insertAfter.line - 1] || '',
            });
          }
        }
        for (const col of currentTable.columns) {
          if (col.isPII && !col.encryptedAtRest) {
            const colLine = lines[col.line - 1] || '';
            editAnchors.push({
              role: 'SQL_COLUMN_ENCRYPTION_ANNOTATION',
              symbol: col.name,
              line: col.line,
              column: 0,
              endLine: col.line,
              endColumn: colLine.length,
              sourceText: colLine,
            });
          }
        }

        findings.push({
          id: `ast-sql-${file.path}-${currentTable.tableName}`,
          filePath: file.path,
          line: currentTable.startLine,
          endLine: currentTable.endLine,
          column: 1,
          language: 'sql',
          astNodeKind: 'CreateTableStatement',
          constructType: 'POSTGRES_DDL_TABLE',
          functionName: `CREATE TABLE ${currentTable.tableName}`,
          codeSnippet: snippetLines.join('\n'),
          metadata: {
            usesTenantIsolatedKms: currentTable.hasTenantKeyIsolation,
            encryptionCipher: currentTable.hasTenantKeyIsolation
              ? 'AES-256-GCM-TENANT-KMS'
              : 'AES-256-GCM',
            retentionTtlHours: currentTable.retentionHoursConfigured ?? 720,
            hasCascadeDelete: currentTable.hasErasureCascade,
            containsPii: currentTable.containsPII,
            encryptsPii: currentTable.unencryptedPiiColumns.length === 0,
          },
          editAnchors,
        });

        currentTable = null;
        pendingCommentAnnotations = '';
        continue;
      }

      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('--')) {
        pendingCommentAnnotations += ` ${trimmed}`;
        continue;
      }

      astNodeCount += 3;
      const colMatch = trimmed.match(/^([a-zA-Z0-9_]+)\s+([A-Z0-9_(),\s]+)/i);
      if (!colMatch) {
        pendingCommentAnnotations = '';
        continue;
      }

      const colName = colMatch[1];
      const dataType = colMatch[2].split(/\s+/)[0];
      const isPrimaryKey = /PRIMARY\s+KEY/i.test(trimmed);
      const isNullable = !/NOT\s+NULL/i.test(trimmed) && !isPrimaryKey;
      const annotationSource = `${pendingCommentAnnotations} ${trimmed}`;
      const annotations = parseSqlAnnotations(annotationSource);

      const inferredPii = isInferredPiiColumn(colName);
      const isPII = Boolean(annotations.piiClass) || inferredPii;
      const piiClassification: SQLColumnNode['piiClassification'] =
        annotations.piiClass || (isPII ? 'DIRECT_IDENTIFIER' : 'NONE');
      const piiInference: SQLColumnNode['piiInference'] = annotations.piiClass
        ? 'ANNOTATION'
        : inferredPii
          ? 'NAME_PATTERN'
          : 'NONE';

      const encryptedAtRest = Boolean(annotations.encryptedAlg);
      const encryptionAlgorithm = annotations.encryptedAlg;

      const hasTenantKeyCol =
        /tenant_kms_key_id/i.test(colName) ||
        annotations.tenantIsolated ||
        /@tenant_isolated_kms/i.test(trimmed);
      if (hasTenantKeyCol) {
        currentTable.hasTenantKeyIsolation = true;
      }

      const retHoursMatch =
        annotations.retentionHours != null
          ? [String(annotations.retentionHours), String(annotations.retentionHours)]
          : trimmed.match(/retention_ttl_hours\s+INT\s+DEFAULT\s+(\d+)/i) ||
            trimmed.match(/retention_hours\s+INT\s+DEFAULT\s+(\d+)/i);
      if (retHoursMatch) {
        const hrs = parseInt(retHoursMatch[1], 10);
        currentTable.retentionHoursConfigured = hrs;
        currentTable.retentionDaysConfigured = Math.round((hrs / 24) * 10) / 10;
      } else if (annotations.retentionHours != null) {
        currentTable.retentionHoursConfigured = annotations.retentionHours;
        currentTable.retentionDaysConfigured =
          Math.round((annotations.retentionHours / 24) * 10) / 10;
      }

      const fkMatch = trimmed.match(
        /REFERENCES\s+([a-zA-Z0-9_]+)\s*\(\s*([a-zA-Z0-9_]+)\s*\)(?:\s+ON\s+DELETE\s+(CASCADE|RESTRICT|SET\s+NULL|NO\s+ACTION))?/i
      );
      const onDeleteCascade = /ON\s+DELETE\s+CASCADE/i.test(trimmed);
      if (onDeleteCascade) {
        currentTable.hasErasureCascade = true;
      }
      if (fkMatch) {
        pendingFk.push({
          parentTable: fkMatch[1],
          childTable: currentTable.tableName,
          childColumn: colName,
          filePath: file.path,
          line: lineNum,
          onDeleteCascade,
          implicit: !onDeleteCascade,
        });
      }

      if (isPII) {
        currentTable.containsPII = true;
        if (encryptedAtRest) {
          currentTable.encryptedColumnsCount++;
        } else {
          currentTable.unencryptedPiiColumns.push(colName);
        }
      }

      currentTable.columns.push({
        name: colName,
        dataType,
        isPrimaryKey,
        isNullable,
        isPII,
        piiClassification,
        encryptedAtRest,
        encryptionAlgorithm,
        hasTenantKeyIsolation: hasTenantKeyCol,
        foreignKeyReference: fkMatch
          ? {
              table: fkMatch[1],
              column: fkMatch[2],
              onDeleteCascade,
              implicit: !onDeleteCascade,
            }
          : undefined,
        piiInference,
        line: lineNum,
      });
      pendingCommentAnnotations = '';
    }
  }

  for (const fk of pendingFk) {
    const parent = tables.find((t) => t.tableName === fk.parentTable);
    const child = tables.find((t) => t.tableName === fk.childTable);
    if (parent) {
      parent.dependentForeignKeys = parent.dependentForeignKeys || [];
      parent.dependentForeignKeys.push({
        childTable: fk.childTable,
        childColumn: fk.childColumn,
        filePath: fk.filePath,
        line: fk.line,
        onDeleteCascade: fk.onDeleteCascade,
        implicit: fk.implicit,
      });
      if (fk.onDeleteCascade) {
        parent.hasErasureCascade = true;
      }
    }
    if (child && fk.onDeleteCascade) {
      child.hasErasureCascade = true;
    }
  }

  for (const finding of findings) {
    const table = tables.find((t) => finding.functionName.endsWith(t.tableName));
    if (table) {
      finding.metadata.hasCascadeDelete = table.hasErasureCascade;
    }
  }

  return { tables, findings, astNodeCount };
}

const PYTHON_AST_SCRIPT = `
import ast, json, sys

src = sys.stdin.read()
tree = ast.parse(src)
node_count = sum(1 for _ in ast.walk(tree))

assignments = {}
functions = []
classes = []
calls = []

def dotted(node):
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Name):
        return node.id
    return ""

def deco_name(d):
    if isinstance(d, ast.Call):
        return dotted(d.func)
    return dotted(d)

for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                val = None
                if isinstance(node.value, ast.Constant):
                    val = node.value.value
                assignments[target.id] = {
                    "value": val,
                    "lineno": node.lineno,
                    "end_lineno": getattr(node, "end_lineno", node.lineno),
                    "col_offset": node.col_offset
                }
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        val = None
        if isinstance(node.value, ast.Constant):
            val = node.value.value
        assignments[node.target.id] = {
            "value": val,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno),
            "col_offset": node.col_offset
        }
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        functions.append({
            "name": node.name,
            "kind": type(node).__name__,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno),
            "col_offset": node.col_offset,
            "args": [a.arg for a in node.args.args],
            "decorators": [deco_name(d) for d in node.decorator_list]
        })
    elif isinstance(node, ast.ClassDef):
        classes.append({
            "name": node.name,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno)
        })
    elif isinstance(node, ast.Call):
        func_name = dotted(node.func)
        arg_repr = []
        for a in node.args:
            try:
                arg_repr.append(ast.unparse(a) if hasattr(ast, "unparse") else "")
            except Exception:
                arg_repr.append("")
        calls.append({
            "func": func_name,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno),
            "col_offset": node.col_offset,
            "unparsed": ast.unparse(node) if hasattr(ast, "unparse") else "",
            "args": arg_repr
        })

print(json.dumps({
    "node_count": node_count,
    "assignments": assignments,
    "functions": functions,
    "classes": classes,
    "calls": calls
}))
`;

function parsePythonAstCached(content: string): ParsedPythonAst | null {
  const digest = sha256Hex(content);
  const cached = pythonAstCache.get(digest);
  if (cached) {
    return cached;
  }
  try {
    const stdout = execFileSync('python3', ['-c', PYTHON_AST_SCRIPT], {
      input: content,
      encoding: 'utf8',
      timeout: 3000,
    });
    const parsed = JSON.parse(stdout) as ParsedPythonAst;
    pythonAstCache.set(digest, parsed);
    if (pythonAstCache.size > 256) {
      const first = pythonAstCache.keys().next().value;
      if (first) pythonAstCache.delete(first);
    }
    return parsed;
  } catch {
    return null;
  }
}

function looksLikePiiSymbol(name: string): boolean {
  return PII_IDENT_RE.test(name);
}

function assignmentBool(parsed: ParsedPythonAst | null, predicate: (name: string) => boolean): boolean {
  if (!parsed) return false;
  for (const [name, meta] of Object.entries(parsed.assignments)) {
    if (predicate(name) && meta.value === true) return true;
  }
  return false;
}

function assignmentNumber(
  parsed: ParsedPythonAst | null,
  predicate: (name: string) => boolean
): { name: string; value: number; lineno: number; end_lineno: number; col_offset: number } | null {
  if (!parsed) return null;
  for (const [name, meta] of Object.entries(parsed.assignments)) {
    if (predicate(name) && typeof meta.value === 'number') {
      return {
        name,
        value: meta.value,
        lineno: meta.lineno,
        end_lineno: meta.end_lineno,
        col_offset: meta.col_offset,
      };
    }
  }
  return null;
}

function assignmentString(
  parsed: ParsedPythonAst | null,
  predicate: (name: string) => boolean
): { name: string; value: string; lineno: number } | null {
  if (!parsed) return null;
  for (const [name, meta] of Object.entries(parsed.assignments)) {
    if (predicate(name) && typeof meta.value === 'string') {
      return { name, value: meta.value, lineno: meta.lineno };
    }
  }
  return null;
}

function anchorForAssignment(
  role: SourceEditAnchor['role'],
  name: string,
  meta: { value: unknown; lineno: number; end_lineno: number; col_offset: number },
  lineText: string
): SourceEditAnchor {
  const sourceText = String(meta.value);
  const col = Math.max(0, lineText.indexOf(sourceText));
  return {
    role,
    symbol: name,
    line: meta.lineno,
    column: col,
    endLine: meta.end_lineno,
    endColumn: col + sourceText.length,
    sourceText,
    numericValue: typeof meta.value === 'number' ? meta.value : undefined,
    booleanValue: typeof meta.value === 'boolean' ? meta.value : undefined,
    stringValue: typeof meta.value === 'string' ? meta.value : undefined,
  };
}

/**
 * Uses Python 3's native `ast` module to parse `.py` files into real AST nodes.
 * Results are cached by SHA-256 of file content so unchanged files are never
 * re-parsed in a subprocess. Taint analysis tracks PII flowing into logging
 * sinks, cache TTL calls, and KMS envelope configs across ANY `.py` file.
 */
export function parsePythonAstFile(file: TargetRepoFile): {
  findings: ASTFindingNode[];
  astNodeCount: number;
} {
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = [];
  const parsedPy = parsePythonAstCached(file.content);
  const astNodeCount = parsedPy?.node_count ?? 48;

  const usesTenantKms =
    assignmentBool(parsedPy, (n) => KMS_ASSIGN_NAMES.test(n)) ||
    /USING_TENANT_ISOLATED_KMS\s*=\s*True/.test(file.content) ||
    /USE_TENANT_KMS_ENVELOPE\s*=\s*True/.test(file.content);

  const cipherAssign = assignmentString(parsedPy, (n) => CIPHER_ASSIGN_NAMES.test(n));
  const cipherVal =
    cipherAssign?.value ||
    (usesTenantKms ? 'AES-256-GCM-TENANT-KMS' : 'AES-256-GCM-SHARED-KEY');

  const ttlAssign =
    assignmentNumber(parsedPy, (n) => TTL_ASSIGN_NAMES.test(n) || /PII_CACHE_TTL_HOURS/i.test(n)) ||
    assignmentNumber(parsedPy, (n) => /ttl/i.test(n));
  const ttlHours =
    ttlAssign?.value ??
    parseInt(
      file.content.match(/(?:PII_CACHE_TTL_HOURS|RETENTION_TTL_HOURS|TTL_HOURS)\s*=\s*(\d+)/)?.[1] ||
        '720',
      10
    );

  const piiSymbols = new Set<string>();
  for (const fn of parsedPy?.functions || []) {
    for (const arg of fn.args) {
      if (looksLikePiiSymbol(arg)) piiSymbols.add(arg);
    }
  }
  for (const name of Object.keys(parsedPy?.assignments || {})) {
    if (looksLikePiiSymbol(name)) piiSymbols.add(name);
  }

  const leakingCalls = (parsedPy?.calls || []).filter((c) => {
    const isSink = LOGGING_SINKS.test(c.func) || PRINT_SINKS.test(c.func);
    if (!isSink) return false;
    const hasRedaction = /redact_pii|mask_pii|sha256_redact|\[REDACTED/i.test(c.unparsed);
    const hasPii =
      PII_IDENT_RE.test(c.unparsed) ||
      [...piiSymbols].some((s) => c.unparsed.includes(s)) ||
      /payload\.(ssn|email|diagnosis_code|phone|full_name)/.test(c.unparsed);
    return hasPii && !hasRedaction;
  });

  const leakedFields = new Set<string>();
  for (const call of leakingCalls) {
    const matches = call.unparsed.matchAll(
      /\b(ssn|email|phone|dob|passport|national_id|tax_id|credit_card|full_name|diagnosis_code|patient_\w+|biometric_\w+)\b/gi
    );
    for (const m of matches) leakedFields.add(m[1].toLowerCase());
  }
  const logsPlaintextPii = leakingCalls.length > 0;

  const fastapiFns = (parsedPy?.functions || []).filter((f) =>
    f.decorators.some((d) => /app\.(post|put|patch|get|delete)|router\.(post|put|patch|get|delete)/i.test(d))
  );
  const piiFns = (parsedPy?.functions || []).filter(
    (f) =>
      f.args.some((a) => looksLikePiiSymbol(a) || /payload|patient|pii/i.test(a)) ||
      /ingest|encrypt|patient|pii/i.test(f.name)
  );
  const primaryFn = fastapiFns[0] || piiFns[0];
  const hasFastapiSurface =
    fastapiFns.length > 0 || /FastAPI|APIRouter|@app\.(post|put|patch)/.test(file.content);
  const hasKmsOrCipher = Object.keys(parsedPy?.assignments || {}).some(
    (n) => KMS_ASSIGN_NAMES.test(n) || CIPHER_ASSIGN_NAMES.test(n)
  );
  const ttlConstPresent =
    ttlAssign != null ||
    /PII_CACHE_TTL_HOURS|RETENTION_TTL_HOURS|TTL_HOURS|CACHE_TTL/.test(file.content);

  if (
    hasFastapiSurface ||
    (hasKmsOrCipher && primaryFn && !ttlConstPresent && !hasFastapiSurface)
  ) {
    const fnStart = primaryFn?.lineno ?? 1;
    const fnEnd = primaryFn?.end_lineno ?? Math.min(lines.length, fnStart + 24);
    const editAnchors: SourceEditAnchor[] = [];
    for (const [name, meta] of Object.entries(parsedPy?.assignments || {})) {
      if (KMS_ASSIGN_NAMES.test(name) && typeof meta.value === 'boolean') {
        editAnchors.push(
          anchorForAssignment('TENANT_KMS_FLAG', name, meta, lines[meta.lineno - 1] || '')
        );
      }
      if (CIPHER_ASSIGN_NAMES.test(name) && typeof meta.value === 'string') {
        editAnchors.push(
          anchorForAssignment('CIPHER_LABEL', name, meta, lines[meta.lineno - 1] || '')
        );
      }
    }
    for (const call of parsedPy?.calls || []) {
      if (/encrypt_shared_aes256|encrypt_aes|encrypt_with_shared/i.test(call.func)) {
        editAnchors.push({
          role: 'SHARED_KEY_ENCRYPT_CALL',
          symbol: call.func,
          line: call.lineno,
          column: call.col_offset,
          endLine: call.end_lineno,
          endColumn: call.col_offset + call.func.length,
          sourceText: call.unparsed,
        });
      }
    }

    findings.push({
      id: `ast-py-endpoint-${file.path}-${primaryFn?.name || 'module'}`,
      filePath: file.path,
      line: fnStart,
      endLine: fnEnd,
      column: 1,
      language: 'python',
      astNodeKind: primaryFn?.kind || 'AsyncFunctionDef',
      constructType: fastapiFns.length > 0 || /FastAPI/.test(file.content)
        ? 'FASTAPI_ENDPOINT'
        : 'PII_PROCESSING_FUNCTION',
      functionName: primaryFn?.name || 'module',
      codeSnippet: snippet(lines, Math.max(1, fnStart - 1), fnEnd),
      metadata: {
        usesTenantIsolatedKms: usesTenantKms,
        encryptionCipher: cipherVal,
        logsPlaintextPii,
        leakedFields: [...leakedFields],
        containsPii: true,
      },
      editAnchors,
    });
  }

  for (const loggerCall of leakingCalls) {
    findings.push({
      id: `ast-py-logger-${file.path}-${loggerCall.lineno}`,
      filePath: file.path,
      line: loggerCall.lineno,
      endLine: loggerCall.end_lineno,
      column: loggerCall.col_offset + 1,
      language: 'python',
      astNodeKind: `Call(${loggerCall.func})`,
      constructType: 'LOGGER_CALL',
      functionName: loggerCall.func,
      codeSnippet: snippet(lines, loggerCall.lineno, loggerCall.end_lineno),
      metadata: {
        logsPlaintextPii: true,
        leakedFields: [...leakedFields],
      },
      editAnchors: [
        {
          role: 'PII_LOG_ARGUMENT',
          symbol: loggerCall.func,
          line: loggerCall.lineno,
          column: loggerCall.col_offset,
          endLine: loggerCall.end_lineno,
          endColumn: loggerCall.col_offset + loggerCall.unparsed.length,
          sourceText: loggerCall.unparsed,
        },
      ],
    });
  }

  const cacheCalls = (parsedPy?.calls || []).filter((c) => CACHE_TTL_CALLS.test(c.func));
  const envelopeAssign = Object.entries(parsedPy?.assignments || {}).find(([n]) =>
    KMS_ASSIGN_NAMES.test(n)
  );
  const usesTenantEnvelope =
    (envelopeAssign?.[1].value === true) ||
    /USE_TENANT_KMS_ENVELOPE\s*=\s*True/.test(file.content);

  if (cacheCalls.length > 0 || ttlConstPresent) {
    const ttlLine = ttlAssign?.lineno ?? cacheCalls[0]?.lineno ?? 1;
    const ownerClass = (parsedPy?.classes || []).find(
      (c) => c.lineno <= ttlLine && c.end_lineno >= ttlLine
    );
    const cacheFn =
      (parsedPy?.functions || []).find((f) => /cache|session|setex|ttl|purge|retain/i.test(f.name)) ||
      (parsedPy?.functions || [])[0];
    const editAnchors: SourceEditAnchor[] = [];
    if (ttlAssign) {
      editAnchors.push(
        anchorForAssignment(
          'RETENTION_TTL_LITERAL',
          ttlAssign.name,
          {
            value: ttlAssign.value,
            lineno: ttlAssign.lineno,
            end_lineno: ttlAssign.end_lineno,
            col_offset: ttlAssign.col_offset,
          },
          lines[ttlAssign.lineno - 1] || ''
        )
      );
    }
    if (envelopeAssign) {
      editAnchors.push(
        anchorForAssignment(
          'TENANT_KMS_FLAG',
          envelopeAssign[0],
          envelopeAssign[1],
          lines[envelopeAssign[1].lineno - 1] || ''
        )
      );
    }

    findings.push({
      id: `ast-py-cache-${file.path}-${ttlLine}`,
      filePath: file.path,
      line: ttlLine,
      endLine: Math.min(lines.length, (cacheFn?.end_lineno ?? ttlLine + 24)),
      column: 1,
      language: 'python',
      astNodeKind: ownerClass ? `ClassDef(${ownerClass.name})` : 'Module',
      constructType: cacheCalls.length > 0 || /redis|cache/i.test(file.content)
        ? 'REDIS_CACHE_WORKER'
        : 'DATA_RETENTION_POLICY',
      functionName:
        cacheFn?.name ||
        (ownerClass ? `${ownerClass.name}.cache` : 'cache_ttl'),
      codeSnippet: snippet(lines, Math.max(1, ttlLine - 1), Math.min(lines.length, ttlLine + 22)),
      metadata: {
        retentionTtlHours: ttlHours,
        usesTenantIsolatedKms: usesTenantEnvelope,
      },
      editAnchors,
    });
  }

  return { findings, astNodeCount };
}

interface TsCollected {
  astNodeCount: number;
  constants: Record<
    string,
    { value: string | number | boolean; line: number; column: number; endColumn: number; sourceText: string }
  >;
  functions: Array<{ name: string; startLine: number; endLine: number }>;
}

function collectTypeScriptAst(file: TargetRepoFile): TsCollected {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.ES2022, true);
  let astNodeCount = 0;
  const constants: TsCollected['constants'] = {};
  const functions: TsCollected['functions'] = [];

  function visit(node: ts.Node) {
    astNodeCount++;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const varName = node.name.text;
      const start = sourceFile.getLineAndCharacterOfPosition(node.initializer.getStart());
      const end = sourceFile.getLineAndCharacterOfPosition(node.initializer.getEnd());
      const sourceText = node.initializer.getText(sourceFile);
      if (ts.isNumericLiteral(node.initializer)) {
        constants[varName] = {
          value: parseFloat(node.initializer.text),
          line: start.line + 1,
          column: start.character,
          endColumn: end.character,
          sourceText,
        };
      } else if (ts.isStringLiteral(node.initializer)) {
        constants[varName] = {
          value: node.initializer.text,
          line: start.line + 1,
          column: start.character,
          endColumn: end.character,
          sourceText,
        };
      } else if (node.initializer.kind === ts.SyntaxKind.TrueKeyword) {
        constants[varName] = {
          value: true,
          line: start.line + 1,
          column: start.character,
          endColumn: end.character,
          sourceText,
        };
      } else if (node.initializer.kind === ts.SyntaxKind.FalseKeyword) {
        constants[varName] = {
          value: false,
          line: start.line + 1,
          column: start.character,
          endColumn: end.character,
          sourceText,
        };
      }
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      const start = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
      functions.push({ name: node.name.text, startLine: start, endLine: end });
    } else if (
      (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) &&
      ts.isVariableDeclaration(node.parent) &&
      ts.isIdentifier(node.parent.name)
    ) {
      const start = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
      functions.push({
        name: node.parent.name.text,
        startLine: start,
        endLine: end,
      });
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return { astNodeCount, constants, functions };
}

function pickConstant(
  constants: TsCollected['constants'],
  predicate: (name: string) => boolean
): { name: string; meta: TsCollected['constants'][string] } | undefined {
  const hit = Object.entries(constants).find(([name]) => predicate(name));
  return hit ? { name: hit[0], meta: hit[1] } : undefined;
}

/**
 * Uses the real TypeScript Compiler API (`ts.createSourceFile`) to parse ANY `.ts` file
 * and walk `ts.Node` trees for confidence gates, human-oversight flags, audit logs,
 * and cross-border region strings.
 */
export function parseTypeScriptAstFile(file: TargetRepoFile): {
  findings: ASTFindingNode[];
  astNodeCount: number;
} {
  const collected = collectTypeScriptAst(file);
  const { astNodeCount, constants, functions } = collected;
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = [];

  const confidence = pickConstant(constants, (n) => CONFIDENCE_NAMES.test(n));
  const humanGate = pickConstant(constants, (n) => HUMAN_GATE_NAMES.test(n));
  const auditLog = pickConstant(constants, (n) => AUDIT_LOG_NAMES.test(n));
  const region = pickConstant(
    constants,
    (n) => REGION_NAMES.test(n) && typeof constants[n].value === 'string'
  );

  const aiFn = functions.find((f) =>
    /evaluat|triage|infer|predict|score|decision|credit|risk/i.test(f.name)
  );
  const egressFn = functions.find((f) =>
    /replicat|sync|transfer|egress|export|region/i.test(f.name)
  );

  const hasAiSignals =
    confidence != null ||
    humanGate != null ||
    auditLog != null ||
    /MIN_CONFIDENCE|HUMAN_OVERSIGHT|WRITE_IMMUTABLE_AUDIT/.test(file.content);

  if (hasAiSignals) {
    const minConfidence =
      typeof confidence?.meta.value === 'number' ? (confidence.meta.value as number) : 0.68;
    const hasHumanGate = humanGate?.meta.value === true;
    const writesAudit = auditLog?.meta.value === true;
    const startLine = confidence?.meta.line ?? aiFn?.startLine ?? 1;
    const endLine = aiFn?.endLine ?? Math.min(lines.length, startLine + 24);
    const editAnchors: SourceEditAnchor[] = [];
    if (confidence) {
      editAnchors.push({
        role: 'AI_CONFIDENCE_THRESHOLD',
        symbol: confidence.name,
        line: confidence.meta.line,
        column: confidence.meta.column,
        endLine: confidence.meta.line,
        endColumn: confidence.meta.endColumn,
        sourceText: confidence.meta.sourceText,
        numericValue: minConfidence,
      });
    }
    if (humanGate) {
      editAnchors.push({
        role: 'HUMAN_OVERSIGHT_FLAG',
        symbol: humanGate.name,
        line: humanGate.meta.line,
        column: humanGate.meta.column,
        endLine: humanGate.meta.line,
        endColumn: humanGate.meta.endColumn,
        sourceText: humanGate.meta.sourceText,
        booleanValue: hasHumanGate,
      });
    }
    if (auditLog) {
      editAnchors.push({
        role: 'AUDIT_LOG_FLAG',
        symbol: auditLog.name,
        line: auditLog.meta.line,
        column: auditLog.meta.column,
        endLine: auditLog.meta.line,
        endColumn: auditLog.meta.endColumn,
        sourceText: auditLog.meta.sourceText,
        booleanValue: writesAudit,
      });
    }

    findings.push({
      id: `ast-ts-ai-${file.path}-${startLine}`,
      filePath: file.path,
      line: startLine,
      endLine,
      column: 1,
      language: 'typescript',
      astNodeKind: `FunctionDeclaration(${aiFn?.name || 'module'})`,
      constructType: 'LLM_INFERENCE_CALL',
      functionName: aiFn?.name || confidence?.name || 'ai_inference',
      codeSnippet: snippet(lines, Math.max(1, startLine - 1), endLine),
      metadata: {
        aiConfidenceThreshold: minConfidence,
        hasHumanOversightGate: hasHumanGate,
        writesAuditLog: writesAudit,
      },
      editAnchors,
    });
  }

  const hasRegionSignals =
    region != null ||
    /REPLICA_TARGET_REGION|us-east-1|eu-central-1|eu-west-1/.test(file.content);

  if (hasRegionSignals && region) {
    const targetRegion =
      typeof region.meta.value === 'string' ? (region.meta.value as string) : 'us-east-1';
    const startLine = region.meta.line ?? egressFn?.startLine ?? 1;
    const endLine = egressFn?.endLine ?? Math.min(lines.length, startLine + 16);
    const sovereign = pickConstant(constants, (n) =>
      /sovereign|enforce_eu|boundary/i.test(n)
    );

    findings.push({
      id: `ast-ts-egress-${file.path}-${startLine}`,
      filePath: file.path,
      line: startLine,
      endLine,
      column: 1,
      language: 'typescript',
      astNodeKind: `FunctionDeclaration(${egressFn?.name || 'module'})`,
      constructType: 'CROSS_BORDER_EGRESS',
      functionName: egressFn?.name || region.name,
      codeSnippet: snippet(lines, Math.max(1, startLine - 1), endLine),
      metadata: {
        egressRegion: targetRegion,
        sovereignGuardEnabled: sovereign?.meta.value === true,
      },
      editAnchors: [
        {
          role: 'EGRESS_REGION_LITERAL',
          symbol: region.name,
          line: region.meta.line,
          column: region.meta.column,
          endLine: region.meta.line,
          endColumn: region.meta.endColumn,
          sourceText: region.meta.sourceText,
          stringValue: targetRegion,
        },
        ...(sovereign
          ? [
              {
                role: 'SOVEREIGN_BOUNDARY_FLAG' as const,
                symbol: sovereign.name,
                line: sovereign.meta.line,
                column: sovereign.meta.column,
                endLine: sovereign.meta.line,
                endColumn: sovereign.meta.endColumn,
                sourceText: sovereign.meta.sourceText,
                booleanValue: sovereign.meta.value === true,
              },
            ]
          : []),
      ],
    });
  } else if (hasRegionSignals && !region) {
    const regionMatch = file.content.match(/["']((?:us|eu|ap)-[a-z]+-\d+)["']/);
    const targetRegion = regionMatch?.[1] || 'us-east-1';
    const line = file.content.split('\n').findIndex((l) => l.includes(targetRegion)) + 1;
    findings.push({
      id: `ast-ts-egress-${file.path}-${line || 1}`,
      filePath: file.path,
      line: line || 1,
      endLine: (egressFn?.endLine ?? line) || 1,
      column: 1,
      language: 'typescript',
      astNodeKind: `FunctionDeclaration(${egressFn?.name || 'module'})`,
      constructType: 'CROSS_BORDER_EGRESS',
      functionName: egressFn?.name || 'cross_border_sync',
      codeSnippet: snippet(lines, Math.max(1, line - 1), egressFn?.endLine || line + 8),
      metadata: { egressRegion: targetRegion },
    });
  }

  return { findings, astNodeCount };
}

export function analyzeFullRepository(files: TargetRepoFile[]): {
  sqlTables: SQLTableSchema[];
  astFindings: ASTFindingNode[];
  enrichedFiles: TargetRepoFile[];
} {
  const sqlTables: SQLTableSchema[] = [];
  const astFindings: ASTFindingNode[] = [];
  const enrichedFiles: TargetRepoFile[] = [];

  for (const file of files) {
    if (file.language === 'sql') {
      const res = parseSqlSchemaFile(file);
      sqlTables.push(...res.tables);
      astFindings.push(...res.findings);
      enrichedFiles.push({ ...file, astNodeCount: res.astNodeCount });
    } else if (file.language === 'python') {
      const res = parsePythonAstFile(file);
      astFindings.push(...res.findings);
      enrichedFiles.push({ ...file, astNodeCount: res.astNodeCount });
    } else if (file.language === 'typescript') {
      const res = parseTypeScriptAstFile(file);
      astFindings.push(...res.findings);
      enrichedFiles.push({ ...file, astNodeCount: res.astNodeCount });
    } else {
      enrichedFiles.push(file);
    }
  }

  return { sqlTables, astFindings, enrichedFiles };
}
