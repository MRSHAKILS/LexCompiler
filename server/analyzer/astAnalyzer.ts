import { execFileSync, spawn } from 'node:child_process';
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
import { resolvePython } from '../util/python.js';
import { collectGovernanceFindings } from './governanceFacts.js';

/** Identifier is PII when its last `_`-separated token(s) name a personal-data field. */
const PII_IDENTIFIER =
  /(^|_)(ssn|email|phone|dob|date_of_birth|birthdate|passport|national_id|tax_id|credit_card|card_number|full_name|diagnosis_code|diagnosis)$/i;
const PII_COLUMN_PREFIX = /^(patient_|biometric_)/i;
const TTL_NAMES = /(ttl|retention|expir|purge)/i;
const KMS_FLAG_NAMES = /(tenant.*kms|kms.*envelope|tenant_isolated_kms)/i;
const CIPHER_NAMES = /(encryption_cipher|^cipher$|kms_cipher)/i;
const CONFIDENCE_NAMES = /(confidence|threshold|auto_approval|min_score|min_conf)/i;
const HUMAN_GATE_NAMES = /(human_oversight|human_in_the_loop|hitl|manual_approval|human_review|enforce_human)/i;
const AUDIT_LOG_NAMES = /(audit_log|immutable_audit|write_audit|audit_trail)/i;
const REGION_NAMES = /(region|replica_target|egress|data_residency|destination)/i;
const SOVEREIGN_NAMES = /(sovereign|enforce_eu|boundary)/i;
const CLOUD_REGION = /^(us|eu|ap|ca|sa|me|af|il|mx)-(north|south|east|west|central|northeast|northwest|southeast|southwest)-\d$/;

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function snippet(lines: string[], startLine: number, endLine: number): string {
  return lines.slice(Math.max(0, startLine - 1), Math.max(startLine, endLine)).join('\n');
}

export function isPiiIdentifier(name: string): boolean {
  return PII_IDENTIFIER.test(name);
}

function isInferredPiiColumn(colName: string): boolean {
  if (/_id$/i.test(colName) && !/^(national_id|tax_id)$/i.test(colName)) return false;
  return PII_IDENTIFIER.test(colName) || PII_COLUMN_PREFIX.test(colName);
}

/**
 * Hours represented by one unit of a TTL identifier, from its name. Returns
 * `assumed: true` when the identifier carries no unit (hours are assumed).
 */
export function ttlUnitFromName(name: string): { hoursPerUnit: number; unit: string; assumed: boolean } {
  if (/(^|_)(ms|millis|milliseconds)($|_)/i.test(name)) return { hoursPerUnit: 1 / 3_600_000, unit: 'milliseconds', assumed: false };
  if (/(^|_)(s|sec|secs|seconds?)($|_)/i.test(name)) return { hoursPerUnit: 1 / 3600, unit: 'seconds', assumed: false };
  if (/(^|_)(m|min|mins|minutes?)($|_)/i.test(name)) return { hoursPerUnit: 1 / 60, unit: 'minutes', assumed: false };
  if (/(^|_)(h|hr|hrs|hours?)($|_)/i.test(name)) return { hoursPerUnit: 1, unit: 'hours', assumed: false };
  if (/(^|_)(d|days?)($|_)/i.test(name)) return { hoursPerUnit: 24, unit: 'days', assumed: false };
  if (/(^|_)(w|wk|wks|weeks?)($|_)/i.test(name)) return { hoursPerUnit: 168, unit: 'weeks', assumed: false };
  return { hoursPerUnit: 1, unit: 'hours', assumed: true };
}

function roundHours(h: number): number {
  return Math.round(h * 1000) / 1000;
}

// ============================================================================
// SQL DDL
// ============================================================================

interface SqlToken {
  kind: 'word' | 'quoted' | 'string' | 'number' | 'punct' | 'comment';
  text: string;
  /** Unquoted identifier text for `word` / `quoted`. */
  value: string;
  line: number;
  column: number;
  endColumn: number;
}

/** Tokenizes SQL keeping comments (they carry @pii/@encrypted annotations). */
export function tokenizeSql(content: string): { tokens: SqlToken[]; error?: string } {
  const tokens: SqlToken[] = [];
  const lines = content.split('\n');
  let line = 1;
  let col = 0;
  let i = 0;
  const advance = (n: number) => {
    for (let k = 0; k < n; k++) {
      if (content[i] === '\n') {
        line++;
        col = 0;
      } else {
        col++;
      }
      i++;
    }
  };
  while (i < content.length) {
    const ch = content[i];
    if (/\s/.test(ch)) {
      advance(1);
      continue;
    }
    const startLine = line;
    const startCol = col;
    if (ch === '-' && content[i + 1] === '-') {
      const end = content.indexOf('\n', i);
      const text = content.slice(i, end === -1 ? content.length : end);
      tokens.push({ kind: 'comment', text, value: text, line: startLine, column: startCol, endColumn: startCol + text.length });
      advance(text.length);
      continue;
    }
    if (ch === '/' && content[i + 1] === '*') {
      const end = content.indexOf('*/', i + 2);
      if (end === -1) return { tokens, error: `Unterminated block comment at line ${startLine}` };
      const text = content.slice(i, end + 2);
      tokens.push({ kind: 'comment', text, value: text, line: startLine, column: startCol, endColumn: startCol + text.length });
      advance(text.length);
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < content.length) {
        if (content[j] === ch && content[j + 1] === ch) {
          j += 2;
          continue;
        }
        if (content[j] === ch) break;
        j++;
      }
      if (j >= content.length) {
        return { tokens, error: `Unterminated ${ch === "'" ? 'string' : 'quoted identifier'} at line ${startLine}` };
      }
      const text = content.slice(i, j + 1);
      tokens.push({
        kind: ch === "'" ? 'string' : 'quoted',
        text,
        value: text.slice(1, -1).replace(ch === "'" ? /''/g : /""/g, ch),
        line: startLine,
        column: startCol,
        endColumn: startCol + text.length,
      });
      advance(text.length);
      continue;
    }
    const num = content.slice(i).match(/^\d+(?:\.\d+)?/);
    if (num) {
      tokens.push({ kind: 'number', text: num[0], value: num[0], line: startLine, column: startCol, endColumn: startCol + num[0].length });
      advance(num[0].length);
      continue;
    }
    const word = content.slice(i).match(/^[A-Za-z_][A-Za-z0-9_$]*/);
    if (word) {
      tokens.push({ kind: 'word', text: word[0], value: word[0], line: startLine, column: startCol, endColumn: startCol + word[0].length });
      advance(word[0].length);
      continue;
    }
    tokens.push({ kind: 'punct', text: ch, value: ch, line: startLine, column: startCol, endColumn: startCol + 1 });
    advance(1);
  }
  void lines;
  return { tokens };
}

const COLUMN_CONSTRAINT_KEYWORDS = new Set([
  'NOT',
  'NULL',
  'DEFAULT',
  'PRIMARY',
  'REFERENCES',
  'UNIQUE',
  'CHECK',
  'CONSTRAINT',
  'GENERATED',
  'COLLATE',
]);

function upper(t: SqlToken | undefined): string {
  return t && t.kind === 'word' ? t.value.toUpperCase() : '';
}

function isIdent(t: SqlToken | undefined): boolean {
  return !!t && (t.kind === 'word' || t.kind === 'quoted');
}

/** Splits tokens (excluding comments) into top-level items separated by commas. */
function splitTopLevel(tokens: SqlToken[]): SqlToken[][] {
  const items: SqlToken[][] = [];
  let depth = 0;
  let current: SqlToken[] = [];
  for (const t of tokens) {
    if (t.kind === 'punct' && t.text === '(') depth++;
    if (t.kind === 'punct' && t.text === ')') depth--;
    if (t.kind === 'punct' && t.text === ',' && depth === 0) {
      items.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.length > 0) items.push(current);
  return items;
}

interface ParsedForeignKey {
  childColumn: string;
  parentTable: string;
  parentColumn: string;
  onDelete: string | null;
  line: number;
  /** Position just after the REFERENCES … (col) group, or the ON DELETE action span. */
  anchor: { line: number; column: number; endColumn: number; sourceText: string };
}

interface ParsedTable {
  table: SQLTableSchema;
  foreignKeys: ParsedForeignKey[];
  retentionAnchor?: { line: number; column: number; endColumn: number; sourceText: string; hoursPerUnit: number };
  retentionAnnotationAnchors: Array<{ line: number; column: number; endColumn: number; sourceText: string; value: number }>;
}

function parseReferences(
  tokens: SqlToken[],
  start: number
): { parentTable: string; parentColumn: string; onDelete: string | null; end: number; anchor: ParsedForeignKey['anchor'] } | null {
  // tokens[start] is REFERENCES
  let k = start + 1;
  if (!isIdent(tokens[k])) return null;
  let parentTable = tokens[k].value;
  if (tokens[k + 1]?.text === '.' && isIdent(tokens[k + 2])) {
    parentTable = tokens[k + 2].value;
    k += 2;
  }
  k++;
  let parentColumn = '';
  if (tokens[k]?.text === '(') {
    parentColumn = tokens[k + 1]?.value || '';
    while (k < tokens.length && tokens[k].text !== ')') k++;
  }
  const closing = tokens[k]?.text === ')' ? tokens[k] : tokens[k - 1];
  let onDelete: string | null = null;
  let anchor: ParsedForeignKey['anchor'] = {
    line: closing.line,
    column: closing.endColumn,
    endColumn: closing.endColumn,
    sourceText: '',
  };
  for (let m = k + 1; m < tokens.length - 1; m++) {
    if (upper(tokens[m]) === 'ON' && upper(tokens[m + 1]) === 'DELETE') {
      const actionTokens: SqlToken[] = [];
      let n = m + 2;
      while (n < tokens.length && ['CASCADE', 'RESTRICT', 'SET', 'NULL', 'DEFAULT', 'NO', 'ACTION'].includes(upper(tokens[n]))) {
        actionTokens.push(tokens[n]);
        n++;
      }
      onDelete = actionTokens.map((t) => t.value.toUpperCase()).join(' ') || null;
      if (actionTokens.length > 0 && tokens[m].line === actionTokens[actionTokens.length - 1].line) {
        anchor = {
          line: tokens[m].line,
          column: tokens[m].column,
          endColumn: actionTokens[actionTokens.length - 1].endColumn,
          sourceText: `ON DELETE ${actionTokens.map((t) => t.text).join(' ')}`,
        };
      }
      break;
    }
  }
  return { parentTable, parentColumn, onDelete, end: k, anchor };
}

function annotationsFrom(comments: SqlToken[]): {
  piiClass?: SQLColumnNode['piiClassification'];
  encryptedAlg?: string;
  tenantIsolated: boolean;
  retention?: { value: number; token: SqlToken; index: number; match: string };
} {
  const out: ReturnType<typeof annotationsFrom> = { tenantIsolated: false };
  for (const c of comments) {
    const pii = c.text.match(/@pii\(([A-Z_]+)\)/i);
    if (pii) out.piiClass = pii[1].toUpperCase() as SQLColumnNode['piiClassification'];
    const enc = c.text.match(/@encrypted\(([A-Za-z0-9_-]+)\)/i);
    if (enc) out.encryptedAlg = enc[1];
    if (/@tenant_isolated_kms/i.test(c.text)) out.tenantIsolated = true;
    const ret = c.text.match(/@retention_hours\((\d+)\)/i);
    if (ret && ret.index != null) out.retention = { value: parseInt(ret[1], 10), token: c, index: ret.index, match: ret[0] };
  }
  return out;
}

function newTable(name: string, filePath: string, line: number): SQLTableSchema {
  return {
    tableName: name,
    filePath,
    startLine: line,
    endLine: line,
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
}

function addColumn(parsed: ParsedTable, item: SqlToken[], comments: SqlToken[]): void {
  const table = parsed.table;
  const nameTok = item[0];
  const colName = nameTok.value;
  const typeTokens: SqlToken[] = [];
  let k = 1;
  while (k < item.length && !COLUMN_CONSTRAINT_KEYWORDS.has(upper(item[k]))) {
    typeTokens.push(item[k]);
    k++;
  }
  const dataType =
    typeTokens
      .map((t) => t.text)
      .join(' ')
      .replace(/\s*\(\s*/g, '(')
      .replace(/\s*\)/g, ')')
      .replace(/\s*,\s*/g, ', ') || 'UNKNOWN';
  let isPrimaryKey = false;
  let notNull = false;
  let defaultTok: SqlToken | undefined;
  let fk: ParsedForeignKey | undefined;
  for (; k < item.length; k++) {
    const u = upper(item[k]);
    if (u === 'PRIMARY' && upper(item[k + 1]) === 'KEY') isPrimaryKey = true;
    if (u === 'NOT' && upper(item[k + 1]) === 'NULL') notNull = true;
    if (u === 'DEFAULT') defaultTok = item[k + 1];
    if (u === 'REFERENCES') {
      const ref = parseReferences(item, k);
      if (ref) {
        fk = {
          childColumn: colName,
          parentTable: ref.parentTable,
          parentColumn: ref.parentColumn,
          onDelete: ref.onDelete,
          line: item[k].line,
          anchor: ref.anchor,
        };
        k = ref.end;
      }
    }
  }

  const ann = annotationsFrom(comments);
  const inferredPii = isInferredPiiColumn(colName);
  const isPII = Boolean(ann.piiClass) || inferredPii;
  // Application-level ciphertext columns (e.g. `ssn_encrypted BYTEA`) count as encrypted at rest.
  const ciphertextColumn = /(_enc|_encrypted|_ciphertext)$/i.test(colName) && /BYTEA|BLOB|BINARY/i.test(dataType);
  const encryptedAtRest = Boolean(ann.encryptedAlg) || ciphertextColumn;
  const hasTenantKeyCol = /tenant_kms_key_id/i.test(colName) || ann.tenantIsolated;
  if (hasTenantKeyCol) table.hasTenantKeyIsolation = true;

  const retentionCol = colName.match(/^(?:.*_)?retention(?:_ttl)?_(hours|days)$/i);
  if (retentionCol && defaultTok?.kind === 'number') {
    const hoursPerUnit = retentionCol[1].toLowerCase() === 'days' ? 24 : 1;
    const hrs = parseFloat(defaultTok.value) * hoursPerUnit;
    table.retentionHoursConfigured = hrs;
    table.retentionDaysConfigured = Math.round((hrs / 24) * 10) / 10;
    parsed.retentionAnchor = {
      line: defaultTok.line,
      column: defaultTok.column,
      endColumn: defaultTok.endColumn,
      sourceText: defaultTok.text,
      hoursPerUnit,
    };
  }
  if (ann.retention) {
    if (table.retentionHoursConfigured == null) {
      table.retentionHoursConfigured = ann.retention.value;
      table.retentionDaysConfigured = Math.round((ann.retention.value / 24) * 10) / 10;
    }
    parsed.retentionAnnotationAnchors.push({
      line: ann.retention.token.line,
      column: ann.retention.token.column + ann.retention.index,
      endColumn: ann.retention.token.column + ann.retention.index + ann.retention.match.length,
      sourceText: ann.retention.match,
      value: ann.retention.value,
    });
  }

  if (isPII) {
    table.containsPII = true;
    if (encryptedAtRest) table.encryptedColumnsCount++;
    else table.unencryptedPiiColumns.push(colName);
  }

  table.columns.push({
    name: colName,
    dataType,
    isPrimaryKey,
    isNullable: !notNull && !isPrimaryKey,
    isPII,
    piiClassification: ann.piiClass || (isPII ? 'DIRECT_IDENTIFIER' : 'NONE'),
    encryptedAtRest,
    encryptionAlgorithm: ann.encryptedAlg || (ciphertextColumn ? 'APPLICATION_CIPHERTEXT' : undefined),
    hasTenantKeyIsolation: hasTenantKeyCol,
    foreignKeyReference: fk
      ? { table: fk.parentTable, column: fk.parentColumn, onDeleteCascade: fk.onDelete === 'CASCADE', implicit: fk.onDelete == null }
      : undefined,
    piiInference: ann.piiClass ? 'ANNOTATION' : inferredPii ? 'NAME_PATTERN' : 'NONE',
    line: nameTok.line,
  });
  if (fk) parsed.foreignKeys.push(fk);
}

function addTableConstraint(parsed: ParsedTable, item: SqlToken[]): void {
  let k = 0;
  if (upper(item[0]) === 'CONSTRAINT') k = 2;
  const u = upper(item[k]);
  if (u === 'PRIMARY' && upper(item[k + 1]) === 'KEY') {
    const names = item.slice(k + 2).filter(isIdent).map((t) => t.value);
    for (const c of parsed.table.columns) {
      if (names.includes(c.name)) {
        c.isPrimaryKey = true;
        c.isNullable = false;
      }
    }
    return;
  }
  if (u === 'FOREIGN' && upper(item[k + 1]) === 'KEY') {
    const open = item.findIndex((t, idx) => idx > k && t.text === '(');
    const childColumn = item[open + 1]?.value || '';
    const refIdx = item.findIndex((t) => upper(t) === 'REFERENCES');
    const ref = refIdx >= 0 ? parseReferences(item, refIdx) : null;
    if (ref) {
      parsed.foreignKeys.push({
        childColumn,
        parentTable: ref.parentTable,
        parentColumn: ref.parentColumn,
        onDelete: ref.onDelete,
        line: item[refIdx].line,
        anchor: ref.anchor,
      });
      const col = parsed.table.columns.find((c) => c.name === childColumn);
      if (col) {
        col.foreignKeyReference = {
          table: ref.parentTable,
          column: ref.parentColumn,
          onDeleteCascade: ref.onDelete === 'CASCADE',
          implicit: ref.onDelete == null,
        };
      }
    }
  }
}

/**
 * Parses SQL DDL with a tokenizer (not line regexes): CREATE TABLE bodies split at
 * top-level commas, multi-line columns, table constraints, quoted identifiers,
 * schema-qualified names, and ALTER TABLE … ADD COLUMN / ADD FOREIGN KEY.
 * PII/encryption metadata comes from `-- @pii(...)` / `-- @encrypted(...)` comments
 * attached to a column, ciphertext column conventions, or PII name patterns.
 */
export function parseSqlSchemaFile(file: TargetRepoFile): {
  tables: SQLTableSchema[];
  findings: ASTFindingNode[];
  astNodeCount: number;
  syntaxError?: string;
} {
  const lines = file.content.split('\n');
  const { tokens, error } = tokenizeSql(file.content);
  const parsedTables = new Map<string, ParsedTable>();
  const order: ParsedTable[] = [];

  // Split into statements at top-level semicolons.
  const statements: SqlToken[][] = [];
  let current: SqlToken[] = [];
  let depth = 0;
  for (const t of tokens) {
    if (t.kind === 'punct' && t.text === '(') depth++;
    if (t.kind === 'punct' && t.text === ')') depth--;
    if (t.kind === 'punct' && t.text === ';' && depth === 0) {
      statements.push(current);
      current = [];
      continue;
    }
    current.push(t);
  }
  if (current.some((t) => t.kind !== 'comment')) statements.push(current);
  const syntaxError = error || (depth !== 0 ? 'Unbalanced parentheses in SQL file' : undefined);

  const commentsByLine = new Map<number, SqlToken[]>();
  for (const t of tokens) {
    if (t.kind === 'comment') {
      const list = commentsByLine.get(t.line) || [];
      list.push(t);
      commentsByLine.set(t.line, list);
    }
  }

  const tableName = (code: SqlToken[], at: number): { name: string; next: number } | null => {
    let k = at;
    if (!isIdent(code[k])) return null;
    let name = code[k].value;
    if (code[k + 1]?.text === '.' && isIdent(code[k + 2])) {
      name = code[k + 2].value;
      k += 2;
    }
    return { name, next: k + 1 };
  };

  for (const stmt of statements) {
    const code = stmt.filter((t) => t.kind !== 'comment');
    if (code.length === 0) continue;
    const first = upper(code[0]);

    if (first === 'CREATE') {
      let k = 1;
      while (['TEMP', 'TEMPORARY', 'UNLOGGED', 'GLOBAL', 'LOCAL'].includes(upper(code[k]))) k++;
      if (upper(code[k]) !== 'TABLE') continue;
      k++;
      if (upper(code[k]) === 'IF' && upper(code[k + 1]) === 'NOT' && upper(code[k + 2]) === 'EXISTS') k += 3;
      const tn = tableName(code, k);
      if (!tn || code[tn.next]?.text !== '(') continue;
      const open = tn.next;
      let close = open;
      let d = 0;
      for (let m = open; m < code.length; m++) {
        if (code[m].text === '(') d++;
        if (code[m].text === ')') d--;
        if (d === 0) {
          close = m;
          break;
        }
      }
      const parsed: ParsedTable = {
        table: newTable(tn.name, file.path, code[0].line),
        foreignKeys: [],
        retentionAnnotationAnchors: [],
      };
      parsed.table.endLine = code[close]?.line ?? code[code.length - 1].line;
      const body = code.slice(open + 1, close);
      const items = splitTopLevel(body);
      let prevItemEndLine = code[open].line;
      for (const item of items) {
        if (item.length === 0) continue;
        const firstLine = item[0].line;
        const lastLine = item[item.length - 1].line;
        // Comments on the item's lines (including trailing ones after the comma) and
        // standalone comment lines between the previous item and this one.
        const comments: SqlToken[] = [];
        for (let ln = prevItemEndLine + 1; ln <= lastLine; ln++) {
          comments.push(...(commentsByLine.get(ln) || []));
        }
        if (firstLine === prevItemEndLine) {
          // Item starts on the previous item's line: only take comments after its own tokens.
          comments.push(
            ...(commentsByLine.get(firstLine) || []).filter((c) => c.column > item[0].column)
          );
        }
        prevItemEndLine = lastLine;
        const lead = upper(item[0]);
        if (['CONSTRAINT', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'CHECK', 'EXCLUDE', 'LIKE'].includes(lead)) {
          addTableConstraint(parsed, item);
        } else if (isIdent(item[0])) {
          addColumn(parsed, item, comments);
        }
      }
      parsedTables.set(tn.name.toLowerCase(), parsed);
      order.push(parsed);
      continue;
    }

    if (first === 'ALTER' && upper(code[1]) === 'TABLE') {
      let k = 2;
      if (upper(code[k]) === 'ONLY') k++;
      if (upper(code[k]) === 'IF' && upper(code[k + 1]) === 'EXISTS') k += 2;
      const tn = tableName(code, k);
      if (!tn) continue;
      const parsed = parsedTables.get(tn.name.toLowerCase());
      if (!parsed) continue;
      for (const action of splitTopLevel(code.slice(tn.next))) {
        if (upper(action[0]) !== 'ADD') continue;
        let rest = action.slice(1);
        if (upper(rest[0]) === 'COLUMN') rest = rest.slice(1);
        if (upper(rest[0]) === 'IF' && upper(rest[1]) === 'NOT' && upper(rest[2]) === 'EXISTS') rest = rest.slice(3);
        if (['CONSTRAINT', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'CHECK'].includes(upper(rest[0]))) {
          addTableConstraint(parsed, rest);
        } else if (isIdent(rest[0])) {
          const comments = (commentsByLine.get(rest[rest.length - 1].line) || []).slice();
          addColumn(parsed, rest, comments);
        }
      }
      parsed.table.endLine = Math.max(parsed.table.endLine, code[code.length - 1].line);
    }
  }

  // Resolve foreign keys: record dependents on the parent and cascade flags.
  for (const child of order) {
    for (const fk of child.foreignKeys) {
      const parent = parsedTables.get(fk.parentTable.toLowerCase());
      const cascade = fk.onDelete === 'CASCADE';
      const dep: SQLDependentForeignKey = {
        childTable: child.table.tableName,
        childColumn: fk.childColumn,
        filePath: file.path,
        line: fk.line,
        onDeleteCascade: cascade,
        implicit: fk.onDelete == null,
      };
      if (parent) {
        parent.table.dependentForeignKeys = parent.table.dependentForeignKeys || [];
        parent.table.dependentForeignKeys.push(dep);
      }
      if (cascade) child.table.hasErasureCascade = true;
    }
  }
  for (const p of order) {
    const deps = p.table.dependentForeignKeys || [];
    if (deps.length > 0) p.table.hasErasureCascade = deps.every((d) => d.onDeleteCascade);
  }

  const findings: ASTFindingNode[] = [];
  for (const p of order) {
    const t = p.table;
    const editAnchors: SourceEditAnchor[] = [];
    if (p.retentionAnchor) {
      editAnchors.push({
        role: 'RETENTION_TTL_LITERAL',
        symbol: 'retention',
        line: p.retentionAnchor.line,
        column: p.retentionAnchor.column,
        endLine: p.retentionAnchor.line,
        endColumn: p.retentionAnchor.endColumn,
        sourceText: p.retentionAnchor.sourceText,
        numericValue: t.retentionHoursConfigured ?? undefined,
        hoursPerUnit: p.retentionAnchor.hoursPerUnit,
      });
    }
    for (const a of p.retentionAnnotationAnchors) {
      editAnchors.push({
        role: 'RETENTION_ANNOTATION_LITERAL',
        symbol: '@retention_hours',
        line: a.line,
        column: a.column,
        endLine: a.line,
        endColumn: a.endColumn,
        sourceText: a.sourceText,
        numericValue: a.value,
        hoursPerUnit: 1,
      });
    }
    // New columns are inserted before the first column (always followed by a comma-separated item).
    const firstColumn = t.columns[0];
    if (firstColumn) {
      const lineText = lines[firstColumn.line - 1] || '';
      const indent = lineText.match(/^\s*/)?.[0] || '    ';
      editAnchors.push({
        role: 'SQL_COLUMN_INSERTION_POINT',
        symbol: t.tableName,
        line: firstColumn.line,
        column: 0,
        endLine: firstColumn.line,
        endColumn: 0,
        sourceText: '',
        context: { indent },
      });
    }
    for (const col of t.columns) {
      if (col.isPII && !col.encryptedAtRest) {
        const lineText = lines[col.line - 1] || '';
        editAnchors.push({
          role: 'SQL_COLUMN_ENCRYPTION_ANNOTATION',
          symbol: col.name,
          line: col.line,
          column: lineText.length,
          endLine: col.line,
          endColumn: lineText.length,
          sourceText: '',
          context: { hasComment: /--/.test(lineText) ? 'true' : 'false' },
        });
      }
    }
    for (const dep of t.dependentForeignKeys || []) {
      if (dep.onDeleteCascade) continue;
      const child = parsedTables.get(dep.childTable.toLowerCase());
      const fk = child?.foreignKeys.find((f) => f.childColumn === dep.childColumn && f.line === dep.line);
      if (!fk) continue;
      editAnchors.push({
        role: 'SQL_FOREIGN_KEY_ON_DELETE',
        symbol: `${dep.childTable}.${dep.childColumn}`,
        line: fk.anchor.line,
        column: fk.anchor.column,
        endLine: fk.anchor.line,
        endColumn: fk.anchor.endColumn,
        sourceText: fk.anchor.sourceText,
      });
    }

    findings.push({
      id: `ast-sql-${file.path}-${t.tableName}`,
      filePath: file.path,
      line: t.startLine,
      endLine: t.endLine,
      column: 1,
      language: 'sql',
      astNodeKind: 'CreateTableStatement',
      constructType: 'POSTGRES_DDL_TABLE',
      functionName: `CREATE TABLE ${t.tableName}`,
      codeSnippet: snippet(lines, t.startLine, t.endLine),
      metadata: {
        usesTenantIsolatedKms: t.hasTenantKeyIsolation,
        encryptionCipher: t.hasTenantKeyIsolation ? 'AES-256-GCM-TENANT-KMS' : 'AES-256-GCM',
        retentionTtlHours: t.retentionHoursConfigured,
        hasCascadeDelete: t.hasErasureCascade,
        containsPii: t.containsPII,
        encryptsPii: t.unencryptedPiiColumns.length === 0,
      },
      editAnchors,
    });
  }

  return {
    tables: order.map((p) => p.table),
    findings,
    astNodeCount: tokens.filter((t) => t.kind !== 'comment').length,
    syntaxError,
  };
}

// ============================================================================
// Python
// ============================================================================

interface PySpan {
  line: number;
  col: number;
  end_line: number;
  end_col: number;
  text: string;
}

export interface ParsedPythonAst {
  syntax_error?: string;
  node_count: number;
  assignments: Array<{
    name: string;
    value: number | string | boolean | null;
    folded: boolean;
    env_var: string | null;
    span: PySpan | null;
    lineno: number;
    end_lineno: number;
    scope: string;
  }>;
  functions: Array<{
    name: string;
    kind: string;
    lineno: number;
    end_lineno: number;
    args: string[];
    decorators: string[];
    calls?: string[];
    annotations?: Record<string, string>;
    body_line?: number;
    body_col?: number;
  }>;
  classes: Array<{ name: string; lineno: number; end_lineno: number; bases?: string[]; fields?: Array<{ name: string; lineno: number; end_lineno: number }> }>;
  attr_reads?: string[];
  sinks: Array<{
    func: string;
    lineno: number;
    end_lineno: number;
    col: number;
    text: string;
    leaks: Array<PySpan & { field: string }>;
  }>;
  encrypt_calls: Array<{
    func: string;
    kind: 'shared' | 'tenant';
    callee: PySpan;
    call: PySpan;
    tenant_arg: string | null;
  }>;
  cache_calls: Array<{ func: string; lineno: number; ttl_seconds: number | null; ttl_span: PySpan | null; ttl_refs: string[] }>;
}

/**
 * Python-side analysis (run with `python3 -I`): module/class/function assignments with
 * constant folding (`24 * 30`, references to earlier constants, `int(os.getenv(…, 72))`),
 * flow-insensitive PII taint propagation through assignments into logging sinks
 * (sanitizer calls such as redact/mask/hash helpers stop taint), encrypt calls, and cache
 * TTL calls. Columns are converted to UTF-16-safe character offsets.
 */
const PYTHON_AST_SCRIPT = String.raw`
import ast, json, re, sys

src = sys.stdin.read()
try:
    tree = ast.parse(src)
except SyntaxError as e:
    print(json.dumps({"syntax_error": f"{e.msg} (line {e.lineno})"}))
    sys.exit(0)

lines = src.split("\n")
PII = re.compile(r"(^|_)(ssn|email|phone|dob|date_of_birth|birthdate|passport|national_id|tax_id|credit_card|card_number|full_name|diagnosis_code|diagnosis)$", re.I)
SANITIZER = re.compile(r"(redact|mask|hash|sha256|hmac|tokeni[sz]e|anonymi[sz]e|pseudonymi[sz]e)", re.I)
LOG_METHODS = {"info", "warning", "warn", "error", "debug", "exception", "critical", "log", "fatal"}

def ccol(lineno, col):
    if lineno is None or col is None:
        return None
    line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    return len(line.encode("utf-8")[:col].decode("utf-8", errors="ignore"))

def span(n):
    return {
        "line": n.lineno, "col": ccol(n.lineno, n.col_offset),
        "end_line": n.end_lineno, "end_col": ccol(n.end_lineno, n.end_col_offset),
        "text": ast.get_source_segment(src, n) or "",
    }

def dotted(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    elif isinstance(n, ast.Call):
        parts.append(dotted(n.func) + "()")
    return ".".join(reversed(parts))

consts = {}

def fold(n):
    if isinstance(n, ast.Constant) and isinstance(n.value, (int, float, str, bool)):
        return n.value
    if isinstance(n, ast.Name) and n.id in consts:
        return consts[n.id]
    if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
        v = fold(n.operand)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return -v if isinstance(n.op, ast.USub) else v
    if isinstance(n, ast.BinOp):
        l, r = fold(n.left), fold(n.right)
        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (l, r)):
            try:
                if isinstance(n.op, ast.Add): return l + r
                if isinstance(n.op, ast.Sub): return l - r
                if isinstance(n.op, ast.Mult): return l * r
                if isinstance(n.op, ast.Div): return l / r
                if isinstance(n.op, ast.FloorDiv): return l // r
                if isinstance(n.op, ast.Mod): return l % r
                if isinstance(n.op, ast.Pow) and abs(r) <= 16: return l ** r
            except ZeroDivisionError:
                return None
    return None

def env_default(n):
    # int(os.getenv("X", 72)) / float(os.environ.get("X", "72")) / os.getenv("X", "72")
    call = n
    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in ("int", "float") and call.args:
        call = call.args[0]
    if isinstance(call, ast.Call) and dotted(call.func) in ("os.getenv", "os.environ.get", "getenv", "environ.get") and len(call.args) >= 2:
        d = call.args[1]
        v = fold(d)
        if isinstance(v, str):
            try:
                v = float(v) if "." in v else int(v)
            except ValueError:
                return None
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            name = call.args[0].value if isinstance(call.args[0], ast.Constant) else None
            return (v, d, name)
    return None

parents = {}
for node in ast.walk(tree):
    for child in ast.iter_child_nodes(node):
        parents[child] = node

def scope_of(n):
    p = parents.get(n)
    while p is not None:
        if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return p.name
        p = parents.get(p)
    return "<module>"

def enclosing_function(n):
    p = parents.get(n)
    while p is not None:
        if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return p
        p = parents.get(p)
    return None

assignments = []
assign_nodes = sorted(
    [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None],
    key=lambda n: (n.lineno, n.col_offset),
)
for node in assign_nodes:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        env = env_default(node.value)
        if env:
            value, value_node, env_var = env
        else:
            value, value_node, env_var = fold(node.value), node.value, None
        if value is not None and scope_of(node) == "<module>":
            consts[target.id] = value
        assignments.append({
            "name": target.id,
            "value": value,
            "folded": value is not None and not isinstance(value_node, ast.Constant),
            "env_var": env_var,
            "span": span(value_node) if value is not None else None,
            "lineno": node.lineno,
            "end_lineno": node.end_lineno,
            "scope": scope_of(node),
        })

functions, classes = [], []
for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = [a.arg for a in node.args.args + node.args.kwonlyargs]
        decos = [dotted(d.func) if isinstance(d, ast.Call) else dotted(d) for d in node.decorator_list]
        calls = sorted({dotted(c.func) for c in ast.walk(node) if isinstance(c, ast.Call) and dotted(c.func)})
        annotations = {a.arg: dotted(a.annotation) for a in node.args.args + node.args.kwonlyargs if a.annotation is not None and dotted(a.annotation)}
        body = node.body
        first = body[1] if (len(body) > 1 and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str)) else body[0]
        functions.append({"name": node.name, "kind": type(node).__name__, "lineno": node.lineno,
                          "end_lineno": node.end_lineno, "args": args, "decorators": decos,
                          "calls": calls, "annotations": annotations,
                          "body_line": first.lineno, "body_col": ccol(first.lineno, first.col_offset)})
    elif isinstance(node, ast.ClassDef):
        fields = []
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fields.append({"name": stmt.target.id, "lineno": stmt.lineno, "end_lineno": stmt.end_lineno})
        classes.append({"name": node.name, "lineno": node.lineno, "end_lineno": node.end_lineno,
                        "bases": [dotted(b) for b in node.bases if dotted(b)], "fields": fields})

# Attribute / key reads anywhere in the module (data-minimisation: which collected fields are used).
attr_reads = sorted({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)}
                    | {n.slice.value for n in ast.walk(tree) if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str)})

# --- PII taint: seeds are PII-named parameters; propagate through assignments to a fixpoint.
tainted = set()
origin = {}  # tainted name -> PII field it carries
for f in functions:
    for a in f["args"]:
        if PII.search(a):
            tainted.add(a)
            origin[a] = a

def is_sanitizer_call(n):
    return isinstance(n, ast.Call) and bool(SANITIZER.search(dotted(n.func).split(".")[-1] or ""))

def tainted_leaves(expr):
    out = []
    def visit(n):
        if is_sanitizer_call(n):
            return
        if isinstance(n, ast.Attribute) and PII.search(n.attr):
            out.append((n, n.attr)); return
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str) and PII.search(n.slice.value):
            out.append((n, n.slice.value)); return
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in tainted:
            out.append((n, origin.get(n.id, n.id))); return
        for c in ast.iter_child_nodes(n):
            visit(c)
    visit(expr)
    return out

changed = True
while changed:
    changed = False
    for node in assign_nodes:
        leaves = tainted_leaves(node.value)
        if leaves:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id not in tainted:
                    tainted.add(t.id)
                    origin[t.id] = leaves[0][1]
                    changed = True

def is_log_sink(name):
    parts = name.split(".")
    if name in ("print", "pprint", "pprint.pprint"):
        return True
    if len(parts) >= 2 and parts[-1] in LOG_METHODS:
        return any("log" in p.lower() for p in parts[:-1])
    return False

sinks, encrypt_calls, cache_calls = [], [], []
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    name = dotted(node.func)
    last = name.split(".")[-1] if name else ""
    if is_log_sink(name):
        leaks = []
        for arg in list(node.args) + [k.value for k in node.keywords]:
            for leaf, field in tainted_leaves(arg):
                s = span(leaf)
                s["field"] = field
                leaks.append(s)
        sinks.append({"func": name, "lineno": node.lineno, "end_lineno": node.end_lineno,
                      "col": ccol(node.lineno, node.col_offset), "text": ast.get_source_segment(src, node) or "",
                      "leaks": leaks})
    kind = None
    if re.search(r"encrypt_shared|encrypt_aes|encrypt_with_shared|shared_key_encrypt", last, re.I):
        kind = "shared"
    elif re.search(r"tenant_kms|kms_encrypt|encrypt_with_tenant", last, re.I):
        kind = "tenant"
    if kind:
        fn = enclosing_function(node)
        tenant_arg = None
        if fn is not None:
            for a in fn.args.args + fn.args.kwonlyargs:
                if "tenant" in a.arg.lower():
                    tenant_arg = a.arg
                    break
        encrypt_calls.append({"func": name, "kind": kind, "callee": span(node.func), "call": span(node), "tenant_arg": tenant_arg})
    if re.search(r"^(setex|psetex|expire|pexpire|set_ex)$", last) or (last == "set" and any(k.arg in ("ex", "px") for k in node.keywords)):
        ttl_node = None
        scale = 1
        if last in ("setex", "expire", "set_ex") and len(node.args) >= 2:
            ttl_node = node.args[1]
        elif last in ("psetex", "pexpire") and len(node.args) >= 2:
            ttl_node, scale = node.args[1], 0.001
        else:
            for k in node.keywords:
                if k.arg in ("ex", "px"):
                    ttl_node, scale = k.value, (0.001 if k.arg == "px" else 1)
        ttl_val = fold(ttl_node) if ttl_node is not None else None
        refs = sorted({n.id for n in ast.walk(ttl_node) if isinstance(n, ast.Name)}) if ttl_node is not None else []
        cache_calls.append({
            "func": name, "lineno": node.lineno,
            "ttl_seconds": (ttl_val * scale) if isinstance(ttl_val, (int, float)) and not isinstance(ttl_val, bool) else None,
            "ttl_span": span(ttl_node) if (ttl_node is not None and isinstance(ttl_node, ast.Constant)) else None,
            "ttl_refs": refs,
        })

print(json.dumps({
    "node_count": sum(1 for _ in ast.walk(tree)),
    "assignments": assignments,
    "functions": functions,
    "classes": classes,
    "attr_reads": attr_reads,
    "sinks": sinks,
    "encrypt_calls": encrypt_calls,
    "cache_calls": cache_calls,
}))
`;

const pythonAstCache = new Map<string, ParsedPythonAst | null>();

export function parsePythonAstCached(content: string): ParsedPythonAst | null {
  const digest = sha256Hex(content);
  if (pythonAstCache.has(digest)) return pythonAstCache.get(digest) ?? null;
  let parsed: ParsedPythonAst | null = null;
  const python = resolvePython();
  if (!python) return null;
  try {
    const stdout = execFileSync(python.command, [...python.prefixArgs, '-I', '-c', PYTHON_AST_SCRIPT], {
      input: content,
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 8 * 1024 * 1024,
    });
    parsed = JSON.parse(stdout) as ParsedPythonAst;
  } catch {
    parsed = null;
  }
  pythonAstCache.set(digest, parsed);
  if (pythonAstCache.size > 256) {
    const first = pythonAstCache.keys().next().value;
    if (first) pythonAstCache.delete(first);
  }
  return parsed;
}

/** Parses a Python file in a child process without blocking the event loop. */
function parsePythonAstAsync(content: string): Promise<ParsedPythonAst | null> {
  const python = resolvePython();
  if (!python) return Promise.resolve(null);
  return new Promise((resolve) => {
    const child = spawn(python.command, [...python.prefixArgs, '-I', '-c', PYTHON_AST_SCRIPT], {
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true,
    });
    let out = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (out += chunk));
    child.on('error', () => {
      clearTimeout(timer);
      resolve(null);
    });
    child.on('close', () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(out) as ParsedPythonAst);
      } catch {
        resolve(null);
      }
    });
    child.stdin.end(content);
  });
}

/**
 * Parses every uncached Python file concurrently in child processes so the following
 * synchronous analysis is served from the cache instead of blocking the event loop.
 */
export async function primePythonAstCache(files: TargetRepoFile[]): Promise<void> {
  const pending = files.filter((f) => f.language === 'python' && !pythonAstCache.has(sha256Hex(f.content)));
  await Promise.all(
    pending.map(async (f) => {
      const parsed = await parsePythonAstAsync(f.content);
      if (parsed) pythonAstCache.set(sha256Hex(f.content), parsed);
    })
  );
}

function anchorFromSpan(
  role: SourceEditAnchor['role'],
  symbol: string,
  s: PySpan,
  extra: Partial<SourceEditAnchor> = {}
): SourceEditAnchor {
  return {
    role,
    symbol,
    line: s.line,
    column: s.col,
    endLine: s.end_line,
    endColumn: s.end_col,
    sourceText: s.text,
    ...extra,
  };
}

/**
 * Analyzes any `.py` file through Python's own `ast` module (see PYTHON_AST_SCRIPT).
 * Emits one finding per PII-handling endpoint/function, per leaking log call, and per
 * retention constant or literal cache TTL, each with exact edit anchors.
 */
export function parsePythonAstFile(file: TargetRepoFile): {
  findings: ASTFindingNode[];
  astNodeCount: number;
  syntaxError?: string;
} {
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = [];
  const py = parsePythonAstCached(file.content);
  if (!py) {
    return { findings, astNodeCount: 0, syntaxError: 'python3 is unavailable or the analyzer failed' };
  }
  if (py.syntax_error) {
    return { findings, astNodeCount: 0, syntaxError: py.syntax_error };
  }

  const boolAssign = (re: RegExp) => py.assignments.filter((a) => re.test(a.name) && typeof a.value === 'boolean');
  const kmsFlags = boolAssign(KMS_FLAG_NAMES);
  const sharedCalls = py.encrypt_calls.filter((c) => c.kind === 'shared');
  const tenantCalls = py.encrypt_calls.filter((c) => c.kind === 'tenant');
  const kmsFlagOn = kmsFlags.some((a) => a.value === true);
  const usesTenantKms = (kmsFlagOn || tenantCalls.length > 0) && sharedCalls.length === 0;
  const cipherAssign = py.assignments.find((a) => CIPHER_NAMES.test(a.name) && typeof a.value === 'string');

  const leakingSinks = py.sinks.filter((s) => s.leaks.length > 0);
  const leakedFields = [...new Set(leakingSinks.flatMap((s) => s.leaks.map((l) => l.field.toLowerCase())))];
  const logsPlaintextPii = leakingSinks.length > 0;

  const routeFns = py.functions.filter((f) =>
    f.decorators.some((d) => /\b(app|router|api|bp|blueprint)\.(post|put|patch|get|delete|route)$/i.test(d))
  );
  const piiFns = py.functions.filter((f) => f.args.some((a) => isPiiIdentifier(a) || /payload|patient|pii/i.test(a)));
  const primaryFn = routeFns[0] || piiFns[0];
  const isCacheFile = py.cache_calls.length > 0 || /\bredis\b|\bcache\b/i.test(file.content);
  // A cache worker's envelope flag belongs to the cache finding, not to an endpoint.
  const isPiiEndpoint =
    routeFns.length > 0 ||
    py.encrypt_calls.length > 0 ||
    (kmsFlags.length > 0 && !isCacheFile) ||
    (logsPlaintextPii && piiFns.length > 0);

  if (isPiiEndpoint) {
    const fnStart = primaryFn?.lineno ?? 1;
    const fnEnd = primaryFn?.end_lineno ?? Math.min(lines.length, fnStart + 24);
    const editAnchors: SourceEditAnchor[] = [];
    for (const a of isCacheFile ? [] : kmsFlags) {
      if (a.span) editAnchors.push(anchorFromSpan('TENANT_KMS_FLAG', a.name, a.span, { booleanValue: a.value === true }));
    }
    if (cipherAssign?.span) {
      editAnchors.push(anchorFromSpan('CIPHER_LABEL', cipherAssign.name, cipherAssign.span, { stringValue: String(cipherAssign.value) }));
    }
    for (const c of sharedCalls) {
      editAnchors.push(
        anchorFromSpan('SHARED_KEY_ENCRYPT_CALL', c.func, c.callee, {
          context: {
            tenantArg: c.tenant_arg || '',
            callEndLine: String(c.call.end_line),
            callEndColumn: String(c.call.end_col),
          },
        })
      );
    }
    findings.push({
      id: `ast-py-endpoint-${file.path}-${primaryFn?.name || 'module'}`,
      filePath: file.path,
      line: fnStart,
      endLine: fnEnd,
      column: 1,
      language: 'python',
      astNodeKind: primaryFn?.kind || 'Module',
      constructType: routeFns.length > 0 ? 'FASTAPI_ENDPOINT' : 'PII_PROCESSING_FUNCTION',
      functionName: primaryFn?.name || 'module',
      codeSnippet: snippet(lines, Math.max(1, fnStart - 1), fnEnd),
      metadata: {
        usesTenantIsolatedKms: usesTenantKms,
        encryptionCipher: (cipherAssign?.value as string | undefined) || (usesTenantKms ? 'AES-256-GCM-TENANT-KMS' : 'AES-256-GCM-SHARED-KEY'),
        encryptsPii: py.encrypt_calls.length > 0,
        logsPlaintextPii,
        leakedFields,
        containsPii: true,
      },
      editAnchors,
    });
  }

  for (const sink of leakingSinks) {
    findings.push({
      id: `ast-py-logger-${file.path}-${sink.lineno}-${sink.col}`,
      filePath: file.path,
      line: sink.lineno,
      endLine: sink.end_lineno,
      column: sink.col + 1,
      language: 'python',
      astNodeKind: `Call(${sink.func})`,
      constructType: 'LOGGER_CALL',
      functionName: sink.func,
      codeSnippet: snippet(lines, sink.lineno, sink.end_lineno),
      metadata: {
        logsPlaintextPii: true,
        leakedFields: [...new Set(sink.leaks.map((l) => l.field.toLowerCase()))],
      },
      editAnchors: sink.leaks.map((leak) => anchorFromSpan('PII_LOG_ARGUMENT', leak.field, leak)),
    });
  }

  // Retention: every TTL/retention constant (with unit from its name), plus literal cache TTLs.
  const envelopeFlag = kmsFlags.find((a) => /envelope|cache/i.test(a.name)) || kmsFlags[0];
  const ttlAssigns = py.assignments.filter(
    (a) => TTL_NAMES.test(a.name) && typeof a.value === 'number' && a.span && a.scope !== '' && !CONFIDENCE_NAMES.test(a.name)
  );
  const retentionEntries: Array<{
    key: string;
    hours: number;
    source: string;
    assumed: boolean;
    anchor: SourceEditAnchor;
    line: number;
  }> = [];
  for (const a of ttlAssigns) {
    const unit = ttlUnitFromName(a.name);
    retentionEntries.push({
      key: a.name,
      hours: roundHours((a.value as number) * unit.hoursPerUnit),
      source: `${a.name}${a.env_var ? ` (env ${a.env_var} default)` : ''} (${unit.unit}${unit.assumed ? ', assumed' : ''})`,
      assumed: unit.assumed,
      anchor: anchorFromSpan('RETENTION_TTL_LITERAL', a.name, a.span!, {
        numericValue: a.value as number,
        hoursPerUnit: unit.hoursPerUnit,
      }),
      line: a.lineno,
    });
  }
  for (const c of py.cache_calls) {
    if (c.ttl_seconds == null || !c.ttl_span) continue;
    if (c.ttl_refs.some((r) => ttlAssigns.some((a) => a.name === r))) continue;
    retentionEntries.push({
      key: `${c.func}@${c.lineno}`,
      hours: roundHours(c.ttl_seconds / 3600),
      source: `${c.func} literal TTL (seconds)`,
      assumed: false,
      anchor: anchorFromSpan('RETENTION_TTL_LITERAL', c.func, c.ttl_span, {
        numericValue: c.ttl_seconds,
        hoursPerUnit: 1 / 3600,
      }),
      line: c.lineno,
    });
  }

  for (const entry of retentionEntries) {
    const ownerClass = py.classes.find((c) => c.lineno <= entry.line && c.end_lineno >= entry.line);
    const cacheFn =
      py.functions.find((f) => /cache|session|setex|ttl|purge|retain/i.test(f.name)) || py.functions[0];
    const editAnchors: SourceEditAnchor[] = [entry.anchor];
    if (isCacheFile && envelopeFlag?.span) {
      editAnchors.push(
        anchorFromSpan('TENANT_KMS_FLAG', envelopeFlag.name, envelopeFlag.span, { booleanValue: envelopeFlag.value === true })
      );
    }
    findings.push({
      id: `ast-py-retention-${file.path}-${entry.key}`,
      filePath: file.path,
      line: entry.line,
      endLine: Math.min(lines.length, cacheFn?.end_lineno ?? entry.line + 24),
      column: 1,
      language: 'python',
      astNodeKind: ownerClass ? `ClassDef(${ownerClass.name})` : 'Module',
      constructType: isCacheFile ? 'REDIS_CACHE_WORKER' : 'DATA_RETENTION_POLICY',
      functionName: cacheFn?.name || entry.key,
      codeSnippet: snippet(lines, Math.max(1, entry.line - 1), Math.min(lines.length, entry.line + 22)),
      metadata: {
        retentionTtlHours: entry.hours,
        retentionSource: entry.source,
        retentionUnitAssumed: entry.assumed,
        // Only cache stores carry their own tenant KMS envelope.
        usesTenantIsolatedKms: isCacheFile ? envelopeFlag?.value === true : undefined,
      },
      editAnchors,
    });
  }

  return { findings, astNodeCount: py.node_count };
}

// ============================================================================
// TypeScript
// ============================================================================

interface TsConstant {
  name: string;
  value: string | number | boolean;
  folded: boolean;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  sourceText: string;
}

function collectTypeScriptAst(file: TargetRepoFile): {
  astNodeCount: number;
  constants: TsConstant[];
  functions: Array<{ name: string; startLine: number; endLine: number }>;
  syntaxError?: string;
} {
  const sourceFile = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.ES2022, true);
  const diagnostics = (sourceFile as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics || [];
  const syntaxError = diagnostics.length
    ? ts.flattenDiagnosticMessageText(diagnostics[0].messageText, '\n')
    : undefined;
  let astNodeCount = 0;
  const constants: TsConstant[] = [];
  const known = new Map<string, string | number | boolean>();
  const functions: Array<{ name: string; startLine: number; endLine: number }> = [];

  const fold = (node: ts.Expression): string | number | boolean | undefined => {
    if (ts.isNumericLiteral(node)) return parseFloat(node.text.replace(/_/g, ''));
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
      return fold(node.expression);
    }
    if (ts.isIdentifier(node)) return known.get(node.text);
    if (ts.isPrefixUnaryExpression(node)) {
      const v = fold(node.operand);
      if (typeof v === 'number') {
        if (node.operator === ts.SyntaxKind.MinusToken) return -v;
        if (node.operator === ts.SyntaxKind.PlusToken) return v;
      }
      if (typeof v === 'boolean' && node.operator === ts.SyntaxKind.ExclamationToken) return !v;
      return undefined;
    }
    if (ts.isBinaryExpression(node)) {
      const l = fold(node.left);
      const r = fold(node.right);
      if (typeof l === 'number' && typeof r === 'number') {
        switch (node.operatorToken.kind) {
          case ts.SyntaxKind.PlusToken:
            return l + r;
          case ts.SyntaxKind.MinusToken:
            return l - r;
          case ts.SyntaxKind.AsteriskToken:
            return l * r;
          case ts.SyntaxKind.SlashToken:
            return r === 0 ? undefined : l / r;
          default:
            return undefined;
        }
      }
    }
    return undefined;
  };

  function visit(node: ts.Node) {
    astNodeCount++;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const value = fold(node.initializer);
      if (value !== undefined) {
        const start = sourceFile.getLineAndCharacterOfPosition(node.initializer.getStart(sourceFile));
        const end = sourceFile.getLineAndCharacterOfPosition(node.initializer.getEnd());
        known.set(node.name.text, value);
        constants.push({
          name: node.name.text,
          value,
          folded: !(
            ts.isNumericLiteral(node.initializer) ||
            ts.isStringLiteral(node.initializer) ||
            node.initializer.kind === ts.SyntaxKind.TrueKeyword ||
            node.initializer.kind === ts.SyntaxKind.FalseKeyword
          ),
          line: start.line + 1,
          column: start.character,
          endLine: end.line + 1,
          endColumn: end.character,
          sourceText: node.initializer.getText(sourceFile),
        });
      }
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      functions.push({
        name: node.name.text,
        startLine: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
        endLine: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      });
    } else if (
      (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) &&
      ts.isVariableDeclaration(node.parent) &&
      ts.isIdentifier(node.parent.name)
    ) {
      functions.push({
        name: node.parent.name.text,
        startLine: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
        endLine: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      });
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return { astNodeCount, constants, functions, syntaxError };
}

function tsAnchor(role: SourceEditAnchor['role'], c: TsConstant, extra: Partial<SourceEditAnchor> = {}): SourceEditAnchor {
  return {
    role,
    symbol: c.name,
    line: c.line,
    column: c.column,
    endLine: c.endLine,
    endColumn: c.endColumn,
    sourceText: c.sourceText,
    ...extra,
  };
}

/**
 * Parses any `.ts` file with the TypeScript Compiler API, folding constant
 * initializers (`0.17 * 5`, `as const`, references to earlier constants), and emits
 * AI-decision and cross-border egress findings with exact initializer anchors.
 */
export function parseTypeScriptAstFile(file: TargetRepoFile): {
  findings: ASTFindingNode[];
  astNodeCount: number;
  syntaxError?: string;
} {
  const { astNodeCount, constants, functions, syntaxError } = collectTypeScriptAst(file);
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = [];
  const pick = (re: RegExp, type: 'number' | 'boolean' | 'string') =>
    constants.find((c) => re.test(c.name) && typeof c.value === type);

  const confidence = constants.find(
    (c) => CONFIDENCE_NAMES.test(c.name) && typeof c.value === 'number' && c.value >= 0 && c.value <= 100
  );
  const humanGate = pick(HUMAN_GATE_NAMES, 'boolean');
  const auditLog = pick(AUDIT_LOG_NAMES, 'boolean');
  const aiFn = functions.find((f) => /evaluat|triage|infer|predict|score|decision|credit|risk|approv/i.test(f.name));

  if (confidence || humanGate || auditLog) {
    const raw = confidence ? (confidence.value as number) : null;
    const threshold = raw == null ? null : raw > 1 ? raw / 100 : raw;
    const startLine = confidence?.line ?? humanGate?.line ?? aiFn?.startLine ?? 1;
    const endLine = aiFn?.endLine ?? Math.min(lines.length, startLine + 24);
    const editAnchors: SourceEditAnchor[] = [];
    if (confidence) {
      editAnchors.push(
        tsAnchor('AI_CONFIDENCE_THRESHOLD', confidence, {
          numericValue: confidence.value as number,
          context: { scale: (confidence.value as number) > 1 ? 'percent' : 'fraction' },
        })
      );
    }
    if (humanGate) editAnchors.push(tsAnchor('HUMAN_OVERSIGHT_FLAG', humanGate, { booleanValue: humanGate.value === true }));
    if (auditLog) editAnchors.push(tsAnchor('AUDIT_LOG_FLAG', auditLog, { booleanValue: auditLog.value === true }));
    findings.push({
      id: `ast-ts-ai-${file.path}-${confidence?.name || humanGate?.name || 'module'}`,
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
        aiConfidenceThreshold: threshold,
        hasHumanOversightGate: humanGate?.value === true,
        writesAuditLog: auditLog?.value === true,
      },
      editAnchors,
    });
  }

  const egressFn = functions.find((f) => /replicat|sync|transfer|egress|export|upload|ship/i.test(f.name));
  const sovereign = pick(SOVEREIGN_NAMES, 'boolean');
  const regionConsts = constants.filter(
    (c) => typeof c.value === 'string' && CLOUD_REGION.test(c.value) && (REGION_NAMES.test(c.name) || egressFn)
  );
  for (const region of regionConsts) {
    const startLine = region.line;
    const endLine = egressFn?.endLine ?? Math.min(lines.length, startLine + 16);
    findings.push({
      id: `ast-ts-egress-${file.path}-${region.name}`,
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
        egressRegion: region.value as string,
        sovereignGuardEnabled: sovereign?.value === true,
      },
      editAnchors: [
        tsAnchor('EGRESS_REGION_LITERAL', region, { stringValue: region.value as string }),
        ...(sovereign ? [tsAnchor('SOVEREIGN_BOUNDARY_FLAG', sovereign, { booleanValue: sovereign.value === true })] : []),
      ],
    });
  }

  return { findings, astNodeCount, syntaxError };
}

// ============================================================================
// Repository
// ============================================================================

/** Re-parses a file with its language's real parser; used to validate synthesized patches. */
export function checkSourceSyntax(file: TargetRepoFile): { passed: boolean; message?: string } {
  if (file.language === 'python') {
    const py = parsePythonAstCached(file.content);
    if (!py) return { passed: false, message: 'python3 is unavailable or the analyzer failed' };
    return py.syntax_error ? { passed: false, message: py.syntax_error } : { passed: true };
  }
  if (file.language === 'typescript') {
    const { syntaxError } = collectTypeScriptAst(file);
    return syntaxError ? { passed: false, message: syntaxError } : { passed: true };
  }
  const { syntaxError } = parseSqlSchemaFile(file);
  return syntaxError ? { passed: false, message: syntaxError } : { passed: true };
}

/** analyzeFullRepository with Python parsing done off the event loop. */
export async function analyzeFullRepositoryAsync(files: TargetRepoFile[]): Promise<ReturnType<typeof analyzeFullRepository>> {
  await primePythonAstCache(files);
  return analyzeFullRepository(files);
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
  astFindings.push(...collectGovernanceFindings(files, astFindings));

  return { sqlTables, astFindings, enrichedFiles };
}
