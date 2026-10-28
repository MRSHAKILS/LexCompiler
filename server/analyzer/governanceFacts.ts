import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import type { ASTFindingNode, SourceEditAnchor, TargetRepoFile } from '../../shared/types.js';
import { TARGET_REPO_ROOT } from './repoBaseline.js';
import { isPiiIdentifier, parsePythonAstCached, type ParsedPythonAst } from './astAnalyzer.js';
import { classifyPii } from './piiClassifier.js';

/**
 * Facts for the governance categories (consent / lawful basis, breach notification,
 * DPIA, data minimisation, purpose limitation), read from the Python `ast` output and
 * the TypeScript compiler AST.
 */

const CONSENT_CALL = /consent|lawful_basis|legal_basis/i;
const PURPOSE_CONST = /^(PROCESSING_PURPOSE|DATA_PROCESSING_PURPOSE|PURPOSE_OF_PROCESSING)$/i;
const BREACH_CONST = /BREACH.*(HOURS|DEADLINE|WINDOW|SECONDS|MINUTES|DAYS)|NOTIF.*BREACH/i;
const DPIA_CONST = /(^|_)DPIA(_|$)|DATA_PROTECTION_IMPACT_ASSESSMENT/i;
const SERIALISES_WHOLE_MODEL = new Set(['dict', 'model_dump', 'model_dump_json', 'json', '__dict__']);

function hoursPerUnit(name: string): number {
  if (/SECOND|_S$|SECS/i.test(name)) return 1 / 3600;
  if (/MINUTE|MINS/i.test(name)) return 1 / 60;
  if (/DAY/i.test(name)) return 24;
  return 1;
}

const lineOf = (lines: string[], n: number) => lines[n - 1] ?? '';
const snippet = (lines: string[], a: number, b: number) => lines.slice(Math.max(0, a - 1), Math.max(a, b)).join('\n');

function pythonFindings(file: TargetRepoFile, py: ParsedPythonAst): ASTFindingNode[] {
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = [];
  const moduleConsts = py.assignments.filter((a) => a.scope === '<module>');

  // Pydantic / dataclass models that collect PII.
  type PyField = NonNullable<ParsedPythonAst['classes'][number]['fields']>[number];
  const piiOf = (f: PyField) => classifyPii({ name: f.name, typeText: f.annotation, description: f.description, patterns: f.patterns, samples: f.samples });
  const models = py.classes.filter((c) => (c.bases || []).some((b) => /BaseModel|TypedDict/.test(b)) && (c.fields || []).some((f) => piiOf(f).pii));
  const reads = new Set(py.attr_reads || []);
  const wholeModelUse = [...SERIALISES_WHOLE_MODEL].some((m) => reads.has(m));
  for (const m of models) {
    const pii = (m.fields || []).filter((f) => piiOf(f).pii);
    const unused = wholeModelUse ? [] : pii.filter((f) => !reads.has(f.name));
    findings.push({
      id: `ast-py-model-${file.path}-${m.name}`,
      filePath: file.path,
      line: m.lineno,
      endLine: m.end_lineno,
      column: 1,
      language: 'python',
      astNodeKind: `ClassDef(${m.name})`,
      constructType: 'PII_COLLECTION_MODEL',
      functionName: m.name,
      codeSnippet: snippet(lines, m.lineno, m.end_lineno),
      metadata: {
        containsPii: true,
        collectedPiiFields: pii.map((f) => f.name),
        unusedPiiFields: unused.map((f) => f.name),
        piiFieldEvidence: Object.fromEntries(pii.map((f) => [f.name, piiOf(f)])),
      },
      editAnchors: unused.map(
        (f): SourceEditAnchor => ({
          role: 'PII_MODEL_FIELD',
          symbol: `${m.name}.${f.name}`,
          // The whole field line(s), including the newline, so removal leaves no blank line.
          line: f.lineno,
          column: 0,
          endLine: f.end_lineno + 1,
          endColumn: 0,
          sourceText: `${lines.slice(f.lineno - 1, f.end_lineno).join('\n')}\n`,
        })
      ),
    });
  }

  // Entry points that process PII: routed handlers, or functions taking PII arguments / PII models.
  const modelNames = new Set(models.map((m) => m.name));
  const purpose = moduleConsts.find((a) => PURPOSE_CONST.test(a.name) && typeof a.value === 'string');
  for (const fn of py.functions) {
    const piiArgs = fn.args.filter((a) => isPiiIdentifier(a));
    const modelArgs = Object.entries(fn.annotations || {}).filter(([, t]) => modelNames.has(t)).map(([a]) => a);
    if (!piiArgs.length && !modelArgs.length) continue;
    if (fn.body_line == null) continue;
    const hasConsentCheck = (fn.calls || []).some((c) => CONSENT_CALL.test(c)) || fn.decorators.some((d) => CONSENT_CALL.test(d));
    const subject = modelArgs[0] || piiArgs[0] || fn.args[0] || 'None';
    const bodyLine = lineOf(lines, fn.body_line);
    const indent = bodyLine.slice(0, fn.body_col ?? 4);
    const anchors: SourceEditAnchor[] = [
      {
        role: 'CONSENT_CHECK_INSERTION_POINT',
        symbol: fn.name,
        line: fn.body_line,
        column: 0,
        endLine: fn.body_line,
        endColumn: 0,
        sourceText: '',
        context: { indent, subject },
      },
    ];
    if (purpose?.span) {
      anchors.push({
        role: 'PROCESSING_PURPOSE_LITERAL',
        symbol: purpose.name,
        line: purpose.span.line,
        column: purpose.span.col,
        endLine: purpose.span.end_line,
        endColumn: purpose.span.end_col,
        sourceText: purpose.span.text,
        stringValue: String(purpose.value),
      });
    }
    findings.push({
      id: `ast-py-entry-${file.path}-${fn.name}`,
      filePath: file.path,
      line: fn.lineno,
      endLine: fn.end_lineno,
      column: 1,
      language: 'python',
      astNodeKind: `${fn.kind}(${fn.name})`,
      constructType: 'PII_ENTRYPOINT',
      functionName: fn.name,
      codeSnippet: snippet(lines, fn.lineno, Math.min(fn.end_lineno, fn.lineno + 14)),
      metadata: { containsPii: true, hasConsentCheck, declaredPurpose: purpose ? String(purpose.value) : null },
      editAnchors: anchors,
    });
  }

  for (const a of moduleConsts) {
    if (BREACH_CONST.test(a.name) && typeof a.value === 'number' && a.span) {
      const perUnit = hoursPerUnit(a.name);
      findings.push(breachFinding(file, lines, a.name, a.lineno, a.value * perUnit, {
        role: 'BREACH_DEADLINE_LITERAL', symbol: a.name, line: a.span.line, column: a.span.col, endLine: a.span.end_line, endColumn: a.span.end_col,
        sourceText: a.span.text, numericValue: a.value, hoursPerUnit: perUnit,
      }));
    }
    if (DPIA_CONST.test(a.name) && typeof a.value === 'string') findings.push(dpiaFinding(file, lines, a.name, a.lineno, a.value));
  }
  return findings;
}

function breachFinding(file: TargetRepoFile, lines: string[], name: string, line: number, hours: number | null, anchor?: SourceEditAnchor): ASTFindingNode {
  return {
    id: `ast-breach-${file.path}-${name}`,
    filePath: file.path,
    line,
    endLine: line,
    column: 1,
    language: file.language,
    astNodeKind: `Assign(${name})`,
    constructType: 'BREACH_NOTIFICATION_POLICY',
    functionName: name,
    codeSnippet: lineOf(lines, line),
    metadata: { breachNotificationHours: hours },
    editAnchors: anchor ? [anchor] : [],
  };
}

function dpiaFinding(file: TargetRepoFile, lines: string[], name: string, line: number, ref: string): ASTFindingNode {
  return {
    id: `ast-dpia-${file.path}-${name}`,
    filePath: file.path,
    line,
    endLine: line,
    column: 1,
    language: file.language,
    astNodeKind: `Assign(${name})`,
    constructType: 'DPIA_RECORD',
    functionName: name,
    codeSnippet: lineOf(lines, line),
    metadata: { dpiaReference: ref || null, dpiaRecordExists: false },
  };
}

/**
 * Interfaces and object type aliases whose properties hold PII, judged from the property name,
 * its declared type (`Email`, `PhoneNumber`, …) and its JSDoc (`@pii`, "date of birth", …).
 */
function typeScriptPiiModels(file: TargetRepoFile, sf: ts.SourceFile, lines: string[]): ASTFindingNode[] {
  const out: ASTFindingNode[] = [];
  for (const st of sf.statements) {
    const members = ts.isInterfaceDeclaration(st) ? st.members : ts.isTypeAliasDeclaration(st) && ts.isTypeLiteralNode(st.type) ? st.type.members : null;
    if (!members || !(ts.isInterfaceDeclaration(st) || ts.isTypeAliasDeclaration(st))) continue;
    const evidence: Record<string, ReturnType<typeof classifyPii>> = {};
    for (const m of members) {
      if (!ts.isPropertySignature(m) || !m.name || !(ts.isIdentifier(m.name) || ts.isStringLiteral(m.name))) continue;
      const doc = ts.getJSDocCommentsAndTags(m).map((d) => d.getText(sf)).join(' ');
      const c = classifyPii({ name: m.name.text, typeText: m.type?.getText(sf), description: doc || undefined });
      if (c.pii) evidence[m.name.text] = c;
    }
    if (!Object.keys(evidence).length) continue;
    const start = sf.getLineAndCharacterOfPosition(st.getStart()).line + 1;
    const end = sf.getLineAndCharacterOfPosition(st.getEnd()).line + 1;
    out.push({
      id: `ast-ts-model-${file.path}-${st.name.text}`,
      filePath: file.path,
      line: start,
      endLine: end,
      column: 1,
      language: 'typescript',
      astNodeKind: `${ts.SyntaxKind[st.kind]}(${st.name.text})`,
      constructType: 'PII_COLLECTION_MODEL',
      functionName: st.name.text,
      codeSnippet: snippet(lines, start, end),
      metadata: { containsPii: true, collectedPiiFields: Object.keys(evidence), unusedPiiFields: [], piiFieldEvidence: evidence },
      editAnchors: [],
    });
  }
  return out;
}

function typeScriptFindings(file: TargetRepoFile): ASTFindingNode[] {
  const sf = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const lines = file.content.split('\n');
  const findings: ASTFindingNode[] = typeScriptPiiModels(file, sf, lines);
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    for (const d of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(d.name) || !d.initializer) continue;
      const name = d.name.text;
      const line = sf.getLineAndCharacterOfPosition(d.getStart()).line + 1;
      if (BREACH_CONST.test(name) && ts.isNumericLiteral(d.initializer)) {
        const start = sf.getLineAndCharacterOfPosition(d.initializer.getStart());
        const end = sf.getLineAndCharacterOfPosition(d.initializer.getEnd());
        const perUnit = hoursPerUnit(name);
        const value = Number(d.initializer.text);
        findings.push(breachFinding(file, lines, name, line, value * perUnit, {
          role: 'BREACH_DEADLINE_LITERAL', symbol: name, line: start.line + 1, column: start.character, endLine: end.line + 1, endColumn: end.character,
          sourceText: d.initializer.getText(), numericValue: value, hoursPerUnit: perUnit,
        }));
      }
      if (DPIA_CONST.test(name) && (ts.isStringLiteral(d.initializer) || ts.isNoSubstitutionTemplateLiteral(d.initializer))) {
        findings.push(dpiaFinding(file, lines, name, line, d.initializer.text));
      }
    }
  }
  return findings;
}

/** Per-file governance findings plus repository-level facts (missing breach policy, DPIA files). */
export function collectGovernanceFindings(files: TargetRepoFile[], existing: ASTFindingNode[]): ASTFindingNode[] {
  const out: ASTFindingNode[] = [];
  for (const file of files) {
    if (file.language === 'python') {
      const py = parsePythonAstCached(file.content);
      if (py && !py.syntax_error) out.push(...pythonFindings(file, py));
    } else if (file.language === 'typescript') {
      out.push(...typeScriptFindings(file));
    }
  }
  const paths = new Set(files.map((f) => f.path));
  for (const f of out) {
    if (f.constructType !== 'DPIA_RECORD' || !f.metadata.dpiaReference) continue;
    const ref = f.metadata.dpiaReference.replace(/^\.\//, '');
    f.metadata.dpiaRecordExists = paths.has(ref) || (!path.isAbsolute(ref) && !ref.includes('..') && fs.existsSync(path.join(TARGET_REPO_ROOT, ref)));
  }
  // No breach-notification deadline anywhere while PII is processed: a repository-level gap,
  // attached to the first PII entry point so a policy constant can be added there.
  const processesPii = out.some((f) => f.constructType === 'PII_ENTRYPOINT') || existing.some((f) => f.metadata.containsPii);
  const host = out.find((f) => f.constructType === 'PII_ENTRYPOINT' && f.language === 'python');
  if (processesPii && host && !out.some((f) => f.constructType === 'BREACH_NOTIFICATION_POLICY')) {
    const lines = files.find((f) => f.path === host.filePath)!.content.split('\n');
    out.push({ ...breachFinding(files.find((f) => f.path === host.filePath)!, lines, 'BREACH_NOTIFICATION_DEADLINE_HOURS', 1, null), codeSnippet: '(no breach-notification deadline is configured)' });
  }
  return out;
}
