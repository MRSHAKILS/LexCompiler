import ts from 'typescript';
import type { SymExpr, SymPath, SymbolicSummary } from '../../shared/types.js';

/**
 * Path-sensitive symbolic execution of one TypeScript function: module constants are
 * folded, parameters and their fields are free symbols, every `if` / `?:` splits the path,
 * and each path records its condition and the fields it returns. Constructs outside the
 * modelled subset are left unconstrained (an over-approximation) and listed.
 */
const MAX_PATHS = 64;

type Env = Map<string, SymExpr>;
const T: SymExpr = { k: 'bool', v: true };
const and = (a: SymExpr, b: SymExpr): SymExpr => (a.k === 'bool' && a.v ? b : b.k === 'bool' && b.v ? a : { k: 'op', op: 'and', args: [a, b] });
const not = (a: SymExpr): SymExpr => (a.k === 'bool' ? { k: 'bool', v: !a.v } : { k: 'op', op: 'not', args: [a] });

export function sortOf(e: SymExpr): 'num' | 'bool' | 'str' {
  switch (e.k) {
    case 'num':
      return 'num';
    case 'bool':
      return 'bool';
    case 'str':
      return 'str';
    case 'var':
      return e.sort;
    case 'ite':
      return sortOf(e.t);
    case 'op':
      return ['add', 'sub', 'mul', 'div', 'neg'].includes(e.op) ? 'num' : 'bool';
  }
}

/** Field types of interfaces / type literals declared in the file, for parameter fields. */
function fieldSorts(sf: ts.SourceFile): Map<string, Map<string, 'num' | 'bool' | 'str'>> {
  const out = new Map<string, Map<string, 'num' | 'bool' | 'str'>>();
  const sortOfType = (t: ts.TypeNode | undefined) =>
    !t ? null : t.kind === ts.SyntaxKind.NumberKeyword ? 'num' : t.kind === ts.SyntaxKind.BooleanKeyword ? 'bool' : t.kind === ts.SyntaxKind.StringKeyword || ts.isLiteralTypeNode(t) || ts.isUnionTypeNode(t) ? 'str' : null;
  for (const st of sf.statements) {
    if (!ts.isInterfaceDeclaration(st)) continue;
    const m = new Map<string, 'num' | 'bool' | 'str'>();
    for (const mem of st.members) {
      if (ts.isPropertySignature(mem) && mem.name && ts.isIdentifier(mem.name)) {
        const s = sortOfType(mem.type);
        if (s) m.set(mem.name.text, s);
      }
    }
    out.set(st.name.text, m);
  }
  return out;
}

export function moduleConstants(sf: ts.SourceFile): Env {
  const env: Env = new Map();
  const ctx = { approximations: [] as string[], params: new Map<string, Map<string, 'num' | 'bool' | 'str'>>(), havoc: 0 };
  for (const st of sf.statements) {
    if (!ts.isVariableStatement(st) || !(st.declarationList.flags & ts.NodeFlags.Const)) continue;
    for (const d of st.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.initializer) {
        const v = evalExpr(d.initializer, env, ctx);
        if (v.k === 'num' || v.k === 'bool' || v.k === 'str') env.set(d.name.text, v);
      }
    }
  }
  return env;
}

interface Ctx {
  approximations: string[];
  params: Map<string, Map<string, 'num' | 'bool' | 'str'>>;
  havoc: number;
}

function havoc(ctx: Ctx, node: ts.Node, sort: 'num' | 'bool' | 'str', why: string): SymExpr {
  ctx.approximations.push(`${why}: ${node.getText().slice(0, 60)}`);
  return { k: 'var', name: `__unknown_${ctx.havoc++}`, sort };
}

function evalExpr(e: ts.Expression, env: Env, ctx: Ctx, want: 'num' | 'bool' | 'str' = 'num'): SymExpr {
  if (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) || ts.isTypeAssertionExpression(e) || ts.isSatisfiesExpression(e)) {
    return evalExpr(e.expression, env, ctx, want);
  }
  if (ts.isNumericLiteral(e)) return { k: 'num', v: Number(e.text) };
  if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return { k: 'str', v: e.text };
  if (e.kind === ts.SyntaxKind.TrueKeyword) return { k: 'bool', v: true };
  if (e.kind === ts.SyntaxKind.FalseKeyword) return { k: 'bool', v: false };
  if (ts.isIdentifier(e)) {
    const bound = env.get(e.text);
    if (bound) return bound;
    return { k: 'var', name: e.text, sort: want };
  }
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
    const fields = ctx.params.get(e.expression.text);
    const bound = env.get(`${e.expression.text}.${e.name.text}`);
    if (bound) return bound;
    if (fields) return { k: 'var', name: `${e.expression.text}.${e.name.text}`, sort: fields.get(e.name.text) || want };
    return havoc(ctx, e, want, 'property of a non-parameter object');
  }
  if (ts.isPrefixUnaryExpression(e)) {
    if (e.operator === ts.SyntaxKind.ExclamationToken) return not(evalExpr(e.operand, env, ctx, 'bool'));
    if (e.operator === ts.SyntaxKind.MinusToken) {
      const v = evalExpr(e.operand, env, ctx, 'num');
      return v.k === 'num' ? { k: 'num', v: -v.v } : { k: 'op', op: 'neg', args: [v] };
    }
    if (e.operator === ts.SyntaxKind.PlusToken) return evalExpr(e.operand, env, ctx, 'num');
  }
  if (ts.isConditionalExpression(e)) {
    const c = evalExpr(e.condition, env, ctx, 'bool');
    const t = evalExpr(e.whenTrue, env, ctx, want);
    const f = evalExpr(e.whenFalse, env, ctx, sortOf(t));
    if (c.k === 'bool') return c.v ? t : f;
    return { k: 'ite', c, t, e: f };
  }
  if (ts.isBinaryExpression(e)) {
    const k = e.operatorToken.kind;
    const logical = { [ts.SyntaxKind.AmpersandAmpersandToken]: 'and', [ts.SyntaxKind.BarBarToken]: 'or' } as const;
    if (k in logical) {
      const a = evalExpr(e.left, env, ctx, 'bool');
      const b = evalExpr(e.right, env, ctx, 'bool');
      const op = logical[k as keyof typeof logical];
      if (a.k === 'bool') return op === 'and' ? (a.v ? b : a) : a.v ? a : b;
      return { k: 'op', op, args: [a, b] };
    }
    const cmp: Partial<Record<ts.SyntaxKind, 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge'>> = {
      [ts.SyntaxKind.EqualsEqualsEqualsToken]: 'eq', [ts.SyntaxKind.EqualsEqualsToken]: 'eq',
      [ts.SyntaxKind.ExclamationEqualsEqualsToken]: 'ne', [ts.SyntaxKind.ExclamationEqualsToken]: 'ne',
      [ts.SyntaxKind.LessThanToken]: 'lt', [ts.SyntaxKind.LessThanEqualsToken]: 'le',
      [ts.SyntaxKind.GreaterThanToken]: 'gt', [ts.SyntaxKind.GreaterThanEqualsToken]: 'ge',
    };
    const arith: Partial<Record<ts.SyntaxKind, 'add' | 'sub' | 'mul' | 'div'>> = {
      [ts.SyntaxKind.PlusToken]: 'add', [ts.SyntaxKind.MinusToken]: 'sub', [ts.SyntaxKind.AsteriskToken]: 'mul', [ts.SyntaxKind.SlashToken]: 'div',
    };
    if (cmp[k]) {
      const a = evalExpr(e.left, env, ctx, 'num');
      const b = evalExpr(e.right, env, ctx, sortOf(a));
      // An untyped symbol takes the sort of what it is compared with.
      const a2 = a.k === 'var' && sortOf(a) !== sortOf(b) ? { ...a, sort: sortOf(b) } : a;
      const b2 = b.k === 'var' && sortOf(a2) !== sortOf(b) ? { ...b, sort: sortOf(a2) } : b;
      if (sortOf(a2) !== sortOf(b2)) return havoc(ctx, e, 'bool', 'comparison of different types');
      return { k: 'op', op: cmp[k]!, args: [a2, b2] };
    }
    if (arith[k]) {
      const a = evalExpr(e.left, env, ctx, 'num');
      const b = evalExpr(e.right, env, ctx, 'num');
      if (sortOf(a) !== 'num' || sortOf(b) !== 'num') return havoc(ctx, e, want, 'non-numeric arithmetic');
      if (a.k === 'num' && b.k === 'num') {
        const v = arith[k] === 'add' ? a.v + b.v : arith[k] === 'sub' ? a.v - b.v : arith[k] === 'mul' ? a.v * b.v : a.v / b.v;
        return { k: 'num', v };
      }
      return { k: 'op', op: arith[k]!, args: [a, b] };
    }
  }
  return havoc(ctx, e, want, 'unmodelled expression');
}

function blockStatements(s: ts.Statement): ts.Statement[] {
  return ts.isBlock(s) ? [...s.statements] : [s];
}

function callName(e: ts.CallExpression): string {
  return e.expression.getText().slice(0, 80);
}

function exec(stmts: ts.Statement[], env: Env, pc: SymExpr, events: NonNullable<SymPath['events']>, ctx: Ctx, out: SymPath[], sf: ts.SourceFile): void {
  if (out.length >= MAX_PATHS) {
    ctx.approximations.push(`path limit (${MAX_PATHS}) reached`);
    return;
  }
  if (stmts.length === 0) {
    out.push({ pc, returns: {}, events });
    return;
  }
  const [s, ...rest] = stmts;
  const line = sf.getLineAndCharacterOfPosition(s.getStart()).line + 1;
  const record = (node: ts.Node) => {
    const evs: typeof events = [];
    const visit = (n: ts.Node) => {
      if (ts.isCallExpression(n)) evs.push({ call: callName(n), line: sf.getLineAndCharacterOfPosition(n.getStart()).line + 1 });
      ts.forEachChild(n, visit);
    };
    visit(node);
    return evs;
  };
  if (ts.isVariableStatement(s)) {
    const next = new Map(env);
    for (const d of s.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.initializer) next.set(d.name.text, evalExpr(d.initializer, next, ctx, 'bool'));
      else ctx.approximations.push(`destructuring at line ${line}`);
    }
    return exec(rest, next, pc, [...events, ...record(s)], ctx, out, sf);
  }
  if (ts.isExpressionStatement(s)) {
    const next = new Map(env);
    const x = s.expression;
    if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(x.left)) {
      next.set(x.left.text, evalExpr(x.right, env, ctx, 'bool'));
    }
    return exec(rest, next, pc, [...events, ...record(s)], ctx, out, sf);
  }
  if (ts.isIfStatement(s)) {
    const c = evalExpr(s.expression, env, ctx, 'bool');
    const evs = [...events, ...record(s.expression)];
    if (!(c.k === 'bool' && !c.v)) exec([...blockStatements(s.thenStatement), ...rest], env, and(pc, c), evs, ctx, out, sf);
    if (!(c.k === 'bool' && c.v)) exec([...(s.elseStatement ? blockStatements(s.elseStatement) : []), ...rest], env, and(pc, not(c)), evs, ctx, out, sf);
    return;
  }
  if (ts.isBlock(s)) return exec([...s.statements, ...rest], env, pc, events, ctx, out, sf);
  if (ts.isReturnStatement(s)) {
    const returns: Record<string, SymExpr> = {};
    let x = s.expression;
    while (x && (ts.isParenthesizedExpression(x) || ts.isAsExpression(x) || ts.isSatisfiesExpression(x))) x = x.expression;
    if (x && ts.isObjectLiteralExpression(x)) {
      for (const p of x.properties) {
        if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) returns[p.name.text] = evalExpr(p.initializer, env, ctx, 'bool');
        else if (ts.isShorthandPropertyAssignment(p)) returns[p.name.text] = evalExpr(p.name, env, ctx, 'bool');
        else ctx.approximations.push(`spread / computed property at line ${line}`);
      }
    } else if (x) {
      returns.value = evalExpr(x, env, ctx, 'bool');
    }
    out.push({ pc, returns, events: [...events, ...(x ? record(x) : [])] });
    return;
  }
  if (ts.isThrowStatement(s)) {
    out.push({ pc, returns: { __throws: T }, events });
    return;
  }
  ctx.approximations.push(`${ts.SyntaxKind[s.kind]} at line ${line} skipped`);
  return exec(rest, env, pc, [...events, ...record(s)], ctx, out, sf);
}

/** Symbolic summary of the named function (declaration or `const f = (…) => {…}`); null if absent. */
export function summarizeTypeScriptFunction(source: string, fileName: string, functionName: string): SymbolicSummary | null {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let fn: ts.FunctionLikeDeclaration | undefined;
  const visit = (n: ts.Node) => {
    if (fn) return;
    if (ts.isFunctionDeclaration(n) && n.name?.text === functionName) fn = n;
    else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === functionName && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) fn = n.initializer;
    ts.forEachChild(n, visit);
  };
  visit(sf);
  if (!fn || !fn.body) return null;
  const interfaces = fieldSorts(sf);
  const ctx: Ctx = { approximations: [], params: new Map(), havoc: 0 };
  for (const p of fn.parameters) {
    if (!ts.isIdentifier(p.name)) continue;
    const typeName = p.type && ts.isTypeReferenceNode(p.type) && ts.isIdentifier(p.type.typeName) ? p.type.typeName.text : '';
    ctx.params.set(p.name.text, interfaces.get(typeName) || new Map());
  }
  const env = moduleConstants(sf);
  const paths: SymPath[] = [];
  if (ts.isBlock(fn.body)) exec([...fn.body.statements], env, T, [], ctx, paths, sf);
  else paths.push({ pc: T, returns: { value: evalExpr(fn.body, env, ctx, 'bool') }, events: [] });
  return { functionName, paths, approximations: [...new Set(ctx.approximations)] };
}
