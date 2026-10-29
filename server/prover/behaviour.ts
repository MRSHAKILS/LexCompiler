import type { ASTFindingNode, LegalClause, SymExpr, SymPath, SymbolicSummary } from '../../shared/types.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Z3Any = any;

/**
 * Behavioural verdict for one construct: Z3 searched the symbolic paths of its function for
 * an input that violates the clause. `violated: false` is a proof over every input.
 */
export interface BehaviourVerdict {
  violated: boolean;
  /** Input values of a violating execution (from the Z3 model). */
  witness?: Record<string, string | number | boolean>;
  property: string;
  /** The executor over-approximated these constructs; a violation may be spurious. */
  approximations: string[];
  solverStatus: 'sat' | 'unsat' | 'unknown';
}

const CONSENT_CALL = /consent|lawful_basis|legal_basis/i;

/** Translates analyzer IR to Z3; strings become integers over a per-query string table. */
function toZ3(Z3: Z3Any, e: SymExpr, strs: Map<string, number>, vars: Map<string, Z3Any>): Z3Any {
  const strId = (s: string) => {
    if (!strs.has(s)) strs.set(s, strs.size);
    return strs.get(s)!;
  };
  switch (e.k) {
    case 'num':
      return Z3.Real.val(String(e.v));
    case 'bool':
      return Z3.Bool.val(e.v);
    case 'str':
      return Z3.Int.val(strId(e.v));
    case 'var': {
      const key = `${e.name}:${e.sort}`;
      if (!vars.has(key)) vars.set(key, e.sort === 'num' ? Z3.Real.const(e.name) : e.sort === 'bool' ? Z3.Bool.const(e.name) : Z3.Int.const(`${e.name}__str`));
      return vars.get(key);
    }
    case 'ite':
      return Z3.If(toZ3(Z3, e.c, strs, vars), toZ3(Z3, e.t, strs, vars), toZ3(Z3, e.e, strs, vars));
    case 'op': {
      // Python semantics for mixed sorts (`True < 2`, `if count:`): booleans are 0/1 in
      // arithmetic and comparisons, Int is widened to Real, and numbers are truthy when non-zero.
      const asBool = (x: Z3Any) => (Z3.isBool(x) ? x : x.neq(Z3.isInt(x) ? Z3.Int.val(0) : Z3.Real.val('0')));
      const asNum = (x: Z3Any) => (Z3.isBool(x) ? Z3.If(x, Z3.Real.val('1'), Z3.Real.val('0')) : x);
      const raw = e.args.map((x) => toZ3(Z3, x, strs, vars));
      if (e.op === 'and' || e.op === 'or' || e.op === 'not') {
        const b = raw.map(asBool);
        return e.op === 'and' ? Z3.And(...b) : e.op === 'or' ? Z3.Or(...b) : Z3.Not(b[0]);
      }
      const sameSort = raw.length < 2 || (Z3.isBool(raw[0]) && Z3.isBool(raw[1])) || (Z3.isInt(raw[0]) && Z3.isInt(raw[1])) || (Z3.isReal(raw[0]) && Z3.isReal(raw[1]));
      const a = sameSort && !(['lt', 'le', 'gt', 'ge', 'add', 'sub', 'mul', 'div', 'neg'].includes(e.op) && Z3.isBool(raw[0]))
        ? raw
        : raw.map(asNum).map((x) => (Z3.isInt(x) ? Z3.ToReal(x) : x));
      switch (e.op) {
        case 'eq':
          return a[0].eq(a[1]);
        case 'ne':
          return a[0].neq(a[1]);
        case 'lt':
          return a[0].lt(a[1]);
        case 'le':
          return a[0].le(a[1]);
        case 'gt':
          return a[0].gt(a[1]);
        case 'ge':
          return a[0].ge(a[1]);
        case 'add':
          return a[0].add(a[1]);
        case 'sub':
          return a[0].sub(a[1]);
        case 'mul':
          return a[0].mul(a[1]);
        case 'div':
          return a[0].div(a[1]);
        case 'neg':
          return a[0].neg();
      }
    }
  }
  throw new Error(`unsupported symbolic expression ${JSON.stringify(e)}`);
}

/** Parses Z3 numerals: `0.5`, `17/25`, `(/ 17.0 25.0)`, `(- 3.0)`, `(- (/ 1.0 2.0))`. */
function parseRational(text: string): number {
  const t = text.trim();
  const neg = /^\(-\s+(.*)\)$/.exec(t);
  if (neg) return -parseRational(neg[1]);
  const div = /^\(\/\s+(\S+)\s+(\S+)\)$/.exec(t) || /^(\S+)\/(\S+)$/.exec(t);
  if (div) return Math.round((Number(div[1]) / Number(div[2])) * 1e6) / 1e6;
  return Number(t);
}

const fieldMatching = (p: SymPath, re: RegExp) => Object.entries(p.returns).find(([k]) => re.test(k))?.[1];
const throws = (p: SymPath) => '__throws' in p.returns;

function varsIn(e: SymExpr, out: Array<{ name: string; sort: string }> = []): Array<{ name: string; sort: string }> {
  if (e.k === 'var') out.push({ name: e.name, sort: e.sort });
  else if (e.k === 'op') e.args.forEach((x) => varsIn(x, out));
  else if (e.k === 'ite') [e.c, e.t, e.e].forEach((x) => varsIn(x, out));
  return out;
}

/**
 * Searches for a path and inputs where `violation(path)` holds. `extra` adds constraints over
 * the symbol table (e.g. confidence < the legal minimum).
 */
async function search(
  Z3: Z3Any,
  summary: SymbolicSummary,
  property: string,
  violation: (p: SymPath, z: (e: SymExpr) => Z3Any) => Z3Any | null
): Promise<BehaviourVerdict> {
  const strs = new Map<string, number>();
  const vars = new Map<string, Z3Any>();
  const z = (e: SymExpr) => toZ3(Z3, e, strs, vars);
  const disjuncts: Z3Any[] = [];
  for (const p of summary.paths) {
    const v = violation(p, z);
    if (v) disjuncts.push(Z3.And(z(p.pc), v));
  }
  if (disjuncts.length === 0) return { violated: false, property, approximations: summary.approximations, solverStatus: 'unsat' };
  const solver = new Z3.Solver();
  solver.set('timeout', 10000);
  solver.add(Z3.Or(...disjuncts));
  const status = (await solver.check()) as 'sat' | 'unsat' | 'unknown';
  if (status !== 'sat') return { violated: status !== 'unsat', property, approximations: summary.approximations, solverStatus: status };
  const model = solver.model();
  const witness: Record<string, string | number | boolean> = {};
  const names = new Map(summary.paths.flatMap((p) => [...varsIn(p.pc), ...Object.values(p.returns).flatMap((r) => varsIn(r))]).map((v) => [`${v.name}:${v.sort}`, v]));
  const strName = new Map([...strs].map(([s, i]) => [i, s]));
  for (const [key, v] of names) {
    if (v.name.startsWith('__unknown') || !vars.has(key)) continue;
    const val = model.eval(vars.get(key), true).toString();
    witness[v.name] =
      v.sort === 'bool' ? val === 'true' : v.sort === 'str' ? strName.get(Number(val)) ?? `<string #${val}>` : parseRational(val);
  }
  return { violated: true, witness, property, approximations: summary.approximations, solverStatus: status };
}

/** Behavioural verdicts per finding id, for the clause categories with a behavioural property. */
export async function behaviourVerdicts(Z3: Z3Any, clause: LegalClause, findings: ASTFindingNode[]): Promise<Map<string, BehaviourVerdict>> {
  const p = clause.deontic.extractedParameters;
  const out = new Map<string, BehaviourVerdict>();
  const withSummary = (type: ASTFindingNode['constructType']) => findings.filter((f) => f.constructType === type && f.metadata.symbolic);

  if (clause.category === 'AI_HUMAN_IN_THE_LOOP') {
    const min = p.minAiConfidenceThreshold ?? 0.85;
    for (const f of withSummary('LLM_INFERENCE_CALL')) {
      const s = f.metadata.symbolic!;
      const conf = s.paths.flatMap((x) => [...varsIn(x.pc), ...Object.values(x.returns).flatMap((r) => varsIn(r))]).find((v) => v.sort === 'num' && /confidence|score/i.test(v.name));
      if (!conf) continue;
      out.set(
        f.id,
        await search(Z3, s, `no input with ${conf.name} < ${min} is decided autonomously`, (path, z) => {
          if (throws(path)) return null;
          const mode = fieldMatching(path, /executionMode|mode/i);
          const approved = fieldMatching(path, /approved|autoApproved|decision/i);
          const autonomous: Z3Any[] = [];
          if (mode && (mode.k === 'str' || mode.k === 'ite' || mode.k === 'var')) autonomous.push(z(mode).eq(z({ k: 'str', v: 'AUTONOMOUS_AI' })));
          if (approved && approved.k !== 'str') autonomous.push(z(approved).eq(Z3.Bool.val(true)));
          if (!autonomous.length) return null;
          return Z3.And(z({ k: 'var', name: conf.name, sort: 'num' }).lt(Z3.Real.val(String(min))), Z3.Or(...autonomous));
        })
      );
    }
  }

  if (clause.category === 'CROSS_BORDER_TRANSFER') {
    const allowed = p.allowedDataRegions?.length ? p.allowedDataRegions : ['eu-central-1', 'eu-west-1'];
    for (const f of withSummary('CROSS_BORDER_EGRESS')) {
      out.set(
        f.id,
        await search(Z3, f.metadata.symbolic!, `every replication targets one of ${allowed.join(', ')}`, (path, z) => {
          if (throws(path)) return null;
          const region = fieldMatching(path, /region|destination/i);
          if (!region) return null;
          const replicated = fieldMatching(path, /replicated|sent|transferred/i);
          const outside = Z3.And(...allowed.map((r) => z(region).neq(z({ k: 'str', v: r }))));
          return replicated ? Z3.And(outside, z(replicated).eq(Z3.Bool.val(true))) : outside;
        })
      );
    }
  }

  if (clause.category === 'PII_LOGGING_BAN') {
    for (const f of withSummary('LOGGER_CALL')) {
      out.set(
        f.id,
        await search(Z3, f.metadata.symbolic!, `the PII-leaking log call at line ${f.line} is unreachable`, (path) =>
          (path.events || []).some((e) => e.line === f.line && (e.leaks || []).length > 0) ? Z3.Bool.val(true) : null
        )
      );
    }
  }

  if (clause.category === 'CONSENT_LAWFUL_BASIS') {
    for (const f of withSummary('PII_ENTRYPOINT')) {
      out.set(
        f.id,
        await search(Z3, f.metadata.symbolic!, 'every path that processes personal data checks consent first', (path) =>
          !throws(path) && !(path.events || []).some((e) => CONSENT_CALL.test(e.call)) ? Z3.Bool.val(true) : null
        )
      );
    }
  }
  return out;
}

export function describeWitness(v: BehaviourVerdict): string {
  const w = Object.entries(v.witness || {}).map(([k, x]) => `${k} = ${JSON.stringify(x)}`).join(', ');
  return `${w ? `counterexample: ${w}` : 'reachable on every input'}${v.approximations.length ? ' (the symbolic model over-approximates some constructs)' : ''}`;
}
