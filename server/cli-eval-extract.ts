/**
 * Extraction eval: how often LexCompiler reads the right number from a clause (product guide 5.3).
 *
 *   npm run eval:extract -- [--model off|local|cloud] [--local-model qwen2.5-coder:0.5b] [--only id,id] [--json report.json]
 *
 * Four modes:
 * - parser: what the compiler enforces from the text alone (the strictest candidate value).
 * - parser, checked: the rule card without AI; ambiguous clauses become questions.
 * - model: the model's value, unchecked.
 * - model, checked: the rule card with AI; a value only when the quote is in the clause and the
 *   parser reads the same value from the quote and the clause.
 * The checked modes must never be wrong, so the command exits 1 if either is.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getAiGateway, type AiMode } from './ai/gateway.js';
import {
  checkExtraction,
  checkParserOnly,
  EXTRACTION_SCHEMA,
  extractionPrompt,
  numericFieldFor,
  parserReading,
  validateExtraction,
  type ModelExtraction,
} from './ai/extraction.js';
import { closeDb } from './db/index.js';
import type { RuleCategory } from '../shared/types.js';

interface LabelledClause {
  id: string;
  language: string;
  category: RuleCategory;
  text: string;
  expected: number | null;
  note?: string;
}

type Outcome = 'correct' | 'wrong' | 'question';
const same = (a: number, b: number) => Math.abs(a - b) < 1e-6;

/** correct: the right number, or a question when the clause fixes none. question: asked although a value was right there. */
export function score(result: number | null, expected: number | null): Outcome {
  if (result === null) return expected === null ? 'correct' : 'question';
  return expected !== null && same(result, expected) ? 'correct' : 'wrong';
}

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  const mode = (opt('model') || 'off') as AiMode;
  if (!['off', 'local', 'cloud'].includes(mode)) throw new Error('--model must be off, local or cloud');
  const file = path.join(path.dirname(fileURLToPath(import.meta.url)), 'compiler', 'eval', 'clauses.json');
  let clauses = (JSON.parse(fs.readFileSync(file, 'utf8')) as { clauses: LabelledClause[] }).clauses;
  const only = opt('only')?.split(',');
  if (only) clauses = clauses.filter((c) => only.includes(c.id));

  const gateway = getAiGateway();
  const rows: Array<{
    id: string;
    expected: number | null;
    parser: number | null;
    parserChecked: number | null;
    model?: number | null;
    checked?: number | null;
    question?: string | null;
    modelError?: string;
    tokens?: number;
    ms?: number;
  }> = [];
  let modelLabel = 'none';
  for (const c of clauses) {
    const field = numericFieldFor(c.category);
    if (!field) throw new Error(`${c.id}: category ${c.category} has no number to extract`);
    const row: (typeof rows)[number] = {
      id: c.id,
      expected: c.expected,
      parser: parserReading(c.text, field).value,
      parserChecked: checkParserOnly(c.text, c.category)?.value ?? null,
    };
    if (mode !== 'off') {
      const { system, prompt } = extractionPrompt(c.text, field);
      const r = await gateway.complete({
        workspaceId: null,
        task: 'drafting',
        mode,
        localModel: opt('local-model'),
        system,
        prompt,
        schema: EXTRACTION_SCHEMA,
        validate: validateExtraction,
        maxTokens: 200,
        timeoutMs: 120_000,
      });
      if (r.refused) throw new Error(`the model call was refused (${r.refused}); check LEXCOMPILER_DEMO_AI_MODE and the model settings`);
      modelLabel = `${r.model} via ${r.endpointHost} (${r.mode})`;
      const answer = r.ok ? (r.json as ModelExtraction) : null;
      const checked = checkExtraction(c.text, c.category, answer);
      Object.assign(row, {
        model: answer && typeof answer.value === 'number' ? answer.value : null,
        checked: checked?.value ?? null,
        question: checked?.question ?? null,
        modelError: r.ok ? undefined : r.invalid || r.error,
        tokens: r.usage.promptTokens + r.usage.completionTokens,
        ms: r.latencyMs,
      });
    }
    rows.push(row);
  }

  const show = (v: number | null | undefined) => (v === undefined ? '' : v === null ? '?' : String(v));
  const langs = clauses.reduce<Record<string, number>>((m, c) => ((m[c.language] = (m[c.language] ?? 0) + 1), m), {});
  console.log(`Extraction eval: ${clauses.length} clauses (${Object.entries(langs).map(([l, n]) => `${l} ${n}`).join(', ')}); model: ${modelLabel}`);
  console.log('"?" means a question for Legal instead of a value.\n');
  console.log(['id'.padEnd(14), 'expected'.padStart(9), 'parser'.padStart(9), 'checked'.padStart(9), ...(mode !== 'off' ? ['model'.padStart(9), 'checked'.padStart(9)] : [])].join(' '));
  for (const r of rows) {
    const mark = (v: number | null | undefined) => (v === undefined ? '' : score(v, r.expected) === 'wrong' ? `${show(v)}✗` : show(v));
    console.log([r.id.padEnd(14), show(r.expected).padStart(9), mark(r.parser).padStart(9), mark(r.parserChecked).padStart(9), ...(mode !== 'off' ? [mark(r.model).padStart(9), mark(r.checked).padStart(9)] : [])].join(' '));
  }

  const modes: Array<[string, (r: (typeof rows)[number]) => number | null | undefined]> = [
    ['parser', (r) => r.parser],
    ['parser, checked', (r) => r.parserChecked],
    ...(mode !== 'off'
      ? ([
          ['model', (r) => r.model],
          ['model, checked', (r) => r.checked],
        ] as Array<[string, (r: (typeof rows)[number]) => number | null | undefined]>)
      : []),
  ];
  const summary: Record<string, Record<Outcome, number>> = {};
  console.log(`\n${'mode'.padEnd(16)} ${'correct'.padStart(8)} ${'wrong'.padStart(6)} ${'asked, but a value was clear'.padStart(29)}`);
  for (const [name, get] of modes) {
    const counts: Record<Outcome, number> = { correct: 0, wrong: 0, question: 0 };
    for (const r of rows) counts[score(get(r) ?? null, r.expected)]++;
    summary[name] = counts;
    console.log(`${name.padEnd(16)} ${String(counts.correct).padStart(8)} ${String(counts.wrong).padStart(6)} ${String(counts.question).padStart(29)}`);
  }
  if (mode !== 'off') {
    const n = rows.length || 1;
    const tokens = rows.reduce((t, r) => t + (r.tokens ?? 0), 0);
    const ms = rows.reduce((t, r) => t + (r.ms ?? 0), 0);
    const invalid = rows.filter((r) => r.modelError).length;
    console.log(`\nModel: ${Math.round(tokens / n)} tokens and ${(ms / n / 1000).toFixed(1)} s per clause on average; ${invalid} answer(s) were not valid JSON or failed.`);
  }
  const out = opt('json');
  if (out) fs.writeFileSync(out, JSON.stringify({ model: modelLabel, summary, rows }, null, 2));
  closeDb();
  const failed = ['parser, checked', 'model, checked'].filter((m) => (summary[m]?.wrong ?? 0) > 0);
  if (failed.length > 0) {
    console.error(`\nFAIL: ${failed.join(' and ')} produced wrong values; a disagreement or ambiguity must become a question.`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
