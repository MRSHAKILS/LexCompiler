import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chat, type LlmConfig } from '../agents/llmClient.js';
import type { RagQueryExecutionReport } from '../../shared/types.js';

export interface EvalQuestion {
  id: string;
  query: string;
  /** chunk id → graded relevance (2 primary, 1 supporting). */
  relevant: Record<string, number>;
}

export function loadEvalDataset(file = path.join(path.dirname(fileURLToPath(import.meta.url)), 'eval', 'dataset.json')): EvalQuestion[] {
  const dir = fs.existsSync(file) ? file : path.join(process.cwd(), 'server/rag/eval/dataset.json');
  return (JSON.parse(fs.readFileSync(dir, 'utf8')) as { questions: EvalQuestion[] }).questions;
}

export interface RetrievalScores {
  precisionAtK: number;
  recallAtK: number;
  mrr: number;
  ndcgAtK: number;
  hitRate: number;
}

/** Standard IR metrics for one ranked list against graded labels. */
export function scoreRanking(ranked: string[], relevant: Record<string, number>, k: number): RetrievalScores {
  const top = ranked.slice(0, k);
  const rel = (id: string) => relevant[id] ?? 0;
  const hits = top.filter((id) => rel(id) > 0).length;
  const totalRelevant = Object.values(relevant).filter((g) => g > 0).length;
  const firstHit = ranked.findIndex((id) => rel(id) > 0);
  const dcg = top.reduce((acc, id, i) => acc + (2 ** rel(id) - 1) / Math.log2(i + 2), 0);
  const ideal = Object.values(relevant).sort((a, b) => b - a).slice(0, k).reduce((acc, g, i) => acc + (2 ** g - 1) / Math.log2(i + 2), 0);
  return {
    precisionAtK: top.length ? hits / k : 0,
    recallAtK: totalRelevant ? hits / totalRelevant : 1,
    mrr: firstHit >= 0 ? 1 / (firstHit + 1) : 0,
    ndcgAtK: ideal ? dcg / ideal : 0,
    hitRate: hits > 0 ? 1 : 0,
  };
}

export interface JudgeScores {
  /** RAGAS faithfulness: share of the answer's claims supported by the retrieved contexts. */
  faithfulness: number;
  /** RAGAS-style answer relevancy, judged 0..1. */
  answerRelevancy: number;
  claims: Array<{ claim: string; supported: boolean }>;
}

const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    claims: { type: 'array', items: { type: 'object', properties: { claim: { type: 'string' }, supported: { type: 'boolean' } }, required: ['claim', 'supported'] } },
    answerRelevancy: { type: 'number' },
  },
  required: ['claims', 'answerRelevancy'],
};

type JudgeReply = { claims?: Array<{ claim: string; supported: boolean }>; answerRelevancy?: number };

function parseJudgeReply(text: string): JudgeReply | null {
  try {
    const parsed = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as JudgeReply;
    return parsed && typeof parsed === 'object' && Array.isArray(parsed.claims) ? parsed : null;
  } catch {
    return null;
  }
}

/** LLM judge following the RAGAS definitions (claim extraction → per-claim support verdicts). */
export async function judgeAnswer(llm: LlmConfig, query: string, answer: string, contexts: string[]): Promise<JudgeScores> {
  const prompt = `Question: ${query}\nAnswer: ${answer}\nContexts:\n${contexts.map((c, i) => `[${i + 1}] ${c.slice(0, 1200)}`).join('\n')}\n\n` +
    'Split the answer into atomic factual claims. For each claim decide whether the contexts support it. Rate how directly the answer addresses the question (0-1). ' +
    'Reply with only JSON: {"claims":[{"claim":"...","supported":true}],"answerRelevancy":0.0}';
  const messages: Parameters<typeof chat>[1] = [{ role: 'system', content: 'You are a strict RAG evaluation judge.' }, { role: 'user', content: prompt }];
  let res = await chat(llm, messages, [], { maxTokens: 1500, jsonSchema: JUDGE_SCHEMA });
  let parsed = parseJudgeReply(res.content);
  if (!parsed) {
    // One corrective turn, as the agent runtime does for invalid structured output.
    messages.push({ role: 'assistant', content: res.content }, { role: 'user', content: 'That was not valid JSON in the requested shape. Reply with only the JSON object, keeping each claim short.' });
    res = await chat(llm, messages, [], { maxTokens: 1500, jsonSchema: JUDGE_SCHEMA });
    parsed = parseJudgeReply(res.content);
  }
  if (!parsed) throw new Error(`Judge ${llm.label || llm.model} did not return valid JSON (finish reason: ${res.finishReason})`);
  const claims = (parsed.claims || []).map((c) => ({ claim: String(c.claim), supported: c.supported === true }));
  return {
    faithfulness: claims.length ? claims.filter((c) => c.supported).length / claims.length : 0,
    answerRelevancy: Math.max(0, Math.min(1, Number(parsed.answerRelevancy) || 0)),
    claims,
  };
}

export interface EvalReport {
  k: number;
  questions: number;
  /** Judge means cover only the questions the judge scored (`judgedQuestions`). */
  aggregate: RetrievalScores & { faithfulness?: number; answerRelevancy?: number; judgedQuestions?: number };
  perQuestion: Array<{ id: string; query: string; ranked: string[]; scores: RetrievalScores; judge?: JudgeScores; judgeError?: string }>;
  judgeModel?: string;
}

const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);
const r3 = (v: number) => Math.round(v * 1000) / 1000;

export async function evaluateRag(run: (query: string, k: number) => Promise<RagQueryExecutionReport>, opts: { k?: number; judge?: LlmConfig | null; dataset?: EvalQuestion[] } = {}): Promise<EvalReport> {
  const k = opts.k ?? 5;
  const perQuestion: EvalReport['perQuestion'] = [];
  for (const q of opts.dataset || loadEvalDataset()) {
    const report = await run(q.query, k);
    const ranked = report.retrievedChunks.map((r) => r.chunk.chunkId);
    let judge: JudgeScores | undefined;
    let judgeError: string | undefined;
    if (opts.judge) {
      try {
        judge = await judgeAnswer(opts.judge, q.query, report.synthesizedNeuroSymbolicAnswer, report.retrievedChunks.map((r) => r.chunk.contextualizedText));
      } catch (err) {
        // An unparseable verdict leaves the question unjudged instead of scoring it 0 or aborting the run.
        judgeError = (err as Error).message;
      }
    }
    perQuestion.push({ id: q.id, query: q.query, ranked, scores: scoreRanking(ranked, q.relevant, k), ...(judge ? { judge } : {}), ...(judgeError ? { judgeError } : {}) });
  }
  const agg = (key: keyof RetrievalScores) => r3(mean(perQuestion.map((p) => p.scores[key])));
  const judged = perQuestion.flatMap((p) => (p.judge ? [p.judge] : []));
  return {
    k,
    questions: perQuestion.length,
    aggregate: {
      precisionAtK: agg('precisionAtK'),
      recallAtK: agg('recallAtK'),
      mrr: agg('mrr'),
      ndcgAtK: agg('ndcgAtK'),
      hitRate: agg('hitRate'),
      ...(opts.judge
        ? { faithfulness: r3(mean(judged.map((j) => j.faithfulness))), answerRelevancy: r3(mean(judged.map((j) => j.answerRelevancy))), judgedQuestions: judged.length }
        : {}),
    },
    perQuestion,
    ...(opts.judge ? { judgeModel: opts.judge.label || opts.judge.model } : {}),
  };
}
