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

/** LLM judge following the RAGAS definitions (claim extraction → per-claim support verdicts). */
export async function judgeAnswer(llm: LlmConfig, query: string, answer: string, contexts: string[]): Promise<JudgeScores> {
  const prompt = `Question: ${query}\nAnswer: ${answer}\nContexts:\n${contexts.map((c, i) => `[${i + 1}] ${c.slice(0, 1200)}`).join('\n')}\n\n` +
    'Split the answer into atomic factual claims. For each claim decide whether the contexts support it. Rate how directly the answer addresses the question (0-1). ' +
    'Reply with only JSON: {"claims":[{"claim":"...","supported":true}],"answerRelevancy":0.0}';
  const res = await chat(llm, [{ role: 'system', content: 'You are a strict RAG evaluation judge.' }, { role: 'user', content: prompt }], [], { maxTokens: 800 });
  const text = res.content;
  const parsed = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as { claims?: Array<{ claim: string; supported: boolean }>; answerRelevancy?: number };
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
  aggregate: RetrievalScores & { faithfulness?: number; answerRelevancy?: number };
  perQuestion: Array<{ id: string; query: string; ranked: string[]; scores: RetrievalScores; judge?: JudgeScores }>;
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
    const judge = opts.judge ? await judgeAnswer(opts.judge, q.query, report.synthesizedNeuroSymbolicAnswer, report.retrievedChunks.map((r) => r.chunk.contextualizedText)) : undefined;
    perQuestion.push({ id: q.id, query: q.query, ranked, scores: scoreRanking(ranked, q.relevant, k), ...(judge ? { judge } : {}) });
  }
  const agg = (key: keyof RetrievalScores) => r3(mean(perQuestion.map((p) => p.scores[key])));
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
        ? { faithfulness: r3(mean(perQuestion.map((p) => p.judge!.faithfulness))), answerRelevancy: r3(mean(perQuestion.map((p) => p.judge!.answerRelevancy))) }
        : {}),
    },
    perQuestion,
    ...(opts.judge ? { judgeModel: opts.judge.label || opts.judge.model } : {}),
  };
}
