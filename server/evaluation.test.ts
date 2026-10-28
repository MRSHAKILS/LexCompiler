import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles } from './analyzer/repoBaseline.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';
import { evaluateRag, judgeAnswer, loadEvalDataset, scoreRanking } from './rag/evaluation.js';
import { executeHybridRagQuery } from './rag/hybridRagEngine.js';

describe('retrieval evaluation', () => {
  it('computes standard IR metrics', () => {
    const s = scoreRanking(['x', 'a', 'b'], { a: 2, b: 1, c: 1 }, 3);
    expect(s.precisionAtK).toBeCloseTo(2 / 3);
    expect(s.recallAtK).toBeCloseTo(2 / 3);
    expect(s.mrr).toBe(0.5);
    const dcg = 3 / Math.log2(3) + 1 / Math.log2(4);
    const ideal = 3 / Math.log2(2) + 1 / Math.log2(3) + 1 / Math.log2(4);
    expect(s.ndcgAtK).toBeCloseTo(dcg / ideal);
  });

  it('labels only chunks that exist and keeps retrieval quality above the regression floor', async () => {
    const clauses = getInitialClauses();
    const a = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const v = await verifyRepositoryAgainstClauses(clauses, a.sqlTables, a.astFindings);
    const all = executeHybridRagQuery('x', clauses, a.sqlTables, a.astFindings, v.proofs, 100).retrievedChunks.map((r) => r.chunk.chunkId);
    for (const q of loadEvalDataset()) for (const id of Object.keys(q.relevant)) expect(all).toContain(id);
    const report = await evaluateRag(async (q, k) => executeHybridRagQuery(q, clauses, a.sqlTables, a.astFindings, v.proofs, k));
    expect(report.questions).toBe(16);
    // Measured on the fixture: MRR 0.656, nDCG@5 0.542, hit rate 0.938.
    expect(report.aggregate.mrr).toBeGreaterThanOrEqual(0.6);
    expect(report.aggregate.ndcgAtK).toBeGreaterThanOrEqual(0.5);
    expect(report.aggregate.hitRate).toBeGreaterThanOrEqual(0.9);
  });

  it('LLM judge: faithfulness is the share of supported claims', async () => {
    const server = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const content = JSON.stringify({ claims: [{ claim: 'A', supported: true }, { claim: 'B', supported: true }, { claim: 'C', supported: false }], answerRelevancy: 0.8 });
        res.end(JSON.stringify({ choices: [{ message: { content }, finish_reason: 'stop' }], usage: {} }));
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      const j = await judgeAnswer({ provider: 'openai', model: 'judge', baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }, 'q', 'a', ['ctx']);
      expect(j.faithfulness).toBeCloseTo(2 / 3);
      expect(j.answerRelevancy).toBe(0.8);
    } finally {
      server.close();
    }
  });
});
