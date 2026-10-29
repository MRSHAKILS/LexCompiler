import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

/**
 * A fake Ollama /api/embed: 8-dimensional vectors from character codes. Inputs containing
 * "patient_records" fail with HTTP 500, like all-minilm did for over-long input.
 */
function fakeOllama() {
  const calls: Array<{ model: string; truncate: unknown; input: string }> = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (req.url !== '/api/embed') return void res.writeHead(404).end();
      const msg = JSON.parse(body) as { model: string; input: string; truncate?: boolean };
      calls.push({ model: msg.model, truncate: msg.truncate, input: msg.input });
      if (msg.input.includes('patient_records')) {
        res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'the input length exceeds the context length' }));
        return;
      }
      const v = Array.from({ length: 8 }, (_, i) => [...msg.input].reduce((a, ch, j) => a + (j % 8 === i ? ch.charCodeAt(0) : 0), 1) / 1000);
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ model: msg.model, embeddings: [v] }));
    });
  });
  return { server, calls };
}

describe('neural embeddings for RAG', () => {
  const ollama = fakeOllama();
  beforeAll(async () => {
    await new Promise<void>((resolve) => ollama.server.listen(0, '127.0.0.1', resolve));
    process.env.OLLAMA_HOST = `http://127.0.0.1:${(ollama.server.address() as AddressInfo).port}`;
    process.env.LEXCOMPILER_EMBEDDING_MODEL = 'fake-embed';
    vi.resetModules();
  });
  afterAll(() => {
    ollama.server.close();
    process.env.LEXCOMPILER_EMBEDDING_MODEL = 'none';
  });

  it('asks /api/embed to truncate long input and caches by model and text', async () => {
    const { computeRealNeuralEmbedding } = await import('./services/realAiServiceMesh.js');
    const long = 'retention '.repeat(2000);
    const first = await computeRealNeuralEmbedding(long);
    expect(first.embedding).toHaveLength(8);
    expect(first.modelUsed).toBe('fake-embed (Ollama)');
    expect(ollama.calls.at(-1)).toMatchObject({ model: 'fake-embed', truncate: true });
    const again = await computeRealNeuralEmbedding(long);
    expect(again.fromCache).toBe(true);
    // Same label whether cached or not: it names the vector space.
    expect(again.modelUsed).toBe(first.modelUsed);
  });

  it('reports why an embedding failed instead of throwing', async () => {
    const { computeRealNeuralEmbedding } = await import('./services/realAiServiceMesh.js');
    const failed = await computeRealNeuralEmbedding('CREATE TABLE patient_records (ssn TEXT)');
    expect(failed.embedding).toEqual([]);
    expect(failed.error).toContain('HTTP 500');
  });

  it('keeps answering when some chunks cannot be embedded', async () => {
    const [{ executeNeuralRetrieval }, { getInitialClauses }, { analyzeFullRepositoryAsync }, { readTargetRepoFiles }, { verifyRepositoryAgainstClauses }] = await Promise.all([
      import('./rag/hybridRagEngine.js'),
      import('./compiler/legalCompiler.js'),
      import('./analyzer/astAnalyzer.js'),
      import('./analyzer/repoBaseline.js'),
      import('./prover/z3Engine.js'),
    ]);
    const clauses = getInitialClauses();
    const { sqlTables, astFindings } = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const { proofs } = await verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings);
    const report = await executeNeuralRetrieval('Which tables keep PII longer than 72 hours?', clauses, sqlTables, astFindings, proofs, 5);
    expect(report.retrievedChunks.length).toBeGreaterThan(0);
    expect(report.techniquesExecuted.join(' ')).toMatch(/Dense retrieval: fake-embed \(Ollama\); \d+ of \d+ chunks not embedded/);
    // The chunk that failed to embed is still found by its keywords.
    const failedChunk = report.retrievedChunks.find((c) => c.chunk.contextualizedText.includes('patient_records'));
    expect(failedChunk ? failedChunk.denseVectorScore : 0).toBe(0);
  });
});
