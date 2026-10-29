import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles } from './analyzer/repoBaseline.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { compressWithLlmLingua, deduplicateByEmbedding, measuredCacheTelemetry, recordLlmUsage } from './optimization/neuralCompression.js';
import { runTokenOptimizationBenchmarkAsync } from './optimization/tokenOptimizer.js';
import { resolvePython } from './util/python.js';

describe('model-based token optimisation stages', () => {
  it('dedups by embedding cosine similarity', async () => {
    const vec: Record<string, number[]> = { a: [1, 0], 'a again': [0.99, 0.05], b: [0, 1] };
    const out = await deduplicateByEmbedding(['a', 'b', 'a again'], async (t) => vec[t]);
    expect(out).toEqual({ kept: ['a', 'b'], removed: ['a again'] });
  });

  it('runs the LLMLingua-2 sidecar protocol and falls back when it is unavailable', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lingua-'));
    const script = path.join(dir, 'fake.py');
    // Stand-in for the sidecar: same stdin/stdout protocol, keeps the first word of each text.
    fs.writeFileSync(script, 'import json,sys\nr=json.load(sys.stdin)\njson.dump({"texts":[t.split()[0] for t in r["texts"]]},sys.stdout)\n');
    const python = resolvePython();
    expect(await compressWithLlmLingua(['shall purge within 72 hours', 'must not log'], 0.5, python!.command, script)).toEqual(['shall', 'must']);
    expect(await compressWithLlmLingua(['x'], 0.5, undefined, script)).toBeNull();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reports measured provider cache hits and neural dedup in the benchmark', async () => {
    recordLlmUsage({ promptTokens: 1000, completionTokens: 50, cachedPromptTokens: 600, cacheWriteTokens: 0 });
    expect(measuredCacheTelemetry()?.cacheHitRatePercent).toBe(60);
    const clauses = getInitialClauses();
    const a = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const report = await runTokenOptimizationBenchmarkAsync(clauses, a.enrichedFiles, a.sqlTables, a.astFindings, { embed: async (t) => [t.length % 7, 1] });
    expect(report.cachedPrefixHitRatePercent).toBe(60);
    const dedup = report.stages.find((s) => s.techniqueId === 'opt-semantic-dedup')!;
    expect(dedup.description).toContain('neural embedding cosine');
    expect(report.stages.find((s) => s.techniqueId === 'opt-kv-context-cache')!.description).toContain('Measured');
  });
});
