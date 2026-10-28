import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { LlmUsage } from '../agents/llmClient.js';

/** Cosine-similarity dedup: drops a segment whose embedding is ≥ threshold to an earlier kept one. */
export async function deduplicateByEmbedding(
  segments: string[],
  embed: (text: string) => Promise<number[]>,
  threshold = 0.92
): Promise<{ kept: string[]; removed: string[] }> {
  const kept: Array<{ text: string; v: number[] }> = [];
  const removed: string[] = [];
  const cos = (a: number[], b: number[]) => {
    let dot = 0, na = 0, nb = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    return na && nb ? dot / Math.sqrt(na * nb) : 0;
  };
  for (const text of segments) {
    const v = await embed(text);
    if (v.length && kept.some((k) => cos(k.v, v) >= threshold)) removed.push(text);
    else kept.push({ text, v });
  }
  return { kept: kept.map((k) => k.text), removed };
}

/**
 * LLMLingua-2 through the Python sidecar (agents/lexcompiler_agents/llmlingua_compress.py), with
 * LEXCOMPILER_LLMLINGUA_PYTHON pointing at an interpreter that has `llmlingua` installed.
 * Returns null when it is not configured or fails.
 */
export function compressWithLlmLingua(texts: string[], rate = 0.5, python = process.env.LEXCOMPILER_LLMLINGUA_PYTHON, script = path.join(process.cwd(), 'agents/lexcompiler_agents/llmlingua_compress.py')): Promise<string[] | null> {
  if (!python || !fs.existsSync(script)) return Promise.resolve(null);
  return new Promise((resolve) => {
    const child = execFile(python, [script], { timeout: 600_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(null);
      try {
        const out = JSON.parse(stdout) as { texts?: string[] };
        resolve(Array.isArray(out.texts) && out.texts.length === texts.length ? out.texts : null);
      } catch {
        resolve(null);
      }
    });
    child.stdin?.end(JSON.stringify({ texts, rate }));
  });
}

// Provider-reported prompt-cache usage from LLM agent runs (cumulative for this process).
const measured: LlmUsage = { promptTokens: 0, completionTokens: 0, cachedPromptTokens: 0, cacheWriteTokens: 0 };

export function recordLlmUsage(u: LlmUsage): void {
  for (const k of Object.keys(measured) as Array<keyof LlmUsage>) measured[k] += u[k];
}

export function measuredCacheTelemetry(): (LlmUsage & { cacheHitRatePercent: number }) | null {
  if (measured.promptTokens === 0) return null;
  return { ...measured, cacheHitRatePercent: Math.round((measured.cachedPromptTokens / measured.promptTokens) * 1000) / 10 };
}
