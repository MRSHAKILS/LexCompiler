import { countTokens as countO200kTokens } from 'gpt-tokenizer/encoding/o200k_base';
import { sha256Hex } from '../util/hash.js';
import type {
  ASTFindingNode,
  LegalClause,
  SQLTableSchema,
  TargetRepoFile,
  TokenOptimizationBenchmarkReport,
  TokenOptimizationStageMetric,
} from '../../shared/types.js';

const LEGAL_STOPWORDS = new Set([
  'the',
  'a',
  'an',
  'of',
  'in',
  'to',
  'for',
  'with',
  'on',
  'at',
  'from',
  'by',
  'about',
  'as',
  'into',
  'like',
  'through',
  'after',
  'over',
  'between',
  'out',
  'against',
  'during',
  'without',
  'before',
  'under',
  'around',
  'among',
  'whereas',
  'pursuant',
  'thereof',
  'herein',
  'hereby',
  'thereto',
  'whereby',
  'accordance',
  'applicable',
  'including',
  'particular',
  'undergoing',
  'processing',
]);

/**
 * LLMLingua-2 / Caveman Perplexity Token Slimmer:
 * Compresses legal prose by removing low-information recital stopwords while strictly
 * preserving deontic modalities (must, shall, prohibited), numbers, citations, and technical terms.
 */
export function compressLegalProseCaveman(rawProse: string): string {
  return rawProse
    .split(/\s+/)
    .filter((token) => {
      const clean = token.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!clean) return false;
      if (/^\d+$/.test(clean)) return true;
      if (
        /^(must|shall|not|never|prohibited|forbidden|encrypted|purged|hours|days|tenant|isolated|keys|kms|pii|phi|gdpr|hipaa|art|section|confidence|human|oversight|audit)$/.test(
          clean
        )
      ) {
        return true;
      }
      return !LEGAL_STOPWORDS.has(clean);
    })
    .join(' ');
}

/**
 * Codeburn — Code-Aware Dead-Weight Pruner:
 * Strips comments, docstrings, blank lines, and trailing whitespace from Python,
 * TypeScript, and SQL while preserving indentation (so Python stays valid).
 */
export function pruneCodeWithCodeburn(rawCode: string): string {
  const withoutDocstrings = rawCode.replace(/^[ \t]*("""|''')[\s\S]*?\1[ \t]*$/gm, '');
  return withoutDocstrings
    .split('\n')
    .map((l) => l.replace(/\s+$/, ''))
    .filter((l) => {
      const t = l.trim();
      return t.length > 0 && !t.startsWith('#') && !t.startsWith('//') && !t.startsWith('--') && !t.startsWith('/*') && !t.startsWith('*');
    })
    .join('\n');
}

/**
 * Graphify — Graph-Based Prompt & AST Compression:
 * Converts verbose multi-file source code + SQL schemas into a dense typed S-Expression
 * Compliance Property Graph for ultra-low-token LLM & symbolic reasoning.
 */
export function compressRepoToGraphifySExpr(
  sqlTables: SQLTableSchema[],
  astFindings: ASTFindingNode[]
): string {
  const tableNodes = sqlTables
    .map(
      (t) =>
        `(SQLTable ${t.tableName} :ttl_h ${t.retentionHoursConfigured ?? 720} :tenant_kms ${t.hasTenantKeyIsolation} :pii_cols [${t.columns
          .filter((c) => c.isPII)
          .map((c) => c.name)
          .join(',')}])`
    )
    .join(' ');

  const astNodes = astFindings
    .map(
      (f) =>
        // The symbolic summary is a derived proof artefact, not context for the model.
        `(ASTNode ${f.constructType} :fn ${f.functionName} :loc "${f.filePath}:${f.line}" :meta ${JSON.stringify({
          ...f.metadata,
          symbolic: undefined,
        })})`
    )
    .join(' ');

  return `(ComplianceGraph ${tableNodes} ${astNodes})`;
}

/** Real BPE token count (o200k_base, the GPT-4o / o-series tokenizer). */
export function countTokens(text: string): number {
  return text ? countO200kTokens(text) : 0;
}

function shingles(text: string): Set<string> {
  const words = text.toLowerCase().split(/\W+/).filter(Boolean);
  const out = new Set<string>();
  for (let i = 0; i + 2 < words.length; i++) out.add(words.slice(i, i + 3).join(' '));
  if (words.length < 3 && words.length > 0) out.add(words.join(' '));
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

/**
 * Removes segments (sentences / graph nodes) that are near-duplicates of an earlier
 * segment (word-trigram Jaccard ≥ threshold).
 */
export function deduplicateSegments(segments: string[], threshold = 0.8): { kept: string[]; removed: string[] } {
  const kept: string[] = [];
  const keptShingles: Array<Set<string>> = [];
  const removed: string[] = [];
  for (const seg of segments) {
    const sh = shingles(seg);
    if (keptShingles.some((k) => jaccard(k, sh) >= threshold)) {
      removed.push(seg);
      continue;
    }
    kept.push(seg);
    keptShingles.push(sh);
  }
  return { kept, removed };
}

/** Pricing/throughput assumptions; override with env vars to match your provider. */
function benchmarkAssumptions() {
  const num = (name: string, fallback: number) => {
    const v = Number(process.env[name]);
    return Number.isFinite(v) && v > 0 ? v : fallback;
  };
  return {
    inputPricePerMTokUsd: num('LEXCOMPILER_INPUT_PRICE_PER_MTOK_USD', 3.0),
    cacheReadMultiplier: num('LEXCOMPILER_CACHE_READ_MULTIPLIER', 0.1),
    prefillTokensPerSecond: num('LEXCOMPILER_PREFILL_TOKENS_PER_SEC', 5000),
  };
}

const pct = (before: number, after: number) => (before > 0 ? Math.round(((before - after) / before) * 1000) / 10 : 0);

/**
 * Measures the five-stage prompt optimization on the active clauses and repository with
 * a real tokenizer. The baseline is the prompt a naive pipeline sends (static policy
 * ontology + full clause text + full source files); each stage replaces part of it.
 * The cache stage counts the static ontology prefix at the provider's cache-read price
 * (LEXCOMPILER_CACHE_READ_MULTIPLIER), and latency/cost use the stated assumptions.
 */
export function runTokenOptimizationBenchmark(
  clauses: LegalClause[],
  files: TargetRepoFile[],
  sqlTables: SQLTableSchema[],
  astFindings: ASTFindingNode[]
): TokenOptimizationBenchmarkReport {
  const a = benchmarkAssumptions();
  const staticPrefix = clauses.map((c) => `${c.compiled.smtLib2Snippet}\n${c.compiled.opaRegoRule}`).join('\n\n');
  const legal = clauses.map((c) => `${c.citation}: ${c.rawLegalText}`).join('\n\n');
  const code = files.map((f) => `// ${f.path}\n${f.content}`).join('\n\n');

  const prefixTokens = countTokens(staticPrefix);
  const legalTokens = countTokens(legal);
  const rawContextTokens = prefixTokens + legalTokens + countTokens(code);

  // Stage 1: Codeburn
  const codeburn = files.map((f) => `// ${f.path}\n${pruneCodeWithCodeburn(f.content)}`).join('\n\n');
  const afterCodeburn = prefixTokens + legalTokens + countTokens(codeburn);

  // Stage 2: Graphify replaces source code with the compliance property graph
  const graph = compressRepoToGraphifySExpr(sqlTables, astFindings);
  const afterGraphify = prefixTokens + legalTokens + countTokens(graph);

  // Stage 3: Caveman legal prose slimming
  const caveman = clauses.map((c) => `${c.citation}: ${compressLegalProseCaveman(c.rawLegalText)}`).join('\n');
  const afterCaveman = prefixTokens + countTokens(caveman) + countTokens(graph);

  // Stage 4: near-duplicate removal across clause sentences and graph nodes
  const segments = [
    ...caveman.split(/(?<=[.;])\s+|\n/).filter((x) => x.trim()),
    ...graph.split(/(?=\((?:SQLTable|ASTNode) )/).filter((x) => x.trim()),
  ];
  const dedup = deduplicateSegments(segments);
  const afterDedup = prefixTokens + countTokens(dedup.kept.join('\n'));

  // Stage 5: static ontology prefix served from the provider prompt cache
  const dynamicTokens = afterDedup - prefixTokens;
  const billableEquivalent = Math.round(dynamicTokens + prefixTokens * a.cacheReadMultiplier);
  const cachedPrefixHitRatePercent = afterDedup > 0 ? Math.round((prefixTokens / afterDedup) * 1000) / 10 : 0;

  const saved = (before: number, after: number) => Math.round(((before - after) / a.prefillTokensPerSecond) * 1000 * 10) / 10;
  const stages: TokenOptimizationStageMetric[] = [
    {
      techniqueId: 'opt-codeburn',
      techniqueName: 'Codeburn — Code-Aware Dead-Weight Pruner',
      category: 'Codeburn (Dead-Branch AST Pruning)',
      tokensBefore: rawContextTokens,
      tokensAfter: afterCodeburn,
      reductionPercent: pct(rawContextTokens, afterCodeburn),
      latencySavedMs: saved(rawContextTokens, afterCodeburn),
      description: 'Strips comments, docstrings, and blank lines from every source file (indentation preserved).',
      beforeSnippet: files[1]?.content.slice(0, 210) || '',
      afterSnippet: pruneCodeWithCodeburn(files[1]?.content || '').slice(0, 160),
    },
    {
      techniqueId: 'opt-graphify',
      techniqueName: 'Graphify — S-Expression Compliance Property Graph Compression',
      category: 'Graphify (AST & Legal Graph Compression)',
      tokensBefore: afterCodeburn,
      tokensAfter: afterGraphify,
      reductionPercent: pct(afterCodeburn, afterGraphify),
      latencySavedMs: saved(afterCodeburn, afterGraphify),
      description: 'Replaces source code with the extracted compliance property graph (tables, PII sinks, KMS flags, TTLs).',
      beforeSnippet: codeburn.slice(0, 200),
      afterSnippet: graph.slice(0, 200),
    },
    {
      techniqueId: 'opt-llmlingua-caveman',
      techniqueName: 'Caveman — Normative Legal Prose Slimmer',
      category: 'LLMLingua-2 / Caveman (Perplexity Token Slimming)',
      tokensBefore: afterGraphify,
      tokensAfter: afterCaveman,
      reductionPercent: pct(afterGraphify, afterCaveman),
      latencySavedMs: saved(afterGraphify, afterCaveman),
      description: 'Drops recital stopwords while keeping deontic operators, numbers, and citations.',
      beforeSnippet: clauses[0]?.rawLegalText.slice(0, 190) || '',
      afterSnippet: compressLegalProseCaveman(clauses[0]?.rawLegalText || '').slice(0, 160),
    },
    {
      techniqueId: 'opt-semantic-dedup',
      techniqueName: 'Near-Duplicate Segment Dedup',
      category: 'Semantic Chunk Dedup & Sliding Window',
      tokensBefore: afterCaveman,
      tokensAfter: afterDedup,
      reductionPercent: pct(afterCaveman, afterDedup),
      latencySavedMs: saved(afterCaveman, afterDedup),
      description: `Removed ${dedup.removed.length} of ${segments.length} segments with word-trigram Jaccard ≥ 0.8 to an earlier segment.`,
      beforeSnippet: dedup.removed[0]?.slice(0, 160) || 'No near-duplicate segments found.',
      afterSnippet: dedup.kept.slice(0, 2).join(' | ').slice(0, 160),
    },
    {
      techniqueId: 'opt-kv-context-cache',
      techniqueName: 'Prompt-Cache Prefix Pinning',
      category: 'Anthropic / DeepSeek / Gemini Context Caching',
      tokensBefore: afterDedup,
      tokensAfter: billableEquivalent,
      reductionPercent: pct(afterDedup, billableEquivalent),
      latencySavedMs: saved(afterDedup, billableEquivalent),
      description: `Pins the ${prefixTokens}-token static SMT-LIB2/Rego ontology as a cached prefix, billed at ${a.cacheReadMultiplier}× the input price on cache hits.`,
      beforeSnippet: staticPrefix.slice(0, 160),
      afterSnippet: `cache_control: ephemeral · prefix sha256 ${sha256Hex(staticPrefix).slice(0, 12)} · ${prefixTokens} tokens`,
    },
  ];

  const costPer1k = (tokens: number) => Math.round(tokens * 1000 * (a.inputPricePerMTokUsd / 1e6) * 100) / 100;
  return {
    benchmarkId: `TOK-BENCH-${sha256Hex(staticPrefix + legal + code).slice(0, 8)}`,
    rawContextTokens,
    finalCompressedTokens: billableEquivalent,
    totalReductionPercent: pct(rawContextTokens, billableEquivalent),
    cachedPrefixHitRatePercent,
    estimatedCostPer1kScansRawUsd: costPer1k(rawContextTokens),
    estimatedCostPer1kScansOptimizedUsd: costPer1k(billableEquivalent),
    stages,
  };
}
