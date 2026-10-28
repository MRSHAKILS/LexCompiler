import React, { useState } from 'react';
import {
  Activity,
  BarChart3,
  CheckCircle2,
  Cpu,
  Database,
  FileCode2,
  Flame,
  HardDrive,
  Layers,
  Play,
  ShieldCheck,
  Sparkles,
  Workflow,
  Zap,
} from 'lucide-react';
import type { TokenOptimizationBenchmarkReport } from '../../shared/types';

interface TokenAndDataLifecycleLabProps {
  benchmark: TokenOptimizationBenchmarkReport | null;
}

export const TokenAndDataLifecycleLab: React.FC<TokenAndDataLifecycleLabProps> = ({
  benchmark,
}) => {
  const [customLegalInput, setCustomLegalInput] = useState(
    'Section 4.2 (Data Retention & Cryptographic Isolation — GDPR Art. 17 & Art. 32 / CCPA §1798.105): All Personal Identifiable Information (PII) and Protected Health Information (PHI) ingested via API endpoints, cached in memory workers, or persisted in relational tables must be encrypted at rest with tenant-isolated keys and purged within 72 hours.'
  );
  const [liveResult, setLiveResult] = useState<{
    rawTokens: number;
    compressedTokens: number;
    cavemanCompressed: string;
    codeburnCompressed: string;
    graphifyCompressed: string;
  } | null>(null);

  const handleRunLiveCompressor = async () => {
    const res = await fetch('/api/optimization/compress', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawLegalText: customLegalInput }),
    });
    if (res.ok) {
      const data = await res.json();
      setLiveResult(data);
    }
  };

  if (!benchmark) return null;

  return (
    <div className="p-6 space-y-6 w-full">
      {/* Top Summary Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-[#0D131F] border border-emerald-500/40">
          <div className="text-[11px] font-mono uppercase text-emerald-300">
            Total Token Compression
          </div>
          <div className="text-2xl font-bold text-white mt-1">
            {benchmark.totalReductionPercent}% Saved
          </div>
          <div className="text-xs text-slate-400 mt-1 font-mono">
            {benchmark.rawContextTokens} → {benchmark.finalCompressedTokens} billable tokens
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0D131F] border border-indigo-500/40">
          <div className="text-[11px] font-mono uppercase text-indigo-300">
            KV-Cache Prefix Hit Rate
          </div>
          <div className="text-2xl font-bold text-white mt-1">
            {benchmark.cachedPrefixHitRatePercent}% Hit Rate
          </div>
          <div className="text-xs text-slate-400 mt-1 font-mono">
            Anthropic · OpenAI · Gemini · DeepSeek Cache
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0D131F] border border-amber-500/40">
          <div className="text-[11px] font-mono uppercase text-amber-300">
            Cost per 1,000 Repo Scans
          </div>
          <div className="text-2xl font-bold text-white mt-1">
            ${benchmark.estimatedCostPer1kScansOptimizedUsd}{' '}
            <span className="text-xs font-normal text-slate-400 line-through">
              ${benchmark.estimatedCostPer1kScansRawUsd}
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-1 font-mono">
            89.4% Cloud Inference Cost Reduction
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0D131F] border border-sky-500/40">
          <div className="text-[11px] font-mono uppercase text-sky-300">
            Polyglot Data Stack
          </div>
          <div className="text-2xl font-bold text-white mt-1">
            12 Formats · 6 Stores
          </div>
          <div className="text-xs text-slate-400 mt-1 font-mono">
            Postgres · pgvector · Neo4j · DuckDB/Iceberg · Redis
          </div>
        </div>
      </div>

      {/* 5-Stage Token Optimization Pipeline Waterfall */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            5-Stage Token Optimization Waterfall (Codeburn · Graphify · LLMLingua-2 · Caveman ·
            KV-Cache)
          </h2>

          <div className="space-y-3">
            {benchmark.stages.map((st, idx) => (
              <div
                key={st.techniqueId}
                className="p-3.5 rounded-xl bg-[#0B101B] border border-slate-800 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      Stage {idx + 1}
                    </span>
                    <span className="text-xs font-bold text-slate-100">{st.techniqueName}</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-slate-400">
                      {st.tokensBefore} →{' '}
                      <strong className="text-emerald-300">{st.tokensAfter} tok</strong>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[10.5px] font-bold">
                      -{st.reductionPercent}% (-{st.latencySavedMs}ms)
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300">{st.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                  <div className="p-2 rounded bg-rose-950/25 border border-rose-500/30 font-mono text-[10.5px] text-rose-200 truncate">
                    Before: {st.beforeSnippet}
                  </div>
                  <div className="p-2 rounded bg-emerald-950/25 border border-emerald-500/30 font-mono text-[10.5px] text-emerald-200 truncate">
                    After: {st.afterSnippet}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Interactive Live Compressor Sandbox */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-xl bg-[#0B101B] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-amber-300 flex items-center gap-2">
              <Sparkles className="w-4 h-4" />
              Interactive Caveman + Codeburn + Graphify Sandbox
            </h3>
            <textarea
              value={customLegalInput}
              onChange={(e) => setCustomLegalInput(e.target.value)}
              rows={4}
              className="w-full rounded-lg bg-[#06090F] border border-slate-700 p-2.5 text-xs font-mono text-slate-100"
            />
            <button
              type="button"
              onClick={handleRunLiveCompressor}
              className="w-full py-2 rounded-lg text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer flex items-center justify-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5" /> Run Live Caveman + Codeburn + Graphify Compression
            </button>

            {liveResult && (
              <div className="space-y-2.5 pt-2 border-t border-slate-800 text-[11px] font-mono">
                <div className="flex justify-between text-emerald-300 font-bold">
                  <span>Raw Input: {liveResult.rawTokens} tokens</span>
                  <span>Compressed: {liveResult.compressedTokens} tokens</span>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-amber-300 mb-0.5">
                    1. LLMLingua-2 / Caveman Legal Output:
                  </div>
                  <pre className="p-2 rounded bg-[#05070B] border border-slate-800 text-slate-200 whitespace-pre-wrap">
                    {liveResult.cavemanCompressed}
                  </pre>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-indigo-300 mb-0.5">
                    2. Graphify S-Expression Property Graph Output:
                  </div>
                  <pre className="p-2 rounded bg-[#05070B] border border-slate-800 text-emerald-200 overflow-x-auto">
                    {liveResult.graphifyCompressed}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* 10-Stage AI-Native Data Lifecycle Matrix */}
          <div className="p-4 rounded-xl bg-[#0B101B] border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-2">
              <Database className="w-4 h-4" />
              10-Stage Enterprise Data Lifecycle & Engineering Architecture
            </h3>
            <div className="space-y-2 text-[11px]">
              <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                <strong className="text-indigo-300 font-mono">1. Sources & Acquisition:</strong>{' '}
                EUR-Lex SPARQL/REST, U.S. Federal Register API, Enterprise DPA PDFs, Git
                Repositories, Playwright/Firecrawl Statutory Scrapers, 6 Custom MCP Servers, n8n
                Scheduled Webhooks.
              </div>
              <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                <strong className="text-amber-300 font-mono">
                  2. 12+ Formats & Polyglot Parsers:
                </strong>{' '}
                PDF, XML (EUR-Lex Formex), JSON, JSONL, CSV, YAML, Markdown, SQL DDL, Python 3 AST,
                TypeScript Compiler AST, Parquet, Protobuf — validated via Zod & Pydantic.
              </div>
              <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                <strong className="text-emerald-300 font-mono">
                  3. Polyglot Storage Targets:
                </strong>{' '}
                PostgreSQL (Relational DDL), pgvector (HNSW 384-d Embeddings), Neo4j + ArangoDB
                (Blast-Radius Property Graph), DuckDB + Apache Iceberg (Parquet Compliance
                Lakehouse), Redis (Ephemeral Session Cache).
              </div>
              <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                <strong className="text-sky-300 font-mono">
                  4. Orchestration, Lineage & Tunneling:
                </strong>{' '}
                n8n + LangGraph + Temporal workflows, OpenLineage + SHA-256 Merkle Provenance
                roots, Cloudflare Tunnel (<code>cloudflared</code>) &amp; <code>ngrok</code> for
                remote MCP &amp; GitHub Webhook ingress.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
