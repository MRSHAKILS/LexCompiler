import React, { useState } from 'react';
import {
  Database,
  Layers,
  Network,
  Search,
  Sparkles,
} from 'lucide-react';
import type { RagQueryExecutionReport } from '../../shared/types';

interface HybridRagStudioProps {
  initialReport: RagQueryExecutionReport | null;
}

const SAMPLE_RAG_QUERIES = [
  'Which SQL tables and Python endpoints violate GDPR Art. 17 72-hour retention and tenant-isolated KMS encryption?',
  'Where does the FastAPI service leak unredacted SSN or clinical diagnosis PHI to stdout logs under HIPAA §164.312(b)?',
  'Does the TypeScript AI credit triage model enforce the EU AI Act Article 14 85% confidence human oversight gate?',
  'Which replication service violates GDPR Chapter V Article 44 sovereign EEA data residency?',
];

export const HybridRagStudio: React.FC<HybridRagStudioProps> = ({ initialReport }) => {
  const [query, setQuery] = useState(SAMPLE_RAG_QUERIES[0]);
  const [ragReport, setRagReport] = useState<RagQueryExecutionReport | null>(initialReport);
  const [isSearching, setIsSearching] = useState(false);

  const handleRunQuery = async (customQuery?: string) => {
    const q = customQuery ?? query;
    setQuery(q);
    setIsSearching(true);
    try {
      const res = await fetch('/api/rag/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, topK: 5 }),
      });
      if (res.ok) {
        const data = (await res.json()) as RagQueryExecutionReport;
        setRagReport(data);
      }
    } finally {
      setIsSearching(false);
    }
  };

  if (!ragReport) return null;

  return (
    <div className="p-6 space-y-5 w-full">
      {/* Top RAG Architecture Badges */}
      <div className="p-4 rounded-xl bg-[#0D131F] border border-indigo-500/40 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-400" />
              Contextual RAG + Semantic/Late Chunking + pgvector/BM25 RRF + Neo4j Graph RAG Studio
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Vector DB: {ragReport.vectorDbBackend} · Graph DB: {ragReport.graphDbBackend}
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
              RAGAS Overall: {(ragReport.ragasMetrics.overallRagasScore * 100).toFixed(1)}%
            </span>
            <span className="px-2.5 py-1 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
              Latency: {ragReport.latencyMs} ms
            </span>
          </div>
        </div>

        {/* Active Retrieval Techniques Pills */}
        <div className="flex flex-wrap gap-1.5">
          {ragReport.techniquesExecuted.map((tech) => (
            <span
              key={tech}
              className="px-2 py-0.5 rounded text-[10.5px] font-mono bg-indigo-950/80 text-indigo-200 border border-indigo-500/30"
            >
              ✓ {tech}
            </span>
          ))}
        </div>

        {/* Search Input Bar */}
        <div className="flex flex-col sm:flex-row gap-2 pt-1">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask any cross-cutting legal-to-AST question..."
            className="flex-1 rounded-lg bg-[#070A10] border border-slate-700 px-3.5 py-2 text-xs font-mono text-slate-100 focus:border-indigo-400 focus:outline-none"
          />
          <button
            type="button"
            disabled={isSearching}
            onClick={() => handleRunQuery()}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" />
            {isSearching ? 'Retrieving...' : 'Execute Hybrid + Graph RAG'}
          </button>
        </div>

        {/* Preset Query Chips */}
        <div className="flex flex-wrap gap-1.5">
          {SAMPLE_RAG_QUERIES.map((sq, i) => (
            <button
              key={i}
              type="button"
              onClick={() => handleRunQuery(sq)}
              className="text-left px-2.5 py-1 rounded text-[10.5px] font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 cursor-pointer truncate max-w-md"
            >
              Q{i + 1}: {sq}
            </button>
          ))}
        </div>
      </div>

      {/* HyDE Query Expansion & RAGAS Evaluation Strip */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-7 p-4 rounded-xl bg-[#0A0E17] border border-slate-800 space-y-2.5">
          <div className="text-xs font-mono font-bold uppercase text-amber-300 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" />
            Stage 1 & 2: Query Rewriting + HyDE (Hypothetical Formal SMT Document Expansion)
          </div>
          <div className="text-[11px] font-mono text-slate-300 bg-[#06090F] p-2.5 rounded border border-slate-800">
            <span className="text-indigo-400">Deontic Query Rewrite:</span>{' '}
            {ragReport.rewrittenDeonticQuery}
          </div>
          <div className="text-[11px] font-mono text-emerald-300 bg-[#06090F] p-2.5 rounded border border-slate-800">
            <span className="text-amber-400">HyDE SMT-LIB2 Hypothesis:</span>{' '}
            {ragReport.hydeHypotheticalFormalQuery}
          </div>
          <div className="p-3 rounded-lg bg-indigo-950/35 border border-indigo-500/40 text-xs text-slate-200 leading-relaxed">
            <strong className="text-indigo-300 font-mono">
              Self-RAG & CRAG Grounded Synthesis:{' '}
            </strong>
            {ragReport.synthesizedNeuroSymbolicAnswer}
          </div>
        </div>

        {/* RAGAS Metrics Card */}
        <div className="lg:col-span-5 p-4 rounded-xl bg-[#0A0E17] border border-slate-800 space-y-3">
          <div className="text-xs font-mono font-bold uppercase text-emerald-300">
            Live RAGAS & Corrective RAG (CRAG) Faithfulness Telemetry
          </div>
          <div className="space-y-2">
            {[
              { label: 'Faithfulness (Zero Hallucination)', val: ragReport.ragasMetrics.faithfulness },
              { label: 'Deontic Alignment with Z3 Proof', val: ragReport.ragasMetrics.deonticAlignmentScore },
              { label: 'Context Recall (Statute + AST)', val: ragReport.ragasMetrics.contextRecall },
              { label: 'Answer Relevance', val: ragReport.ragasMetrics.answerRelevance },
              { label: 'Context Precision', val: ragReport.ragasMetrics.contextPrecision },
            ].map((m) => (
              <div key={m.label} className="space-y-1">
                <div className="flex justify-between text-[11px] font-mono">
                  <span className="text-slate-300">{m.label}</span>
                  <span className="text-emerald-300 font-bold">{(m.val * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-indigo-500 to-emerald-400"
                    style={{ width: `${m.val * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Retrieved Contextual RAG Chunks + Knowledge Graph Triples */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            Retrieved Anthropic-Style Contextual Chunks (Reranked via Dense + BM25 + Graph RRF)
          </h3>

          {ragReport.retrievedChunks.map((item, idx) => (
            <div
              key={item.chunk.chunkId}
              className="p-3.5 rounded-xl bg-[#0B101B] border border-slate-800 space-y-2"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                    Rank #{idx + 1} · {item.chunk.sourceType}
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-100">
                    {item.chunk.citationOrPath}
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[9.5px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    {item.chunk.chunkStrategy}
                  </span>
                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Rerank: {item.crossEncoderRerankScore} · {item.cragVerdict}
                </span>
              </div>

              {/* Anthropic Contextual Prefix Highlight */}
              <div className="p-2 rounded bg-indigo-950/40 border border-indigo-500/30 text-[10.5px] font-mono text-indigo-200">
                {item.chunk.anthropicContextualPrefix}
              </div>

              {/* Raw Chunk Content */}
              <pre className="p-2.5 rounded bg-[#06090F] border border-slate-800/90 text-[11px] font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap">
                {item.chunk.rawChunkText}
              </pre>

              {/* Hybrid Scoring Breakdown */}
              <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-slate-400 pt-1">
                <span>pgvector Cosine: {item.denseVectorScore}</span>
                <span>BM25 Sparse: {item.bm25KeywordScore}</span>
                <span>Graph RAG 2-Hop Boost: +{item.graphTraversalBoost}</span>
                <span className="text-indigo-300 font-semibold">
                  Hybrid RRF: {item.rrfHybridScore}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Neo4j Knowledge Graph Triples & Cypher Queries */}
        <div className="lg:col-span-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Network className="w-4 h-4 text-emerald-400" />
            Graph RAG Knowledge Triples & Neo4j Cypher Traversal
          </h3>

          <div className="space-y-2.5">
            {ragReport.matchedGraphTriples.map((tr) => (
              <div
                key={tr.id}
                className="p-3 rounded-xl bg-[#0B101B] border border-slate-800 space-y-1.5"
              >
                <div className="flex items-center justify-between text-[10.5px] font-mono">
                  <span className="text-amber-300 font-semibold">{tr.subject}</span>
                  <span className="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300">
                    —[{tr.predicate}]→
                  </span>
                  <span className="text-emerald-300 font-semibold truncate max-w-[180px]">
                    {tr.object}
                  </span>
                </div>
                <pre className="p-2 rounded bg-[#06090F] text-[10px] font-mono text-slate-400 overflow-x-auto">
                  {tr.cypherQuerySnippet}
                </pre>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
