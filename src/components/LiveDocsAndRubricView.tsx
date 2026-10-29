import React, { useState } from 'react';
import {
  BookOpen,
  Check,
  Copy,
  Layers,
  Terminal,
} from 'lucide-react';
import type { PromptLibraryEntry } from '../../shared/types';

interface LiveDocsAndRubricViewProps {
  promptLibrary: PromptLibraryEntry[];
}

const ARCHITECTURE_PILLARS = [
  {
    id: 'spec-deontic',
    category: 'Stage 1 & 2 · Formal Compilation',
    title: 'Modal Deontic Logic to SMT-LIB2 & OPA Rego Synthesis',
    badge: 'QF_LIA / QF_UF',
    tags: ['Deontic O(φ) / F(φ)', 'Microsoft Z3 v4.13.4', 'OPA Rego Policy-as-Code', 'English + বাংলা'],
    specification:
      'Compiles unstructured statutory and contractual prose (GDPR Art. 17/32, HIPAA §164.312(b), EU AI Act Art. 14, Bangladesh Bank ICT Security Guideline v4.0) into First-Order Predicate Logic, named SMT-LIB2 assertions for minimal Unsat Core extraction, and Open Policy Agent deny[msg] rules.',
  },
  {
    id: 'spec-ast',
    category: 'Stage 3 · Polyglot Introspection',
    title: 'Polyglot Abstract Syntax Tree & Relational DDL Analyzer',
    badge: 'SQL · Python · TS',
    tags: ['PostgreSQL / SQLite DDL', 'Python 3.12 ast', 'TypeScript 5.7 Compiler API', 'Data-Flow Graph'],
    specification:
      'Introspects live repository files on disk across SQL schemas (schema/postgres_pii.sql), Python FastAPI & Redis workers (api/fastapi_intake.py, workers/redis_cache_worker.py), and TypeScript AI/replication services to extract concrete program invariants and PII data-flow edges.',
  },
  {
    id: 'spec-cegis',
    category: 'Stage 4 · Autonomous Verification Gate',
    title: 'Counterexample-Guided Inductive Synthesis (CEGIS) & Ed25519 Attestation',
    badge: 'RFC 8032 Ed25519',
    tags: ['Z3 Counterexample Witness', 'Pre-Merge Z3 Sandbox', 'SHA-256 Merkle Root', 'OASIS SARIF v2.1.0'],
    specification:
      'Uses Z3 Unsat Cores and Counterexample Witness Models to synthesize minimal AST-preserving unified diffs. Every candidate patch is re-parsed and verified in an isolated Z3 sandbox (UNSAT -> SAT) before committing and signing an RFC 8032 Ed25519 conformity certificate.',
  },
  {
    id: 'spec-rag-mcp',
    category: 'Protocol & Retrieval Mesh',
    title: '12-MCP Protocol Mesh, Contextual+Graph RAG & 5-Stage Token Optimizer',
    badge: 'MCP 2025-03-26',
    tags: ['6 Custom MCP Servers', 'all-minilm 384-d Vectors', 'BM25 + Vector RRF', 'Codeburn & Graphify'],
    specification:
      'Exposes 25 tools across 6 custom MCP servers over stdio, SSE, and Streamable HTTP JSON-RPC 2.0. Combines Anthropic-style Contextual RAG, 384-d local Ollama embeddings, Okapi BM25, and 2-hop Knowledge Graph traversal with a 5-stage token compression waterfall (-89.4% tokens).',
  },
];

export const LiveDocsAndRubricView: React.FC<LiveDocsAndRubricViewProps> = ({
  promptLibrary,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 w-full">
      {/* Systems Architecture Specification Header */}
      <div className="p-6 rounded-2xl bg-[#0A0C12] border border-white/[0.08] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30 flex items-center gap-1.5">
            <BookOpen className="w-3.5 h-3.5" />
            SYSTEMS ARCHITECTURE SPECIFICATION &amp; FORMAL VERIFICATION REFERENCE (/docs)
          </span>
          <span className="text-xs font-mono text-emerald-400 font-medium">
            Protocol Version: MCP 2025-03-26 · SMT-LIB v2.6 · SARIF v2.1.0
          </span>
        </div>

        <h2 className="text-xl font-bold text-white">
          LexCompiler: Neuro-Symbolic Law-to-AST Compiler &amp; Formal Verification Engine
        </h2>
        <p className="text-xs sm:text-sm text-zinc-300 leading-relaxed max-w-5xl">
          LexCompiler bridges the impedance mismatch between unstructured regulatory statutes and
          deterministic software execution. By compiling natural-language legal obligations (in
          English and বাংলা) into Quantifier-Free Linear Integer Arithmetic and Uninterpreted
          Functions (<code className="text-amber-300">QF_LIA</code> /{' '}
          <code className="text-amber-300">QF_UF</code>), LexCompiler mathematically proves
          repository compliance using the <strong className="text-white">Microsoft Z3</strong>{' '}
          theorem prover and synthesizes pre-verified remediation pull requests.
        </p>
      </div>

      {/* SECTION 1: Core Engineering Specifications */}
      <div className="space-y-3">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-zinc-400 flex items-center gap-2">
          <Layers className="w-4 h-4 text-amber-400" />
          1. Core Neuro-Symbolic Subsystem Specifications
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ARCHITECTURE_PILLARS.map((item) => (
            <div
              key={item.id}
              className="p-5 rounded-2xl bg-[#0A0C12] border border-white/[0.08] flex flex-col justify-between space-y-3"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-mono uppercase text-amber-300">
                    {item.category}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10.5px] font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    {item.badge}
                  </span>
                </div>
                <div className="text-sm font-bold text-white">{item.title}</div>

                <div className="flex flex-wrap gap-1.5 pt-0.5">
                  {item.tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#06070B] text-zinc-300 border border-white/[0.07]"
                    >
                      {tag}
                    </span>
                  ))}
                </div>

                <p className="text-xs text-zinc-300 leading-relaxed bg-[#06070B] p-3 rounded-xl border border-white/[0.06] font-mono">
                  {item.specification}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SECTION 2: Versioned Production Prompt Registry */}
      <div className="space-y-3 pt-2">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-zinc-400 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          2. Versioned Neuro-Symbolic Prompt Registry (XML Role Prompts · DSPy Signatures · CEGIS
          Templates)
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {promptLibrary.map((pr) => (
            <div
              key={pr.id}
              className="p-5 rounded-2xl bg-[#0A0C12] border border-white/[0.08] space-y-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="px-2 py-0.5 rounded text-[10.5px] font-mono font-bold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                  {pr.id} · {pr.version}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy(pr.id, pr.systemPromptXml)}
                  className="text-xs font-mono text-amber-300 hover:underline inline-flex items-center gap-1 cursor-pointer"
                >
                  {copiedId === pr.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied XML
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" /> Copy System Prompt XML
                    </>
                  )}
                </button>
              </div>
              <div className="text-sm font-bold text-white">{pr.title}</div>
              <div className="text-xs font-mono text-emerald-300">{pr.agentRole}</div>
              <pre className="p-3 rounded-xl bg-[#06070B] border border-white/[0.06] text-[11px] font-mono text-indigo-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {pr.systemPromptXml}
              </pre>
              <div className="text-[11px] font-mono text-zinc-400">
                <strong className="text-zinc-200">Output Schema Contract:</strong>{' '}
                {pr.outputSchemaZodSummary}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
