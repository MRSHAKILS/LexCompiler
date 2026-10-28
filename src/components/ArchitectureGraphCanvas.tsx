import React from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  Cpu,
  Database,
  FileCode2,
  Globe2,
  Layers,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react';
import type {
  ArchitectureGraphEdge,
  ArchitectureGraphNode,
  ClauseVerificationProof,
} from '../../shared/types';

interface ArchitectureGraphCanvasProps {
  nodes: ArchitectureGraphNode[];
  edges: ArchitectureGraphEdge[];
  selectedNodeId: string;
  activeClauseId: string;
  shockwaveActive: boolean;
  shockwaveStage: string | null;
  proofs: ClauseVerificationProof[];
  onSelectNode: (nodeId: string) => void;
  onQuickApplyNodePatch: (nodeId: string, e: React.MouseEvent) => void;
}

// Coordinates (in percentage of canvas width/height) for clean topological layout
const NODE_POSITIONS: Record<string, { x: number; y: number; cx: number; cy: number }> = {
  'node-fastapi-endpoint': { x: 4, y: 34, cx: 18, cy: 48 },
  'node-postgres-schema': { x: 40, y: 6, cx: 54, cy: 20 },
  'node-redis-worker': { x: 40, y: 39, cx: 54, cy: 53 },
  'node-ai-engine': { x: 40, y: 71, cx: 54, cy: 85 },
  'node-cross-border': { x: 73, y: 22, cx: 86, cy: 36 },
};

export const ArchitectureGraphCanvas: React.FC<ArchitectureGraphCanvasProps> = ({
  nodes,
  edges,
  selectedNodeId,
  activeClauseId,
  shockwaveActive,
  shockwaveStage,
  proofs,
  onSelectNode,
  onQuickApplyNodePatch,
}) => {
  const activeProof = proofs.find((p) => p.clauseId === activeClauseId);

  const getNodeIcon = (role: ArchitectureGraphNode['nodeRole'], isViolation: boolean) => {
    const colorClass = isViolation ? 'text-rose-400' : 'text-emerald-400';
    switch (role) {
      case 'POSTGRES_SCHEMA':
        return <Database className={`w-4 h-4 ${colorClass}`} />;
      case 'FASTAPI_ENDPOINT':
        return <Server className={`w-4 h-4 ${colorClass}`} />;
      case 'REDIS_WORKER':
        return <Layers className={`w-4 h-4 ${colorClass}`} />;
      case 'AI_DECISION_ENGINE':
        return <Cpu className={`w-4 h-4 ${colorClass}`} />;
      case 'CROSS_BORDER_SYNC':
        return <Globe2 className={`w-4 h-4 ${colorClass}`} />;
      default:
        return <FileCode2 className={`w-4 h-4 ${colorClass}`} />;
    }
  };

  const getLangBadge = (lang: ArchitectureGraphNode['language']) => {
    switch (lang) {
      case 'python':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-mono font-medium rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">
            Python AST
          </span>
        );
      case 'sql':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-mono font-medium rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
            Postgres DDL
          </span>
        );
      case 'typescript':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-mono font-medium rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
            TS Compiler AST
          </span>
        );
    }
  };

  return (
    <div className="relative w-full h-[395px] bg-[#070A10] border-b border-slate-800/80 overflow-hidden select-none">
      {/* Subtle architectural grid background */}
      <div
        className="absolute inset-0 opacity-25 pointer-events-none"
        style={{
          backgroundImage:
            'radial-gradient(circle at 1px 1px, rgba(148, 163, 184, 0.22) 1px, transparent 0)',
          backgroundSize: '22px 22px',
        }}
      />

      {/* Top Overlay Bar: Graph Legend & Blast-Radius Telemetry */}
      <div className="relative z-20 flex items-center justify-between px-4 py-2 bg-[#0B0F19]/90 backdrop-blur border-b border-slate-800/70">
        <div className="flex items-center gap-2.5">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold tracking-wider uppercase text-slate-300">
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            Live Polyglot AST & Data-Flow Blast-Radius Graph
          </span>
          <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">
            (Click any Crimson node to inspect offending AST line & auto-remediation diff)
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="inline-flex items-center gap-1.5 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#10B981]" />
            SAT (Compliant)
          </span>
          <span className="inline-flex items-center gap-1.5 text-rose-400">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse shadow-[0_0_10px_#F43F5E]" />
            UNSAT (Violation)
          </span>
        </div>
      </div>

      {/* Shockwave Stage Banner when regulatory mutation is propagating */}
      {shockwaveStage && (
        <div className="absolute top-11 left-1/2 -translate-x-1/2 z-30 px-4 py-1.5 rounded-full bg-rose-950/95 border border-rose-500/70 text-rose-200 text-xs font-mono flex items-center gap-2 shadow-[0_0_30px_rgba(244,63,94,0.45)] animate-bounce">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span>{shockwaveStage}</span>
        </div>
      )}

      {/* Animated Shockwave Rings */}
      {shockwaveActive && (
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center z-10">
          <div className="w-72 h-72 rounded-full border-2 border-rose-500/70 bg-rose-500/10 animate-shockwave" />
          <div
            className="w-56 h-56 rounded-full border border-amber-400/60 animate-shockwave"
            style={{ animationDelay: '150ms' }}
          />
        </div>
      )}

      {/* SVG Data-Flow Edges Layer */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none z-0"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
      >
        <defs>
          <marker
            id="arrow-crimson"
            viewBox="0 0 10 10"
            refX="7"
            refY="5"
            markerWidth="4.5"
            markerHeight="4.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#F43F5E" />
          </marker>
          <marker
            id="arrow-emerald"
            viewBox="0 0 10 10"
            refX="7"
            refY="5"
            markerWidth="4.5"
            markerHeight="4.5"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#10B981" />
          </marker>
        </defs>

        {edges.map((edge) => {
          const src = NODE_POSITIONS[edge.source];
          const dst = NODE_POSITIONS[edge.target];
          if (!src || !dst) return null;

          const isEdgeViolated = edge.violatedClauseIds.length > 0;
          const isHighlightedByActiveClause =
            edge.violatedClauseIds.includes(activeClauseId);

          const midX = (src.cx + dst.cx) / 2;
          const pathD = `M ${src.cx} ${src.cy} C ${midX} ${src.cy}, ${midX} ${dst.cy}, ${dst.cx} ${dst.cy}`;

          return (
            <g key={edge.id}>
              {/* Glow under-stroke */}
              <path
                d={pathD}
                fill="none"
                stroke={isEdgeViolated ? 'rgba(244, 63, 94, 0.22)' : 'rgba(16, 185, 129, 0.16)'}
                strokeWidth={isHighlightedByActiveClause ? 1.4 : 0.8}
              />
              {/* Animated foreground flow */}
              <path
                d={pathD}
                fill="none"
                stroke={isEdgeViolated ? '#F43F5E' : '#10B981'}
                strokeWidth={isHighlightedByActiveClause ? 0.65 : 0.45}
                className="animate-edge-flow"
                markerEnd={isEdgeViolated ? 'url(#arrow-crimson)' : 'url(#arrow-emerald)'}
              />
            </g>
          );
        })}
      </svg>

      {/* Layer Column Headers */}
      <div className="absolute top-10 left-4 text-[10px] font-mono uppercase tracking-widest text-slate-500 pointer-events-none">
        Layer 1 · API Ingress
      </div>
      <div className="absolute top-10 left-[40%] text-[10px] font-mono uppercase tracking-widest text-slate-500 pointer-events-none">
        Layer 2 · Storage, Cache & AI Runtime
      </div>
      <div className="absolute top-10 left-[73%] text-[10px] font-mono uppercase tracking-widest text-slate-500 pointer-events-none">
        Layer 3 · External Replication
      </div>

      {/* Interactive Architecture Nodes */}
      {nodes.map((node) => {
        const pos = NODE_POSITIONS[node.id] || { x: 10, y: 10 };
        const isViolation = node.status === 'VIOLATION';
        const isSelected = node.id === selectedNodeId;
        const isAffectedByActiveClause =
          activeProof?.affectedGraphNodeIds.includes(node.id) ?? false;

        return (
          <div
            key={node.id}
            onClick={() => onSelectNode(node.id)}
            style={{ left: `${pos.x}%`, top: `${pos.y + 6}%` }}
            className={`absolute z-10 w-[24.5%] min-w-[215px] max-w-[275px] rounded-lg p-2.5 cursor-pointer transition-all duration-200 border backdrop-blur-md ${
              isViolation
                ? isSelected
                  ? 'bg-rose-950/85 border-rose-400 shadow-[0_0_25px_rgba(244,63,94,0.45)] ring-2 ring-rose-400/60 scale-[1.02]'
                  : 'bg-rose-950/60 border-rose-500/70 hover:border-rose-400 shadow-[0_0_16px_rgba(244,63,94,0.25)]'
                : isSelected
                ? 'bg-emerald-950/70 border-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)] ring-2 ring-emerald-400/50 scale-[1.02]'
                : 'bg-[#0F1624]/90 border-emerald-500/40 hover:border-emerald-400/80'
            }`}
          >
            {/* Top row: Icon + Label + Verdict Badge */}
            <div className="flex items-start justify-between gap-1.5 mb-1">
              <div className="flex items-center gap-1.5 min-w-0">
                {getNodeIcon(node.nodeRole, isViolation)}
                <span className="text-xs font-semibold text-slate-100 truncate">
                  {node.label}
                </span>
              </div>

              {isViolation ? (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/25 text-rose-200 border border-rose-400/50 shrink-0">
                  <AlertOctagon className="w-3 h-3 text-rose-400 animate-pulse" />
                  UNSAT
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-200 border border-emerald-400/40 shrink-0">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  SAT
                </span>
              )}
            </div>

            {/* File path & line number + language badge */}
            <div className="flex items-center justify-between gap-1 mb-1.5">
              <span className="text-[11px] font-mono text-slate-300 truncate">
                {node.filePath}:{node.line}
              </span>
              {getLangBadge(node.language)}
            </div>

            {/* Extracted AST Metrics pills */}
            <div className="flex flex-wrap gap-1 mb-1.5">
              {Object.entries(node.metrics).map(([k, v]) => {
                const isBadMetric =
                  isViolation &&
                  ((k === 'retention_ttl_hours' && String(v).startsWith('720')) ||
                    (k === 'cache_ttl_hours' && String(v).startsWith('720')) ||
                    (k === 'tenant_kms_column' && v === false) ||
                    (k === 'tenant_kms_isolated' && v === false) ||
                    (k === 'tenant_kms_envelope' && v === false) ||
                    (k === 'logs_plaintext_pii' && v === true) ||
                    (k === 'human_oversight_gate' && v === false) ||
                    (k === 'eu_sovereign' && v === false));

                return (
                  <span
                    key={k}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                      isBadMetric
                        ? 'bg-rose-500/25 text-rose-200 border border-rose-500/40 font-semibold'
                        : 'bg-slate-800/90 text-slate-300 border border-slate-700/70'
                    }`}
                  >
                    {k}: {String(v)}
                  </span>
                );
              })}
            </div>

            {/* Bottom bar: Violated clause citation or Quick Patch trigger */}
            <div className="flex items-center justify-between pt-1 border-t border-slate-800/80 text-[10px] font-mono">
              {isViolation ? (
                <>
                  <span className="text-rose-300 truncate flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3 shrink-0 text-rose-400" />
                    {node.violatedClauseIds.length} clause violation
                    {node.violatedClauseIds.length > 1 ? 's' : ''}
                    {isAffectedByActiveClause ? ' (Active Clause)' : ''}
                  </span>
                  <button
                    type="button"
                    onClick={(e) => onQuickApplyNodePatch(node.id, e)}
                    className="px-1.5 py-0.5 rounded bg-emerald-500/20 hover:bg-emerald-500/35 text-emerald-200 border border-emerald-400/50 font-semibold transition-colors shrink-0"
                    title="Apply Z3-verified AST remediation patch to this file"
                  >
                    Fix Node →
                  </button>
                </>
              ) : (
                <span className="text-emerald-300/90 flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  Z3 Proven Compliant (Q.E.D.)
                </span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
