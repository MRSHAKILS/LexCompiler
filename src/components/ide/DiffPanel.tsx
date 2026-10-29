import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import type { ArchitectureGraphNode, ClauseVerificationProof, FilePatchDiff, TargetRepoFile } from '../../../shared/types';

export type OffendingLocation = ClauseVerificationProof['offendingLocations'][number] & { citation: string };

interface DiffPanelProps {
  selectedNode: ArchitectureGraphNode;
  selectedFile: TargetRepoFile;
  nodePatch: FilePatchDiff | undefined;
  offendingLocations: OffendingLocation[];
}

/** Why the node violates which clause, and the synthesized patch as a unified diff. */
export const DiffPanel: React.FC<DiffPanelProps> = ({ selectedNode, selectedFile, nodePatch, offendingLocations }) => (
  <>
    {/* Offending AST Line Explanations */}
    {offendingLocations.length > 0 ? (
      <div className="space-y-2">
        {offendingLocations.map((loc, idx) => (
          <div key={idx} className="p-3 rounded-lg bg-rose-950/35 border border-rose-500/40 space-y-1.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono font-bold text-rose-300 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
                VIOLATION OF {loc.citation} AT {loc.filePath}:{loc.line}–{loc.endLine}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-200 border border-rose-500/30">
                AST Node: {loc.astNodeType}
              </span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed">{loc.explanation}</p>
            <div className="text-[11px] font-mono text-emerald-300 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1 rounded">
              ✓ Synthesized AST Fix: {loc.remediationPreview}
            </div>
          </div>
        ))}
      </div>
    ) : (
      <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/40 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" aria-hidden="true" />
          <div>
            <div className="text-xs font-mono font-bold text-emerald-300">
              {selectedNode.filePath} IS MATHEMATICALLY COMPLIANT (SAT — Q.E.D.)
            </div>
            <div className="text-[11px] text-slate-300">
              All AST nodes and schema constraints in this module satisfy active legal obligations.
            </div>
          </div>
        </div>
        <span className="px-2 py-1 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-200">Z3 Verified: SAT</span>
      </div>
    )}

    {/* Unified Diff Viewer */}
    {nodePatch ? (
      <div className="rounded-lg border border-slate-800 overflow-hidden bg-[#05080E]">
        <div className="flex items-center justify-between px-3 py-2 bg-[#0D131F] border-b border-slate-800 text-xs font-mono">
          <span className="text-slate-200 font-semibold">Synthesized Patch: {nodePatch.filePath}</span>
          <div className="flex items-center gap-3">
            <span className="text-emerald-400">+{nodePatch.linesAdded} lines</span>
            <span className="text-rose-400">-{nodePatch.linesRemoved} lines</span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px]">
              Pre-PR Z3 Sandbox Check: SAT
            </span>
          </div>
        </div>

        <div className="p-3 overflow-x-auto font-mono text-[11.5px] leading-relaxed" aria-label={`Unified diff of ${nodePatch.filePath}`} role="region" tabIndex={0}>
          {nodePatch.unifiedDiff.split('\n').map((line, i) => {
            const isAdd = line.startsWith('+') && !line.startsWith('+++');
            const isRem = line.startsWith('-') && !line.startsWith('---');
            const isHunk = line.startsWith('@@');
            return (
              <div
                key={i}
                className={`px-2 py-0.5 whitespace-pre rounded-xs ${
                  isAdd
                    ? 'bg-emerald-500/15 text-emerald-200 border-l-2 border-emerald-400'
                    : isRem
                    ? 'bg-rose-500/20 text-rose-200 border-l-2 border-rose-500'
                    : isHunk
                    ? 'text-indigo-400 bg-indigo-950/30 my-1'
                    : 'text-slate-400'
                }`}
              >
                {line}
              </div>
            );
          })}
        </div>
      </div>
    ) : (
      <div className="rounded-lg border border-slate-800 bg-[#05080E] p-3">
        <div className="text-[11px] font-mono text-slate-400 mb-2">Current Verified Source ({selectedFile.path}):</div>
        <pre className="text-[11.5px] font-mono text-emerald-200/90 overflow-x-auto leading-relaxed" tabIndex={0}>
          {selectedFile.content}
        </pre>
      </div>
    )}
  </>
);
