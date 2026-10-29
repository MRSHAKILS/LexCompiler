import React from 'react';
import { Check, CheckCircle2 } from 'lucide-react';
import { prLabel } from '../../prLabel';
import type { RemediationPullRequest } from '../../../shared/types';

interface PrBundlePanelProps {
  remediationPR: RemediationPullRequest | null;
  prBlocked: boolean;
  onApplyFullPR: () => void;
}

/** The whole remediation bundle: summary, pre/post Z3 status, and every file patch. */
export const PrBundlePanel: React.FC<PrBundlePanelProps> = ({ remediationPR, prBlocked, onApplyFullPR }) => (
  <div className="space-y-3">
    {remediationPR ? (
      <div className="p-3.5 rounded-lg bg-[#05080E] border border-indigo-500/40 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                AUTO-GENERATED {prLabel(remediationPR)}
              </span>
              <span className="text-xs font-mono text-slate-400">
                {remediationPR.branchName} → {remediationPR.baseBranch}
              </span>
            </div>
            <h4 className="text-sm font-semibold text-slate-100 mt-1">{remediationPR.title}</h4>
          </div>

          <button
            type="button"
            disabled={prBlocked}
            onClick={onApplyFullPR}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-emerald-700 hover:bg-emerald-800 text-white cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Check className="w-3.5 h-3.5" aria-hidden="true" />
            {prBlocked ? 'Blocked by Z3 Gate' : `Apply All ${remediationPR.filePatches.length} Patches`}
          </button>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">{remediationPR.executiveSummary}</p>

        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">Pre-Patch Z3: {remediationPR.prePatchZ3Status}</span>
          <span className="text-slate-400" aria-hidden="true">
            →
          </span>
          <span
            className={`px-2 py-0.5 rounded border ${
              prBlocked ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
            }`}
          >
            Post-Patch Z3 Sandbox: {remediationPR.postPatchZ3Status} ({remediationPR.postPatchVerifyTimeMs} ms)
          </span>
          {prBlocked && (remediationPR.unresolvedClauseIds?.length ?? 0) > 0 && (
            <span className="text-rose-300">Unresolved: {remediationPR.unresolvedClauseIds!.join(', ')}</span>
          )}
        </div>

        <ul className="space-y-2 pt-2" aria-label="File patches">
          {remediationPR.filePatches.map((fp) => (
            <li key={fp.filePath} className="p-2.5 rounded bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-2">
              <div>
                <div className="text-xs font-mono font-semibold text-slate-200">{fp.filePath}</div>
                <div className="text-[11px] text-slate-400">{fp.summary}</div>
              </div>
              <div className="flex items-center gap-2 font-mono text-xs shrink-0">
                <span className="text-emerald-400">+{fp.linesAdded}</span>
                <span className="text-rose-400">-{fp.linesRemoved}</span>
              </div>
            </li>
          ))}
        </ul>
      </div>
    ) : (
      <div className="p-6 rounded-lg bg-emerald-950/25 border border-emerald-500/40 text-center space-y-2">
        <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" aria-hidden="true" />
        <div className="text-sm font-semibold text-emerald-200">All Statutory & Contractual Obligations Satisfied (100% SAT — Q.E.D.)</div>
        <p className="text-xs text-slate-400 max-w-lg mx-auto">
          The repository has zero active compliance violations. Trigger a Regulatory Amendment or mutate a clause on the left to test a new statutory blast radius.
        </p>
      </div>
    )}
  </div>
);
