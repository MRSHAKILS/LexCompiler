import React from 'react';
import { Flame, GitBranch, GitPullRequest, RotateCcw, ShieldAlert, ShieldCheck } from 'lucide-react';

interface CommandBarProps {
  repositoryName: string;
  commitHash: string;
  activeLocale: 'en' | 'bn';
  isAllCompliant: boolean;
  isApplyingPatch: boolean;
  violatedClausesCount: number;
  totalZ3ExecutionMs: number;
  onSwitchLocale: (locale: 'en' | 'bn') => void;
  onSetBaseline: () => void;
  onSimulateAmendment: () => void;
  onApplyFullPR: () => void;
}

/** Repository identity, statutory corpus switch, the three demo steps, and the Z3 verdict. */
export const CommandBar: React.FC<CommandBarProps> = ({
  repositoryName,
  commitHash,
  activeLocale,
  isAllCompliant,
  isApplyingPatch,
  violatedClausesCount,
  totalZ3ExecutionMs,
  onSwitchLocale,
  onSetBaseline,
  onSimulateAmendment,
  onApplyFullPR,
}) => (
  <header className="sticky top-0 z-40 bg-[#07090E]/90 backdrop-blur-md border-b border-white/[0.07] px-5 py-3">
    <div className="flex flex-wrap items-center justify-between gap-3">
      {/* Left: Active Regime, Locale Switcher & Git Telemetry */}
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/[0.08] text-xs font-mono text-zinc-300">
          <GitBranch className="w-3.5 h-3.5 text-amber-300" aria-hidden="true" />
          <span>{repositoryName}</span>
          <span className="text-zinc-400">@</span>
          <span className="text-amber-300 font-semibold">{commitHash}</span>
        </div>

        {/* Bilingual EN / বাংলা Statutory Corpus Switcher */}
        <div role="group" aria-label="Statutory corpus" className="inline-flex items-center rounded-lg bg-white/[0.04] border border-white/[0.1] p-0.5 text-[11px] font-mono">
          <button
            type="button"
            aria-pressed={activeLocale === 'en'}
            onClick={() => onSwitchLocale('en')}
            className={`px-2 py-0.5 rounded-md transition-all cursor-pointer ${activeLocale === 'en' ? 'bg-amber-400 text-black font-bold' : 'text-zinc-400 hover:text-zinc-200'}`}
          >
            EN (Global)
          </button>
          <button
            type="button"
            lang="bn"
            aria-pressed={activeLocale === 'bn'}
            onClick={() => onSwitchLocale('bn')}
            className={`px-2.5 py-0.5 rounded-md transition-all cursor-pointer ${activeLocale === 'bn' ? 'bg-emerald-400 text-black font-bold' : 'text-zinc-300 hover:text-white'}`}
          >
            বাংলা (BD Laws)
          </button>
        </div>
      </div>

      {/* Center: 3-Step Interactive Demo Scenario Triggers */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onSetBaseline}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-white/[0.04] hover:bg-white/[0.09] text-zinc-200 border border-white/[0.09] transition-all cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
          1. Baseline (30d)
        </button>

        <button
          type="button"
          onClick={onSimulateAmendment}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-400 hover:bg-amber-300 text-black shadow-[0_0_20px_rgba(229,193,88,0.28)] transition-all cursor-pointer"
        >
          <Flame className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
          2. Simulate Regulatory Amendment (30d → 72h + KMS)
        </button>

        <button
          type="button"
          disabled={isAllCompliant || isApplyingPatch}
          onClick={onApplyFullPR}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-white/[0.04] disabled:text-zinc-600 text-black shadow-[0_0_20px_rgba(16,185,129,0.28)] border border-emerald-400/50 disabled:border-white/[0.05] transition-all cursor-pointer"
        >
          <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
          3. Auto-Remediate &amp; Prove SAT
        </button>
      </div>

      {/* Right: Z3 Formal Verdict Pill */}
      <div role="status" aria-label="Z3 verdict" className="flex items-center gap-2.5 text-xs font-mono">
        {isAllCompliant ? (
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
            <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            SAT · 100% COMPLIANT ({totalZ3ExecutionMs}ms)
          </div>
        ) : (
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/40">
            <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" aria-hidden="true" />
            UNSAT · {violatedClausesCount} VIOLATIONS ({totalZ3ExecutionMs}ms)
          </div>
        )}
      </div>
    </div>
  </header>
);
