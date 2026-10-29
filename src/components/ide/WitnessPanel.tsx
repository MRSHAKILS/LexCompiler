import React from 'react';
import type { ClauseVerificationProof } from '../../../shared/types';

/** Per-clause Z3 verdict, counterexample witness, and the cryptographic provenance chain. */
export const WitnessPanel: React.FC<{ proofs: ClauseVerificationProof[] }> = ({ proofs }) => (
  <div className="space-y-3">
    {proofs.map((proof) => (
      <section key={proof.clauseId} aria-label={`${proof.citation} proof`} className="p-3 rounded-lg bg-[#05080E] border border-slate-800 space-y-2">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-mono font-bold text-slate-200">
            {proof.citation} — {proof.title}
          </h4>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
              proof.status === 'UNSAT_VIOLATION'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
            }`}
          >
            Z3: {proof.z3SolverStatus.toUpperCase()} ({proof.z3SolveTimeMs} ms)
          </span>
        </div>

        {/* Counterexample Witness Assignments */}
        <dl className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
          {Object.entries(proof.counterexampleWitness).map(([k, v]) => (
            <div key={k} className="p-1.5 rounded bg-slate-900/90 border border-slate-800 text-[10.5px] font-mono">
              <dt className="text-slate-400 truncate">{k}</dt>
              <dd className="text-slate-100 font-semibold">{String(v)}</dd>
            </div>
          ))}
        </dl>

        {/* Cryptographic Provenance Chain */}
        <div className="pt-1 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-1 text-[10px] font-mono text-slate-400">
          <div>
            Statute SHA-256: <span className="text-slate-200">{proof.cryptographicProvenance.statuteSha256.slice(0, 20)}…</span>
          </div>
          <div>
            Deontic IR SHA-256: <span className="text-slate-200">{proof.cryptographicProvenance.deonticIrSha256.slice(0, 20)}…</span>
          </div>
          <div>
            SMT-LIB2 SHA-256: <span className="text-slate-200">{proof.cryptographicProvenance.smtFormulaSha256.slice(0, 20)}…</span>
          </div>
          <div>
            Merkle Proof Root: <span className="text-indigo-300 font-semibold">{proof.cryptographicProvenance.merkleProofHash.slice(0, 20)}…</span>
          </div>
        </div>
      </section>
    ))}
  </div>
);
