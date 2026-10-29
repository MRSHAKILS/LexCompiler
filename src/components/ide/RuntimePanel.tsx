import React from 'react';
import { Play, Terminal } from 'lucide-react';

/** RealWorldSandboxReport (server/sandbox/realWorldSandbox.ts), as returned by /api/sandbox/verify-runtime. */
export type SandboxRuntimeReport = any;

interface RuntimePanelProps {
  runtimeReport: SandboxRuntimeReport | null;
  runtimeDisabledReason: string | null;
  isRunningSandbox: boolean;
  onRerun: () => void;
}

const card = (bad: boolean) => (bad ? 'bg-rose-950/30 border-rose-500/40' : 'bg-emerald-950/25 border-emerald-500/40');

/** Live output of the runtime sandbox: Git history, FastAPI, the database, Redis, and both TS services. */
export const RuntimePanel: React.FC<RuntimePanelProps> = ({ runtimeReport, runtimeDisabledReason, isRunningSandbox, onRerun }) => {
  if (!runtimeReport) {
    return runtimeDisabledReason ? (
      <div className="p-3 rounded-lg bg-[#0D131F] border border-amber-500/40 text-xs font-mono text-amber-200">{runtimeDisabledReason}</div>
    ) : (
      <div role="status" className="text-xs font-mono text-slate-300">
        {isRunningSandbox ? 'Executing the target app in the sandbox…' : 'No sandbox run yet.'}
      </div>
    );
  }
  const py = runtimeReport.pythonFastApiExecution;
  const sql = runtimeReport.sqlDatabaseExecution;
  const redis = runtimeReport.pythonRedisWorkerExecution;
  const ai = runtimeReport.typescriptAiTriageExecution;
  const egress = runtimeReport.typescriptCrossBorderExecution;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-[#0D131F] border border-slate-800">
        <div className="flex items-center gap-2 text-xs font-mono">
          <Terminal className="w-4 h-4 text-emerald-400" aria-hidden="true" />
          <span className="font-bold text-white">Real Local Sandbox Execution (`target-repo/.git` + SQLite3 + Python 3.12 + TS)</span>
        </div>
        <button
          type="button"
          disabled={isRunningSandbox}
          onClick={onRerun}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-semibold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
        >
          <Play className="w-3 h-3" aria-hidden="true" />
          {isRunningSandbox ? 'Executing...' : 'Re-Execute Target App in Sandbox'}
        </button>
      </div>

      {/* 1. Real Git Repository State */}
      <div className="p-3 rounded-lg bg-[#05080E] border border-slate-800 space-y-1.5 font-mono text-[11px]">
        <div className="flex items-center justify-between text-indigo-300 font-bold">
          <span>1. Real Local Git Repository (`target-repo/.git`)</span>
          <span>
            Branch: {runtimeReport.git.branch} @ {runtimeReport.git.headCommit}
          </span>
        </div>
        <div className="text-slate-300 space-y-0.5">
          {runtimeReport.git.commitLog.map((logLine: string, idx: number) => (
            <div key={idx} className="truncate">
              • {logLine}
            </div>
          ))}
        </div>
      </div>

      {/* 2. Real Python FastAPI & Logger Execution */}
      <div className={`p-3 rounded-lg border space-y-1.5 font-mono text-[11px] ${card(py.leakedPlaintextSsnInLogs || !py.returnedResponse?.kms_isolated)}`}>
        <div className="flex items-center justify-between font-bold">
          <span className="text-slate-100">
            2. Python FastAPI Intake Runtime (`api/fastapi_intake.py` · {py.runtimeVersion})
          </span>
          <span className={py.leakedPlaintextSsnInLogs ? 'text-rose-300' : 'text-emerald-300'}>
            Plaintext SSN Leaked in Stdout: {String(py.leakedPlaintextSsnInLogs)}
          </span>
        </div>
        <div className="p-2 rounded bg-[#05070B] border border-slate-800 text-amber-200 overflow-x-auto">Captured Stdout: {py.capturedLoggerOutput}</div>
        <div className="text-slate-300 overflow-x-auto">Returned Payload: {JSON.stringify(py.returnedResponse)}</div>
      </div>

      {/* 3. Real SQLite3 Database & Redis Worker Execution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
        <div className={`p-3 rounded-lg border space-y-1 ${card(!sql.hasTenantKmsKeyColumn || sql.actualDefaultRetentionHours > 72)}`}>
          <div className="font-bold text-slate-100">3. Relational DB Engine (`schema/postgres_pii.sql`)</div>
          <div className="text-slate-300">
            hasTenantKmsKeyColumn: <strong>{String(sql.hasTenantKmsKeyColumn)}</strong>
          </div>
          <div className="text-slate-300">
            Inserted Row Default TTL: <strong>{sql.actualDefaultRetentionHours}h</strong>
          </div>
        </div>

        <div className={`p-3 rounded-lg border space-y-1 ${card(redis.capturedSetexTtlHours > 72)}`}>
          <div className="font-bold text-slate-100">4. Python Redis Worker (`workers/redis_cache_worker.py`)</div>
          <div className="text-slate-300 truncate">
            Key: <code>{redis.capturedSetexKey}</code>
          </div>
          <div className="text-slate-300">
            SETEX TTL:{' '}
            <strong>
              {redis.capturedSetexTtlSeconds}s ({redis.capturedSetexTtlHours}h)
            </strong>
          </div>
        </div>
      </div>

      {/* 4. Real TypeScript AI Triage & Cross-Border Replication */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
        <div className={`p-3 rounded-lg border space-y-1 ${card(ai.violatedEuAiActArt14)}`}>
          <div className="font-bold text-slate-100">5. TS AI Triage (`services/ai_credit_triage.ts` @ conf=0.78)</div>
          <div className="text-slate-300">
            Mode: <strong>{ai.returnedDecision.executionMode}</strong>
          </div>
          <div className="text-slate-300">
            Audit Recorded: <strong>{String(ai.returnedDecision.auditTrailRecorded)}</strong>
          </div>
        </div>

        <div className={`p-3 rounded-lg border space-y-1 ${card(egress.violatedGdprArt44)}`}>
          <div className="font-bold text-slate-100">6. TS Cross-Border Sync (`services/cross_border_sync.ts`)</div>
          <div className="text-slate-300">
            Target Region: <strong>{egress.returnedSyncStatus.destinationRegion}</strong>
          </div>
          <div className="text-slate-300">
            Sovereign EEA Verified: <strong>{String(egress.returnedSyncStatus.sovereignVerified)}</strong>
          </div>
        </div>
      </div>
    </div>
  );
};
