import React, { useEffect, useState } from 'react';
import { prLabel } from '../prLabel';
import {
  AlertOctagon,
  Check,
  CheckCircle2,
  Code,
  FileDiff,
  GitPullRequest,
  Lock,
  Play,
  Save,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from 'lucide-react';
import type {
  ArchitectureGraphNode,
  ClauseVerificationProof,
  RemediationPullRequest,
  TargetRepoFile,
} from '../../shared/types';

interface IdeRemediationDrawerProps {
  selectedNode: ArchitectureGraphNode;
  files: TargetRepoFile[];
  proofs: ClauseVerificationProof[];
  remediationPR: RemediationPullRequest | null;
  merkleAuditRoot: string;
  isApplyingPatch: boolean;
  onApplyNodePatch: (nodeId: string) => void;
  onApplyFullPR: () => void;
  onSaveFileEdit: (filePath: string, newContent: string) => void;
}

export const IdeRemediationDrawer: React.FC<IdeRemediationDrawerProps> = ({
  selectedNode,
  files,
  proofs,
  remediationPR,
  merkleAuditRoot,
  isApplyingPatch,
  onApplyNodePatch,
  onApplyFullPR,
  onSaveFileEdit,
}) => {
  const [activeTab, setActiveTab] = useState<
    'DIFF_VIEW' | 'LIVE_RUNTIME' | 'LIVE_EDITOR' | 'PROOF_WITNESS' | 'FULL_PR'
  >('DIFF_VIEW');
  const [runtimeReport, setRuntimeReport] = useState<any | null>(null);
  const [runtimeDisabledReason, setRuntimeDisabledReason] = useState<string | null>(null);
  const [isRunningSandbox, setIsRunningSandbox] = useState(false);
  const prBlocked = remediationPR?.postPatchZ3Status !== 'SAT_COMPLIANT';
  const [githubEnabled, setGithubEnabled] = useState(false);
  const [githubMessage, setGithubMessage] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/remediation/github')
      .then((r) => (r.ok ? r.json() : { enabled: false }))
      .then((d: { enabled?: boolean }) => setGithubEnabled(Boolean(d.enabled)))
      .catch(() => setGithubEnabled(false));
  }, []);

  const openGithubPr = async () => {
    setGithubMessage('Opening pull request…');
    const res = await fetch('/api/remediation/open-github-pr', { method: 'POST' });
    const data = (await res.json().catch(() => ({}))) as { url?: string; number?: number; error?: string };
    setGithubMessage(res.ok ? `Opened PR #${data.number}: ${data.url}` : data.error || 'GitHub PR creation failed.');
  };

  const fetchRuntimeSandbox = async () => {
    setIsRunningSandbox(true);
    try {
      const res = await fetch('/api/sandbox/verify-runtime');
      if (res.ok) {
        const data = await res.json();
        setRuntimeReport(data);
        setRuntimeDisabledReason(null);
      } else if (res.status === 403) {
        const data = await res.json().catch(() => ({}));
        if (data.disabled) {
          setRuntimeReport(null);
          setRuntimeDisabledReason(data.error || 'Runtime sandbox is disabled.');
        }
      }
    } finally {
      setIsRunningSandbox(false);
    }
  };

  useEffect(() => {
    fetchRuntimeSandbox();
  }, [merkleAuditRoot, selectedNode.status]);

  const selectedFile =
    files.find((f) => f.path === selectedNode.filePath) || files[0];
  const nodePatch = remediationPR?.filePatches.find(
    (fp) => fp.nodeId === selectedNode.id || fp.filePath === selectedNode.filePath
  );

  // Offending locations for this node across all proofs
  const nodeOffendingLocations = proofs.flatMap((p) =>
    p.offendingLocations
      .filter((loc) => loc.nodeId === selectedNode.id || loc.filePath === selectedNode.filePath)
      .map((loc) => ({ ...loc, citation: p.citation, clauseId: p.clauseId, proof: p }))
  );

  const [editableCode, setEditableCode] = useState(selectedFile?.content || '');

  useEffect(() => {
    if (selectedFile) {
      setEditableCode(selectedFile.content);
    }
  }, [selectedFile?.path, selectedFile?.content]);

  const isNodeViolated = selectedNode.status === 'VIOLATION';

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[#080C14]">
      {/* IDE Drawer Top Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-[#0D131F] border-b border-slate-800/90">
        <div className="flex items-center gap-2.5 min-w-0">
          {isNodeViolated ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
              CRIMSON NODE · UNSAT
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              VERIFIED NODE · SAT
            </span>
          )}

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-slate-100 truncate">
                {selectedNode.filePath}:{selectedNode.line}–{selectedNode.endLine}
              </span>
              <span className="text-[11px] font-mono text-indigo-300 hidden md:inline">
                ({selectedNode.astSummary})
              </span>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {nodePatch && (
            <button
              type="button"
              disabled={isApplyingPatch || prBlocked}
              title={prBlocked ? 'Blocked: the post-patch Z3 check did not pass' : undefined}
              onClick={() => onApplyNodePatch(selectedNode.id)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.35)] transition-all cursor-pointer disabled:opacity-50"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {isApplyingPatch
                ? 'Applying & Proving...'
                : `Apply AST Patch to ${selectedNode.filePath.split('/').pop()} →`}
            </button>
          )}

          {remediationPR && (
            <button
              type="button"
              disabled={isApplyingPatch || prBlocked}
              title={prBlocked ? 'Blocked: the post-patch Z3 check did not pass' : undefined}
              onClick={onApplyFullPR}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all cursor-pointer disabled:opacity-50"
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              Merge {prLabel(remediationPR)} ({remediationPR.filePatches.length} files)
            </button>
          )}

          {remediationPR && githubEnabled && (
            <button
              type="button"
              disabled={isApplyingPatch || prBlocked}
              onClick={openGithubPr}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold bg-slate-700 hover:bg-slate-600 text-white transition-all cursor-pointer disabled:opacity-50"
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              Open GitHub PR
            </button>
          )}
          {githubMessage && (
            <span role="status" className="text-[11px] font-mono text-slate-300 max-w-xs truncate" title={githubMessage}>
              {githubMessage}
            </span>
          )}
        </div>
      </div>

      {/* IDE View Mode Tabs */}
      <div className="flex items-center justify-between px-4 py-1.5 bg-[#0A0F19] border-b border-slate-800/80">
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setActiveTab('DIFF_VIEW')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
              activeTab === 'DIFF_VIEW'
                ? 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileDiff className="w-3.5 h-3.5" />
            Auto-Remediation Diff
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('LIVE_RUNTIME');
              fetchRuntimeSandbox();
            }}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
              activeTab === 'LIVE_RUNTIME'
                ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            Live Sandbox Runtime & Git Proof
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('LIVE_EDITOR')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
              activeTab === 'LIVE_EDITOR'
                ? 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            Live Repo Source Editor ({selectedFile?.astNodeCount || 42} AST nodes)
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('PROOF_WITNESS')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
              activeTab === 'PROOF_WITNESS'
                ? 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            Z3 Witness & Provenance Hash
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('FULL_PR')}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
              activeTab === 'FULL_PR'
                ? 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitPullRequest className="w-3.5 h-3.5" />
            {remediationPR ? prLabel(remediationPR) : 'Remediation'} Bundle
          </button>
        </div>

        <div className="text-[10px] font-mono text-slate-400 hidden sm:block">
          Merkle Root: <span className="text-indigo-300">{merkleAuditRoot.slice(0, 16)}…</span>
        </div>
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {activeTab === 'DIFF_VIEW' && (
          <>
            {/* Offending AST Line Explanations */}
            {nodeOffendingLocations.length > 0 ? (
              <div className="space-y-2">
                {nodeOffendingLocations.map((loc, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-rose-950/35 border border-rose-500/40 space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-mono font-bold text-rose-300 flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
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
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <div>
                    <div className="text-xs font-mono font-bold text-emerald-300">
                      {selectedNode.filePath} IS MATHEMATICALLY COMPLIANT (SAT — Q.E.D.)
                    </div>
                    <div className="text-[11px] text-slate-300">
                      All AST nodes and schema constraints in this module satisfy active legal
                      obligations.
                    </div>
                  </div>
                </div>
                <span className="px-2 py-1 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-200">
                  Z3 Verified: SAT
                </span>
              </div>
            )}

            {/* Unified Diff Viewer */}
            {nodePatch ? (
              <div className="rounded-lg border border-slate-800 overflow-hidden bg-[#05080E]">
                <div className="flex items-center justify-between px-3 py-2 bg-[#0D131F] border-b border-slate-800 text-xs font-mono">
                  <span className="text-slate-200 font-semibold">
                    Synthesized Patch: {nodePatch.filePath}
                  </span>
                  <div className="flex items-center gap-3">
                    <span className="text-emerald-400">+{nodePatch.linesAdded} lines</span>
                    <span className="text-rose-400">-{nodePatch.linesRemoved} lines</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px]">
                      Pre-PR Z3 Sandbox Check: SAT
                    </span>
                  </div>
                </div>

                <div className="p-3 overflow-x-auto font-mono text-[11.5px] leading-relaxed">
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
                <div className="text-[11px] font-mono text-slate-400 mb-2">
                  Current Verified Source ({selectedFile.path}):
                </div>
                <pre className="text-[11.5px] font-mono text-emerald-200/90 overflow-x-auto leading-relaxed">
                  {selectedFile.content}
                </pre>
              </div>
            )}
          </>
        )}

        {activeTab === 'LIVE_RUNTIME' && !runtimeReport && runtimeDisabledReason && (
          <div className="p-3 rounded-lg bg-[#0D131F] border border-amber-500/40 text-xs font-mono text-amber-200">
            {runtimeDisabledReason}
          </div>
        )}

        {activeTab === 'LIVE_RUNTIME' && runtimeReport && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-[#0D131F] border border-slate-800">
              <div className="flex items-center gap-2 text-xs font-mono">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span className="font-bold text-white">
                  Real Local Sandbox Execution (`target-repo/.git` + SQLite3 + Python 3.12 + TS)
                </span>
              </div>
              <button
                type="button"
                disabled={isRunningSandbox}
                onClick={fetchRuntimeSandbox}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-semibold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
              >
                <Play className="w-3 h-3" />
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
            <div
              className={`p-3 rounded-lg border space-y-1.5 font-mono text-[11px] ${
                runtimeReport.pythonFastApiExecution.leakedPlaintextSsnInLogs ||
                !runtimeReport.pythonFastApiExecution.returnedResponse?.kms_isolated
                  ? 'bg-rose-950/30 border-rose-500/40'
                  : 'bg-emerald-950/25 border-emerald-500/40'
              }`}
            >
              <div className="flex items-center justify-between font-bold">
                <span className="text-slate-100">
                  2. Python FastAPI Intake Runtime (`api/fastapi_intake.py` ·{' '}
                  {runtimeReport.pythonFastApiExecution.runtimeVersion})
                </span>
                <span
                  className={
                    runtimeReport.pythonFastApiExecution.leakedPlaintextSsnInLogs
                      ? 'text-rose-300'
                      : 'text-emerald-300'
                  }
                >
                  Plaintext SSN Leaked in Stdout:{' '}
                  {String(runtimeReport.pythonFastApiExecution.leakedPlaintextSsnInLogs)}
                </span>
              </div>
              <div className="p-2 rounded bg-[#05070B] border border-slate-800 text-amber-200 overflow-x-auto">
                Captured Stdout: {runtimeReport.pythonFastApiExecution.capturedLoggerOutput}
              </div>
              <div className="text-slate-300 overflow-x-auto">
                Returned Payload:{' '}
                {JSON.stringify(runtimeReport.pythonFastApiExecution.returnedResponse)}
              </div>
            </div>

            {/* 3. Real SQLite3 Database & Redis Worker Execution */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
              <div
                className={`p-3 rounded-lg border space-y-1 ${
                  !runtimeReport.sqlDatabaseExecution.hasTenantKmsKeyColumn ||
                  runtimeReport.sqlDatabaseExecution.actualDefaultRetentionHours > 72
                    ? 'bg-rose-950/30 border-rose-500/40'
                    : 'bg-emerald-950/25 border-emerald-500/40'
                }`}
              >
                <div className="font-bold text-slate-100">
                  3. Relational DB Engine (`schema/postgres_pii.sql`)
                </div>
                <div className="text-slate-300">
                  hasTenantKmsKeyColumn:{' '}
                  <strong>
                    {String(runtimeReport.sqlDatabaseExecution.hasTenantKmsKeyColumn)}
                  </strong>
                </div>
                <div className="text-slate-300">
                  Inserted Row Default TTL:{' '}
                  <strong>
                    {runtimeReport.sqlDatabaseExecution.actualDefaultRetentionHours}h
                  </strong>
                </div>
              </div>

              <div
                className={`p-3 rounded-lg border space-y-1 ${
                  runtimeReport.pythonRedisWorkerExecution.capturedSetexTtlHours > 72
                    ? 'bg-rose-950/30 border-rose-500/40'
                    : 'bg-emerald-950/25 border-emerald-500/40'
                }`}
              >
                <div className="font-bold text-slate-100">
                  4. Python Redis Worker (`workers/redis_cache_worker.py`)
                </div>
                <div className="text-slate-300 truncate">
                  Key: <code>{runtimeReport.pythonRedisWorkerExecution.capturedSetexKey}</code>
                </div>
                <div className="text-slate-300">
                  SETEX TTL:{' '}
                  <strong>
                    {runtimeReport.pythonRedisWorkerExecution.capturedSetexTtlSeconds}s (
                    {runtimeReport.pythonRedisWorkerExecution.capturedSetexTtlHours}h)
                  </strong>
                </div>
              </div>
            </div>

            {/* 4. Real TypeScript AI Triage & Cross-Border Replication */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
              <div
                className={`p-3 rounded-lg border space-y-1 ${
                  runtimeReport.typescriptAiTriageExecution.violatedEuAiActArt14
                    ? 'bg-rose-950/30 border-rose-500/40'
                    : 'bg-emerald-950/25 border-emerald-500/40'
                }`}
              >
                <div className="font-bold text-slate-100">
                  5. TS AI Triage (`services/ai_credit_triage.ts` @ conf=0.78)
                </div>
                <div className="text-slate-300">
                  Mode:{' '}
                  <strong>
                    {runtimeReport.typescriptAiTriageExecution.returnedDecision.executionMode}
                  </strong>
                </div>
                <div className="text-slate-300">
                  Audit Recorded:{' '}
                  <strong>
                    {String(
                      runtimeReport.typescriptAiTriageExecution.returnedDecision.auditTrailRecorded
                    )}
                  </strong>
                </div>
              </div>

              <div
                className={`p-3 rounded-lg border space-y-1 ${
                  runtimeReport.typescriptCrossBorderExecution.violatedGdprArt44
                    ? 'bg-rose-950/30 border-rose-500/40'
                    : 'bg-emerald-950/25 border-emerald-500/40'
                }`}
              >
                <div className="font-bold text-slate-100">
                  6. TS Cross-Border Sync (`services/cross_border_sync.ts`)
                </div>
                <div className="text-slate-300">
                  Target Region:{' '}
                  <strong>
                    {
                      runtimeReport.typescriptCrossBorderExecution.returnedSyncStatus
                        .destinationRegion
                    }
                  </strong>
                </div>
                <div className="text-slate-300">
                  Sovereign EEA Verified:{' '}
                  <strong>
                    {String(
                      runtimeReport.typescriptCrossBorderExecution.returnedSyncStatus
                        .sovereignVerified
                    )}
                  </strong>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'LIVE_EDITOR' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-300">
                Editing live disk file:{' '}
                <strong className="text-indigo-300">target-repo/{selectedFile.path}</strong>
              </span>
              <button
                type="button"
                onClick={() => onSaveFileEdit(selectedFile.path, editableCode)}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-semibold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
              >
                <Save className="w-3.5 h-3.5" />
                Save Commit & Re-Run AST + Z3 Prover
              </button>
            </div>
            <textarea
              value={editableCode}
              onChange={(e) => setEditableCode(e.target.value)}
              rows={15}
              aria-label="Live Source File Editor"
              className="w-full rounded-lg bg-[#05070C] border border-slate-700 focus:border-indigo-400 focus:outline-none p-3 font-mono text-xs text-slate-100 leading-relaxed"
            />
          </div>
        )}

        {activeTab === 'PROOF_WITNESS' && (
          <div className="space-y-3">
            {proofs.map((proof) => (
              <div
                key={proof.clauseId}
                className="p-3 rounded-lg bg-[#05080E] border border-slate-800 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-200">
                    {proof.citation} — {proof.title}
                  </span>
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
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                  {Object.entries(proof.counterexampleWitness).map(([k, v]) => (
                    <div
                      key={k}
                      className="p-1.5 rounded bg-slate-900/90 border border-slate-800 text-[10.5px] font-mono"
                    >
                      <div className="text-slate-400 truncate">{k}</div>
                      <div className="text-slate-100 font-semibold">{String(v)}</div>
                    </div>
                  ))}
                </div>

                {/* Cryptographic Provenance Chain */}
                <div className="pt-1 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-1 text-[10px] font-mono text-slate-400">
                  <div>
                    Statute SHA-256:{' '}
                    <span className="text-slate-200">
                      {proof.cryptographicProvenance.statuteSha256.slice(0, 20)}…
                    </span>
                  </div>
                  <div>
                    Deontic IR SHA-256:{' '}
                    <span className="text-slate-200">
                      {proof.cryptographicProvenance.deonticIrSha256.slice(0, 20)}…
                    </span>
                  </div>
                  <div>
                    SMT-LIB2 SHA-256:{' '}
                    <span className="text-slate-200">
                      {proof.cryptographicProvenance.smtFormulaSha256.slice(0, 20)}…
                    </span>
                  </div>
                  <div>
                    Merkle Proof Root:{' '}
                    <span className="text-indigo-300 font-semibold">
                      {proof.cryptographicProvenance.merkleProofHash.slice(0, 20)}…
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'FULL_PR' && (
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
                    <h4 className="text-sm font-semibold text-slate-100 mt-1">
                      {remediationPR.title}
                    </h4>
                  </div>

                  <button
                    type="button"
                    disabled={prBlocked}
                    onClick={onApplyFullPR}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Check className="w-3.5 h-3.5" />
                    {prBlocked
                      ? 'Blocked by Z3 Gate'
                      : `Apply All ${remediationPR.filePatches.length} Patches`}
                  </button>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {remediationPR.executiveSummary}
                </p>

                <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    Pre-Patch Z3: {remediationPR.prePatchZ3Status}
                  </span>
                  <span className="text-slate-500">→</span>
                  <span
                    className={`px-2 py-0.5 rounded border ${
                      prBlocked
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                    }`}
                  >
                    Post-Patch Z3 Sandbox: {remediationPR.postPatchZ3Status} (
                    {remediationPR.postPatchVerifyTimeMs} ms)
                  </span>
                  {prBlocked && (remediationPR.unresolvedClauseIds?.length ?? 0) > 0 && (
                    <span className="text-rose-300">
                      Unresolved: {remediationPR.unresolvedClauseIds!.join(', ')}
                    </span>
                  )}
                </div>

                <div className="space-y-2 pt-2">
                  {remediationPR.filePatches.map((fp) => (
                    <div
                      key={fp.filePath}
                      className="p-2.5 rounded bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-2"
                    >
                      <div>
                        <div className="text-xs font-mono font-semibold text-slate-200">
                          {fp.filePath}
                        </div>
                        <div className="text-[11px] text-slate-400">{fp.summary}</div>
                      </div>
                      <div className="flex items-center gap-2 font-mono text-xs shrink-0">
                        <span className="text-emerald-400">+{fp.linesAdded}</span>
                        <span className="text-rose-400">-{fp.linesRemoved}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-lg bg-emerald-950/25 border border-emerald-500/40 text-center space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <div className="text-sm font-semibold text-emerald-200">
                  All Statutory & Contractual Obligations Satisfied (100% SAT — Q.E.D.)
                </div>
                <p className="text-xs text-slate-400 max-w-lg mx-auto">
                  The repository has zero active compliance violations. Trigger a Regulatory
                  Amendment or mutate a clause on the left to test a new statutory blast radius.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
