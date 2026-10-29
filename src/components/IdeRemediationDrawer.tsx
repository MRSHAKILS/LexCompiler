import React, { useEffect, useState } from 'react';
import { prLabel } from '../prLabel';
import { AlertOctagon, CheckCircle2, Code, FileDiff, GitPullRequest, Lock, Sparkles, Terminal } from 'lucide-react';
import type {
  ArchitectureGraphNode,
  ClauseVerificationProof,
  RemediationPullRequest,
  TargetRepoFile,
} from '../../shared/types';
import { useRovingTabs } from './a11y/useRovingTabs';
import { DiffPanel } from './ide/DiffPanel';
import { EditorPanel } from './ide/EditorPanel';
import { PrBundlePanel } from './ide/PrBundlePanel';
import { RuntimePanel, type SandboxRuntimeReport } from './ide/RuntimePanel';
import { WitnessPanel } from './ide/WitnessPanel';

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

const TABS = ['DIFF_VIEW', 'LIVE_RUNTIME', 'LIVE_EDITOR', 'PROOF_WITNESS', 'FULL_PR'] as const;
type DrawerTab = (typeof TABS)[number];

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
  const [activeTab, setActiveTab] = useState<DrawerTab>('DIFF_VIEW');
  const [runtimeReport, setRuntimeReport] = useState<SandboxRuntimeReport | null>(null);
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

  const selectedFile = files.find((f) => f.path === selectedNode.filePath) || files[0];
  const nodePatch = remediationPR?.filePatches.find((fp) => fp.nodeId === selectedNode.id || fp.filePath === selectedNode.filePath);

  // Offending locations for this node across all proofs
  const nodeOffendingLocations = proofs.flatMap((p) =>
    p.offendingLocations
      .filter((loc) => loc.nodeId === selectedNode.id || loc.filePath === selectedNode.filePath)
      .map((loc) => ({ ...loc, citation: p.citation }))
  );

  const isNodeViolated = selectedNode.status === 'VIOLATION';

  const selectTab = (tab: DrawerTab) => {
    setActiveTab(tab);
    if (tab === 'LIVE_RUNTIME') fetchRuntimeSandbox();
  };
  const tabs = useRovingTabs('ide-drawer', TABS, activeTab, selectTab);
  const tabClass = (tab: DrawerTab, activeColour: 'indigo' | 'emerald') =>
    `inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
      activeTab === tab
        ? activeColour === 'emerald'
          ? 'bg-emerald-500/20 text-emerald-200 border border-emerald-500/40'
          : 'bg-indigo-500/20 text-indigo-200 border border-indigo-500/40'
        : 'text-slate-400 hover:text-slate-200'
    }`;

  return (
    <section aria-label="Remediation workbench" className="flex-1 flex flex-col min-h-0 bg-[#080C14]">
      {/* IDE Drawer Top Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-[#0D131F] border-b border-slate-800/90">
        <div className="flex items-center gap-2.5 min-w-0">
          {isNodeViolated ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />
              CRIMSON NODE · UNSAT
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
              VERIFIED NODE · SAT
            </span>
          )}

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-slate-100 truncate">
                {selectedNode.filePath}:{selectedNode.line}–{selectedNode.endLine}
              </span>
              <span className="text-[11px] font-mono text-indigo-300 hidden md:inline">({selectedNode.astSummary})</span>
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
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-semibold bg-emerald-700 hover:bg-emerald-800 text-white shadow-[0_0_15px_rgba(16,185,129,0.35)] transition-all cursor-pointer disabled:opacity-50"
            >
              <Sparkles className="w-3.5 h-3.5" aria-hidden="true" />
              {isApplyingPatch ? 'Applying & Proving...' : `Apply AST Patch to ${selectedNode.filePath.split('/').pop()} →`}
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
              <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
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
              <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
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
        <div className="flex items-center gap-1" aria-label="Remediation views" {...tabs.tabListProps}>
          <button {...tabs.tabProps('DIFF_VIEW')} className={tabClass('DIFF_VIEW', 'indigo')}>
            <FileDiff className="w-3.5 h-3.5" aria-hidden="true" />
            Auto-Remediation Diff
          </button>
          <button {...tabs.tabProps('LIVE_RUNTIME')} className={tabClass('LIVE_RUNTIME', 'emerald')}>
            <Terminal className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
            Live Sandbox Runtime & Git Proof
          </button>
          <button {...tabs.tabProps('LIVE_EDITOR')} className={tabClass('LIVE_EDITOR', 'indigo')}>
            <Code className="w-3.5 h-3.5" aria-hidden="true" />
            Live Repo Source Editor ({selectedFile?.astNodeCount || 42} AST nodes)
          </button>
          <button {...tabs.tabProps('PROOF_WITNESS')} className={tabClass('PROOF_WITNESS', 'indigo')}>
            <Lock className="w-3.5 h-3.5" aria-hidden="true" />
            Z3 Witness & Provenance Hash
          </button>
          <button {...tabs.tabProps('FULL_PR')} className={tabClass('FULL_PR', 'indigo')}>
            <GitPullRequest className="w-3.5 h-3.5" aria-hidden="true" />
            {remediationPR ? prLabel(remediationPR) : 'Remediation'} Bundle
          </button>
        </div>

        <div className="text-[10px] font-mono text-slate-400 hidden sm:block">
          Merkle Root: <span className="text-indigo-300">{merkleAuditRoot.slice(0, 16)}…</span>
        </div>
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3" {...tabs.panelProps(activeTab)}>
        {activeTab === 'DIFF_VIEW' && (
          <DiffPanel selectedNode={selectedNode} selectedFile={selectedFile} nodePatch={nodePatch} offendingLocations={nodeOffendingLocations} />
        )}
        {activeTab === 'LIVE_RUNTIME' && (
          <RuntimePanel runtimeReport={runtimeReport} runtimeDisabledReason={runtimeDisabledReason} isRunningSandbox={isRunningSandbox} onRerun={fetchRuntimeSandbox} />
        )}
        {activeTab === 'LIVE_EDITOR' && selectedFile && <EditorPanel file={selectedFile} onSave={onSaveFileEdit} />}
        {activeTab === 'PROOF_WITNESS' && <WitnessPanel proofs={proofs} />}
        {activeTab === 'FULL_PR' && <PrBundlePanel remediationPR={remediationPR} prBlocked={prBlocked} onApplyFullPR={onApplyFullPR} />}
      </div>
    </section>
  );
};
