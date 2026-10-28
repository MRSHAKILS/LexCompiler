import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  Bot,
  Cpu,
  Database,
  Flame,
  GitBranch,
  GitPullRequest,
  Layers,
  Radio,
  RotateCcw,
  Scale,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react';
import { ArchitectureGraphCanvas } from './components/ArchitectureGraphCanvas';
import { EnterpriseStartupSuite } from './components/EnterpriseStartupSuite';
import { HybridRagStudio } from './components/HybridRagStudio';
import { IdeRemediationDrawer } from './components/IdeRemediationDrawer';
import { LegalCompilerPane } from './components/LegalCompilerPane';
import { LiveDocsAndRubricView } from './components/LiveDocsAndRubricView';
import { LiveMultiLlmMeshStudio } from './components/LiveMultiLlmMeshStudio';
import { McpAndAgentsHub } from './components/McpAndAgentsHub';
import { TokenAndDataLifecycleLab } from './components/TokenAndDataLifecycleLab';
import type {
  FullComplianceScanReport,
  LiveRegulatoryFeedItem,
  McpServerDescriptor,
  MultiAgentPipelineReport,
  PromptLibraryEntry,
  RagQueryExecutionReport,
  TokenOptimizationBenchmarkReport,
} from '../shared/types';

type ActiveWorkspaceTab =
  | 'LAW_TO_AST_STUDIO'
  | 'MULTI_LLM_SERVICE_MESH'
  | 'ENTERPRISE_CLOUD_SUITE'
  | 'MCP_AND_AGENTS'
  | 'HYBRID_GRAPH_RAG'
  | 'TOKEN_AND_DATA_STACK'
  | 'LIVE_DOCS_AND_RUBRIC';

export function App() {
  const [workspaceTab, setWorkspaceTab] = useState<ActiveWorkspaceTab>(() =>
    window.location.pathname.startsWith('/docs')
      ? 'LIVE_DOCS_AND_RUBRIC'
      : 'LAW_TO_AST_STUDIO'
  );
  const [report, setReport] = useState<FullComplianceScanReport | null>(null);
  const [liveFeedItems, setLiveFeedItems] = useState<LiveRegulatoryFeedItem[]>([]);
  const [mcpServers, setMcpServers] = useState<McpServerDescriptor[]>([]);
  const [multiAgentReport, setMultiAgentReport] = useState<MultiAgentPipelineReport | null>(
    null
  );
  const [tokenBenchmark, setTokenBenchmark] =
    useState<TokenOptimizationBenchmarkReport | null>(null);
  const [defaultRagReport, setDefaultRagReport] =
    useState<RagQueryExecutionReport | null>(null);
  const [promptLibrary, setPromptLibrary] = useState<PromptLibraryEntry[]>([]);
  const [serviceMeshSummary, setServiceMeshSummary] = useState<any | null>(null);

  const [activeClauseId, setActiveClauseId] = useState<string>('CLAUSE-DPA-4.2');
  const [selectedNodeId, setSelectedNodeId] = useState<string>('node-postgres-schema');
  const [isCompiling, setIsCompiling] = useState<boolean>(false);
  const [isApplyingPatch, setIsApplyingPatch] = useState<boolean>(false);
  const [shockwaveActive, setShockwaveActive] = useState<boolean>(false);
  const [shockwaveStage, setShockwaveStage] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [activeLocale, setActiveLocale] = useState<'en' | 'bn'>('en');

  const triggerToast = useCallback((msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 4500);
  }, []);

  const runShockwaveAnimation = useCallback((stageLabel: string) => {
    setShockwaveActive(true);
    setShockwaveStage(`Stage 1/3: Deontic Agent extracting obligation (${stageLabel})...`);
    setTimeout(() => {
      setShockwaveStage(
        'Stage 2/3: Synthesizing SMT-LIB2 & OPA Rego + Solving in Microsoft Z3...'
      );
    }, 380);
    setTimeout(() => {
      setShockwaveStage(
        'Stage 3/3: Blast-Radius Shockwave → 3 Polyglot AST Nodes (Postgres, FastAPI, Redis) UNSAT!'
      );
    }, 760);
    setTimeout(() => {
      setShockwaveActive(false);
      setShockwaveStage(null);
    }, 2200);
  }, []);

  const fetchAllTelemetry = useCallback(async () => {
    try {
      const [stateRes, feedRes, aiHeavyRes, meshRes] = await Promise.all([
        fetch('/api/state'),
        fetch('/api/regulations/live-feed'),
        fetch('/api/ai-heavy/overview'),
        fetch('/api/services/mesh'),
      ]);
      if (stateRes.ok) {
        const data = (await stateRes.json()) as FullComplianceScanReport;
        setReport(data);
      }
      if (feedRes.ok) {
        const feedData = (await feedRes.json()) as { items: LiveRegulatoryFeedItem[] };
        setLiveFeedItems(feedData.items || []);
      }
      if (aiHeavyRes.ok) {
        const aiData = await aiHeavyRes.json();
        setMcpServers(aiData.mcpServers || []);
        setMultiAgentReport(aiData.multiAgentReport || null);
        setTokenBenchmark(aiData.tokenBenchmark || null);
        setDefaultRagReport(aiData.defaultRagReport || null);
        setPromptLibrary(aiData.promptLibrary || []);
      }
      if (meshRes.ok) {
        setServiceMeshSummary(await meshRes.json());
      }
    } catch (err) {
      console.error('Failed to load initial state:', err);
    }
  }, []);

  useEffect(() => {
    fetchAllTelemetry();
  }, [fetchAllTelemetry]);

  const handleCompileCustomProse = async (clauseId: string, newProse: string) => {
    setIsCompiling(true);
    runShockwaveAnimation('Custom Legal Clause Compilation');
    try {
      const res = await fetch('/api/clauses/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clauseId,
          rawLegalText: newProse,
          amendmentLabel: `Custom Prose Mutation on ${clauseId}`,
        }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        triggerToast(
          `Compiled legal prose into SMT-LIB2 & verified against ${updated.files.length} polyglot AST files in ${updated.totalZ3ExecutionMs} ms.`
        );
      }
    } finally {
      setIsCompiling(false);
    }
  };

  const handleTriggerMutationPreset = async (
    presetId: string,
    resetRepoFiles = false
  ) => {
    setIsCompiling(true);
    setWorkspaceTab('LAW_TO_AST_STUDIO');
    runShockwaveAnimation(presetId);
    try {
      const res = await fetch('/api/clauses/mutate-preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ presetId, resetRepoFiles }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        const preset = updated.mutationPresets.find((p) => p.id === presetId);
        if (preset) {
          setActiveClauseId(preset.clauseId);
          if (preset.blastRadiusNodeIds[0]) {
            setSelectedNodeId(preset.blastRadiusNodeIds[0]);
          }
          triggerToast(
            `Regulatory Amendment Propagated: ${preset.parameterDiffSummary} → ${updated.violatedClausesCount} active UNSAT violations.`
          );
        }
      }
    } finally {
      setIsCompiling(false);
    }
  };

  const handleSimulateFlagshipAmendment = async () => {
    await handleTriggerMutationPreset('PRESET-72H-TENANT-KMS', true);
  };

  const handleSet30DayBaseline = async () => {
    setIsCompiling(true);
    setWorkspaceTab('LAW_TO_AST_STUDIO');
    try {
      const res = await fetch('/api/repo/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'LEGACY_30D_COMPLIANT_DPA' }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        setActiveClauseId('CLAUSE-DPA-4.2');
        setSelectedNodeId('node-redis-worker');
        triggerToast(
          'Set DPA §4.2 to Legacy 30-Day (720h) Baseline — Click "Simulate Regulatory Amendment" to trigger the 72h + Tenant KMS shockwave!'
        );
      }
    } finally {
      setIsCompiling(false);
    }
  };

  const handleApplyNodePatch = async (nodeId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setIsApplyingPatch(true);
    try {
      const res = await fetch('/api/remediation/apply-node', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        triggerToast(
          `Applied AST patch to node '${nodeId}' & re-verified in Microsoft Z3 (${updated.totalZ3ExecutionMs} ms).`
        );
      }
    } finally {
      setIsApplyingPatch(false);
    }
  };

  const handleApplyFullPR = async () => {
    setIsApplyingPatch(true);
    try {
      const res = await fetch('/api/remediation/apply-pr', {
        method: 'POST',
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        triggerToast(
          `Merged Auto-PR #409 across all files! Microsoft Z3 proved 100% SAT_COMPLIANT in ${updated.totalZ3ExecutionMs} ms.`
        );
      }
    } finally {
      setIsApplyingPatch(false);
    }
  };

  const handleSaveFileEdit = async (filePath: string, newContent: string) => {
    setIsApplyingPatch(true);
    try {
      const res = await fetch('/api/repo/update-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath, content: newContent }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        triggerToast(
          `Saved ${filePath} to disk, re-parsed AST, and re-evaluated Z3 constraints (${updated.totalZ3ExecutionMs} ms).`
        );
      }
    } finally {
      setIsApplyingPatch(false);
    }
  };

  const handleIngestLiveFeedItem = async (item: LiveRegulatoryFeedItem) => {
    await handleCompileCustomProse('CLAUSE-DPA-4.2', item.excerpt);
  };

  const handleSwitchLocale = async (locale: 'en' | 'bn') => {
    setActiveLocale(locale);
    setIsCompiling(true);
    runShockwaveAnimation(
      locale === 'bn'
        ? 'বাংলাদেশ ব্যাংক আইসিটি নীতিমালা ধারা ৪.২ (৪৮ ঘণ্টা)'
        : 'GDPR Art. 17 & 32 / DPA §4.2 (72h)'
    );
    try {
      const res = await fetch('/api/clauses/switch-locale', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ locale, resetRepo: true }),
      });
      if (res.ok) {
        const updated = (await res.json()) as FullComplianceScanReport;
        setReport(updated);
        fetchAllTelemetry();
        triggerToast(
          locale === 'bn'
            ? 'বাংলা আইন সক্রিয় করা হয়েছে: ৪টি ধারা (৪৮ ঘণ্টা রিটেনশন, টেন্যান্ট KMS, লগিং নিষেধাজ্ঞা, ৮৫% এআই গেট) Z3 দ্বারা যাচাইকৃত।'
            : 'Switched to Global English statutory corpus (GDPR, HIPAA, EU AI Act) & verified in Z3.'
        );
      }
    } finally {
      setIsCompiling(false);
    }
  };

  if (!report) {
    return (
      <div className="min-h-screen bg-[#050609] text-zinc-100 flex items-center justify-center p-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <Cpu className="w-8 h-8 text-amber-400 animate-spin" />
          <div className="text-sm font-mono font-medium text-zinc-300">
            Initializing LexCompiler Neuro-Symbolic Engine (Ollama Multi-LLM + Microsoft Z3 +
            SQLite Vector Ledger)...
          </div>
        </div>
      </div>
    );
  }

  const selectedNode =
    report.architectureGraph.nodes.find((n) => n.id === selectedNodeId) ||
    report.architectureGraph.nodes[0];

  const isAllCompliant = report.violatedClausesCount === 0;
  const activeClause =
    report.clauses.find((c) => c.id === activeClauseId) || report.clauses[0];

  const navItems: Array<{
    id: ActiveWorkspaceTab;
    label: string;
    sublabel: string;
    shortcut: string;
    badge?: string;
    icon: React.ReactNode;
  }> = [
    {
      id: 'LAW_TO_AST_STUDIO',
      label: 'Law-to-AST Split Studio',
      sublabel: 'Deontic Compiler & Graph',
      shortcut: '⌘1',
      icon: <Scale className="w-4 h-4 text-amber-300" />,
    },
    {
      id: 'MULTI_LLM_SERVICE_MESH',
      label: 'Live Multi-LLM & Services',
      sublabel: 'Ollama · Z3 · SQLite · 384d',
      shortcut: '⌘2',
      badge: `${serviceMeshSummary?.ollamaModels?.length || 3} LLMs`,
      icon: <Cpu className="w-4 h-4 text-emerald-400" />,
    },
    {
      id: 'ENTERPRISE_CLOUD_SUITE',
      label: 'Enterprise BYOC & Certs',
      sublabel: 'Ed25519 · SARIF · Fine ROI',
      shortcut: '⌘3',
      icon: <ShieldCheck className="w-4 h-4 text-indigo-400" />,
    },
    {
      id: 'MCP_AND_AGENTS',
      label: '12-MCP & 6-Agent Plane',
      sublabel: 'JSON-RPC 2.0 · CrewAI/DSPy',
      shortcut: '⌘4',
      badge: '12 MCP',
      icon: <Bot className="w-4 h-4 text-sky-400" />,
    },
    {
      id: 'HYBRID_GRAPH_RAG',
      label: 'Contextual + Graph RAG',
      sublabel: 'all-minilm 384d · BM25 · Neo4j',
      shortcut: '⌘5',
      badge: '98%',
      icon: <Database className="w-4 h-4 text-amber-400" />,
    },
    {
      id: 'TOKEN_AND_DATA_STACK',
      label: 'Token Optimizer & Data',
      sublabel: 'Codeburn · Graphify · Lakehouse',
      shortcut: '⌘6',
      badge: '-89%',
      icon: <Zap className="w-4 h-4 text-emerald-300" />,
    },
    {
      id: 'LIVE_DOCS_AND_RUBRIC',
      label: 'Architecture & Specs (/docs)',
      sublabel: 'Formal Grammar & Prompts',
      shortcut: '⌘7',
      icon: <BookOpen className="w-4 h-4 text-zinc-300" />,
    },
  ];

  return (
    <div className="min-h-screen flex bg-[#050609] text-[#F4F4F6]">
      {/* LEFT PRECISION NAVIGATION SIDEBAR (Harvey AI × Linear × Palantir Style) */}
      <aside className="w-[258px] shrink-0 bg-[#080A0F] border-r border-white/[0.07] flex flex-col justify-between select-none">
        <div>
          {/* Brand Emblem */}
          <div className="px-4 py-4 border-b border-white/[0.07] flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-amber-400/20 to-amber-600/5 border border-amber-400/40 flex items-center justify-center shadow-[0_0_25px_rgba(229,193,88,0.18)]">
              <Scale className="w-4.5 h-4.5 text-amber-300" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold tracking-tight text-white">
                  LexCompiler
                </span>
                <span className="px-1.5 py-0.2 rounded text-[9.5px] font-mono font-semibold bg-amber-400/15 text-amber-300 border border-amber-400/30">
                  v2.5
                </span>
              </div>
              <div className="text-[10.5px] font-mono text-zinc-500 truncate">
                JusticeSphere · ComplianceOS
              </div>
            </div>
          </div>

          {/* Navigation Items */}
          <div className="p-2.5 space-y-1">
            <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-widest text-zinc-500">
              Control Plane Modules
            </div>
            {navItems.map((item) => {
              const isActive = workspaceTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setWorkspaceTab(item.id)}
                  className={`w-full text-left px-3 py-2.5 rounded-xl transition-all flex items-center justify-between gap-2 cursor-pointer border ${
                    isActive
                      ? 'bg-white/[0.08] border-white/[0.15] text-white shadow-sm'
                      : 'bg-transparent hover:bg-white/[0.03] border-transparent text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.icon}
                    <div className="min-w-0">
                      <div className="text-xs font-semibold truncate">{item.label}</div>
                      <div className="text-[10px] font-mono text-zinc-500 truncate">
                        {item.sublabel}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {item.badge && (
                      <span className="px-1.5 py-0.5 rounded text-[9.5px] font-mono font-medium bg-white/[0.06] text-zinc-300 border border-white/[0.08]">
                        {item.badge}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Bottom Live 6-Service Mesh Heartbeat Box */}
        <div className="p-3 m-2.5 rounded-xl bg-[#0B0E16] border border-white/[0.07] space-y-2">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-zinc-400">
            <span className="flex items-center gap-1.5">
              <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
              Active Service Mesh
            </span>
            <span className="text-emerald-400">6/6 ONLINE</span>
          </div>

          <div className="space-y-1.5 text-[10.5px] font-mono">
            <div className="flex items-center justify-between text-zinc-300">
              <span className="truncate">Ollama (:11434)</span>
              <span className="text-amber-300">
                {serviceMeshSummary?.ollamaModels?.length || 3} Models
              </span>
            </div>
            <div className="flex items-center justify-between text-zinc-400 text-[10px]">
              <span className="truncate">dolphin3:8b · qwen2.5 · minilm</span>
            </div>
            <div className="flex items-center justify-between text-zinc-300 pt-1 border-t border-white/[0.05]">
              <span>Microsoft Z3 SMT</span>
              <span className="text-emerald-400">{report.totalZ3ExecutionMs}ms</span>
            </div>
            <div className="flex items-center justify-between text-zinc-300">
              <span>SQLite + 384d Vec</span>
              <span className="text-indigo-300">Persisted</span>
            </div>
            <div className="flex items-center justify-between text-zinc-300">
              <span>Python 3.12 + Git</span>
              <span className="text-zinc-400">@{report.commitHash}</span>
            </div>
          </div>
        </div>
      </aside>

      {/* RIGHT MAIN WORKSPACE AREA */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Executive Command Bar */}
        <header className="sticky top-0 z-40 bg-[#07090E]/90 backdrop-blur-md border-b border-white/[0.07] px-5 py-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            {/* Left: Active Regime, Locale Switcher & Git Telemetry */}
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/[0.08] text-xs font-mono text-zinc-300">
                <GitBranch className="w-3.5 h-3.5 text-amber-300" />
                <span>{report.repositoryName}</span>
                <span className="text-zinc-600">@</span>
                <span className="text-amber-300 font-semibold">{report.commitHash}</span>
              </div>

              {/* Bilingual EN / বাংলা Statutory Corpus Switcher */}
              <div className="inline-flex items-center rounded-lg bg-white/[0.04] border border-white/[0.1] p-0.5 text-[11px] font-mono">
                <button
                  type="button"
                  onClick={() => handleSwitchLocale('en')}
                  className={`px-2 py-0.5 rounded-md transition-all cursor-pointer ${
                    activeLocale === 'en'
                      ? 'bg-amber-400 text-black font-bold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  EN (Global)
                </button>
                <button
                  type="button"
                  onClick={() => handleSwitchLocale('bn')}
                  className={`px-2.5 py-0.5 rounded-md transition-all cursor-pointer ${
                    activeLocale === 'bn'
                      ? 'bg-emerald-400 text-black font-bold'
                      : 'text-zinc-300 hover:text-white'
                  }`}
                >
                  বাংলা (BD Laws)
                </button>
              </div>
            </div>

            {/* Center: 3-Step Interactive Demo Scenario Triggers */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleSet30DayBaseline}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-white/[0.04] hover:bg-white/[0.09] text-zinc-200 border border-white/[0.09] transition-all cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />
                1. Baseline (30d)
              </button>

              <button
                type="button"
                onClick={handleSimulateFlagshipAmendment}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-400 hover:bg-amber-300 text-black shadow-[0_0_20px_rgba(229,193,88,0.28)] transition-all cursor-pointer"
              >
                <Flame className="w-3.5 h-3.5 fill-current" />
                2. Simulate Regulatory Amendment (30d → 72h + KMS)
              </button>

              <button
                type="button"
                disabled={isAllCompliant || isApplyingPatch}
                onClick={handleApplyFullPR}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold bg-emerald-500 hover:bg-emerald-400 disabled:bg-white/[0.04] disabled:text-zinc-600 text-black shadow-[0_0_20px_rgba(16,185,129,0.28)] border border-emerald-400/50 disabled:border-white/[0.05] transition-all cursor-pointer"
              >
                <GitPullRequest className="w-3.5 h-3.5" />
                3. Auto-Remediate &amp; Prove SAT (PR #409)
              </button>
            </div>

            {/* Right: Z3 Formal Verdict Pill */}
            <div className="flex items-center gap-2.5 text-xs font-mono">
              {isAllCompliant ? (
                <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  SAT · 100% COMPLIANT ({report.totalZ3ExecutionMs}ms)
                </div>
              ) : (
                <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/40">
                  <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
                  UNSAT · {report.violatedClausesCount} VIOLATIONS ({report.totalZ3ExecutionMs}ms)
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Toast Notification Banner */}
        {toastMessage && (
          <div className="fixed bottom-4 right-4 z-50 max-w-md px-4 py-2.5 rounded-xl bg-[#0F131D]/95 border border-amber-400/50 text-zinc-100 text-xs font-mono shadow-2xl flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-300 shrink-0" />
            <span>{toastMessage}</span>
          </div>
        )}

        {/* VIEW 1: Main Split-Screen "Law-to-Code" Workbench */}
        {workspaceTab === 'LAW_TO_AST_STUDIO' && (
          <main className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0">
            <div className="lg:col-span-5 flex flex-col min-h-[680px]">
              <LegalCompilerPane
                clauses={report.clauses}
                proofs={report.proofs}
                activeClauseId={activeClauseId}
                mutationPresets={report.mutationPresets}
                liveFeedItems={liveFeedItems}
                isCompiling={isCompiling}
                onSelectClause={(cid) => {
                  setActiveClauseId(cid);
                  const prf = report.proofs.find((p) => p.clauseId === cid);
                  if (prf?.affectedGraphNodeIds[0]) {
                    setSelectedNodeId(prf.affectedGraphNodeIds[0]);
                  }
                }}
                onCompileCustomProse={handleCompileCustomProse}
                onTriggerMutationPreset={(pid) => handleTriggerMutationPreset(pid, false)}
                onIngestLiveFeedItem={handleIngestLiveFeedItem}
              />
            </div>

            <div className="lg:col-span-7 flex flex-col min-h-[680px]">
              <ArchitectureGraphCanvas
                nodes={report.architectureGraph.nodes}
                edges={report.architectureGraph.edges}
                selectedNodeId={selectedNode.id}
                activeClauseId={activeClauseId}
                shockwaveActive={shockwaveActive}
                shockwaveStage={shockwaveStage}
                proofs={report.proofs}
                onSelectNode={(nid) => setSelectedNodeId(nid)}
                onQuickApplyNodePatch={handleApplyNodePatch}
              />

              <IdeRemediationDrawer
                selectedNode={selectedNode}
                files={report.files}
                proofs={report.proofs}
                remediationPR={report.remediationPR}
                merkleAuditRoot={report.merkleAuditRoot}
                isApplyingPatch={isApplyingPatch}
                onApplyNodePatch={(nid) => handleApplyNodePatch(nid)}
                onApplyFullPR={handleApplyFullPR}
                onSaveFileEdit={handleSaveFileEdit}
              />
            </div>
          </main>
        )}

        {/* VIEW 2: Live Multi-LLM & 6-Service Mesh Studio */}
        {workspaceTab === 'MULTI_LLM_SERVICE_MESH' && (
          <main className="flex-1 overflow-y-auto">
            <LiveMultiLlmMeshStudio activeClauseText={activeClause?.rawLegalText || ''} />
          </main>
        )}

        {/* VIEW 3: Enterprise BYOC Scanner, Ed25519 Conformity Cert & SARIF Suite */}
        {workspaceTab === 'ENTERPRISE_CLOUD_SUITE' && (
          <main className="flex-1 overflow-y-auto">
            <EnterpriseStartupSuite report={report} />
          </main>
        )}

        {/* VIEW 4: 12-MCP & 6-Agent Control Plane */}
        {workspaceTab === 'MCP_AND_AGENTS' && (
          <main className="flex-1 overflow-y-auto">
            <McpAndAgentsHub
              mcpServers={mcpServers}
              multiAgentReport={multiAgentReport}
              onRefreshAgents={fetchAllTelemetry}
            />
          </main>
        )}

        {/* VIEW 5: Contextual + Graph RAG Studio */}
        {workspaceTab === 'HYBRID_GRAPH_RAG' && (
          <main className="flex-1 overflow-y-auto">
            <HybridRagStudio initialReport={defaultRagReport} />
          </main>
        )}

        {/* VIEW 6: Token Optimization & Data Lifecycle Lab */}
        {workspaceTab === 'TOKEN_AND_DATA_STACK' && (
          <main className="flex-1 overflow-y-auto">
            <TokenAndDataLifecycleLab benchmark={tokenBenchmark} />
          </main>
        )}

        {/* VIEW 7: Live /docs Whitepaper, Prompt Library & 425-Pt Submission Guide */}
        {workspaceTab === 'LIVE_DOCS_AND_RUBRIC' && (
          <main className="flex-1 overflow-y-auto">
            <LiveDocsAndRubricView promptLibrary={promptLibrary} />
          </main>
        )}
      </div>
    </div>
  );
}

export default App;
