import React from 'react';
import { PanelLeftClose, PanelLeftOpen, Radio, Scale } from 'lucide-react';

export interface WorkspaceNavItem<T extends string> {
  id: T;
  label: string;
  sublabel: string;
  /** Digit of the Ctrl/⌘ + digit shortcut that opens the module. */
  shortcutDigit: number;
  badge?: string;
  icon: React.ReactNode;
}

interface AppSidebarProps<T extends string> {
  items: WorkspaceNavItem<T>[];
  activeId: T;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  onSelect: (id: T) => void;
  ollamaModelCount: number;
  z3ExecutionMs: number;
  commitHash: string;
}

const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

/** Module navigation (Ctrl/⌘ + 1–7) and the service-mesh heartbeat. */
export function AppSidebar<T extends string>({ items, activeId, collapsed, onToggleCollapsed, onSelect, ollamaModelCount, z3ExecutionMs, commitHash }: AppSidebarProps<T>) {
  const modifier = isMac() ? '⌘' : 'Ctrl+';
  return (
    <aside
      className={`${
        collapsed ? 'w-16' : 'w-[258px]'
      } shrink-0 overflow-hidden transition-[width] duration-200 ease-out bg-[#080A0F] border-r border-white/[0.07] flex flex-col justify-between select-none`}
    >
      <div>
        {/* Brand Emblem */}
        <div className={`py-3 border-b border-white/[0.07] flex ${collapsed ? 'flex-col items-center gap-2 px-2' : 'flex-row items-center px-3 gap-2.5'}`}>
          <div className="w-9 h-9 shrink-0 rounded-xl bg-gradient-to-b from-amber-400/20 to-amber-600/5 border border-amber-400/40 flex items-center justify-center shadow-[0_0_25px_rgba(229,193,88,0.18)]">
            <Scale className="w-4.5 h-4.5 text-amber-300" aria-hidden="true" />
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold tracking-tight text-white">LexCompiler</span>
                <span className="px-1.5 py-0.2 rounded text-[9.5px] font-mono font-semibold bg-amber-400/15 text-amber-300 border border-amber-400/30">v2.5</span>
              </div>
              <div className="text-[10.5px] font-mono text-zinc-400 truncate">JusticeSphere · ComplianceOS</div>
            </div>
          )}
          <button
            type="button"
            onClick={onToggleCollapsed}
            aria-expanded={!collapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="shrink-0 w-8 h-8 rounded-lg border border-white/[0.08] bg-white/[0.04] text-zinc-300 hover:text-white hover:bg-white/[0.08] flex items-center justify-center cursor-pointer"
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" aria-hidden="true" /> : <PanelLeftClose className="w-4 h-4" aria-hidden="true" />}
          </button>
        </div>

        {/* Navigation Items */}
        <nav aria-label="Workspace modules" className="p-2 space-y-1">
          {!collapsed && <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-widest text-zinc-400">Control Plane Modules</div>}
          {items.map((item) => {
            const isActive = activeId === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelect(item.id)}
                title={`${item.label} (${modifier}${item.shortcutDigit})`}
                aria-label={item.label}
                aria-current={isActive ? 'page' : undefined}
                aria-keyshortcuts={`Control+${item.shortcutDigit} Meta+${item.shortcutDigit}`}
                className={`w-full text-left rounded-xl transition-all flex items-center cursor-pointer border ${
                  collapsed ? 'justify-center px-0 py-2.5' : 'justify-between gap-2 px-3 py-2.5'
                } ${
                  isActive
                    ? 'bg-white/[0.08] border-white/[0.15] text-white shadow-sm'
                    : 'bg-transparent hover:bg-white/[0.03] border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <div className={`flex items-center min-w-0 ${collapsed ? '' : 'gap-2.5'}`}>
                  <span aria-hidden="true">{item.icon}</span>
                  {!collapsed && (
                    <div className="min-w-0">
                      <div className="text-xs font-semibold truncate">{item.label}</div>
                      <div className="text-[10px] font-mono text-zinc-400 truncate">{item.sublabel}</div>
                    </div>
                  )}
                </div>
                {!collapsed && item.badge && (
                  <span className="px-1.5 py-0.5 rounded text-[9.5px] font-mono font-medium bg-white/[0.06] text-zinc-300 border border-white/[0.08] shrink-0">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Live 6-Service Mesh Heartbeat Box */}
      <div
        className={`m-2 rounded-xl bg-[#0B0E16] border border-white/[0.07] ${collapsed ? 'p-2 flex justify-center' : 'p-3 space-y-2'}`}
        title="Active service mesh · 6/6 online"
      >
        {collapsed ? (
          <Radio className="w-4 h-4 text-emerald-400 animate-pulse" aria-label="Active service mesh · 6/6 online" role="img" />
        ) : (
          <>
            <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-zinc-400">
              <span className="flex items-center gap-1.5">
                <Radio className="w-3 h-3 text-emerald-400 animate-pulse" aria-hidden="true" />
                Active Service Mesh
              </span>
              <span className="text-emerald-400">6/6 ONLINE</span>
            </div>

            <div className="space-y-1.5 text-[10.5px] font-mono">
              <div className="flex items-center justify-between text-zinc-300">
                <span className="truncate">Ollama (:11434)</span>
                <span className="text-amber-300">{ollamaModelCount} Models</span>
              </div>
              <div className="flex items-center justify-between text-zinc-400 text-[10px]">
                <span className="truncate">dolphin3:8b · qwen2.5 · minilm</span>
              </div>
              <div className="flex items-center justify-between text-zinc-300 pt-1 border-t border-white/[0.05]">
                <span>Microsoft Z3 SMT</span>
                <span className="text-emerald-400">{z3ExecutionMs}ms</span>
              </div>
              <div className="flex items-center justify-between text-zinc-300">
                <span>SQLite + 384d Vec</span>
                <span className="text-indigo-300">Persisted</span>
              </div>
              <div className="flex items-center justify-between text-zinc-300">
                <span>Python 3.12 + Git</span>
                <span className="text-zinc-400">@{commitHash}</span>
              </div>
            </div>
          </>
        )}
      </div>
    </aside>
  );
}
