import React from 'react';
import {
  LayoutDashboard,
  Server,
  Radar,
  ShieldCheck,
  Radio,
  FlaskConical,
  ExternalLink
} from 'lucide-react';

export type NavTab = 'overview' | 'inventory' | 'discovery' | 'scopes';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isDemoActive: boolean;
  onToggleDemo: () => void;
  onOpenQuickScan: () => void;
  backendHealthy: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isDemoActive,
  onToggleDemo,
  onOpenQuickScan,
  backendHealthy,
}) => {
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'Overview',
      icon: LayoutDashboard,
      desc: 'Metrics & Inventory posture',
    },
    {
      id: 'inventory' as NavTab,
      label: 'Asset Inventory',
      icon: Server,
      desc: 'Discovered domains, IPs, & services',
    },
    {
      id: 'discovery' as NavTab,
      label: 'Discovery Runs',
      icon: Radar,
      desc: 'Active scan progress & logs',
    },
    {
      id: 'scopes' as NavTab,
      label: 'Scope Settings',
      icon: ShieldCheck,
      desc: 'Authorised targets & policies',
    },
  ];

  return (
    <aside className="w-64 shrink-0 bg-navy-950 border-r border-navy-750 flex flex-col justify-between select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-navy-750">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-violet-500/20 border border-cyan-500/40 shadow-glow-cyan-sm">
              <Radio className="w-5 h-5 text-cyan-400" />
              <div className="absolute inset-0 rounded-xl border border-cyan-400/20 animate-pulse-slow"></div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-wider text-slate-100 font-mono">
                  ARGUS<span className="text-cyan-400">TRACE</span>
                </span>
              </div>
              <p className="text-[10px] tracking-widest text-slate-400 uppercase font-mono">
                PS-011 • Phase 1 Discovery
              </p>
            </div>
          </div>
        </div>

        {/* Quick Action Button */}
        <div className="p-4">
          <button
            onClick={onOpenQuickScan}
            className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 text-navy-950 font-bold text-xs uppercase tracking-wider shadow-glow-cyan-sm transition-all"
          >
            <Radar className="w-4 h-4 animate-spin-slow" />
            Launch Discovery Run
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="px-3 py-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-300 shadow-[0_0_12px_rgba(0,240,255,0.1)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium">{item.label}</div>
                  <div className="text-[11px] text-slate-500 truncate">{item.desc}</div>
                </div>
                {isActive && (
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-glow-cyan-sm" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status & Demo Controls */}
      <div className="p-4 border-t border-navy-750 space-y-3">
        {/* Demo Mode Toggle Banner */}
        <div className={`p-3 rounded-lg border text-xs ${
          isDemoActive
            ? 'bg-violet-950/40 border-violet-500/40 text-violet-300'
            : 'bg-navy-850 border-navy-700 text-slate-400'
        }`}>
          <div className="flex items-center justify-between mb-1.5">
            <span className="flex items-center gap-1.5 font-semibold text-[11px] uppercase tracking-wider">
              <FlaskConical className="w-3.5 h-3.5 text-violet-400" />
              Demo Sample Lab
            </span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
              isDemoActive ? 'bg-violet-500/20 text-violet-300' : 'bg-navy-750 text-slate-500'
            }`}>
              {isDemoActive ? 'ACTIVE' : 'IDLE'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mb-2 leading-tight">
            {isDemoActive
              ? 'Viewing synthetic lab assets. No real targets touched.'
              : 'Load synthetic lab data to preview features without scanning.'}
          </p>
          <button
            onClick={onToggleDemo}
            className={`w-full py-1.5 px-2 rounded text-center text-xs font-medium border transition-colors ${
              isDemoActive
                ? 'bg-rose-950/40 hover:bg-rose-900/50 border-rose-500/40 text-rose-300'
                : 'bg-violet-600/30 hover:bg-violet-600/50 border-violet-500/50 text-violet-200'
            }`}
          >
            {isDemoActive ? 'Clear Demo Lab' : 'Load Demo Sample Data'}
          </button>
        </div>

        {/* Engine Connectivity Status */}
        <div className="flex items-center justify-between px-2 text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${backendHealthy ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-rose-500 animate-ping'}`} />
            Backend API: {backendHealthy ? 'Online' : 'Disconnected'}
          </span>
          <span className="font-mono text-slate-500 text-[10px]">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
};
