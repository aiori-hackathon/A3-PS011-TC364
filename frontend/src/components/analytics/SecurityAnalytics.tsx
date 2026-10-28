import React, { useState } from 'react';
import {
  BarChart3,
  PieChart,
  Activity,
  History,
  ShieldAlert,
  ArrowRight,
  TrendingUp,
  Server,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  Layers,
  Sparkles
} from 'lucide-react';
import type { StatsOverview, DiscoveryTimelineItem, ChangesTimelineItem } from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

interface SecurityAnalyticsProps {
  stats: StatsOverview | null;
  onNavigateTab: (tab: 'inventory' | 'discovery' | 'scopes' | 'changes' | 'findings') => void;
  onFilterInventoryType?: (type: string) => void;
  onFilterFindingsSeverity?: (sev: string) => void;
}

export const SecurityAnalytics: React.FC<SecurityAnalyticsProps> = ({
  stats,
  onNavigateTab,
  onFilterInventoryType,
  onFilterFindingsSeverity,
}) => {
  const [activeTab, setActiveTab] = useState<'all' | 'discovery' | 'findings' | 'assets' | 'changes'>('all');
  const [hoveredBarIndex, setHoveredBarIndex] = useState<number | null>(null);
  const [hoveredSeverity, setHoveredSeverity] = useState<string | null>(null);

  // Asset Types breakdown
  const assetTypes = stats?.asset_types_distribution || (stats as any)?.asset_type_breakdown || {};
  const totalAssets = stats?.total_assets || 0;

  // Severity breakdown
  const findingsSev = stats?.findings_by_severity || {};
  const countCritical = findingsSev['CRITICAL'] ?? (stats as any)?.critical_findings ?? 0;
  const countHigh = findingsSev['HIGH'] ?? (stats as any)?.high_findings ?? 0;
  const countMedium = findingsSev['MEDIUM'] ?? (stats as any)?.medium_findings ?? 0;
  const countLow = findingsSev['LOW'] ?? (stats as any)?.low_findings ?? 0;
  const countInfo = (findingsSev['INFORMATIONAL'] || 0) + (findingsSev['INFO'] || 0) + (findingsSev['NOTICE'] || 0);
  const totalFindings = countCritical + countHigh + countMedium + countLow + countInfo;

  // Discovery Activity Timeline
  const discoveryTimeline: DiscoveryTimelineItem[] = stats?.discovery_timeline || [];

  // Changes Timeline
  const changesTimeline: ChangesTimelineItem[] = stats?.changes_timeline || [];
  const totalChanges = stats?.total_changes || 0;
  const changesByType = stats?.changes_by_type || {};

  return (
    <div className="space-y-4">
      {/* Analytics Navigation Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-2 border-b border-navy-750">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <BarChart3 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Security Analytics & Attack Surface Telemetry
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Phase 4 Real Data
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic trends, discovery velocity, risk posture, and baseline state shifts
            </p>
          </div>
        </div>

        {/* Segmented Filter Controls */}
        <div className="flex items-center bg-navy-950 p-1 rounded-xl border border-navy-750 text-xs font-mono">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeTab === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Views
          </button>
          <button
            onClick={() => setActiveTab('discovery')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeTab === 'discovery'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Discovery ({discoveryTimeline.length})
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeTab === 'findings'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Risks ({totalFindings})
          </button>
          <button
            onClick={() => setActiveTab('changes')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeTab === 'changes'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Changes ({totalChanges})
          </button>
        </div>
      </div>

      {/* Grid of Interactive Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* CHART 1: Discovery Activity & Velocity over Time */}
        {(activeTab === 'all' || activeTab === 'discovery') && (
          <Card className="p-5 border-navy-750 bg-navy-900/60 relative overflow-hidden space-y-4">
            <div className="flex items-center justify-between border-b border-navy-750 pb-3">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <h4 className="text-sm font-semibold text-slate-200">Discovery Activity Timeline</h4>
              </div>
              <span className="text-xs text-slate-500 font-mono">Recent Probes</span>
            </div>

            {discoveryTimeline.length === 0 ? (
              <div className="py-12 text-center text-slate-500 font-mono text-xs italic space-y-2">
                <Calendar className="w-8 h-8 mx-auto text-slate-600 opacity-60" />
                <div>No discovery runs recorded yet.</div>
                <Button variant="ghost" size="sm" onClick={() => onNavigateTab('discovery')}>
                  Launch First Scan
                </Button>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="text-xs text-slate-400 font-sans">
                  Showing targets scanned and assets verified per discovery run. Hover over any bar to view details.
                </div>

                {/* SVG/CSS Interactive Bar Timeline */}
                <div className="relative pt-6 pb-2">
                  <div className="flex items-end justify-between gap-2 h-36 px-2 border-b border-navy-750">
                    {discoveryTimeline.map((run, idx) => {
                      const maxAssets = Math.max(...discoveryTimeline.map((r) => r.assets_discovered || 1), 5);
                      const barHeight = Math.max(12, Math.round(((run.assets_discovered || 0) / maxAssets) * 100));
                      const isHovered = hoveredBarIndex === idx;

                      return (
                        <div
                          key={run.id || idx}
                          onMouseEnter={() => setHoveredBarIndex(idx)}
                          onMouseLeave={() => setHoveredBarIndex(null)}
                          className="flex-1 flex flex-col items-center justify-end h-full relative cursor-pointer group"
                          onClick={() => onNavigateTab('discovery')}
                        >
                          {/* Tooltip on hover */}
                          {isHovered && (
                            <div className="absolute -top-14 z-20 px-2.5 py-1.5 rounded-lg bg-navy-950 border border-cyan-500/40 shadow-xl text-[11px] font-mono text-slate-200 whitespace-nowrap pointer-events-none">
                              <div className="text-cyan-400 font-bold">{run.scope_name}</div>
                              <div>{run.assets_discovered} assets • {run.findings_count} findings</div>
                              <div className="text-slate-400 text-[10px]">
                                {run.started_at ? new Date(run.started_at).toLocaleTimeString() : 'Recent'} ({run.status})
                              </div>
                            </div>
                          )}

                          {/* Bar */}
                          <div
                            style={{ height: `${barHeight}%` }}
                            className={`w-full max-w-[28px] rounded-t transition-all duration-200 ${
                              run.status === 'COMPLETED'
                                ? isHovered
                                  ? 'bg-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                                  : 'bg-gradient-to-t from-cyan-600/70 to-cyan-400'
                                : isHovered
                                ? 'bg-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.4)]'
                                : 'bg-gradient-to-t from-amber-600/60 to-amber-400'
                            }`}
                          />

                          {/* Label below */}
                          <span className="text-[10px] text-slate-500 font-mono mt-1 truncate max-w-[36px]">
                            #{idx + 1}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs text-slate-500 font-mono pt-1">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400" /> Completed Probes
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-amber-400" /> Cancelled / Partial
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => onNavigateTab('discovery')} className="text-xs">
                    Inspect Runs <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}

        {/* CHART 2: Findings Risk Severity Breakdown */}
        {(activeTab === 'all' || activeTab === 'findings') && (
          <Card className="p-5 border-navy-750 bg-navy-900/60 relative overflow-hidden space-y-4">
            <div className="flex items-center justify-between border-b border-navy-750 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <h4 className="text-sm font-semibold text-slate-200">Finding Severity Distribution</h4>
              </div>
              <span className="text-xs text-slate-500 font-mono">{totalFindings} Total</span>
            </div>

            {totalFindings === 0 ? (
              <div className="py-12 text-center text-slate-500 font-mono text-xs italic space-y-2">
                <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500 opacity-60" />
                <div>Zero security findings observed across current scopes.</div>
                <span className="text-[11px] text-slate-400">Inventory posture clean</span>
              </div>
            ) : (
              <div className="space-y-3">
                {/* Visual Stacked Progress Bar */}
                <div className="w-full h-3 rounded-full bg-navy-950 overflow-hidden flex border border-navy-800">
                  {countCritical > 0 && (
                    <div
                      style={{ width: `${(countCritical / totalFindings) * 100}%` }}
                      className="bg-rose-500 h-full transition-all duration-300"
                      title={`Critical: ${countCritical}`}
                    />
                  )}
                  {countHigh > 0 && (
                    <div
                      style={{ width: `${(countHigh / totalFindings) * 100}%` }}
                      className="bg-orange-500 h-full transition-all duration-300"
                      title={`High: ${countHigh}`}
                    />
                  )}
                  {countMedium > 0 && (
                    <div
                      style={{ width: `${(countMedium / totalFindings) * 100}%` }}
                      className="bg-amber-400 h-full transition-all duration-300"
                      title={`Medium: ${countMedium}`}
                    />
                  )}
                  {countLow > 0 && (
                    <div
                      style={{ width: `${(countLow / totalFindings) * 100}%` }}
                      className="bg-cyan-400 h-full transition-all duration-300"
                      title={`Low: ${countLow}`}
                    />
                  )}
                  {countInfo > 0 && (
                    <div
                      style={{ width: `${(countInfo / totalFindings) * 100}%` }}
                      className="bg-slate-500 h-full transition-all duration-300"
                      title={`Informational: ${countInfo}`}
                    />
                  )}
                </div>

                {/* Interactive Severity Rows */}
                <div className="grid grid-cols-1 gap-2 pt-1 font-mono text-xs">
                  {[
                    { label: 'CRITICAL', count: countCritical, color: 'text-rose-400', bg: 'bg-rose-950/30 border-rose-500/30 hover:border-rose-400' },
                    { label: 'HIGH', count: countHigh, color: 'text-orange-400', bg: 'bg-orange-950/30 border-orange-500/30 hover:border-orange-400' },
                    { label: 'MEDIUM', count: countMedium, color: 'text-amber-400', bg: 'bg-amber-950/30 border-amber-500/30 hover:border-amber-400' },
                    { label: 'LOW', count: countLow, color: 'text-cyan-400', bg: 'bg-cyan-950/30 border-cyan-500/30 hover:border-cyan-400' },
                    { label: 'INFORMATIONAL', count: countInfo, color: 'text-slate-400', bg: 'bg-navy-950/50 border-navy-750 hover:border-slate-500' },
                  ].map((item) => {
                    const percent = totalFindings > 0 ? Math.round((item.count / totalFindings) * 100) : 0;
                    return (
                      <div
                        key={item.label}
                        onClick={() => {
                          if (onFilterFindingsSeverity) onFilterFindingsSeverity(item.label);
                          onNavigateTab('findings');
                        }}
                        onMouseEnter={() => setHoveredSeverity(item.label)}
                        onMouseLeave={() => setHoveredSeverity(null)}
                        className={`p-2.5 rounded-lg border transition-all flex items-center justify-between cursor-pointer ${item.bg}`}
                      >
                        <div className="flex items-center gap-2">
                          <span className={`font-bold ${item.color}`}>{item.label}</span>
                          <span className="text-[11px] text-slate-500 font-sans">
                            ({percent}%)
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-200 font-bold">{item.count}</span>
                          <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-slate-300" />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="pt-2 border-t border-navy-750 flex items-center justify-between text-xs text-slate-500">
                  <span>Deterministic Rule Classification</span>
                  <Button variant="ghost" size="sm" onClick={() => onNavigateTab('findings')} className="text-xs">
                    View Findings Desk <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}

        {/* CHART 3: Asset Categories & Attack Surface Distribution */}
        {(activeTab === 'all' || activeTab === 'assets') && (
          <Card className="p-5 border-navy-750 bg-navy-900/60 relative overflow-hidden space-y-4">
            <div className="flex items-center justify-between border-b border-navy-750 pb-3">
              <div className="flex items-center gap-2">
                <PieChart className="w-4 h-4 text-violet-400" />
                <h4 className="text-sm font-semibold text-slate-200">Asset Categories Breakdown</h4>
              </div>
              <span className="text-xs text-slate-500 font-mono">{totalAssets} Discovered</span>
            </div>

            {totalAssets === 0 ? (
              <div className="py-12 text-center text-slate-500 font-mono text-xs italic space-y-2">
                <Server className="w-8 h-8 mx-auto text-slate-600 opacity-60" />
                <div>No assets inventory recorded.</div>
                <Button variant="ghost" size="sm" onClick={() => onNavigateTab('inventory')}>
                  Open Inventory
                </Button>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="text-xs text-slate-400 font-sans">
                  Distribution of authorized domain names, subdomains, and host IP addresses.
                </div>

                <div className="space-y-3 font-mono">
                  {['domain', 'subdomain', 'ipv4', 'ipv6'].map((cat) => {
                    const count = assetTypes[cat] || 0;
                    const percent = totalAssets > 0 ? Math.round((count / totalAssets) * 100) : 0;
                    return (
                      <div
                        key={cat}
                        onClick={() => {
                          if (onFilterInventoryType) onFilterInventoryType(cat);
                          onNavigateTab('inventory');
                        }}
                        className="p-2.5 rounded-lg bg-navy-950 border border-navy-750 hover:border-cyan-500/40 transition-all cursor-pointer group space-y-1.5"
                      >
                        <div className="flex items-center justify-between text-xs">
                          <span className="capitalize text-slate-200 font-semibold group-hover:text-cyan-300 transition-colors">
                            {cat}
                          </span>
                          <span className="text-slate-400">
                            {count} <span className="text-slate-500">({percent}%)</span>
                          </span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-navy-900 overflow-hidden">
                          <div
                            style={{ width: `${percent}%` }}
                            className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-500 transition-all duration-300"
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="pt-2 border-t border-navy-750 flex items-center justify-between text-xs text-slate-500">
                  <span>SSRF Bounded Allowlist</span>
                  <Button variant="ghost" size="sm" onClick={() => onNavigateTab('inventory')} className="text-xs">
                    Inspect Inventory Table <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}

        {/* CHART 4: Asset Change Velocity over Time */}
        {(activeTab === 'all' || activeTab === 'changes') && (
          <Card className="p-5 border-navy-750 bg-navy-900/60 relative overflow-hidden space-y-4">
            <div className="flex items-center justify-between border-b border-navy-750 pb-3">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-emerald-400" />
                <h4 className="text-sm font-semibold text-slate-200">Asset Changes & Diff Velocity</h4>
              </div>
              <span className="text-xs text-slate-500 font-mono">{totalChanges} Changes</span>
            </div>

            {totalChanges === 0 ? (
              <div className="py-12 text-center text-slate-500 font-mono text-xs italic space-y-2">
                <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500 opacity-60" />
                <div>Zero baseline modifications detected.</div>
                <span className="text-[11px] text-slate-400">Attack surface perfectly matched baseline</span>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-2 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30">
                    <span className="text-[10px] text-emerald-400 uppercase">Assets Added</span>
                    <div className="text-xl font-bold text-emerald-300 mt-1">
                      {changesByType['ASSET_ADDED'] || 0}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30">
                    <span className="text-[10px] text-rose-400 uppercase">Assets Removed</span>
                    <div className="text-xl font-bold text-rose-300 mt-1">
                      {changesByType['ASSET_REMOVED'] || 0}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30">
                    <span className="text-[10px] text-cyan-400 uppercase">Attribute Diffs</span>
                    <div className="text-xl font-bold text-cyan-300 mt-1">
                      {totalChanges - (changesByType['ASSET_ADDED'] || 0) - (changesByType['ASSET_REMOVED'] || 0)}
                    </div>
                  </div>
                </div>

                {/* Chronological Date Groups */}
                <div className="space-y-2">
                  <div className="text-xs text-slate-400 font-mono">Recent Activity by Date:</div>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {changesTimeline.map((item) => (
                      <div
                        key={item.date}
                        className="p-2 rounded bg-navy-950 border border-navy-800 text-xs font-mono flex items-center justify-between"
                      >
                        <span className="text-slate-300">{item.date}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-400">+{item.added}</span>
                          <span className="text-rose-400">-{item.removed}</span>
                          <span className="text-cyan-400">~{item.modified}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-2 border-t border-navy-750 flex items-center justify-between text-xs text-slate-500">
                  <span>Phase 2 Diffs & Snapshots</span>
                  <Button variant="ghost" size="sm" onClick={() => onNavigateTab('changes')} className="text-xs">
                    View Change Log <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}
      </div>
    </div>
  );
};
