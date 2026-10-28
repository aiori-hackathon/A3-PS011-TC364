import React from 'react';
import {
  ShieldCheck,
  Server,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Radar,
  ArrowRight,
  Globe,
  Lock,
  Layers,
  Sparkles,
  History,
  ShieldAlert
} from 'lucide-react';
import type { StatsOverview, ScanRun } from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

interface OverviewViewProps {
  stats: StatsOverview | null;
  recentScans: ScanRun[];
  onNavigate: (tab: 'inventory' | 'discovery' | 'scopes' | 'changes' | 'findings') => void;
  onOpenNewScope: () => void;
  onOpenQuickScan: () => void;
  onToggleDemo: () => void;
  isDemoActive: boolean;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  stats,
  recentScans,
  onNavigate,
  onOpenNewScope,
  onOpenQuickScan,
  onToggleDemo,
  isDemoActive,
}) => {
  const totalScopes = stats?.total_scopes ?? 0;
  const totalAssets = stats?.total_assets ?? 0;
  const activeAssets = stats?.active_assets ?? 0;
  const unresponsiveAssets = stats?.unresponsive_assets ?? 0;
  const totalScans = stats?.total_scans ?? 0;
  const lastScan = stats?.last_scan;

  const isEmpty = totalScopes === 0 && totalAssets === 0;

  return (
    <div className="space-y-6">
      {/* Onboarding Banner when no scopes configured */}
      {isEmpty && (
        <div className="p-6 rounded-2xl bg-gradient-to-r from-navy-850 via-navy-800 to-navy-850 border border-cyan-500/30 shadow-glow-cyan-sm relative overflow-hidden">
          <div className="absolute -right-8 -top-8 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="space-y-2 max-w-2xl">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
                <Sparkles className="w-3.5 h-3.5" />
                Phase 1 Prototype Initialized
              </div>
              <h2 className="text-xl font-bold text-slate-100">
                Welcome to ArgusTrace: Authorized Asset Discovery
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed">
                ArgusTrace enables ethical, non-destructive discovery and inventory of your attack surface: DNS record enumeration, bounded opt-in TCP checks, HTTP reachability, and TLS certificate metadata.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-navy-700 text-cyan-400 flex items-center justify-center font-mono font-bold">1</span>
                  <span>Define authorized scope</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-navy-700 text-cyan-400 flex items-center justify-center font-mono font-bold">2</span>
                  <span>Execute bounded probe</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-navy-700 text-cyan-400 flex items-center justify-center font-mono font-bold">3</span>
                  <span>Inventory verified assets</span>
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-3 shrink-0">
              <Button variant="primary" onClick={onOpenNewScope}>
                Configure Scope
              </Button>
              <Button variant="secondary" onClick={onToggleDemo}>
                Load Demo Lab
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Top Inventory Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Metric 1: Scopes */}
        <Card hover className="relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
              Configured Scopes
            </span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 font-mono tracking-tight">
              {totalScopes}
            </span>
            <span className="text-xs text-slate-400">authorized boundaries</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-navy-750 pt-2.5">
            <span>SSRF Protection</span>
            <span className="text-emerald-400 font-mono font-medium">Enforced</span>
          </div>
        </Card>

        {/* Metric 2: Total Assets */}
        <Card hover className="relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
              Discovered Assets
            </span>
            <div className="p-2 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 font-mono tracking-tight">
              {totalAssets}
            </span>
            <span className="text-xs text-slate-400">in inventory</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-navy-750 pt-2.5">
            <span>Active / Unresponsive</span>
            <span className="font-mono text-slate-300">
              <span className="text-emerald-400 font-semibold">{activeAssets}</span> / {unresponsiveAssets}
            </span>
          </div>
        </Card>

        {/* Metric 3: Total Discovery Runs */}
        <Card hover className="relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
              Discovery Runs
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 font-mono tracking-tight">
              {totalScans}
            </span>
            <span className="text-xs text-slate-400">manual runs</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-navy-750 pt-2.5">
            <span>Execution Type</span>
            <span className="text-slate-300 font-mono">Bounded & Opt-in</span>
          </div>
        </Card>

        {/* Metric 4: Last Scan Status */}
        <Card hover className="relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
              Last Discovery Run
            </span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            {lastScan ? (
              <div className="flex items-center gap-2">
                <Badge
                  variant={
                    lastScan.status === 'COMPLETED'
                      ? 'emerald'
                      : lastScan.status === 'IN_PROGRESS'
                      ? 'cyan'
                      : lastScan.status === 'FAILED'
                      ? 'rose'
                      : 'amber'
                  }
                  pulse={lastScan.status === 'IN_PROGRESS'}
                >
                  {lastScan.status}
                </Badge>
                <span className="text-xs text-slate-400 font-mono truncate max-w-[120px]">
                  {lastScan.scope_name}
                </span>
              </div>
            ) : (
              <span className="text-sm text-slate-500 italic">No runs yet</span>
            )}
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-navy-750 pt-2.5">
            <span>Discovered</span>
            <span className="font-mono text-cyan-400 font-medium">
              {lastScan ? `${lastScan.assets_discovered_count} assets` : 'None'}
            </span>
          </div>
        </Card>

        {/* Metric 5: Phase 2 Baseline Changes */}
        <Card
          hover
          className="relative overflow-hidden group cursor-pointer"
          onClick={() => onNavigate('changes')}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider font-mono">
              Baseline Changes
            </span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <History className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyan-400 font-mono tracking-tight">
              {stats?.total_changes ?? 0}
            </span>
            <span className="text-xs text-slate-400">detected</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-navy-750 pt-2.5">
            <span>Phase 2 Monitoring</span>
            <span className="text-cyan-400 font-mono font-medium flex items-center gap-1 text-[11px]">
              View History <ArrowRight className="w-3 h-3" />
            </span>
          </div>
        </Card>
      </div>

      {/* Visual Data Breakdown derived strictly from stored database */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Asset Types Distribution */}
        <Card className="lg:col-span-1 space-y-4">
          <div className="flex items-center justify-between border-b border-navy-750 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Asset Categories</h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">Phase 1 Inventory</span>
          </div>

          {totalAssets === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500 italic">
              No asset records found in database.
            </div>
          ) : (
            <div className="space-y-3">
              {Object.entries(stats?.asset_types_distribution || {}).map(([type, count]) => {
                const percent = Math.round((count / totalAssets) * 100) || 0;
                return (
                  <div key={type} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="capitalize font-mono text-slate-300">{type}</span>
                      <span className="font-mono text-slate-400">
                        {count} <span className="text-slate-600">({percent}%)</span>
                      </span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-navy-950 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-500 transition-all duration-500"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div className="pt-2 border-t border-navy-750 flex items-center justify-between">
            <Button variant="ghost" size="sm" onClick={() => onNavigate('inventory')} icon={<ArrowRight className="w-3.5 h-3.5" />}>
              Open Inventory Table
            </Button>
          </div>
        </Card>

        {/* Card 2: Top Detected Services & Bounded Ports */}
        <Card className="lg:col-span-1 space-y-4">
          <div className="flex items-center justify-between border-b border-navy-750 pb-3">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-violet-400" />
              <h3 className="text-sm font-semibold text-slate-200">Responsive Services</h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">Bounded Probes</span>
          </div>

          {(!stats?.top_open_ports || stats.top_open_ports.length === 0) ? (
            <div className="py-8 text-center text-xs text-slate-500 italic">
              No open services detected yet.
            </div>
          ) : (
            <div className="space-y-2.5">
              {stats.top_open_ports.slice(0, 5).map((p) => {
                const maxCount = stats.top_open_ports[0]?.count || 1;
                const barWidth = Math.round((p.count / maxCount) * 100);
                return (
                  <div key={p.port} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">
                        Port {p.port} <span className="text-slate-500 font-sans">({p.service})</span>
                      </span>
                      <span className="font-mono text-cyan-400 font-medium">{p.count} host{p.count > 1 ? 's' : ''}</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-navy-950 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-violet-500 to-cyan-500"
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div className="pt-2 border-t border-navy-750 flex items-center justify-between text-xs text-slate-500">
            <span>Ports Scanned: Allowlist Bounded</span>
            <span className="font-mono text-cyan-400">Max 50</span>
          </div>
        </Card>

        {/* Card 3: Findings & Risk Classification */}
        <Card className="lg:col-span-1 space-y-4">
          <div className="flex items-center justify-between border-b border-navy-750 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Risk & Findings Posture</h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">Phase 3</span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-navy-900 border border-rose-500/30">
              <span className="text-xs text-rose-400">Critical / High</span>
              <div className="text-xl font-bold font-mono text-rose-300 mt-1">
                {(stats?.findings_by_severity?.CRITICAL ?? 0) + (stats?.findings_by_severity?.HIGH ?? 0)}
              </div>
              <span className="text-[10px] text-slate-500">Requires triage</span>
            </div>

            <div className="p-3 rounded-lg bg-navy-900 border border-amber-500/30">
              <span className="text-xs text-amber-400">Medium Risk</span>
              <div className="text-xl font-bold font-mono text-amber-300 mt-1">
                {stats?.findings_by_severity?.MEDIUM ?? 0}
              </div>
              <span className="text-[10px] text-slate-500">Review config</span>
            </div>

            <div className="p-3 rounded-lg bg-navy-900 border border-cyan-500/30">
              <span className="text-xs text-cyan-400">Low Risk</span>
              <div className="text-xl font-bold font-mono text-cyan-300 mt-1">
                {stats?.findings_by_severity?.LOW ?? 0}
              </div>
              <span className="text-[10px] text-slate-500">Minor deviations</span>
            </div>

            <div className="p-3 rounded-lg bg-navy-900 border border-navy-750">
              <span className="text-xs text-slate-400">Informational</span>
              <div className="text-xl font-bold font-mono text-slate-300 mt-1">
                {stats?.findings_by_severity?.INFORMATIONAL ?? (stats?.findings_by_type?.PORT ?? 0)}
              </div>
              <span className="text-[10px] text-slate-500">Normal telemetry</span>
            </div>
          </div>

          <div className="pt-2 border-t border-navy-750 flex items-center justify-between">
            <Button variant="ghost" size="sm" onClick={() => onNavigate('findings')} icon={<ArrowRight className="w-3.5 h-3.5" />}>
              Open Findings & Risk Desk
            </Button>
          </div>
        </Card>
      </div>

      {/* Recent Discovery Runs Card */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between border-b border-navy-750 pb-3">
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">Recent Discovery Runs</h3>
          </div>
          <Button variant="outline" size="sm" onClick={onOpenQuickScan}>
            New Discovery Run
          </Button>
        </div>

        {recentScans.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500 italic">
            No discovery scans executed yet. Launch a scan to discover and inventory attack surface assets.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-navy-750 text-slate-400 font-mono">
                  <th className="py-2.5 px-3">Scope</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Targets Scanned</th>
                  <th className="py-2.5 px-3">Discovered Assets</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-750">
                {recentScans.slice(0, 5).map((scan) => (
                  <tr key={scan.id} className="hover:bg-navy-750/50 transition-colors">
                    <td className="py-3 px-3 font-medium text-slate-200">
                      {scan.scope_name}
                    </td>
                    <td className="py-3 px-3">
                      <Badge
                        variant={
                          scan.status === 'COMPLETED'
                            ? 'emerald'
                            : scan.status === 'IN_PROGRESS'
                            ? 'cyan'
                            : scan.status === 'CANCELLED'
                            ? 'amber'
                            : 'rose'
                        }
                        pulse={scan.status === 'IN_PROGRESS'}
                      >
                        {scan.status}
                      </Badge>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {scan.targets_scanned} / {scan.targets_total}
                    </td>
                    <td className="py-3 px-3 font-mono text-cyan-400 font-semibold">
                      {scan.assets_discovered_count}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {scan.findings_count}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-500">
                      {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : 'Pending'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};
