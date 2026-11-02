import React, { useState, useEffect, useRef } from 'react';
import {
  Radar,
  Play,
  Square,
  Clock,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Server,
  Layers,
  Activity,
  ArrowRight
} from 'lucide-react';
import type { ScanRun, Scope } from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

interface DiscoveryViewProps {
  scans: ScanRun[];
  activeScan: ScanRun | null;
  scopes: Scope[];
  onOpenNewScan: () => void;
  onCancelScan: (scanId: string) => Promise<void>;
  onSelectScan: (scan: ScanRun) => void;
  isCancelling?: boolean;
}

export const DiscoveryView: React.FC<DiscoveryViewProps> = ({
  scans,
  activeScan,
  scopes,
  onOpenNewScan,
  onCancelScan,
  onSelectScan,
  isCancelling = false,
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Auto-scroll terminal logs to bottom when new logs appear
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [activeScan?.logs, autoScroll]);

  const displayedScan = activeScan || scans[0] || null;
  const isRunning = displayedScan?.status === 'IN_PROGRESS';

  const progressPercent = displayedScan && displayedScan.targets_total > 0
    ? Math.round((displayedScan.targets_scanned / displayedScan.targets_total) * 100)
    : 0;

  return (
    <div className="space-y-6">
      {/* Top Banner & Launch Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Radar className="w-5 h-5 text-cyan-400" />
            Attack Surface Discovery Monitor
          </h2>
          <p className="text-xs text-slate-400">
            Real-time execution monitor for bounded DNS, TCP port, and HTTP/TLS probe runs
          </p>
        </div>

        <Button
          variant="primary"
          onClick={onOpenNewScan}
          icon={<Play className="w-4 h-4 fill-current" />}
        >
          New Discovery Run
        </Button>
      </div>

      {/* Active Scan Execution Card */}
      {displayedScan ? (
        <Card glow={isRunning} className="space-y-5">
          {/* Header Row */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-navy-750 pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <span className="font-mono text-base font-bold text-slate-100">
                  {displayedScan.scope_name}
                </span>
                <Badge
                  variant={
                    displayedScan.status === 'COMPLETED'
                      ? 'emerald'
                      : displayedScan.status === 'IN_PROGRESS'
                      ? 'cyan'
                      : displayedScan.status === 'CANCELLED'
                      ? 'amber'
                      : 'rose'
                  }
                  pulse={isRunning}
                >
                  {displayedScan.status}
                </Badge>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Run ID: {displayedScan.id.substring(0, 8)} • Started:{' '}
                {displayedScan.started_at
                  ? new Date(displayedScan.started_at).toLocaleTimeString()
                  : 'Pending'}
              </span>
            </div>

            {/* Cancel Button if running */}
            {isRunning && (
              <Button
                variant="danger"
                size="sm"
                onClick={() => onCancelScan(displayedScan.id)}
                loading={isCancelling}
                icon={<Square className="w-3.5 h-3.5 fill-current" />}
              >
                Cancel Discovery Run
              </Button>
            )}
          </div>

          {/* Progress Bar & Counters */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-300 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Discovery Progress:
              </span>
              <span className="text-cyan-400 font-bold">
                {displayedScan.targets_scanned} / {displayedScan.targets_total} targets ({progressPercent}%)
              </span>
            </div>

            <div className="w-full h-3 rounded-full bg-navy-950 p-0.5 border border-navy-700/80 overflow-hidden relative">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  isRunning
                    ? 'bg-gradient-to-r from-cyan-500 via-violet-500 to-cyan-400 shadow-glow-cyan-sm animate-pulse-slow'
                    : displayedScan.status === 'COMPLETED'
                    ? 'bg-emerald-500'
                    : 'bg-amber-500'
                }`}
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          {/* Metrics Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">Targets Processed</span>
              <div className="text-lg font-bold font-mono text-slate-100 mt-1">
                {displayedScan.targets_scanned} / {displayedScan.targets_total}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">New Discovered</span>
              <div className="text-lg font-bold font-mono text-cyan-400 mt-1">
                {displayedScan.new_assets_count ?? displayedScan.assets_discovered_count}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">Assets Updated</span>
              <div className="text-lg font-bold font-mono text-emerald-400 mt-1">
                {displayedScan.updated_assets_count ?? 0}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">Total Assets</span>
              <div className="text-lg font-bold font-mono text-slate-200 mt-1">
                {displayedScan.total_assets_count ?? displayedScan.assets_discovered_count}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">Unresolved / Failed</span>
              <div className="text-lg font-bold font-mono text-amber-400 mt-1">
                {displayedScan.failed_targets_count ?? 0}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-navy-900 border border-navy-750 text-center">
              <span className="text-[10px] text-slate-400 uppercase font-mono">Findings Recorded</span>
              <div className="text-lg font-bold font-mono text-violet-400 mt-1">
                {displayedScan.findings_count}
              </div>
            </div>
          </div>

          {/* Real-time Discovery Console Feed */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5 text-slate-300">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Live Execution Console
              </span>
              <label className="flex items-center gap-1.5 cursor-pointer text-[11px]">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded border-navy-700 text-cyan-500 focus:ring-0 bg-navy-950"
                />
                Auto-scroll
              </label>
            </div>

            <div
              ref={terminalRef}
              className="h-64 overflow-y-auto rounded-xl bg-navy-950 border border-navy-700/80 p-4 font-mono text-xs space-y-1.5 shadow-inner"
            >
              {(!displayedScan.logs || displayedScan.logs.length === 0) ? (
                <div className="text-slate-600 italic">No logs recorded yet for this run.</div>
              ) : (
                displayedScan.logs.map((log, idx) => {
                  const levelColors = {
                    INFO: 'text-slate-300',
                    SUCCESS: 'text-emerald-400 font-semibold',
                    WARN: 'text-amber-400',
                    ERROR: 'text-rose-400 font-bold',
                  };
                  return (
                    <div key={idx} className="flex items-start gap-2 leading-relaxed">
                      <span className="text-slate-600 shrink-0 select-none">
                        [{log.timestamp}]
                      </span>
                      <span
                        className={`text-[10px] uppercase font-bold shrink-0 px-1 rounded ${
                          log.level === 'SUCCESS'
                            ? 'bg-emerald-950/80 text-emerald-300'
                            : log.level === 'WARN'
                            ? 'bg-amber-950/80 text-amber-300'
                            : log.level === 'ERROR'
                            ? 'bg-rose-950/80 text-rose-300'
                            : 'bg-navy-850 text-cyan-400'
                        }`}
                      >
                        {log.level}
                      </span>
                      <span className={`${levelColors[log.level] || 'text-slate-300'} break-all`}>
                        {log.message}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </Card>
      ) : (
        <Card className="py-12 text-center space-y-3">
          <Radar className="w-8 h-8 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-300">No Discovery Runs Initiated</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Ready to inventory your attack surface? Launch your first bounded discovery scan.
          </p>
          <Button variant="primary" size="sm" onClick={onOpenNewScan}>
            Launch Discovery Run
          </Button>
        </Card>
      )}

      {/* Discovery Runs History Table */}
      <Card className="p-0 overflow-hidden space-y-0">
        <div className="p-4 border-b border-navy-750 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            Discovery Run History ({scans.length})
          </h3>
          <span className="text-xs text-slate-500 font-mono">Audit Trail Verified</span>
        </div>

        {scans.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 italic">
            No past scan records stored.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-navy-750 bg-navy-900/60 text-slate-400 font-mono">
                  <th className="py-3 px-4">Scope</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Targets Scanned</th>
                  <th className="py-3 px-4">Assets Found</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Started</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-750">
                {scans.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => onSelectScan(s)}
                    className={`hover:bg-navy-750/50 cursor-pointer transition-colors ${
                      displayedScan?.id === s.id ? 'bg-navy-800/80 border-l-2 border-cyan-400' : ''
                    }`}
                  >
                    <td className="py-3 px-4 font-medium text-slate-200">
                      {s.scope_name}
                    </td>
                    <td className="py-3 px-4">
                      <Badge
                        variant={
                          s.status === 'COMPLETED'
                            ? 'emerald'
                            : s.status === 'IN_PROGRESS'
                            ? 'cyan'
                            : s.status === 'CANCELLED'
                            ? 'amber'
                            : 'rose'
                        }
                        size="sm"
                        pulse={s.status === 'IN_PROGRESS'}
                      >
                        {s.status}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {s.targets_scanned} / {s.targets_total}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                      {s.assets_discovered_count}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {s.findings_count}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-500">
                      {s.started_at ? new Date(s.started_at).toLocaleTimeString() : 'Pending'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(s);
                        }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 justify-end ml-auto"
                      >
                        Inspect <ArrowRight className="w-3 h-3" />
                      </button>
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
