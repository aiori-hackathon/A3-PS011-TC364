import React from 'react';
import { ShieldAlert, RefreshCw, PlusCircle, Play } from 'lucide-react';
import { Button } from '../ui/Button';

interface HeaderProps {
  title: string;
  subtitle: string;
  isDemoActive: boolean;
  onRefresh: () => void;
  onOpenNewScope: () => void;
  onOpenQuickScan: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  isDemoActive,
  onRefresh,
  onOpenNewScope,
  onOpenQuickScan,
  isRefreshing = false,
}) => {
  return (
    <header className="h-16 px-8 border-b border-navy-750 bg-navy-950/60 backdrop-blur-md flex items-center justify-between z-10 shrink-0">
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2.5">
            {title}
            {isDemoActive && (
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-500/40 font-semibold tracking-wider">
                SYNTHETIC DEMO DATA
              </span>
            )}
          </h1>
          <p className="text-xs text-slate-400">{subtitle}</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Safety Guardrail Indicator */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-full bg-navy-900 border border-navy-700 text-xs text-slate-400">
          <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
          <span>Scope Enforcement:</span>
          <span className="text-cyan-400 font-mono font-medium">STRICT (NO PROHIBITED RANGES)</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700 text-slate-400 hover:text-slate-200 transition-colors"
          title="Refresh Current Data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* New Scope Button */}
        <Button
          variant="secondary"
          size="sm"
          onClick={onOpenNewScope}
          icon={<PlusCircle className="w-4 h-4 text-slate-300" />}
        >
          New Scope
        </Button>

        {/* Launch Scan Button */}
        <Button
          variant="primary"
          size="sm"
          onClick={onOpenQuickScan}
          icon={<Play className="w-3.5 h-3.5 text-navy-950 fill-current" />}
        >
          Launch Scan
        </Button>
      </div>
    </header>
  );
};
