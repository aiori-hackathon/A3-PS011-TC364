import React from 'react';
import {
  ShieldCheck,
  Plus,
  Trash2,
  Play,
  FlaskConical,
  Clock,
  Layers,
  AlertCircle
} from 'lucide-react';
import type { Scope } from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';

interface ScopeViewProps {
  scopes: Scope[];
  onOpenNewScope: () => void;
  onDeleteScope: (scopeId: string) => Promise<void>;
  onLaunchScanForScope: (scopeId: string) => void;
}

export const ScopeView: React.FC<ScopeViewProps> = ({
  scopes,
  onOpenNewScope,
  onDeleteScope,
  onLaunchScanForScope,
}) => {
  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Authorised Scope Configuration
          </h2>
          <p className="text-xs text-slate-400">
            Define and manage explicitly authorised domains, FQDNs, and target IP ranges
          </p>
        </div>

        <Button
          variant="primary"
          onClick={onOpenNewScope}
          icon={<Plus className="w-4 h-4" />}
        >
          Add Scope
        </Button>
      </div>

      {/* Scope Cards Grid */}
      {scopes.length === 0 ? (
        <Card className="py-16 text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-300">No Scopes Defined</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            You must define an authorized scope before running discovery scans.
          </p>
          <Button variant="primary" size="sm" onClick={onOpenNewScope}>
            Define First Scope
          </Button>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scopes.map((scope) => (
            <Card key={scope.id} hover className="flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                {/* Header */}
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                      {scope.name}
                    </h3>
                    {scope.description && (
                      <p className="text-xs text-slate-400">{scope.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {scope.allow_local_lab && (
                      <Badge variant="violet" size="sm">
                        LOCAL LAB
                      </Badge>
                    )}
                    <Badge variant="emerald" size="sm">
                      AUTHORISED
                    </Badge>
                  </div>
                </div>

                {/* Scope Details */}
                <div className="space-y-2 text-xs">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Authorised By:</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {scope.authorised_by}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Discovered Assets:</span>
                    <span className="font-mono text-slate-200">
                      {scope.asset_count} asset{scope.asset_count === 1 ? '' : 's'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Created:</span>
                    <span className="font-mono text-slate-500">
                      {new Date(scope.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                {/* Targets Preview List */}
                <div className="space-y-1.5 pt-2 border-t border-navy-750">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Configured Targets ({scope.targets.length})</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                    {scope.targets.map((target, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-navy-900 border border-navy-700 text-slate-300 font-mono text-[11px]"
                      >
                        {target}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-3 border-t border-navy-750">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onDeleteScope(scope.id)}
                  className="text-rose-400 hover:text-rose-300 hover:bg-rose-950/40"
                  icon={<Trash2 className="w-3.5 h-3.5" />}
                >
                  Delete
                </Button>

                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => onLaunchScanForScope(scope.id)}
                  icon={<Play className="w-3.5 h-3.5 fill-current" />}
                >
                  Launch Scan
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};
