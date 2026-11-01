import React, { useState } from 'react';
import {
  Radar,
  ShieldCheck,
  Server,
  Lock,
  Globe,
  AlertTriangle,
  Play
} from 'lucide-react';
import type { Scope, ScanConfig } from '../../api/types';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  scopes: Scope[];
  onLaunchScan: (scopeId: string, config: ScanConfig) => Promise<void>;
  initialScopeId?: string;
}

export const NewScanModal: React.FC<NewScanModalProps> = ({
  isOpen,
  onClose,
  scopes,
  onLaunchScan,
  initialScopeId,
}) => {
  const [selectedScopeId, setSelectedScopeId] = useState<string>(initialScopeId || scopes[0]?.id || '');
  const [enableDns, setEnableDns] = useState(true);
  const [enablePorts, setEnablePorts] = useState(true);
  const [enableHttp, setEnableHttp] = useState(true);
  const [enableTls, setEnableTls] = useState(true);

  // Sync selected scope when modal opens or scopes change, preventing stale scope IDs
  React.useEffect(() => {
    if (!isOpen) {
      setErrorMessage(null);
      return;
    }
    if (initialScopeId && scopes.some((s) => s.id === initialScopeId)) {
      setSelectedScopeId(initialScopeId);
    } else if (!scopes.some((s) => s.id === selectedScopeId)) {
      setSelectedScopeId(scopes[0]?.id || '');
    }
  }, [initialScopeId, isOpen, scopes, selectedScopeId]);

  // Port presets
  const [portPreset, setPortPreset] = useState<'web' | 'standard' | 'extended' | 'custom'>('standard');
  const [customPortsInput, setCustomPortsInput] = useState<string>('80, 443, 8080');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const presets = {
    web: [80, 443],
    standard: [21, 22, 25, 53, 80, 443, 3000, 3306, 5432, 8080, 8443],
    extended: [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 5432, 8000, 8080, 8443, 8888],
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!selectedScopeId) {
      setErrorMessage('Please select a target scope.');
      return;
    }

    const targetScope = scopes.find((s) => s.id === selectedScopeId);
    if (!targetScope) {
      setErrorMessage('The selected scope no longer exists. Please refresh and select an active scope.');
      return;
    }

    if (!targetScope.authorised_confirmation) {
      setErrorMessage('Cannot launch discovery scan: Selected scope has not been confirmed as authorised.');
      return;
    }

    let resolvedPorts: number[] = [];
    if (enablePorts) {
      if (portPreset === 'custom') {
        const parsed = customPortsInput
          .split(/[\s,]+/)
          .filter(Boolean)
          .map((p) => parseInt(p, 10));
        
        if (parsed.some(isNaN)) {
          setErrorMessage('Custom ports must be valid numbers.');
          return;
        }
        if (parsed.length > 50) {
          setErrorMessage('Maximum 50 ports allowed to prevent unrestricted scanning.');
          return;
        }
        resolvedPorts = parsed;
      } else {
        resolvedPorts = presets[portPreset];
      }
    }

    setIsSubmitting(true);
    try {
      await onLaunchScan(selectedScopeId, {
        ports: enablePorts ? resolvedPorts : [],
        enable_dns: enableDns,
        enable_ports: enablePorts,
        enable_http: enableHttp,
        enable_tls: enableTls,
      });
      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to start discovery run.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const selectedScope = scopes.find((s) => s.id === selectedScopeId);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Launch Manual Discovery Run"
      subtitle="Configure bounded, opt-in probes for authorized attack surface targets"
      maxWidth="lg"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSubmit}
            disabled={scopes.length === 0 || !selectedScopeId || isSubmitting}
            loading={isSubmitting}
            icon={<Play className="w-3.5 h-3.5 fill-current" />}
          >
            Start Discovery Run
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-5">
        {errorMessage && (
          <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-500/50 text-rose-300 text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{errorMessage}</span>
          </div>
        )}

        {scopes.length === 0 && (
          <div className="p-3.5 rounded-lg bg-navy-900 border border-amber-500/40 text-amber-300 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-slate-200">No Target Scopes Available</div>
              <p className="mt-0.5 text-slate-400">
                Please create and authorize an attack surface scope before launching a discovery run.
              </p>
            </div>
          </div>
        )}

        {/* Scope Selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
            Target Scope
          </label>
          <select
            value={selectedScopeId}
            onChange={(e) => setSelectedScopeId(e.target.value)}
            disabled={scopes.length === 0}
            className="w-full bg-navy-900 border border-navy-700 text-slate-200 text-xs rounded-lg p-2.5 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
          >
            {scopes.length === 0 ? (
              <option value="">No scopes configured</option>
            ) : (
              scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.targets.length} targets) {s.allow_local_lab ? '• Local Lab' : ''}
                </option>
              ))
            )}
          </select>
          {selectedScope && (
            <div className="text-[11px] text-slate-400 font-mono mt-1">
              Authorised by: <span className="text-cyan-400">{selectedScope.authorised_by}</span>
            </div>
          )}
        </div>

        {/* Probe Modules Toggles */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
            Discovery Modules
          </label>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-navy-900 border border-navy-750 cursor-pointer hover:border-navy-600">
              <input
                type="checkbox"
                checked={enableDns}
                onChange={(e) => setEnableDns(e.target.checked)}
                className="rounded border-navy-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-navy-950"
              />
              <Globe className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-200">DNS Enumeration</span>
            </label>

            <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-navy-900 border border-navy-750 cursor-pointer hover:border-navy-600">
              <input
                type="checkbox"
                checked={enablePorts}
                onChange={(e) => setEnablePorts(e.target.checked)}
                className="rounded border-navy-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-navy-950"
              />
              <Server className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-200">Bounded Port Check</span>
            </label>

            <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-navy-900 border border-navy-750 cursor-pointer hover:border-navy-600">
              <input
                type="checkbox"
                checked={enableHttp}
                onChange={(e) => setEnableHttp(e.target.checked)}
                className="rounded border-navy-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-navy-950"
              />
              <Server className="w-4 h-4 text-violet-400" />
              <span className="text-slate-200">HTTP Reachability</span>
            </label>

            <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-navy-900 border border-navy-750 cursor-pointer hover:border-navy-600">
              <input
                type="checkbox"
                checked={enableTls}
                onChange={(e) => setEnableTls(e.target.checked)}
                className="rounded border-navy-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-navy-950"
              />
              <Lock className="w-4 h-4 text-emerald-400" />
              <span className="text-slate-200">TLS Certificate Check</span>
            </label>
          </div>
        </div>

        {/* Port Allowlist Selector */}
        {enablePorts && (
          <div className="space-y-2 p-3.5 rounded-xl bg-navy-900/60 border border-navy-750">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
                TCP Port Allowlist (Max 50)
              </label>
              <span className="text-[10px] text-cyan-400 font-mono">Opt-in Bounded</span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-xs">
              <button
                type="button"
                onClick={() => setPortPreset('web')}
                className={`py-1.5 px-2 rounded-lg border text-center transition-colors ${
                  portPreset === 'web'
                    ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300 font-medium'
                    : 'bg-navy-900 border-navy-750 text-slate-400 hover:text-slate-200'
                }`}
              >
                Web (80, 443)
              </button>

              <button
                type="button"
                onClick={() => setPortPreset('standard')}
                className={`py-1.5 px-2 rounded-lg border text-center transition-colors ${
                  portPreset === 'standard'
                    ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300 font-medium'
                    : 'bg-navy-900 border-navy-750 text-slate-400 hover:text-slate-200'
                }`}
              >
                Standard (11 Ports)
              </button>

              <button
                type="button"
                onClick={() => setPortPreset('extended')}
                className={`py-1.5 px-2 rounded-lg border text-center transition-colors ${
                  portPreset === 'extended'
                    ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300 font-medium'
                    : 'bg-navy-900 border-navy-750 text-slate-400 hover:text-slate-200'
                }`}
              >
                Extended (19 Ports)
              </button>
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={() => setPortPreset('custom')}
                className={`text-xs text-left font-mono ${
                  portPreset === 'custom' ? 'text-cyan-400 underline' : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                Or enter custom comma-separated ports...
              </button>

              {portPreset === 'custom' && (
                <input
                  type="text"
                  value={customPortsInput}
                  onChange={(e) => setCustomPortsInput(e.target.value)}
                  placeholder="e.g. 80, 443, 8080, 8443, 9000"
                  className="mt-2 w-full p-2 text-xs bg-navy-950 border border-navy-700 rounded text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                />
              )}
            </div>
          </div>
        )}

        {/* Ethical / Authorisation Banner */}
        <div className="p-3 rounded-lg bg-navy-900 border border-navy-700 text-xs text-slate-400 space-y-1">
          <div className="flex items-center gap-1.5 text-cyan-400 font-semibold font-mono text-[11px] uppercase">
            <ShieldCheck className="w-3.5 h-3.5" />
            Safety Guardrails Active
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Discovery will execute bounded TCP probes, standard DNS lookups, and HTTP header inspections. No exploits, brute-forcing, stealth scans, or intrusive attacks will run.
          </p>
        </div>
      </form>
    </Modal>
  );
};
