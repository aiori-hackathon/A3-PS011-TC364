import React, { useState, useEffect } from 'react';
import {
  Server,
  Globe,
  Lock,
  FileCode,
  Layers,
  Clock,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Copy,
  Check,
  History,
  ArrowRight,
  AlertTriangle
} from 'lucide-react';
import type { DiscoveredAsset, ScanFinding, AssetChangeRecord } from '../../api/types';
import { api } from '../../api/client';
import { Drawer } from '../ui/Drawer';
import { Badge } from '../ui/Badge';

interface AssetDetailDrawerProps {
  asset: DiscoveredAsset | null;
  findings: ScanFinding[];
  isOpen: boolean;
  onClose: () => void;
}

export const AssetDetailDrawer: React.FC<AssetDetailDrawerProps> = ({
  asset,
  findings,
  isOpen,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'dns' | 'http' | 'tls' | 'evidence' | 'changes'>('overview');
  const [assetChanges, setAssetChanges] = useState<AssetChangeRecord[]>([]);
  const [loadingChanges, setLoadingChanges] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!asset) return;
    let cancelled = false;
    setLoadingChanges(true);
    api.getAssetChanges(asset.id)
      .then((res) => {
        if (!cancelled) setAssetChanges(res);
      })
      .catch(() => {
        if (!cancelled) setAssetChanges([]);
      })
      .finally(() => {
        if (!cancelled) setLoadingChanges(false);
      });
    return () => {
      cancelled = true;
    };
  }, [asset]);

  if (!asset) return null;

  const copyToClipboard = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const tabs = [
    { id: 'overview' as const, label: 'Overview', icon: Layers },
    { id: 'dns' as const, label: 'DNS Records', icon: Globe },
    { id: 'http' as const, label: 'HTTP / Web', icon: Server },
    { id: 'tls' as const, label: 'TLS Certificate', icon: Lock },
    { id: 'changes' as const, label: `Changes (${assetChanges.length})`, icon: History },
    { id: 'evidence' as const, label: 'Findings & Raw Evidence', icon: FileCode },
  ];

  const dns = asset.dns_records || {};
  const http = asset.http_summary || {};
  const tls = asset.tls_summary || {};
  const openPorts = asset.open_ports || [];

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title={asset.host_or_ip}
      subtitle={`Asset Type: ${asset.asset_type.toUpperCase()} • Scope ID: ${asset.scope_id.substring(0, 8)}`}
      badge={
        <Badge variant={asset.status === 'ACTIVE' ? 'emerald' : 'amber'}>
          {asset.status}
        </Badge>
      }
    >
      {/* Tab Navigation */}
      <div className="flex border-b border-navy-750 gap-2 pb-1 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 py-2 px-3 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-750">
              <span className="text-[11px] text-slate-400 uppercase font-mono">Resolved IP Address</span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-base font-mono font-bold text-slate-100">
                  {asset.ip_address || 'Unresolved / Direct Target'}
                </span>
                {asset.ip_address && (
                  <button
                    onClick={() => copyToClipboard(asset.ip_address!, 'ip')}
                    className="p-1 hover:bg-navy-700 rounded text-slate-400 hover:text-slate-200"
                    title="Copy IP"
                  >
                    {copiedField === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-navy-850 border border-navy-750">
              <span className="text-[11px] text-slate-400 uppercase font-mono">Asset Classification</span>
              <div className="mt-1 flex items-center gap-2">
                <Badge variant="cyan" size="md">
                  {asset.asset_type.toUpperCase()}
                </Badge>
                <span className="text-xs text-slate-400">
                  {asset.asset_type === 'ipv4' ? 'Direct Host' : 'Domain Entity'}
                </span>
              </div>
            </div>
          </div>

          {/* Timestamps */}
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                First Observed In Scope:
              </span>
              <span className="font-mono text-slate-200">
                {new Date(asset.first_seen).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center justify-between border-t border-navy-750/50 pt-2">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                Last Verified by Discovery Run:
              </span>
              <span className="font-mono text-cyan-300">
                {new Date(asset.last_seen).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Open Ports Quick Matrix */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
              Detected Responsive TCP Ports ({openPorts.length})
            </h4>
            {openPorts.length === 0 ? (
              <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 text-xs text-slate-500 italic text-center">
                No responsive ports identified in allowlist probes.
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {openPorts.map((op) => (
                  <div
                    key={op.port}
                    className="p-3 rounded-lg bg-navy-850 border border-navy-700/80 flex flex-col justify-between"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-400 font-bold text-sm">
                        Port {op.port}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 font-mono">
                        OPEN
                      </span>
                    </div>
                    <div className="mt-2 text-xs text-slate-300 font-medium">
                      {op.service}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono mt-1">
                      Latency: {op.latency_ms} ms
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: DNS Records */}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 space-y-4">
            <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
              DNS Resolution Lookups
            </h4>

            {/* A Records */}
            <div className="space-y-1">
              <span className="text-xs font-mono font-bold text-cyan-400">A Records (IPv4):</span>
              {dns.A && dns.A.length > 0 ? (
                <div className="space-y-1">
                  {dns.A.map((ip) => (
                    <div key={ip} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-200 flex justify-between items-center">
                      <span>{ip}</span>
                      <button onClick={() => copyToClipboard(ip, `a-${ip}`)} className="text-slate-500 hover:text-slate-300">
                        {copiedField === `a-${ip}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic pl-2">None</div>
              )}
            </div>

            {/* AAAA Records */}
            <div className="space-y-1">
              <span className="text-xs font-mono font-bold text-violet-400">AAAA Records (IPv6):</span>
              {dns.AAAA && dns.AAAA.length > 0 ? (
                <div className="space-y-1">
                  {dns.AAAA.map((ip6) => (
                    <div key={ip6} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-200">
                      {ip6}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic pl-2">None</div>
              )}
            </div>

            {/* CNAME */}
            <div className="space-y-1">
              <span className="text-xs font-mono font-bold text-amber-400">CNAME Records:</span>
              {dns.CNAME && dns.CNAME.length > 0 ? (
                <div className="space-y-1">
                  {dns.CNAME.map((c) => (
                    <div key={c} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-200">
                      {c}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic pl-2">None</div>
              )}
            </div>

            {/* MX Records */}
            <div className="space-y-1">
              <span className="text-xs font-mono font-bold text-emerald-400">MX Mail Exchangers:</span>
              {dns.MX && dns.MX.length > 0 ? (
                <div className="space-y-1">
                  {dns.MX.map((mx) => (
                    <div key={mx} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-200">
                      {mx}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic pl-2">None</div>
              )}
            </div>

            {/* TXT Records */}
            <div className="space-y-1">
              <span className="text-xs font-mono font-bold text-slate-400">TXT Records:</span>
              {dns.TXT && dns.TXT.length > 0 ? (
                <div className="space-y-1">
                  {dns.TXT.map((txt, idx) => (
                    <div key={idx} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-300 break-all">
                      {txt}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic pl-2">None</div>
              )}
            </div>

            {/* PTR Reverse Lookup */}
            {dns.PTR && dns.PTR.length > 0 && (
              <div className="space-y-1">
                <span className="text-xs font-mono font-bold text-cyan-300">PTR Reverse Name:</span>
                <div className="space-y-1">
                  {dns.PTR.map((ptr) => (
                    <div key={ptr} className="font-mono text-xs p-2 rounded bg-navy-900 border border-navy-750 text-slate-200">
                      {ptr}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: HTTP Response */}
      {activeTab === 'http' && (
        <div className="space-y-4">
          {!http.reachable ? (
            <div className="p-6 rounded-xl bg-navy-850 border border-navy-750 text-center text-xs text-slate-500 italic">
              No HTTP/HTTPS response detected or probe skipped.
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 space-y-4">
              <div className="flex items-center justify-between border-b border-navy-750 pb-3">
                <div className="flex items-center gap-2">
                  <Badge variant={http.status_code && http.status_code < 400 ? 'emerald' : 'amber'}>
                    HTTP {http.status_code}
                  </Badge>
                  <span className="font-mono text-xs text-cyan-400 uppercase">
                    {http.scheme} (Port {http.port})
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  Latency: {http.latency_ms} ms
                </span>
              </div>

              {http.title && (
                <div className="space-y-1">
                  <span className="text-[11px] text-slate-400 font-mono uppercase">Page HTML Title</span>
                  <div className="p-2.5 rounded bg-navy-900 border border-navy-750 text-sm font-medium text-slate-100">
                    {http.title}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                  <span className="text-[10px] text-slate-500 font-mono">Server Header</span>
                  <div className="font-mono text-slate-200 mt-0.5 truncate">
                    {http.server || 'Not Disclosed'}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                  <span className="text-[10px] text-slate-500 font-mono">Content-Type</span>
                  <div className="font-mono text-slate-200 mt-0.5 truncate">
                    {http.content_type || 'Unknown'}
                  </div>
                </div>
              </div>

              {http.redirect_count !== undefined && http.redirect_count > 0 && (
                <div className="p-2.5 rounded bg-navy-900 border border-navy-750 text-xs">
                  <span className="text-slate-400">Redirect Chain: </span>
                  <span className="text-cyan-400 font-mono">{http.redirect_count} hop(s)</span>
                  {http.final_url && (
                    <div className="font-mono text-[11px] text-slate-400 truncate mt-1">
                      Final: {http.final_url}
                    </div>
                  )}
                </div>
              )}

              {/* Raw Response Headers */}
              {http.headers && (
                <div className="space-y-2 pt-2">
                  <span className="text-xs font-mono font-semibold text-slate-300 uppercase">
                    Response Headers
                  </span>
                  <div className="max-h-48 overflow-y-auto rounded bg-navy-950 p-3 font-mono text-[11px] space-y-1 text-slate-300 border border-navy-750">
                    {Object.entries(http.headers).map(([k, v]) => (
                      <div key={k} className="flex">
                        <span className="text-cyan-400 shrink-0 mr-2">{k}:</span>
                        <span className="text-slate-300 break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: TLS Certificate */}
      {activeTab === 'tls' && (
        <div className="space-y-4">
          {!tls.has_tls ? (
            <div className="p-6 rounded-xl bg-navy-850 border border-navy-750 text-center text-xs text-slate-500 italic">
              No TLS certificate detected on port 443 / 8443.
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 space-y-4">
              <div className="flex items-center justify-between border-b border-navy-750 pb-3">
                <div className="flex items-center gap-2">
                  <Badge variant={tls.is_expired ? 'rose' : (tls.days_remaining && tls.days_remaining < 30 ? 'amber' : 'emerald')}>
                    {tls.is_expired ? 'EXPIRED' : `${tls.days_remaining} Days Remaining`}
                  </Badge>
                  <span className="font-mono text-xs text-slate-400">{tls.tls_version || 'TLS'}</span>
                </div>
                <span className="font-mono text-[11px] text-slate-400">
                  Port {tls.port || 443}
                </span>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-mono">Subject Common Name</span>
                  <div className="font-mono text-slate-100 font-bold text-sm mt-0.5">
                    {tls.subject_cn || 'None'}
                  </div>
                  {tls.subject_org && (
                    <div className="text-slate-400 text-[11px]">{tls.subject_org}</div>
                  )}
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-mono">Issuer Authority</span>
                  <div className="font-mono text-slate-200 mt-0.5">
                    {tls.issuer_cn || 'Unknown Issuer'}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                    <span className="text-[10px] text-slate-500 font-mono">Valid From</span>
                    <div className="font-mono text-slate-300 mt-0.5 text-[11px]">
                      {tls.valid_from ? new Date(tls.valid_from).toLocaleDateString() : 'N/A'}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                    <span className="text-[10px] text-slate-500 font-mono">Valid Until</span>
                    <div className="font-mono text-slate-300 mt-0.5 text-[11px]">
                      {tls.valid_to ? new Date(tls.valid_to).toLocaleDateString() : 'N/A'}
                    </div>
                  </div>
                </div>

                {/* Subject Alternative Names (SANs) */}
                {tls.sans && tls.sans.length > 0 && (
                  <div className="space-y-1.5 pt-2">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">
                      Subject Alternative Names (SANs) ({tls.sans.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {tls.sans.map((san) => (
                        <span key={san} className="px-2 py-0.5 rounded bg-navy-900 border border-navy-750 text-[11px] font-mono text-slate-300">
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {tls.cipher && (
                  <div className="pt-2">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Cipher Suite</span>
                    <div className="font-mono text-[11px] text-cyan-400 mt-0.5">
                      {tls.cipher}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Findings & Raw Evidence */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
              Discovered Findings & Audit Evidence ({findings.length})
            </h4>

            {findings.length === 0 ? (
              <div className="p-4 rounded-xl bg-navy-850 border border-navy-750 text-xs text-slate-500 italic text-center">
                No individual findings recorded.
              </div>
            ) : (
              <div className="space-y-2.5">
                {findings.map((f) => (
                  <div key={f.id} className="p-3 rounded-lg bg-navy-850 border border-navy-750 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            f.finding_type === 'PORT'
                              ? 'cyan'
                              : f.finding_type === 'TLS'
                              ? 'emerald'
                              : f.finding_type === 'HTTP'
                              ? 'violet'
                              : 'amber'
                          }
                          size="sm"
                        >
                          {f.finding_type}
                        </Badge>
                        <span className="text-xs font-semibold text-slate-200">
                          {f.title}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(f.created_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <pre className="p-2.5 rounded bg-navy-950 text-[10px] font-mono text-slate-300 overflow-x-auto border border-navy-750 max-h-40">
                      {JSON.stringify(f.evidence, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Change History */}
      {activeTab === 'changes' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-slate-400">
              Phase 2 Detected Baseline Changes
            </span>
            <span className="text-xs font-mono text-cyan-400">
              {assetChanges.length} record(s)
            </span>
          </div>

          {loadingChanges ? (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              Loading change history...
            </div>
          ) : assetChanges.length === 0 ? (
            <div className="p-8 rounded-xl bg-navy-850 border border-navy-750 text-center space-y-2">
              <History className="w-8 h-8 mx-auto text-slate-500 opacity-50" />
              <div className="text-xs text-slate-300 font-medium">No Change Diffs Recorded</div>
              <p className="text-[11px] text-slate-500">
                This asset matches its established discovery baseline without detected alterations.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {assetChanges.map((change) => (
                <div key={change.id} className="p-3.5 rounded-xl bg-navy-850 border border-navy-750 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        {change.change_type}
                      </span>
                      {change.is_inconclusive && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          INCONCLUSIVE
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(change.created_at).toLocaleString()}
                    </span>
                  </div>

                  <div className="text-xs font-mono text-slate-300">
                    <span className="text-slate-500">Attribute: </span>
                    <span className="text-cyan-300">{change.attribute_name}</span>
                  </div>

                  {/* Diff */}
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
                    <div className="p-2 rounded bg-navy-950 border border-navy-800">
                      <div className="text-[10px] text-slate-500 uppercase">Previous</div>
                      <div className="text-slate-400 truncate mt-0.5">
                        {change.previous_value !== null && change.previous_value !== undefined
                          ? JSON.stringify(change.previous_value)
                          : 'None'}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-navy-950 border border-navy-800">
                      <div className="text-[10px] text-cyan-400 uppercase">New Detected</div>
                      <div className="text-cyan-300 truncate mt-0.5">
                        {change.new_value !== null && change.new_value !== undefined
                          ? JSON.stringify(change.new_value)
                          : 'None'}
                      </div>
                    </div>
                  </div>

                  {/* Evidence Context */}
                  {change.evidence && (
                    <div className="text-[11px] text-slate-400 pt-1 border-t border-navy-800/80">
                      <span className="text-slate-500 font-mono text-[10px]">Context: </span>
                      {change.evidence.context || JSON.stringify(change.evidence)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
};
