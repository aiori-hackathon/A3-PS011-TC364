import React, { useState } from 'react';
import {
  Search,
  Filter,
  Server,
  Globe,
  Lock,
  ExternalLink,
  Trash2,
  Eye,
  RefreshCw,
  Layers,
  ShieldCheck
} from 'lucide-react';
import type { DiscoveredAsset, ScanFinding, Scope } from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { AssetDetailDrawer } from './AssetDetailDrawer';

interface InventoryViewProps {
  assets: DiscoveredAsset[];
  scopes: Scope[];
  findingsMap: Record<string, ScanFinding[]>;
  onInspectAsset: (asset: DiscoveredAsset) => void;
  onDeleteAsset: (assetId: string) => void;
  onRefresh: () => void;
  selectedAsset: DiscoveredAsset | null;
  onCloseDrawer: () => void;
  isDrawerOpen: boolean;
}

export const InventoryView: React.FC<InventoryViewProps> = ({
  assets,
  scopes,
  findingsMap,
  onInspectAsset,
  onDeleteAsset,
  onRefresh,
  selectedAsset,
  onCloseDrawer,
  isDrawerOpen,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedScope, setSelectedScope] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedPort, setSelectedPort] = useState<string>('all');

  // Collect all unique ports present in assets for the port filter
  const allDetectedPorts = Array.from(
    new Set(
      assets.flatMap((a) => (a.open_ports || []).map((p) => p.port))
    )
  ).sort((a, b) => a - b);

  // Client-side filtering
  const filteredAssets = assets.filter((asset) => {
    // Search
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      const matchHost = asset.host_or_ip.toLowerCase().includes(s);
      const matchIp = asset.ip_address?.toLowerCase().includes(s) ?? false;
      if (!matchHost && !matchIp) return false;
    }
    // Scope
    if (selectedScope !== 'all' && asset.scope_id !== selectedScope) {
      return false;
    }
    // Status
    if (selectedStatus !== 'all' && asset.status !== selectedStatus) {
      return false;
    }
    // Type
    if (selectedType !== 'all' && asset.asset_type !== selectedType) {
      return false;
    }
    // Port
    if (selectedPort !== 'all') {
      const portNum = parseInt(selectedPort, 10);
      const hasPort = (asset.open_ports || []).some((p) => p.port === portNum);
      if (!hasPort) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Filter and Search Bar */}
      <Card className="p-4 space-y-4">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search assets by hostname, FQDN, or IP address..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>

          {/* Filter Dropdowns */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Scope Filter */}
            <select
              value={selectedScope}
              onChange={(e) => setSelectedScope(e.target.value)}
              className="bg-navy-900 border border-navy-700 text-slate-300 text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Scopes ({scopes.length})</option>
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-navy-900 border border-navy-700 text-slate-300 text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="UNRESPONSIVE">UNRESPONSIVE</option>
            </select>

            {/* Asset Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-navy-900 border border-navy-700 text-slate-300 text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Asset Types</option>
              <option value="domain">Domain</option>
              <option value="subdomain">Subdomain</option>
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </select>

            {/* Port Filter */}
            {allDetectedPorts.length > 0 && (
              <select
                value={selectedPort}
                onChange={(e) => setSelectedPort(e.target.value)}
                className="bg-navy-900 border border-navy-700 text-slate-300 text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="all">All Ports</option>
                {allDetectedPorts.map((p) => (
                  <option key={p} value={p.toString()}>
                    Port {p}
                  </option>
                ))}
              </select>
            )}

            {(searchTerm || selectedScope !== 'all' || selectedStatus !== 'all' || selectedType !== 'all' || selectedPort !== 'all') && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchTerm('');
                  setSelectedScope('all');
                  setSelectedStatus('all');
                  setSelectedType('all');
                  setSelectedPort('all');
                }}
              >
                Reset
              </Button>
            )}
          </div>
        </div>

        {/* Inventory Counts bar */}
        <div className="flex items-center justify-between text-xs text-slate-400 border-t border-navy-750/70 pt-2.5">
          <span>
            Showing <span className="font-mono text-cyan-400 font-bold">{filteredAssets.length}</span> of {assets.length} assets
          </span>
          <span className="font-mono text-[11px] text-slate-500">
            Phase 1 Initial Inventory Store
          </span>
        </div>
      </Card>

      {/* Asset Table Card */}
      <Card className="p-0 overflow-hidden">
        {filteredAssets.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <Server className="w-8 h-8 text-slate-600 mx-auto" />
            <h3 className="text-sm font-semibold text-slate-300">No matching assets found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              {assets.length === 0
                ? 'Your inventory is currently empty. Run a manual discovery scan to populate assets.'
                : 'Try adjusting your search criteria or resetting filters.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-navy-750 bg-navy-900/60 text-slate-400 font-mono">
                  <th className="py-3 px-4">Asset Target</th>
                  <th className="py-3 px-4">Resolved IP</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Responsive Ports</th>
                  <th className="py-3 px-4">Web / HTTP</th>
                  <th className="py-3 px-4">TLS Expiry</th>
                  <th className="py-3 px-4">Last Seen</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-750">
                {filteredAssets.map((asset) => {
                  const tls = asset.tls_summary || {};
                  const http = asset.http_summary || {};
                  const openPorts = asset.open_ports || [];

                  return (
                    <tr
                      key={asset.id}
                      onClick={() => onInspectAsset(asset)}
                      className="hover:bg-navy-750/50 cursor-pointer transition-colors group"
                    >
                      {/* Host & Type */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-medium text-slate-200 group-hover:text-cyan-400 transition-colors">
                            {asset.host_or_ip}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-navy-900 border border-navy-700 text-slate-400 font-mono">
                            {asset.asset_type}
                          </span>
                        </div>
                      </td>

                      {/* Resolved IP */}
                      <td className="py-3.5 px-4 font-mono text-slate-300">
                        {asset.ip_address || (
                          <span className="text-slate-500 italic">None</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <Badge
                          variant={asset.status === 'ACTIVE' ? 'emerald' : 'amber'}
                          size="sm"
                        >
                          {asset.status}
                        </Badge>
                      </td>

                      {/* Open Ports */}
                      <td className="py-3.5 px-4">
                        {openPorts.length === 0 ? (
                          <span className="text-slate-500 font-mono text-[11px]">—</span>
                        ) : (
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {openPorts.slice(0, 3).map((op) => (
                              <span
                                key={op.port}
                                className="px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono"
                              >
                                {op.port}
                              </span>
                            ))}
                            {openPorts.length > 3 && (
                              <span className="text-[10px] text-slate-500 font-mono self-center">
                                +{openPorts.length - 3}
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Web / HTTP */}
                      <td className="py-3.5 px-4">
                        {http.reachable ? (
                          <div className="space-y-0.5 max-w-[160px]">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] px-1 rounded bg-navy-900 font-mono text-emerald-400">
                                {http.status_code}
                              </span>
                              <span className="font-mono text-[11px] text-slate-400 uppercase">
                                {http.scheme}
                              </span>
                            </div>
                            {http.title && (
                              <div className="text-[11px] text-slate-300 truncate" title={http.title}>
                                {http.title}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500 font-mono text-[11px]">—</span>
                        )}
                      </td>

                      {/* TLS Expiry */}
                      <td className="py-3.5 px-4">
                        {tls.has_tls ? (
                          <Badge
                            variant={
                              tls.is_expired
                                ? 'rose'
                                : tls.days_remaining && tls.days_remaining < 30
                                ? 'amber'
                                : 'slate'
                            }
                            size="sm"
                          >
                            {tls.is_expired
                              ? 'Expired'
                              : `${tls.days_remaining ?? '?'}d remaining`}
                          </Badge>
                        ) : (
                          <span className="text-slate-500 font-mono text-[11px]">—</span>
                        )}
                      </td>

                      {/* Last Seen */}
                      <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                        {new Date(asset.last_seen).toLocaleDateString()}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => onInspectAsset(asset)}
                            className="p-1.5 rounded hover:bg-navy-700 text-slate-400 hover:text-cyan-400 transition-colors"
                            title="Inspect Details"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onDeleteAsset(asset.id)}
                            className="p-1.5 rounded hover:bg-rose-950 text-slate-500 hover:text-rose-400 transition-colors"
                            title="Delete Asset"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Asset Detail Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        findings={selectedAsset ? findingsMap[selectedAsset.id] || [] : []}
        isOpen={isDrawerOpen}
        onClose={onCloseDrawer}
      />
    </div>
  );
};
