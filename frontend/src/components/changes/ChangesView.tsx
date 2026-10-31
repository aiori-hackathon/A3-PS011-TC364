import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  GitCompare,
  PlusCircle,
  MinusCircle,
  RefreshCw,
  Search,
  Filter,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Layers
} from 'lucide-react';
import { api } from '../../api/client';
import type { AssetChangeRecord, AssetSnapshot, Scope, ChangeType } from '../../api/types';
import { Card } from '../ui/Card';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';

interface ChangesViewProps {
  scopes: Scope[];
  onInspectAsset?: (host: string) => void;
}

export const ChangesView: React.FC<ChangesViewProps> = ({ scopes, onInspectAsset }) => {
  const [changes, setChanges] = useState<AssetChangeRecord[]>([]);
  const [snapshots, setSnapshots] = useState<AssetSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedScope, setSelectedScope] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [filterInconclusiveOnly, setFilterInconclusiveOnly] = useState<boolean>(false);
  const [sortBy, setSortBy] = useState<'date_desc' | 'date_asc' | 'asset_asc' | 'asset_desc' | 'type_asc'>('date_desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  // Detail Modal
  const [selectedChange, setSelectedChange] = useState<AssetChangeRecord | null>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);

  // Active sub-tab: 'changes' or 'snapshots'
  const [subTab, setSubTab] = useState<'changes' | 'snapshots'>('changes');

  const fetchChangeData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [changesRes, snapshotsRes] = await Promise.all([
        api.getChanges(),
        api.getSnapshots()
      ]);
      setChanges(changesRes);
      setSnapshots(snapshotsRes);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve changes.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchChangeData();
  }, [fetchChangeData]);

  // Filtered change records
  const filteredChanges = changes.filter((c) => {
    if (selectedScope !== 'all' && c.scope_id !== selectedScope) {
      return false;
    }
    if (selectedType !== 'all' && c.change_type !== selectedType) {
      return false;
    }
    if (filterInconclusiveOnly && !c.is_inconclusive) {
      return false;
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchAsset = c.asset_identifier.toLowerCase().includes(term);
      const matchAttr = c.attribute_name.toLowerCase().includes(term);
      if (!matchAsset && !matchAttr) return false;
    }
    return true;
  });

  // Client-side sorting for changes
  const sortedChanges = [...filteredChanges].sort((a, b) => {
    if (sortBy === 'date_asc') return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
    if (sortBy === 'asset_asc') return a.asset_identifier.localeCompare(b.asset_identifier);
    if (sortBy === 'asset_desc') return b.asset_identifier.localeCompare(a.asset_identifier);
    if (sortBy === 'type_asc') return a.change_type.localeCompare(b.change_type);
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });

  const totalPages = Math.ceil(sortedChanges.length / pageSize) || 1;
  const paginatedChanges = sortedChanges.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // Scope map for friendly naming
  const scopeMap = new Map<string, string>();
  scopes.forEach((s) => scopeMap.set(s.id, s.name));

  // Compute Metrics
  const totalCount = changes.length;
  const addedCount = changes.filter((c) => c.change_type === 'ASSET_ADDED').length;
  const removedCount = changes.filter((c) => c.change_type === 'ASSET_REMOVED').length;
  const stateShiftsCount = changes.filter(
    (c) =>
      c.change_type === 'IP_CHANGED' ||
      c.change_type === 'DNS_CHANGED' ||
      c.change_type === 'PORT_OPENED' ||
      c.change_type === 'PORT_CLOSED' ||
      c.change_type === 'HTTP_STATUS_CHANGED' ||
      c.change_type === 'TLS_CHANGED'
  ).length;
  const inconclusiveCount = changes.filter((c) => c.is_inconclusive).length;

  const getChangeTypeBadge = (type: ChangeType) => {
    switch (type) {
      case 'ASSET_ADDED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <PlusCircle className="w-3 h-3" />
            ASSET ADDED
          </span>
        );
      case 'ASSET_REMOVED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <MinusCircle className="w-3 h-3" />
            ASSET REMOVED
          </span>
        );
      case 'IP_CHANGED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            IP CHANGED
          </span>
        );
      case 'DNS_CHANGED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            DNS CHANGED
          </span>
        );
      case 'PORT_OPENED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            PORT OPENED
          </span>
        );
      case 'PORT_CLOSED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            PORT CLOSED
          </span>
        );
      case 'HTTP_STATUS_CHANGED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">
            HTTP STATUS
          </span>
        );
      case 'TLS_CHANGED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-violet-500/10 text-violet-400 border border-violet-500/30">
            TLS CERT
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-500/10 text-slate-400 border border-slate-500/30">
            {type}
          </span>
        );
    }
  };

  const renderValueDiff = (change: AssetChangeRecord) => {
    const { change_type, previous_value, new_value } = change;

    if (change_type === 'ASSET_ADDED') {
      return (
        <span className="text-xs text-emerald-400 font-mono">
          Observed in inventory ({new_value?.ip_address || 'DNS/Host'})
        </span>
      );
    }

    if (change_type === 'ASSET_REMOVED') {
      return (
        <span className="text-xs text-rose-400 font-mono">
          Decommissioned / absent in recent discovery run
        </span>
      );
    }

    if (change_type === 'PORT_OPENED') {
      return (
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-500">CLOSED</span>
          <ArrowRight className="w-3 h-3 text-cyan-400" />
          <span className="text-emerald-400 font-bold">PORT {new_value} OPEN</span>
        </div>
      );
    }

    if (change_type === 'PORT_CLOSED') {
      return (
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-emerald-400">PORT {previous_value} OPEN</span>
          <ArrowRight className="w-3 h-3 text-slate-500" />
          <span className="text-rose-400 font-bold">CLOSED / UNRESPONSIVE</span>
        </div>
      );
    }

    if (change_type === 'IP_CHANGED') {
      return (
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400 line-through">{String(previous_value || 'None')}</span>
          <ArrowRight className="w-3 h-3 text-cyan-400" />
          <span className="text-cyan-300 font-bold">{String(new_value || 'None')}</span>
        </div>
      );
    }

    // Default object/string diff view
    const pStr = typeof previous_value === 'object' ? JSON.stringify(previous_value) : String(previous_value ?? 'None');
    const nStr = typeof new_value === 'object' ? JSON.stringify(new_value) : String(new_value ?? 'None');

    return (
      <div className="flex items-center gap-2 font-mono text-xs max-w-md truncate">
        <span className="text-slate-400 truncate max-w-[140px]">{pStr}</span>
        <ArrowRight className="w-3 h-3 shrink-0 text-cyan-400" />
        <span className="text-slate-200 font-medium truncate max-w-[140px]">{nStr}</span>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="p-4 bg-navy-900 border-navy-750">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-slate-400">Total Changes</span>
            <History className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{totalCount}</div>
          <span className="text-[11px] text-slate-500">Across all baseline comparisons</span>
        </Card>

        <Card className="p-4 bg-navy-900 border-navy-750">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-emerald-400">Added Assets</span>
            <PlusCircle className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">{addedCount}</div>
          <span className="text-[11px] text-slate-500">Newly observed surfaces</span>
        </Card>

        <Card className="p-4 bg-navy-900 border-navy-750">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-rose-400">Removed Assets</span>
            <MinusCircle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-2">{removedCount}</div>
          <span className="text-[11px] text-slate-500">Omitted or decommissioned</span>
        </Card>

        <Card className="p-4 bg-navy-900 border-navy-750">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-cyan-400">Service & IP Shifts</span>
            <GitCompare className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-2">{stateShiftsCount}</div>
          <span className="text-[11px] text-slate-500">Ports, DNS, HTTP, TLS</span>
        </Card>

        <Card className="p-4 bg-navy-900 border-navy-750">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider font-mono text-amber-400">Inconclusive Flags</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-2">{inconclusiveCount}</div>
          <span className="text-[11px] text-slate-500">Timeouts / Partial Reachability</span>
        </Card>
      </div>

      {/* Sub Tab Switcher: Changes Feed vs Snapshots Archive */}
      <div className="flex items-center justify-between border-b border-navy-750 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setSubTab('changes')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider transition-colors uppercase font-mono ${
              subTab === 'changes'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/40 shadow-glow-cyan-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Detected Change Records ({filteredChanges.length})
          </button>
          <button
            onClick={() => setSubTab('snapshots')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider transition-colors uppercase font-mono ${
              subTab === 'snapshots'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/40 shadow-glow-cyan-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Baseline Snapshots Archive ({snapshots.length})
          </button>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={fetchChangeData}
          disabled={loading}
          className="flex items-center gap-2 text-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Baseline Data
        </Button>
      </div>

      {/* SUB-TAB 1: DETECTED CHANGES FEED */}
      {subTab === 'changes' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <Card className="p-4 space-y-4">
            <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
              <div className="relative flex-1">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter by asset hostname, IP, or attribute name..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                />
              </div>

              <div className="flex flex-wrap items-center gap-3">
                {/* Scope Filter */}
                <div className="flex items-center gap-1.5">
                  <Filter className="w-3.5 h-3.5 text-slate-400" />
                  <select
                    value={selectedScope}
                    onChange={(e) => {
                      setSelectedScope(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="px-2.5 py-1.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="all">All Authorised Scopes</option>
                    {scopes.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Change Type Filter */}
                <select
                  value={selectedType}
                  onChange={(e) => {
                    setSelectedType(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="all">All Change Types</option>
                  <option value="ASSET_ADDED">Asset Added</option>
                  <option value="ASSET_REMOVED">Asset Removed</option>
                  <option value="IP_CHANGED">IP Changed</option>
                  <option value="DNS_CHANGED">DNS Changed</option>
                  <option value="PORT_OPENED">Port Opened</option>
                  <option value="PORT_CLOSED">Port Closed</option>
                  <option value="HTTP_STATUS_CHANGED">HTTP Status Changed</option>
                  <option value="TLS_CHANGED">TLS Cert Changed</option>
                </select>

                {/* Sort Dropdown */}
                <select
                  value={sortBy}
                  onChange={(e) => {
                    setSortBy(e.target.value as any);
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="date_desc">Sort: Newest First</option>
                  <option value="date_asc">Sort: Oldest First</option>
                  <option value="asset_asc">Sort: Asset (A-Z)</option>
                  <option value="asset_desc">Sort: Asset (Z-A)</option>
                  <option value="type_asc">Sort: Change Type</option>
                </select>

                {/* Inconclusive toggle */}
                <button
                  type="button"
                  onClick={() => {
                    setFilterInconclusiveOnly(!filterInconclusiveOnly);
                    setCurrentPage(1);
                  }}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-colors ${
                    filterInconclusiveOnly
                      ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
                      : 'bg-navy-900 border-navy-700 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Inconclusive Only
                </button>

                {/* Reset button */}
                {(searchTerm || selectedScope !== 'all' || selectedType !== 'all' || filterInconclusiveOnly || sortBy !== 'date_desc') && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setSearchTerm('');
                      setSelectedScope('all');
                      setSelectedType('all');
                      setFilterInconclusiveOnly(false);
                      setSortBy('date_desc');
                      setCurrentPage(1);
                    }}
                    className="text-xs font-mono text-slate-400 hover:text-slate-200"
                  >
                    Reset
                  </Button>
                )}
              </div>
            </div>

            {/* Changes Count Summary Bar */}
            <div className="flex items-center justify-between text-xs text-slate-400 border-t border-navy-750/70 pt-2.5">
              <span>
                Showing <span className="font-mono text-cyan-400 font-bold">{sortedChanges.length}</span> of {changes.length} change events
                {sortedChanges.length !== changes.length && ' (filtered)'}
              </span>
              <span className="font-mono text-[11px] text-slate-500">
                Phase 4 Baseline Delta Explorer
              </span>
            </div>
          </Card>

          {/* Error Message */}
          {error && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs">
              {error}
            </div>
          )}

          {/* Changes Table */}
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-navy-750 bg-navy-900/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Scope</th>
                    <th className="py-3 px-4">Asset Target</th>
                    <th className="py-3 px-4">Change Type</th>
                    <th className="py-3 px-4">Attribute & Value Diff</th>
                    <th className="py-3 px-4 text-center">Status</th>
                    <th className="py-3 px-4 text-right">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-750/50 text-xs font-sans">
                  {loading && changes.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                        <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                        Loading change records and baseline comparisons...
                      </td>
                    </tr>
                  ) : filteredChanges.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                        <History className="w-8 h-8 mx-auto mb-2 opacity-40 text-slate-400" />
                        No change records found matching selected filters.
                        <p className="text-[11px] text-slate-600 mt-1">
                          Run a second discovery scan on an authorized scope to detect differences against the baseline.
                        </p>
                      </td>
                    </tr>
                  ) : (
                    paginatedChanges.map((change) => {
                      const scopeName = scopeMap.get(change.scope_id) || 'Unknown Scope';
                      const createdDate = new Date(change.created_at);
                      const timeStr = createdDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                      const dateStr = createdDate.toLocaleDateString();

                      return (
                        <tr
                          key={change.id}
                          className="hover:bg-navy-850/60 transition-colors group cursor-pointer"
                          onClick={() => {
                            setSelectedChange(change);
                            setIsDetailModalOpen(true);
                          }}
                        >
                          <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                            <div>{timeStr}</div>
                            <div className="text-[10px] text-slate-600">{dateStr}</div>
                          </td>

                          <td className="py-3 px-4 text-slate-300 font-medium">
                            <span className="truncate max-w-[130px] block" title={scopeName}>
                              {scopeName}
                            </span>
                          </td>

                          <td className="py-3 px-4 font-mono font-semibold text-slate-100 whitespace-nowrap">
                            <div className="flex items-center gap-1.5">
                              <span>{change.asset_identifier}</span>
                            </div>
                          </td>

                          <td className="py-3 px-4 whitespace-nowrap">
                            {getChangeTypeBadge(change.change_type)}
                          </td>

                          <td className="py-3 px-4">
                            {renderValueDiff(change)}
                          </td>

                          <td className="py-3 px-4 text-center whitespace-nowrap">
                            {change.is_inconclusive ? (
                              <span
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30"
                                title="Inconclusive observation: partial timeout or unresponsiveness"
                              >
                                <AlertTriangle className="w-3 h-3 text-amber-400" />
                                INCONCLUSIVE
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400">
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                VERIFIED
                              </span>
                            )}
                          </td>

                          <td className="py-3 px-4 text-right whitespace-nowrap">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedChange(change);
                                setIsDetailModalOpen(true);
                              }}
                              className="px-2.5 py-1 text-xs rounded bg-navy-800 hover:bg-navy-700 text-slate-300 border border-navy-700 font-mono transition-colors"
                            >
                              Inspect Diff
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {sortedChanges.length > 0 && (
              <div className="flex flex-col sm:flex-row items-center justify-between px-4 py-3 border-t border-navy-750 bg-navy-950/40 text-xs font-mono gap-3">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Rows per page:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="bg-navy-950 border border-navy-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                  <span className="text-slate-500">
                    Showing {Math.min((currentPage - 1) * pageSize + 1, sortedChanges.length)} - {Math.min(currentPage * pageSize, sortedChanges.length)} of {sortedChanges.length}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-slate-400">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="h-7 px-2.5 text-xs font-mono"
                  >
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="h-7 px-2.5 text-xs font-mono"
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {/* SUB-TAB 2: BASELINE SNAPSHOTS ARCHIVE */}
      {subTab === 'snapshots' && (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-navy-750 bg-navy-900/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Snapshot ID</th>
                  <th className="py-3 px-4">Scope</th>
                  <th className="py-3 px-4">Scan Run ID</th>
                  <th className="py-3 px-4">Discovered Assets Count</th>
                  <th className="py-3 px-4">Captured Timestamp</th>
                  <th className="py-3 px-4 text-center">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-750/50 text-xs font-sans">
                {snapshots.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500 font-mono">
                      <Layers className="w-8 h-8 mx-auto mb-2 opacity-40 text-slate-400" />
                      No baseline snapshots recorded yet.
                    </td>
                  </tr>
                ) : (
                  snapshots.map((snap) => {
                    const scopeName = scopeMap.get(snap.scope_id) || 'Unknown Scope';
                    return (
                      <tr key={snap.id} className="hover:bg-navy-850/60 transition-colors">
                        <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">
                          {snap.id.substring(0, 10)}...
                        </td>
                        <td className="py-3 px-4 text-slate-200 font-medium">
                          {scopeName}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">
                          {snap.scan_run_id.substring(0, 10)}...
                        </td>
                        <td className="py-3 px-4 font-mono font-bold text-slate-100">
                          <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                            {snap.asset_count} assets
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">
                          {new Date(snap.created_at).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-center">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            <CheckCircle2 className="w-3 h-3" />
                            IMMUTABLE BASELINE
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* CHANGE DETAIL MODAL */}
      {selectedChange && (
        <Modal
          isOpen={isDetailModalOpen}
          onClose={() => setIsDetailModalOpen(false)}
          title={`Change Record: ${selectedChange.asset_identifier}`}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-navy-750">
              <div className="flex items-center gap-2">
                {getChangeTypeBadge(selectedChange.change_type)}
                {selectedChange.is_inconclusive && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    INCONCLUSIVE
                  </span>
                )}
              </div>
              <span className="text-xs font-mono text-slate-400">
                {new Date(selectedChange.created_at).toLocaleString()}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                <span className="text-slate-500 uppercase text-[10px]">Scope ID</span>
                <div className="text-slate-200 mt-0.5 truncate">{selectedChange.scope_id}</div>
              </div>
              <div className="p-2.5 rounded bg-navy-900 border border-navy-750">
                <span className="text-slate-500 uppercase text-[10px]">Scan Run ID</span>
                <div className="text-slate-200 mt-0.5 truncate">{selectedChange.scan_run_id}</div>
              </div>
            </div>

            {/* Value Diff Breakdown */}
            <div className="p-3 rounded-lg bg-navy-900 border border-navy-750 space-y-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                Attribute Value Comparison ({selectedChange.attribute_name})
              </span>
              <div className="grid grid-cols-2 gap-3 pt-1">
                <div className="p-2.5 rounded bg-navy-950 border border-navy-800">
                  <span className="text-[10px] text-rose-400 font-mono uppercase">Previous Baseline Value</span>
                  <pre className="mt-1 text-[11px] text-slate-300 font-mono whitespace-pre-wrap overflow-x-auto max-h-32">
                    {selectedChange.previous_value !== null && selectedChange.previous_value !== undefined
                      ? JSON.stringify(selectedChange.previous_value, null, 2)
                      : 'None (Initial Observation)'}
                  </pre>
                </div>
                <div className="p-2.5 rounded bg-navy-950 border border-navy-800">
                  <span className="text-[10px] text-emerald-400 font-mono uppercase">New Detected Value</span>
                  <pre className="mt-1 text-[11px] text-slate-300 font-mono whitespace-pre-wrap overflow-x-auto max-h-32">
                    {selectedChange.new_value !== null && selectedChange.new_value !== undefined
                      ? JSON.stringify(selectedChange.new_value, null, 2)
                      : 'None (Removed)'}
                  </pre>
                </div>
              </div>
            </div>

            {/* Evidence & Context */}
            <div className="p-3 rounded-lg bg-navy-900 border border-navy-750 space-y-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                Supporting Evidence & Context
              </span>
              <pre className="p-2.5 rounded bg-navy-950 border border-navy-800 text-[11px] text-cyan-300 font-mono whitespace-pre-wrap overflow-x-auto max-h-48">
                {JSON.stringify(selectedChange.evidence || {}, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="outline" size="sm" onClick={() => setIsDetailModalOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
