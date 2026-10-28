import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  Info,
  Clock,
  Eye,
  RefreshCw,
  ShieldCheck,
  FileText,
  SlidersHorizontal,
  History,
  Server,
  Zap,
  Tag
} from 'lucide-react';
import { api } from '../../api/client';
import type {
  ScanFinding,
  Scope,
  FindingSeverity,
  ReviewStatus
} from '../../api/types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';

interface FindingsViewProps {
  scopes: Scope[];
  onInspectAsset?: (host: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({ scopes, onInspectAsset }) => {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedScope, setSelectedScope] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Selected finding for detailed review modal
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);

  // Status update state inside detail modal
  const [newStatus, setNewStatus] = useState<ReviewStatus>('OPEN');
  const [statusNote, setStatusNote] = useState<string>('');
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [statusUpdateSuccess, setStatusUpdateSuccess] = useState(false);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFindings({
        scope_id: selectedScope !== 'all' ? selectedScope : undefined,
        severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
        review_status: selectedStatus !== 'all' ? selectedStatus : undefined,
        finding_type: selectedType !== 'all' ? selectedType : undefined,
        search: searchTerm.trim() || undefined,
        limit: 200,
      });
      setFindings(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve findings.');
    } finally {
      setLoading(false);
    }
  }, [selectedScope, selectedSeverity, selectedStatus, selectedType, searchTerm]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  // Open detail modal and reset status form
  const handleOpenDetail = (finding: ScanFinding) => {
    setSelectedFinding(finding);
    setNewStatus(finding.review_status);
    setStatusNote('');
    setStatusUpdateSuccess(false);
    setIsDetailModalOpen(true);
  };

  // Submit status update
  const handleStatusSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;

    setIsUpdatingStatus(true);
    try {
      const updated = await api.updateFindingStatus(
        selectedFinding.id,
        newStatus,
        statusNote.trim() || undefined
      );

      // Update in local state
      setSelectedFinding(updated);
      setFindings((prev) =>
        prev.map((f) => (f.id === updated.id ? updated : f))
      );
      setStatusUpdateSuccess(true);
      setStatusNote('');
      setTimeout(() => setStatusUpdateSuccess(false), 3000);
    } catch (err: any) {
      alert(`Failed to update finding status: ${err.message}`);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  // Scope lookup map
  const scopeMap = new Map<string, string>();
  scopes.forEach((s) => scopeMap.set(s.id, s.name));

  // Severity count helpers
  const countCritical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const countHigh = findings.filter((f) => f.severity === 'HIGH').length;
  const countMedium = findings.filter((f) => f.severity === 'MEDIUM').length;
  const countLow = findings.filter((f) => f.severity === 'LOW').length;
  const countInfo = findings.filter(
    (f) =>
      f.severity === 'INFORMATIONAL' ||
      f.severity === 'INFO' ||
      f.severity === 'NOTICE'
  ).length;

  const countOpen = findings.filter(
    (f) => f.review_status === 'OPEN' || f.review_status === 'IN_REVIEW' || f.review_status === 'ACKNOWLEDGED'
  ).length;
  const countResolved = findings.filter(
    (f) => f.review_status === 'RESOLVED' || f.review_status === 'FALSE_POSITIVE'
  ).length;

  // Helper for severity styling
  const getSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return <Badge variant="rose" size="sm" pulse>CRITICAL</Badge>;
      case 'HIGH':
        return <Badge variant="orange" size="sm">HIGH</Badge>;
      case 'MEDIUM':
        return <Badge variant="amber" size="sm">MEDIUM</Badge>;
      case 'LOW':
        return <Badge variant="cyan" size="sm">LOW</Badge>;
      case 'INFORMATIONAL':
      case 'INFO':
      case 'NOTICE':
      default:
        return <Badge variant="slate" size="sm">INFO</Badge>;
    }
  };

  // Helper for status styling
  const getStatusBadge = (status: ReviewStatus) => {
    switch (status) {
      case 'OPEN':
        return <Badge variant="rose" size="sm">OPEN</Badge>;
      case 'ACKNOWLEDGED':
        return <Badge variant="violet" size="sm">ACKNOWLEDGED</Badge>;
      case 'IN_REVIEW':
        return <Badge variant="cyan" size="sm" pulse>IN REVIEW</Badge>;
      case 'RESOLVED':
        return <Badge variant="emerald" size="sm">RESOLVED</Badge>;
      case 'FALSE_POSITIVE':
        return <Badge variant="slate" size="sm">FALSE POSITIVE</Badge>;
      default:
        return <Badge variant="slate" size="sm">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Severity & Triage Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Findings */}
        <Card className="p-4 border-navy-750 bg-navy-900/60 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Total Findings
            </span>
            <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-slate-100 font-mono">
            {findings.length}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 font-mono">
            {countOpen} active / {countResolved} closed
          </div>
        </Card>

        {/* Critical */}
        <Card className="p-4 border-rose-500/30 bg-rose-950/20 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-rose-400 uppercase tracking-wider">
              Critical
            </span>
            <div className="p-1.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30">
              <AlertTriangle className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-rose-300 font-mono">
            {countCritical}
          </div>
          <div className="mt-1 text-[11px] text-rose-400/70 font-mono">
            Immediate action
          </div>
        </Card>

        {/* High */}
        <Card className="p-4 border-orange-500/30 bg-orange-950/20 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-orange-400 uppercase tracking-wider">
              High Risk
            </span>
            <div className="p-1.5 rounded-lg bg-orange-500/20 text-orange-400 border border-orange-500/30">
              <AlertTriangle className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-orange-300 font-mono">
            {countHigh}
          </div>
          <div className="mt-1 text-[11px] text-orange-400/70 font-mono">
            Elevated exposure
          </div>
        </Card>

        {/* Medium */}
        <Card className="p-4 border-amber-500/30 bg-amber-950/20 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider">
              Medium Risk
            </span>
            <div className="p-1.5 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
              <Info className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-amber-300 font-mono">
            {countMedium}
          </div>
          <div className="mt-1 text-[11px] text-amber-400/70 font-mono">
            Review configuration
          </div>
        </Card>

        {/* Low */}
        <Card className="p-4 border-cyan-500/30 bg-cyan-950/20 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider">
              Low Risk
            </span>
            <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              <Zap className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-cyan-300 font-mono">
            {countLow}
          </div>
          <div className="mt-1 text-[11px] text-cyan-400/70 font-mono">
            Minor deviations
          </div>
        </Card>

        {/* Informational */}
        <Card className="p-4 border-navy-750 bg-navy-900/60 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Informational
            </span>
            <div className="p-1.5 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
              <Tag className="w-3.5 h-3.5" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-extrabold text-slate-300 font-mono">
            {countInfo}
          </div>
          <div className="mt-1 text-[11px] text-slate-500 font-mono">
            Normal telemetry
          </div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-4 border-navy-750 bg-navy-900/80">
        <div className="flex flex-col lg:flex-row gap-4 items-stretch lg:items-center justify-between">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search findings by title, description, asset host, or remediation..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-navy-950 border border-navy-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          {/* Dropdown Filters */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Scope Filter */}
            <select
              value={selectedScope}
              onChange={(e) => setSelectedScope(e.target.value)}
              className="bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="all">All Scopes</option>
              {scopes.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
            </select>

            {/* Review Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="all">All Review Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="IN_REVIEW">In Review</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>

            {/* Finding Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-navy-950 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="all">All Finding Types</option>
              <option value="PORT">Open Port / Service</option>
              <option value="TLS">TLS / Certificate</option>
              <option value="DNS">DNS Configuration</option>
              <option value="HTTP">HTTP Posture</option>
            </select>

            {/* Refresh Button */}
            <Button
              variant="outline"
              size="sm"
              onClick={fetchFindings}
              disabled={loading}
              className="gap-2 shrink-0 font-mono text-xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>
      </Card>

      {/* Main Findings Table */}
      <Card className="border-navy-750 overflow-hidden bg-navy-900/60">
        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center gap-3 text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-sm font-mono">Loading findings and risk evaluations...</span>
          </div>
        ) : error ? (
          <div className="py-16 text-center text-rose-400">
            <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-80" />
            <p className="text-sm font-semibold">{error}</p>
            <Button variant="outline" size="sm" onClick={fetchFindings} className="mt-4">
              Retry
            </Button>
          </div>
        ) : findings.length === 0 ? (
          <div className="py-16 text-center text-slate-400 space-y-3">
            <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400 opacity-80" />
            <div className="text-base font-semibold text-slate-200">No findings match your filters</div>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              No security observations or risk classifications found under the selected filters.
              Adjust your filters or launch a new discovery run.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-navy-950/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-navy-750 font-mono select-none">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Asset / Host</th>
                  <th className="py-3 px-4">Finding Title</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Review Status</th>
                  <th className="py-3 px-4">Last Observed</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-800 font-mono text-xs">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => handleOpenDetail(f)}
                    className="hover:bg-navy-800/40 transition-colors cursor-pointer group"
                  >
                    {/* Severity */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getSeverityBadge(f.severity)}
                    </td>

                    {/* Asset Host */}
                    <td className="py-3.5 px-4 whitespace-nowrap font-medium text-slate-200">
                      <div className="flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-cyan-400/70 shrink-0" />
                        <span className="hover:text-cyan-300 transition-colors">
                          {f.asset_host || 'Target'}
                        </span>
                      </div>
                    </td>

                    {/* Title */}
                    <td className="py-3.5 px-4 text-slate-200 max-w-xs font-sans text-xs">
                      <div className="font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors line-clamp-1">
                        {f.title}
                      </div>
                      {f.description && (
                        <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                          {f.description}
                        </div>
                      )}
                    </td>

                    {/* Finding Type */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400">
                      <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-700 text-[10px] text-slate-300">
                        {f.finding_type}
                      </span>
                    </td>

                    {/* Confidence */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="text-[10px] text-slate-400 border border-navy-750 px-2 py-0.5 rounded font-mono">
                        {f.confidence}
                      </span>
                    </td>

                    {/* Review Status */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusBadge(f.review_status)}
                    </td>

                    {/* Last Observed */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-[11px]">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500 shrink-0" />
                        {new Date(f.last_observed).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </td>

                    {/* Action */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-right">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenDetail(f);
                        }}
                        className="text-xs font-mono h-7 px-2.5"
                      >
                        <Eye className="w-3 h-3 mr-1" />
                        Review
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Finding Detail & Status Review Modal */}
      {selectedFinding && (
        <Modal
          isOpen={isDetailModalOpen}
          onClose={() => setIsDetailModalOpen(false)}
          title="Finding Inspection & Triage Review"
          maxWidth="xl"
        >
          <div className="space-y-6 max-h-[75vh] overflow-y-auto pr-1">
            {/* Header / Badges */}
            <div className="p-4 rounded-xl bg-navy-950 border border-navy-750 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  {getSeverityBadge(selectedFinding.severity)}
                  <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-750 text-xs font-mono text-cyan-400">
                    {selectedFinding.finding_type}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-navy-800 border border-navy-750 text-xs font-mono text-slate-300">
                    Confidence: {selectedFinding.confidence}
                  </span>
                </div>
                <div>{getStatusBadge(selectedFinding.review_status)}</div>
              </div>

              <h3 className="text-lg font-bold text-slate-100">
                {selectedFinding.title}
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-slate-400 pt-2 border-t border-navy-800">
                <div>
                  <span className="text-slate-500">Asset Host: </span>
                  <span className="text-cyan-300 font-semibold">
                    {selectedFinding.asset_host || 'Unknown'}
                  </span>
                  {selectedFinding.asset_host && onInspectAsset && (
                    <button
                      onClick={() => {
                        setIsDetailModalOpen(false);
                        onInspectAsset(selectedFinding.asset_host!);
                      }}
                      className="ml-2 text-cyan-400 hover:text-cyan-300 underline text-[11px]"
                    >
                      (View Asset in Inventory)
                    </button>
                  )}
                </div>
                <div>
                  <span className="text-slate-500">Scope: </span>
                  <span className="text-slate-300">
                    {selectedFinding.scope_id
                      ? scopeMap.get(selectedFinding.scope_id) || selectedFinding.scope_id
                      : 'Default Scope'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">First Detected: </span>
                  <span className="text-slate-300">
                    {new Date(selectedFinding.first_detected).toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Last Observed: </span>
                  <span className="text-slate-300">
                    {new Date(selectedFinding.last_observed).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Explainable Risk Description */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-400 font-mono">
                <FileText className="w-3.5 h-3.5 text-cyan-400" />
                <span>Explainable Risk Rationale</span>
              </div>
              <div className="p-3.5 rounded-lg bg-navy-950/70 border border-navy-750 text-sm text-slate-300 leading-relaxed">
                {selectedFinding.description || selectedFinding.title}
              </div>
            </div>

            {/* Remediation Guidance */}
            {selectedFinding.remediation && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-emerald-400 font-mono">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Recommended Remediation</span>
                </div>
                <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-sm text-emerald-200/90 leading-relaxed">
                  {selectedFinding.remediation}
                </div>
              </div>
            )}

            {/* Technical Evidence */}
            {selectedFinding.evidence && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-400 font-mono">
                  <Zap className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Supporting Technical Evidence</span>
                </div>
                <div className="p-3.5 rounded-lg bg-navy-950 border border-navy-750 font-mono text-xs text-slate-300 overflow-x-auto">
                  <pre className="text-cyan-300/90 whitespace-pre-wrap">
                    {JSON.stringify(selectedFinding.evidence, null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* Status Transition Workflow Form */}
            <div className="p-4 rounded-xl bg-navy-950/90 border border-cyan-500/30 shadow-glow-cyan-sm space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-cyan-400 font-mono font-bold">
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  <span>Review Status Transition Workflow</span>
                </div>
                {statusUpdateSuccess && (
                  <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Status updated successfully!
                  </span>
                )}
              </div>

              <form onSubmit={handleStatusSubmit} className="space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="new-review-status" className="block text-xs font-mono text-slate-400 mb-1">
                      New Review Status
                    </label>
                    <select
                      id="new-review-status"
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as ReviewStatus)}
                      className="w-full bg-navy-900 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      <option value="OPEN">OPEN (Requires triage)</option>
                      <option value="ACKNOWLEDGED">ACKNOWLEDGED (Accepted risk)</option>
                      <option value="IN_REVIEW">IN_REVIEW (Active investigation)</option>
                      <option value="RESOLVED">RESOLVED (Remediation verified)</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE (Benign observation)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">
                      Review Note / Rationale
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Authorized internal database listener verified with ops team"
                      value={statusNote}
                      onChange={(e) => setStatusNote(e.target.value)}
                      className="w-full bg-navy-900 border border-navy-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>
                </div>

                <div className="flex justify-end pt-1">
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    disabled={isUpdatingStatus || newStatus === selectedFinding.review_status && !statusNote.trim()}
                    className="font-mono text-xs gap-1.5"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {isUpdatingStatus ? 'Saving...' : 'Apply Status Update'}
                  </Button>
                </div>
              </form>
            </div>

            {/* Status Transition History Timeline */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-400 font-mono">
                <History className="w-3.5 h-3.5 text-cyan-400" />
                Review Status History ({selectedFinding.status_history?.length || 0})
              </div>

              {(!selectedFinding.status_history || selectedFinding.status_history.length === 0) ? (
                <div className="p-3 rounded-lg bg-navy-950/50 border border-navy-800 text-xs text-slate-500 font-mono">
                  No review status changes recorded yet. Initial status is {selectedFinding.review_status}.
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedFinding.status_history.map((h, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-navy-950 border border-navy-800 font-mono text-xs flex flex-col gap-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-cyan-400 font-semibold">
                          {h.previous_status ? `${h.previous_status} → ` : ''}
                          {h.status}
                        </span>
                        <span className="text-slate-500">
                          {new Date(h.timestamp).toLocaleString()}
                        </span>
                      </div>
                      {h.note && (
                        <div className="text-slate-300 font-sans text-xs bg-navy-900/60 p-2 rounded border border-navy-750">
                          {h.note}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
