import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  Play,
  Calendar,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  History,
  Timer,
  Sliders,
  ArrowRight
} from 'lucide-react';
import { api } from '../../api/client';
import type {
  Scope,
  DiscoverySchedule,
  ScheduleCreatePayload,
  ScheduleUpdatePayload,
  ScheduleFrequency,
  ScanRun
} from '../../api/types';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Card } from '../ui/Card';
import { Modal } from '../ui/Modal';

interface ScheduledDiscoveryViewProps {
  scopes: Scope[];
  onNavigateToScan?: (scanId: string) => void;
}

export const ScheduledDiscoveryView: React.FC<ScheduledDiscoveryViewProps> = ({
  scopes,
  onNavigateToScan,
}) => {
  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [selectedScopeFilter, setSelectedScopeFilter] = useState<string>('all');

  // Trigger loading state
  const [triggeringScheduleId, setTriggeringScheduleId] = useState<string | null>(null);

  // Modal states
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<DiscoverySchedule | null>(null);
  const [modalScopeId, setModalScopeId] = useState<string>('');
  const [modalName, setModalName] = useState('');
  const [modalDescription, setModalDescription] = useState('');
  const [modalFrequency, setModalFrequency] = useState<ScheduleFrequency>('DAILY');
  const [modalIntervalHours, setModalIntervalHours] = useState<number>(24);
  const [modalPortsPreset, setModalPortsPreset] = useState<'common' | 'extended' | 'web' | 'all'>('common');
  const [modalEnableDns, setModalEnableDns] = useState(true);
  const [modalEnablePorts, setModalEnablePorts] = useState(true);
  const [modalEnableHttp, setModalEnableHttp] = useState(true);
  const [modalEnableTls, setModalEnableTls] = useState(true);
  const [modalIsEnabled, setModalIsEnabled] = useState(true);
  const [modalError, setModalError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Executions Drawer / History Modal
  const [selectedScheduleForHistory, setSelectedScheduleForHistory] = useState<DiscoverySchedule | null>(null);
  const [historyExecutions, setHistoryExecutions] = useState<ScanRun[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Filter scopes to only authorised ones for creating schedules
  const authorisedScopes = scopes.filter((s) => s.authorised_confirmation);

  const fetchSchedules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getSchedules(
        selectedScopeFilter !== 'all' ? { scope_id: selectedScopeFilter } : undefined
      );
      setSchedules(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch discovery schedules.');
    } finally {
      setLoading(false);
    }
  }, [selectedScopeFilter]);

  useEffect(() => {
    fetchSchedules();
  }, [fetchSchedules]);

  // Open Create Modal
  const handleOpenCreateModal = () => {
    setEditingSchedule(null);
    setModalScopeId(authorisedScopes.length > 0 ? authorisedScopes[0].id : '');
    setModalName('Nightly Attack-Surface Sweep');
    setModalDescription('Recurring automated asset discovery, baseline comparison, and risk analysis');
    setModalFrequency('DAILY');
    setModalIntervalHours(24);
    setModalPortsPreset('common');
    setModalEnableDns(true);
    setModalEnablePorts(true);
    setModalEnableHttp(true);
    setModalEnableTls(true);
    setModalIsEnabled(true);
    setModalError(null);
    setIsModalOpen(true);
  };

  // Open Edit Modal
  const handleOpenEditModal = (sched: DiscoverySchedule) => {
    setEditingSchedule(sched);
    setModalScopeId(sched.scope_id);
    setModalName(sched.name);
    setModalDescription(sched.description || '');
    setModalFrequency((sched.frequency as ScheduleFrequency) || 'DAILY');
    setModalIntervalHours(sched.interval_hours || 24);
    const cfg = sched.config || {};
    setModalEnableDns(cfg.enable_dns ?? true);
    setModalEnablePorts(cfg.enable_ports ?? true);
    setModalEnableHttp(cfg.enable_http ?? true);
    setModalEnableTls(cfg.enable_tls ?? true);
    setModalIsEnabled(sched.is_enabled);
    setModalError(null);
    setIsModalOpen(true);
  };

  // Save Schedule (Create or Update)
  const handleSaveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);

    if (!modalScopeId) {
      setModalError('Please select a valid authorised target scope.');
      return;
    }
    if (!modalName.trim()) {
      setModalError('Schedule name is required.');
      return;
    }

    const targetScope = scopes.find((s) => s.id === modalScopeId);
    if (!targetScope || !targetScope.authorised_confirmation) {
      setModalError('Selected scope lacks verified authorization confirmation.');
      return;
    }

    setIsSubmitting(true);
    try {
      let ports: number[] = [21, 22, 80, 443, 8080, 8443];
      if (modalPortsPreset === 'web') ports = [80, 443, 8080, 8443];
      if (modalPortsPreset === 'extended') ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8000, 8080, 8443];

      const config = {
        ports,
        enable_dns: modalEnableDns,
        enable_ports: modalEnablePorts,
        enable_http: modalEnableHttp,
        enable_tls: modalEnableTls,
      };

      if (editingSchedule) {
        const payload: ScheduleUpdatePayload = {
          name: modalName.trim(),
          description: modalDescription.trim() || undefined,
          is_enabled: modalIsEnabled,
          frequency: modalFrequency,
          interval_hours: modalFrequency === 'CUSTOM' ? modalIntervalHours : undefined,
          config,
        };
        await api.updateSchedule(editingSchedule.id, payload);
        setActionSuccess(`Schedule '${modalName}' updated successfully.`);
      } else {
        const payload: ScheduleCreatePayload = {
          scope_id: modalScopeId,
          name: modalName.trim(),
          description: modalDescription.trim() || undefined,
          is_enabled: modalIsEnabled,
          frequency: modalFrequency,
          interval_hours: modalFrequency === 'CUSTOM' ? modalIntervalHours : 24,
          config,
        };
        await api.createSchedule(payload);
        setActionSuccess(`New schedule '${modalName}' created and armed.`);
      }

      setIsModalOpen(false);
      await fetchSchedules();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: any) {
      setModalError(err?.message || 'Failed to save schedule.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Toggle Enable / Disable
  const handleToggleEnable = async (sched: DiscoverySchedule) => {
    try {
      await api.updateSchedule(sched.id, { is_enabled: !sched.is_enabled });
      setActionSuccess(`Schedule '${sched.name}' is now ${!sched.is_enabled ? 'enabled' : 'disabled'}.`);
      await fetchSchedules();
      setTimeout(() => setActionSuccess(null), 3000);
    } catch (err: any) {
      setError(err?.message || 'Failed to update schedule status.');
    }
  };

  // Delete Schedule
  const handleDeleteSchedule = async (sched: DiscoverySchedule) => {
    if (!window.confirm(`Are you sure you want to delete discovery schedule '${sched.name}'? Existing scan runs and changes will be preserved.`)) {
      return;
    }
    try {
      await api.deleteSchedule(sched.id);
      setActionSuccess(`Schedule '${sched.name}' deleted successfully.`);
      await fetchSchedules();
      setTimeout(() => setActionSuccess(null), 3000);
    } catch (err: any) {
      setError(err?.message || 'Failed to delete schedule.');
    }
  };

  // Manual "Run Now" Trigger
  const handleTriggerNow = async (sched: DiscoverySchedule) => {
    setTriggeringScheduleId(sched.id);
    setError(null);
    try {
      const scan = await api.triggerSchedule(sched.id);
      setActionSuccess(`Scheduled scan triggered immediately for '${sched.name}'. Scan ID: ${scan.id.slice(0, 8)}...`);
      await fetchSchedules();
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: any) {
      setError(err?.message || 'Failed to trigger schedule execution.');
    } finally {
      setTriggeringScheduleId(null);
    }
  };

  // View Execution History
  const handleViewExecutions = async (sched: DiscoverySchedule) => {
    setSelectedScheduleForHistory(sched);
    setHistoryLoading(true);
    try {
      const execs = await api.getScheduleExecutions(sched.id);
      setHistoryExecutions(execs);
    } catch (err: any) {
      setError(err?.message || 'Failed to load schedule executions.');
    } finally {
      setHistoryLoading(false);
    }
  };

  // Helper for human-readable time countdown
  const formatCountdown = (dateString: string) => {
    try {
      const target = new Date(dateString).getTime();
      const now = new Date().getTime();
      const diffMs = target - now;

      if (diffMs <= 0) return 'Due now (or next scheduler tick)';

      const diffMins = Math.floor(diffMs / (1000 * 60));
      const hours = Math.floor(diffMins / 60);
      const days = Math.floor(hours / 24);
      const remainingHours = hours % 24;
      const remainingMins = diffMins % 60;

      if (days > 0) {
        return `in ${days}d ${remainingHours}h`;
      }
      if (hours > 0) {
        return `in ${hours}h ${remainingMins}m`;
      }
      return `in ${remainingMins}m`;
    } catch {
      return dateString;
    }
  };

  // Calculate summary metrics
  const totalSchedules = schedules.length;
  const activeSchedules = schedules.filter((s) => s.is_enabled).length;
  const totalExecutions = schedules.reduce((acc, s) => acc + (s.execution_count || 0), 0);
  
  // Find soonest upcoming run
  const enabledWithNextRun = schedules
    .filter((s) => s.is_enabled && s.next_run_at)
    .sort((a, b) => new Date(a.next_run_at).getTime() - new Date(b.next_run_at).getTime());
  const nextUpcoming = enabledWithNextRun.length > 0 ? enabledWithNextRun[0] : null;

  return (
    <div className="space-y-6">
      {/* Informational Banner */}
      <div className="flex items-start gap-3 p-4 rounded-xl border border-cyan-500/20 bg-cyan-950/20 text-cyan-200">
        <Clock className="w-5 h-5 shrink-0 text-cyan-400 mt-0.5" />
        <div className="text-sm space-y-1">
          <div className="font-semibold text-cyan-300">Phase 6: Automated & Scheduled Discovery Active</div>
          <p className="text-cyan-200/80 leading-relaxed">
            Recurring discovery scans run on automated intervals against authorised scopes. Each execution automatically takes an immutable Phase 2 baseline snapshot, detects asset additions/removals/attribute changes, executes Phase 3 explainable risk classifications, evaluates Phase 5 alert rules, and generates immutable audit trails.
          </p>
        </div>
      </div>

      {/* Global Alerts */}
      {error && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setError(null)}>Dismiss</Button>
        </div>
      )}

      {actionSuccess && (
        <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{actionSuccess}</span>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setActionSuccess(null)}>Dismiss</Button>
        </div>
      )}

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 bg-navy-900/60 border-navy-750 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400">Active Schedules</div>
            <div className="text-2xl font-bold font-mono text-white mt-0.5">
              {activeSchedules} <span className="text-sm font-normal text-slate-400">/ {totalSchedules}</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-navy-900/60 border-navy-750 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Timer className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400">Next Discovery Scan</div>
            <div className="text-base font-bold font-mono text-emerald-400 mt-0.5 truncate max-w-[190px]" title={nextUpcoming ? `${nextUpcoming.name} (${formatCountdown(nextUpcoming.next_run_at)})` : 'None armed'}>
              {nextUpcoming ? formatCountdown(nextUpcoming.next_run_at) : 'None armed'}
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-navy-900/60 border-navy-750 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <History className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400">Automated Executions</div>
            <div className="text-2xl font-bold font-mono text-purple-400 mt-0.5">
              {totalExecutions}
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-navy-900/60 border-navy-750 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400">Authorised Coverage</div>
            <div className="text-2xl font-bold font-mono text-amber-400 mt-0.5">
              {authorisedScopes.length > 0
                ? `${Math.round((schedules.filter(s => s.is_enabled).length / Math.max(1, authorisedScopes.length)) * 100)}%`
                : '0%'}
            </div>
          </div>
        </Card>
      </div>

      {/* Control Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-navy-900/40 p-4 rounded-xl border border-navy-750">
        <div className="flex items-center gap-3">
          <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">Filter Scope:</label>
          <select
            value={selectedScopeFilter}
            onChange={(e) => setSelectedScopeFilter(e.target.value)}
            className="bg-navy-950 border border-navy-700 text-sm text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Scopes ({scopes.length})</option>
            {scopes.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} {!s.authorised_confirmation ? '(Unconfirmed)' : ''}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="outline"
            onClick={fetchSchedules}
            disabled={loading}
            className="border-navy-700 hover:bg-navy-800 text-slate-300"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <Button
            size="sm"
            variant="primary"
            onClick={handleOpenCreateModal}
            className="bg-cyan-600 hover:bg-cyan-500 text-white font-medium"
          >
            <Plus className="w-4 h-4 mr-2" />
            Configure Schedule
          </Button>
        </div>
      </div>

      {/* Schedules List */}
      {loading && schedules.length === 0 ? (
        <div className="text-center py-16 bg-navy-900/20 rounded-xl border border-navy-800">
          <RefreshCw className="w-8 h-8 animate-spin text-cyan-400 mx-auto mb-3" />
          <p className="text-slate-400 text-sm">Loading discovery schedules...</p>
        </div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-16 bg-navy-900/20 rounded-xl border border-navy-800 space-y-4">
          <div className="w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto text-cyan-400">
            <Clock className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <div className="text-base font-semibold text-white">No Discovery Schedules Configured</div>
            <p className="text-sm text-slate-400 max-w-md mx-auto">
              Automate your attack-surface monitoring by configuring recurring scans against your authorised targets.
            </p>
          </div>
          <Button size="sm" variant="primary" onClick={handleOpenCreateModal}>
            <Plus className="w-4 h-4 mr-2" />
            Create First Schedule
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {schedules.map((sched) => {
            const isCurrentlyTriggering = triggeringScheduleId === sched.id;
            const scope = scopes.find((s) => s.id === sched.scope_id);

            return (
              <Card
                key={sched.id}
                className={`p-5 transition-all duration-200 border ${
                  sched.is_enabled
                    ? 'bg-navy-900/70 border-navy-750 hover:border-cyan-500/50'
                    : 'bg-navy-950/60 border-navy-850 opacity-75'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left: Schedule Information */}
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-3 flex-wrap">
                      <h3 className="text-base font-semibold text-white flex items-center gap-2">
                        {sched.name}
                      </h3>
                      
                      {/* Frequency Badge */}
                      <Badge variant="cyan" size="sm">
                        <Calendar className="w-3 h-3 mr-1 inline" />
                        {sched.frequency === 'DAILY' && 'Every 24 Hours (Daily)'}
                        {sched.frequency === 'WEEKLY' && 'Every 7 Days (Weekly)'}
                        {sched.frequency === 'HOURLY_6' && 'Every 6 Hours'}
                        {sched.frequency === 'HOURLY_12' && 'Every 12 Hours'}
                        {sched.frequency === 'CUSTOM' && `Every ${sched.interval_hours} Hours`}
                        {!['DAILY', 'WEEKLY', 'HOURLY_6', 'HOURLY_12', 'CUSTOM'].includes(sched.frequency) && sched.frequency}
                      </Badge>

                      {/* Scope Badge */}
                      <Badge variant="slate" size="sm">
                        <ShieldCheck className="w-3 h-3 mr-1 inline text-emerald-400" />
                        {sched.scope_name || scope?.name || 'Scope'}
                      </Badge>

                      {/* Enable / Disable Status */}
                      <button
                        onClick={() => handleToggleEnable(sched)}
                        className={`text-xs px-2.5 py-1 rounded-full font-medium transition-colors cursor-pointer border ${
                          sched.is_enabled
                            ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/60'
                            : 'bg-slate-900 border-slate-700 text-slate-400 hover:bg-slate-800'
                        }`}
                        title="Click to toggle enable/disable"
                      >
                        <span className={`inline-block w-2 h-2 rounded-full mr-1.5 ${sched.is_enabled ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                        {sched.is_enabled ? 'Active / Armed' : 'Disabled'}
                      </button>
                    </div>

                    {sched.description && (
                      <p className="text-xs text-slate-400 leading-normal line-clamp-2">
                        {sched.description}
                      </p>
                    )}

                    {/* Schedule Execution Timings */}
                    <div className="flex items-center gap-6 pt-2 text-xs font-mono text-slate-400 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Next Run:</span>
                        <span className="text-white font-semibold">
                          {sched.is_enabled
                            ? `${formatCountdown(sched.next_run_at)} (${new Date(sched.next_run_at).toLocaleString()})`
                            : 'Paused'}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span>Last Status:</span>
                        {sched.last_run_status === 'COMPLETED' && (
                          <span className="text-emerald-400 font-semibold flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> COMPLETED
                          </span>
                        )}
                        {sched.last_run_status === 'IN_PROGRESS' && (
                          <span className="text-blue-400 font-semibold flex items-center gap-1 animate-pulse">
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" /> RUNNING
                          </span>
                        )}
                        {sched.last_run_status === 'SKIPPED_CONCURRENT' && (
                          <span className="text-amber-400 font-semibold flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" /> SKIPPED (ACTIVE RUN)
                          </span>
                        )}
                        {sched.last_run_status === 'FAILED' && (
                          <span className="text-red-400 font-semibold flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" /> FAILED
                          </span>
                        )}
                        {!sched.last_run_status && (
                          <span className="text-slate-500">None yet</span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5">
                        <span>Executions:</span>
                        <span className="text-purple-400 font-semibold">{sched.execution_count}</span>
                      </div>
                    </div>
                  </div>

                  {/* Right: Actions */}
                  <div className="flex items-center gap-2 shrink-0 border-t lg:border-t-0 border-navy-800 pt-3 lg:pt-0">
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => handleTriggerNow(sched)}
                      disabled={isCurrentlyTriggering || !sched.is_enabled}
                      className="bg-cyan-600/90 hover:bg-cyan-500 text-white font-medium text-xs shadow-sm"
                      title={!sched.is_enabled ? 'Enable schedule first to run' : 'Run discovery immediately'}
                    >
                      <Play className={`w-3.5 h-3.5 mr-1.5 ${isCurrentlyTriggering ? 'animate-spin' : ''}`} />
                      {isCurrentlyTriggering ? 'Triggering...' : 'Run Now'}
                    </Button>

                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleViewExecutions(sched)}
                      className="border-navy-700 hover:bg-navy-800 text-slate-300 text-xs"
                      title="View historical runs triggered by this schedule"
                    >
                      <History className="w-3.5 h-3.5 mr-1.5 text-purple-400" />
                      History ({sched.execution_count})
                    </Button>

                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleOpenEditModal(sched)}
                      className="text-slate-400 hover:text-white hover:bg-navy-800"
                      title="Edit schedule configuration"
                    >
                      <Edit className="w-4 h-4" />
                    </Button>

                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleDeleteSchedule(sched)}
                      className="text-slate-400 hover:text-red-400 hover:bg-red-950/40"
                      title="Delete schedule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create / Edit Schedule Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={editingSchedule ? 'Edit Discovery Schedule' : 'Configure Discovery Schedule'}
        subtitle="Establish recurring automated scans and asset change detection workflows."
      >
        <form onSubmit={handleSaveSchedule} className="space-y-4">
          {modalError && (
            <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
              <span>{modalError}</span>
            </div>
          )}

          {/* Scope Selector */}
          <div>
            <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
              Target Scope <span className="text-red-400">*</span>
            </label>
            <select
              value={modalScopeId}
              onChange={(e) => setModalScopeId(e.target.value)}
              disabled={Boolean(editingSchedule)}
              className="w-full bg-navy-950 border border-navy-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="" disabled>-- Select Authorised Scope --</option>
              {scopes.map((s) => (
                <option
                  key={s.id}
                  value={s.id}
                  disabled={!s.authorised_confirmation}
                >
                  {s.name} {!s.authorised_confirmation ? '(Unconfirmed - Not Permitted)' : `(${s.targets.length} targets)`}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Scheduling requires verified authorization confirmation for the target scope.
            </p>
          </div>

          {/* Schedule Name */}
          <div>
            <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
              Schedule Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={modalName}
              onChange={(e) => setModalName(e.target.value)}
              placeholder="e.g. Daily Nightly Perimeter Scan"
              className="w-full bg-navy-950 border border-navy-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Schedule Description */}
          <div>
            <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
              Description (Optional)
            </label>
            <textarea
              value={modalDescription}
              onChange={(e) => setModalDescription(e.target.value)}
              rows={2}
              placeholder="Purpose of this automated discovery schedule..."
              className="w-full bg-navy-950 border border-navy-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500 resize-none"
            />
          </div>

          {/* Frequency & Interval */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                Frequency Preset
              </label>
              <select
                value={modalFrequency}
                onChange={(e) => setModalFrequency(e.target.value as ScheduleFrequency)}
                className="w-full bg-navy-950 border border-navy-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500"
              >
                <option value="DAILY">Daily (Every 24 Hours)</option>
                <option value="WEEKLY">Weekly (Every 7 Days)</option>
                <option value="HOURLY_6">Every 6 Hours</option>
                <option value="HOURLY_12">Every 12 Hours</option>
                <option value="CUSTOM">Custom Interval</option>
              </select>
            </div>

            {modalFrequency === 'CUSTOM' ? (
              <div>
                <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-1">
                  Custom Interval (Hours)
                </label>
                <input
                  type="number"
                  min={1}
                  max={8760}
                  value={modalIntervalHours}
                  onChange={(e) => setModalIntervalHours(Math.max(1, parseInt(e.target.value) || 1))}
                  className="w-full bg-navy-950 border border-navy-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            ) : (
              <div>
                <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
                  Interval Duration
                </label>
                <div className="bg-navy-950/50 border border-navy-800 rounded-lg px-3 py-2 text-sm text-slate-400 font-mono">
                  {modalFrequency === 'DAILY' && '24 hours'}
                  {modalFrequency === 'WEEKLY' && '168 hours (7 days)'}
                  {modalFrequency === 'HOURLY_6' && '6 hours'}
                  {modalFrequency === 'HOURLY_12' && '12 hours'}
                </div>
              </div>
            )}
          </div>

          {/* Scan Options & Presets */}
          <div className="p-3 rounded-lg bg-navy-950/70 border border-navy-800 space-y-3">
            <div className="text-xs font-medium text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              Engine Probing Configuration
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={modalEnableDns}
                  onChange={(e) => setModalEnableDns(e.target.checked)}
                  className="rounded border-navy-700 bg-navy-900 text-cyan-500 focus:ring-0"
                />
                DNS Resolution
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={modalEnablePorts}
                  onChange={(e) => setModalEnablePorts(e.target.checked)}
                  className="rounded border-navy-700 bg-navy-900 text-cyan-500 focus:ring-0"
                />
                Port Scanning
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={modalEnableHttp}
                  onChange={(e) => setModalEnableHttp(e.target.checked)}
                  className="rounded border-navy-700 bg-navy-900 text-cyan-500 focus:ring-0"
                />
                HTTP Banner Probing
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={modalEnableTls}
                  onChange={(e) => setModalEnableTls(e.target.checked)}
                  className="rounded border-navy-700 bg-navy-900 text-cyan-500 focus:ring-0"
                />
                TLS Certificate Inspection
              </label>
            </div>
          </div>

          {/* Enable immediately checkbox */}
          <div className="pt-1">
            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={modalIsEnabled}
                onChange={(e) => setModalIsEnabled(e.target.checked)}
                className="rounded border-navy-700 bg-navy-900 text-cyan-500 focus:ring-0"
              />
              Enable schedule immediately
            </label>
          </div>

          {/* Modal Actions */}
          <div className="flex justify-end gap-3 pt-3 border-t border-navy-800">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsModalOpen(false)}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={isSubmitting}
              className="bg-cyan-600 hover:bg-cyan-500 text-white"
            >
              {isSubmitting ? 'Saving...' : editingSchedule ? 'Save Changes' : 'Create Schedule'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Execution History Modal */}
      <Modal
        isOpen={Boolean(selectedScheduleForHistory)}
        onClose={() => setSelectedScheduleForHistory(null)}
        title={`Execution History: ${selectedScheduleForHistory?.name || ''}`}
        subtitle="Historical discovery runs triggered automatically or manually from this schedule."
      >
        <div className="space-y-4">
          {historyLoading ? (
            <div className="text-center py-8">
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400 mx-auto mb-2" />
              <p className="text-xs text-slate-400">Loading execution records...</p>
            </div>
          ) : historyExecutions.length === 0 ? (
            <div className="text-center py-8 bg-navy-950 rounded-lg border border-navy-800 text-slate-400 text-xs">
              No executions recorded yet for this schedule. Click "Run Now" to initiate the first run.
            </div>
          ) : (
            <div className="max-h-[380px] overflow-y-auto space-y-2 pr-1">
              {historyExecutions.map((scan) => (
                <div
                  key={scan.id}
                  className="p-3 rounded-lg bg-navy-950 border border-navy-800 flex items-center justify-between text-xs font-mono"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">#{scan.id.slice(0, 8)}</span>
                      {scan.status === 'COMPLETED' && (
                        <Badge variant="emerald" size="sm">
                          COMPLETED
                        </Badge>
                      )}
                      {scan.status === 'IN_PROGRESS' && (
                        <Badge variant="cyan" size="sm" pulse>
                          IN PROGRESS
                        </Badge>
                      )}
                      {scan.status === 'FAILED' && (
                        <Badge variant="rose" size="sm">
                          FAILED
                        </Badge>
                      )}
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'Started pending'}
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="text-right text-[11px] space-y-0.5">
                      <div className="text-slate-300">
                        Scanned: <span className="text-cyan-400 font-bold">{scan.targets_scanned}</span> / {scan.targets_total}
                      </div>
                      <div className="text-slate-400">
                        Assets: <span className="text-emerald-400 font-bold">{scan.assets_discovered_count}</span> | Findings: <span className="text-purple-400 font-bold">{scan.findings_count}</span>
                      </div>
                    </div>

                    {onNavigateToScan && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setSelectedScheduleForHistory(null);
                          onNavigateToScan(scan.id);
                        }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 hover:bg-cyan-950/40 px-2 py-1"
                      >
                        Logs <ArrowRight className="w-3 h-3 ml-1" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="flex justify-end pt-2 border-t border-navy-800">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setSelectedScheduleForHistory(null)}
            >
              Close
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
