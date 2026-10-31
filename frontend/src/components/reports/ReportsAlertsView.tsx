import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Bell,
  History,
  ShieldCheck,
  Download,
  Plus,
  Trash2,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  RotateCw,
  Search,
  Lock,
  Mail,
  Webhook,
  Activity,
  Layers
} from 'lucide-react';
import { api } from '../../api/client';
import type {
  Scope,
  NotificationRule,
  NotificationRuleCreatePayload,
  NotificationEvent,
  AuditLog,
  AuditSummary,
  IntegrationStatus
} from '../../api/types';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { Card } from '../ui/Card';
import { Modal } from '../ui/Modal';

interface ReportsAlertsViewProps {
  scopes: Scope[];
}

export const ReportsAlertsView: React.FC<ReportsAlertsViewProps> = ({ scopes }) => {
  const [activeTab, setActiveTab] = useState<'exports' | 'rules' | 'history' | 'integrations' | 'audit'>('exports');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Data states
  const [rules, setRules] = useState<NotificationRule[]>([]);
  const [events, setEvents] = useState<NotificationEvent[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationStatus | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditSummary, setAuditSummary] = useState<AuditSummary | null>(null);

  // Export filters
  const [exportScope, setExportScope] = useState<string>('all');

  // Audit filters
  const [auditActionFilter, setAuditActionFilter] = useState<string>('all');
  const [auditSearch, setAuditSearch] = useState<string>('');
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLog | null>(null);

  // New Rule Modal state
  const [isNewRuleModalOpen, setIsNewRuleModalOpen] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleDescription, setNewRuleDescription] = useState('');
  const [newRuleEventType, setNewRuleEventType] = useState<string>('FINDING_DETECTED');
  const [newRuleScopeId, setNewRuleScopeId] = useState<string>('all');
  const [newRuleSeverities, setNewRuleSeverities] = useState<string[]>(['CRITICAL', 'HIGH']);
  const [newRuleChannels, setNewRuleChannels] = useState<string[]>(['webhook']);
  const [newRuleWebhookUrl, setNewRuleWebhookUrl] = useState('');
  const [newRuleEmail, setNewRuleEmail] = useState('');
  const [isSubmittingRule, setIsSubmittingRule] = useState(false);
  const [ruleModalError, setRuleModalError] = useState<string | null>(null);

  // Retrying event state
  const [retryingEventId, setRetryingEventId] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesRes, eventsRes, integrationsRes, logsRes, summaryRes] = await Promise.all([
        api.getNotificationRules().catch(() => []),
        api.getNotificationHistory({ limit: 100 }).catch(() => []),
        api.getIntegrationStatus().catch(() => null),
        api.getAuditLogs({ limit: 100 }).catch(() => []),
        api.getAuditSummary().catch(() => null),
      ]);
      setRules(rulesRes);
      setEvents(eventsRes);
      setIntegrations(integrationsRes);
      setAuditLogs(logsRes);
      setAuditSummary(summaryRes);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch notification and audit data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const triggerExport = (resource: 'inventory' | 'changes' | 'findings', format: 'csv' | 'json') => {
    const params: Record<string, string> = {};
    if (exportScope !== 'all') {
      params.scope_id = exportScope;
    }
    const url = api.getExportUrl(resource, format, params);
    window.open(url, '_blank');
    setSuccessMessage(`Initiated ${resource.toUpperCase()} ${format.toUpperCase()} download.`);
    setTimeout(() => {
      setSuccessMessage(null);
      // Refresh audit logs since an EXPORT_GENERATED audit event is logged
      api.getAuditLogs({ limit: 100 }).then(setAuditLogs).catch(() => {});
      api.getAuditSummary().then(setAuditSummary).catch(() => {});
    }, 1500);
  };

  const handleToggleRule = async (rule: NotificationRule) => {
    try {
      const updated = await api.updateNotificationRule(rule.id, { is_enabled: !rule.is_enabled });
      setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
      setSuccessMessage(`Alert rule "${rule.name}" is now ${updated.is_enabled ? 'enabled' : 'disabled'}.`);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to update rule status.');
    }
  };

  const handleDeleteRule = async (id: string, name: string) => {
    if (!window.confirm(`Are you sure you want to delete the alert rule "${name}"?`)) return;
    try {
      await api.deleteNotificationRule(id);
      setRules((prev) => prev.filter((r) => r.id !== id));
      setSuccessMessage(`Alert rule "${name}" removed successfully.`);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to delete alert rule.');
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setRuleModalError(null);

    if (!newRuleName.trim()) {
      setRuleModalError('Rule name is required.');
      return;
    }

    if (newRuleChannels.length === 0) {
      setRuleModalError('Select at least one notification channel (Webhook or Email).');
      return;
    }

    if (newRuleChannels.includes('webhook') && !newRuleWebhookUrl.trim()) {
      setRuleModalError('Webhook destination URL is required.');
      return;
    }

    if (newRuleChannels.includes('email') && (!newRuleEmail.trim() || !newRuleEmail.includes('@'))) {
      setRuleModalError('A valid recipient email address is required.');
      return;
    }

    setIsSubmittingRule(true);
    try {
      const payload: NotificationRuleCreatePayload = {
        name: newRuleName.trim(),
        description: newRuleDescription.trim() || undefined,
        event_type: newRuleEventType,
        scope_id: newRuleScopeId === 'all' ? null : newRuleScopeId,
        channels: newRuleChannels,
        webhook_url: newRuleChannels.includes('webhook') ? newRuleWebhookUrl.trim() : null,
        email_recipient: newRuleChannels.includes('email') ? newRuleEmail.trim() : null,
        conditions: newRuleEventType === 'FINDING_DETECTED' ? { severities: newRuleSeverities } : {},
      };

      const created = await api.createNotificationRule(payload);
      setRules((prev) => [created, ...prev]);
      setIsNewRuleModalOpen(false);
      setSuccessMessage(`Alert rule "${created.name}" created successfully.`);
      setTimeout(() => setSuccessMessage(null), 3000);

      // Reset modal fields
      setNewRuleName('');
      setNewRuleDescription('');
      setNewRuleWebhookUrl('');
      setNewRuleEmail('');
    } catch (err: any) {
      setRuleModalError(err.message || 'Failed to create notification rule.');
    } finally {
      setIsSubmittingRule(false);
    }
  };

  const handleRetryEvent = async (id: string) => {
    setRetryingEventId(id);
    try {
      const res = await api.retryNotificationEvent(id);
      setEvents((prev) => prev.map((ev) => (ev.id === id ? res.event : ev)));
      setSuccessMessage(`Notification delivery retry completed. Status: ${res.event.status}`);
      setTimeout(() => setSuccessMessage(null), 3500);
    } catch (err: any) {
      setError(err.message || 'Failed to retry notification delivery.');
    } finally {
      setRetryingEventId(null);
    }
  };

  const filteredAuditLogs = auditLogs.filter((log) => {
    if (auditActionFilter !== 'all' && log.action !== auditActionFilter) return false;
    if (auditSearch.trim()) {
      const query = auditSearch.toLowerCase();
      const inActor = log.actor.toLowerCase().includes(query);
      const inAction = log.action.toLowerCase().includes(query);
      const inEntity = (log.entity_id || '').toLowerCase().includes(query);
      if (!inActor && !inAction && !inEntity) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner / Breadcrumb */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <span>PHASE 5 ENGINE</span>
            <span>•</span>
            <span>ALERTS, EXPORTS & AUDIT TELEMETRY</span>
          </div>
          <h1 className="text-2xl font-extrabold text-slate-100 tracking-tight flex items-center gap-3">
            Reports & Notifications
            <Badge variant="cyan" size="sm">Phase 5</Badge>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Configurable alert rules, bounded webhook delivery, audit logs, and sanitized CSV/JSON reports.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={loading}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            Refresh
          </Button>
          {activeTab === 'rules' && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => setIsNewRuleModalOpen(true)}
              icon={<Plus className="w-4 h-4" />}
            >
              New Alert Rule
            </Button>
          )}
        </div>
      </div>

      {/* Global Alerts */}
      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-center justify-between text-xs text-rose-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}

      {successMessage && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMessage}</span>
          </div>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* Sub-navigation tabs */}
      <div className="flex items-center gap-2 border-b border-navy-750 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab('exports')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider uppercase transition-all ${
            activeTab === 'exports'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
          }`}
        >
          <Download className="w-3.5 h-3.5" />
          Reports & Exports
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider uppercase transition-all ${
            activeTab === 'rules'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
          }`}
        >
          <Bell className="w-3.5 h-3.5" />
          Alert Rules ({rules.length})
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider uppercase transition-all ${
            activeTab === 'history'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          Delivery History ({events.length})
        </button>

        <button
          onClick={() => setActiveTab('integrations')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider uppercase transition-all ${
            activeTab === 'integrations'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          Integrations & Security
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold tracking-wider uppercase transition-all ${
            activeTab === 'audit'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-850'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          Audit Trail ({auditSummary?.total_events || auditLogs.length})
        </button>
      </div>

      {/* TAB 1: REPORTS & EXPORTS */}
      {activeTab === 'exports' && (
        <div className="space-y-6">
          <Card className="p-4 bg-navy-900/60 border-navy-750">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Scope Filtering</h3>
                <p className="text-xs text-slate-400">Limit data exports to a single authorized scope or download global attack-surface datasets.</p>
              </div>
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <span className="text-xs text-slate-400">Target Scope:</span>
                <select
                  value={exportScope}
                  onChange={(e) => setExportScope(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="all">All Authorized Scopes (Global)</option>
                  {scopes.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Inventory Card */}
            <Card className="p-5 flex flex-col justify-between border-navy-750 bg-gradient-to-b from-navy-900 to-navy-950 hover:border-cyan-500/30 transition-all">
              <div>
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
                  <Layers className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-slate-100">Asset Inventory Dataset</h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Complete list of discovered hosts, FQDNs, IP addresses, open ports, banners, DNS records, and TLS certificate summaries.
                </p>
                <div className="mt-4 pt-3 border-t border-navy-800 flex items-center gap-2 text-[11px] text-slate-400">
                  <Lock className="w-3 h-3 text-cyan-400" />
                  <span>Sanitized CSV formula guard active</span>
                </div>
              </div>

              <div className="mt-6 flex items-center gap-3">
                <Button
                  variant="primary"
                  size="sm"
                  className="flex-1"
                  onClick={() => triggerExport('inventory', 'csv')}
                  icon={<Download className="w-3.5 h-3.5" />}
                >
                  Export CSV
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => triggerExport('inventory', 'json')}
                  icon={<FileText className="w-3.5 h-3.5" />}
                >
                  Export JSON
                </Button>
              </div>
            </Card>

            {/* Changes Card */}
            <Card className="p-5 flex flex-col justify-between border-navy-750 bg-gradient-to-b from-navy-900 to-navy-950 hover:border-violet-500/30 transition-all">
              <div>
                <div className="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/30 flex items-center justify-center text-violet-400 mb-4">
                  <History className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-slate-100">Change History Telemetry</h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Sequential snapshot diffs, new asset appearances, removed services, modified DNS records, and inconclusive scan indicators.
                </p>
                <div className="mt-4 pt-3 border-t border-navy-800 flex items-center gap-2 text-[11px] text-slate-400">
                  <ShieldCheck className="w-3 h-3 text-violet-400" />
                  <span>Phase 2 Snapshot lineage tracked</span>
                </div>
              </div>

              <div className="mt-6 flex items-center gap-3">
                <Button
                  variant="primary"
                  size="sm"
                  className="flex-1 bg-violet-600 hover:bg-violet-500 text-white"
                  onClick={() => triggerExport('changes', 'csv')}
                  icon={<Download className="w-3.5 h-3.5" />}
                >
                  Export CSV
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => triggerExport('changes', 'json')}
                  icon={<FileText className="w-3.5 h-3.5" />}
                >
                  Export JSON
                </Button>
              </div>
            </Card>

            {/* Findings Card */}
            <Card className="p-5 flex flex-col justify-between border-navy-750 bg-gradient-to-b from-navy-900 to-navy-950 hover:border-rose-500/30 transition-all">
              <div>
                <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mb-4">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-slate-100">Findings & Risk Report</h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Explainable risk classifications, confidence scores, evidence rationale, remediation guidelines, and human review status histories.
                </p>
                <div className="mt-4 pt-3 border-t border-navy-800 flex items-center gap-2 text-[11px] text-slate-400">
                  <CheckCircle2 className="w-3 h-3 text-rose-400" />
                  <span>Phase 3 Deterministic risk scoring</span>
                </div>
              </div>

              <div className="mt-6 flex items-center gap-3">
                <Button
                  variant="primary"
                  size="sm"
                  className="flex-1 bg-rose-600 hover:bg-rose-500 text-white"
                  onClick={() => triggerExport('findings', 'csv')}
                  icon={<Download className="w-3.5 h-3.5" />}
                >
                  Export CSV
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => triggerExport('findings', 'json')}
                  icon={<FileText className="w-3.5 h-3.5" />}
                >
                  Export JSON
                </Button>
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* TAB 2: ALERT RULES */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              Showing {rules.length} configured alert {rules.length === 1 ? 'rule' : 'rules'}
            </span>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setIsNewRuleModalOpen(true)}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              Add Alert Rule
            </Button>
          </div>

          {rules.length === 0 ? (
            <Card className="p-12 text-center border-navy-750 bg-navy-950">
              <Bell className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-bold text-slate-200">No Alert Rules Configured</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                Create configurable notification rules for newly discovered assets, unexpected changes, or critical security findings.
              </p>
              <Button
                variant="primary"
                size="sm"
                className="mt-4"
                onClick={() => setIsNewRuleModalOpen(true)}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                Create First Alert Rule
              </Button>
            </Card>
          ) : (
            <div className="space-y-3">
              {rules.map((rule) => (
                <Card key={rule.id} className="p-4 border-navy-750 bg-navy-900/60 hover:border-navy-700 transition-all">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                        rule.is_enabled ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-500'
                      }`}>
                        <Bell className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="text-sm font-bold text-slate-100">{rule.name}</h4>
                          <Badge variant={rule.is_enabled ? 'emerald' : 'slate'} size="sm">
                            {rule.is_enabled ? 'Active' : 'Disabled'}
                          </Badge>
                          <Badge variant="cyan" size="sm">
                            {rule.event_type.replace('_', ' ')}
                          </Badge>
                          <span className="text-[11px] text-slate-400 font-mono">
                            Scope: {rule.scope_name || 'All Scopes'}
                          </span>
                        </div>
                        {rule.description && (
                          <p className="text-xs text-slate-400 mt-1">{rule.description}</p>
                        )}
                        <div className="flex items-center gap-3 mt-2 text-[11px] text-slate-400 font-mono">
                          <span>Channels: {rule.channels.join(', ')}</span>
                          {rule.webhook_url && (
                            <span className="truncate max-w-xs text-slate-400">Webhook: {rule.webhook_url}</span>
                          )}
                          {rule.email_recipient && (
                            <span>Email: {rule.email_recipient}</span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end md:self-center">
                      <Button
                        variant={rule.is_enabled ? 'outline' : 'primary'}
                        size="sm"
                        onClick={() => handleToggleRule(rule)}
                      >
                        {rule.is_enabled ? 'Disable' : 'Enable'}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
                        onClick={() => handleDeleteRule(rule.id, rule.name)}
                        icon={<Trash2 className="w-3.5 h-3.5" />}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DELIVERY HISTORY */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              {events.length} notification dispatch events logged
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchData}
              disabled={loading}
              icon={<RotateCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
            >
              Refresh History
            </Button>
          </div>

          {events.length === 0 ? (
            <Card className="p-12 text-center border-navy-750 bg-navy-950">
              <History className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-bold text-slate-200">No Notification Events</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                Triggered notification deliveries and external webhook dispatches will be recorded here with delivery statuses and retry counts.
              </p>
            </Card>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-navy-750 bg-navy-900/60">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950 text-slate-400 border-b border-navy-750 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Event Type</th>
                    <th className="px-4 py-3">Channel</th>
                    <th className="px-4 py-3">Recipient / Endpoint</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Retries</th>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800">
                  {events.map((ev) => (
                    <tr key={ev.id} className="hover:bg-navy-850/50 transition-colors">
                      <td className="px-4 py-3 font-semibold text-slate-200">
                        {ev.event_type}
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant={ev.channel === 'webhook' ? 'cyan' : 'violet'} size="sm">
                          {ev.channel}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-300 max-w-xs truncate">
                        {ev.recipient}
                      </td>
                      <td className="px-4 py-3">
                        {ev.status === 'SENT' && (
                          <Badge variant="emerald" size="sm">SENT</Badge>
                        )}
                        {ev.status === 'FAILED' && (
                          <Badge variant="rose" size="sm">FAILED</Badge>
                        )}
                        {ev.status === 'PENDING' && (
                          <Badge variant="amber" size="sm">PENDING</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                        {ev.retry_count} / {ev.max_retries}
                      </td>
                      <td className="px-4 py-3 text-[11px] text-slate-400 font-mono">
                        {new Date(ev.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {ev.status === 'FAILED' && (
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={retryingEventId === ev.id || ev.retry_count >= ev.max_retries}
                            onClick={() => handleRetryEvent(ev.id)}
                            icon={<RotateCw className={`w-3 h-3 ${retryingEventId === ev.id ? 'animate-spin' : ''}`} />}
                          >
                            Retry
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: INTEGRATIONS & SECURITY */}
      {activeTab === 'integrations' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Webhook Integration Card */}
          <Card className="p-6 border-navy-750 bg-navy-900/60">
            <div className="flex items-center justify-between pb-4 border-b border-navy-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Webhook className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">Webhook Integration</h3>
                  <p className="text-xs text-slate-400">Outbound JSON alerts to SIEM, Slack, or SOAR</p>
                </div>
              </div>
              <Badge variant="emerald" size="sm">Protected</Badge>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">SSRF Guardrail</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Active (Cloud Metadata Blocked)
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">Delivery Timeout</span>
                <span className="text-slate-200 font-mono">
                  {integrations?.webhook_integration.timeout_seconds || 5.0}s bounded
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">Live Dispatch Mode</span>
                <span className="text-cyan-400 font-mono">
                  {integrations?.live_notifications_enabled ? 'ENABLED (Production)' : 'SAFE LAB / TEST MODE'}
                </span>
              </div>
            </div>

            <p className="text-[11px] text-slate-400 mt-4 leading-relaxed">
              Target webhook URLs are strictly validated prior to dispatch. Prohibited destinations including AWS/GCP metadata (`169.254.169.254`), loopbacks, and private RFC 1918 addresses are blocked unless authorized for local testing.
            </p>
          </Card>

          {/* Email Integration Card */}
          <Card className="p-6 border-navy-750 bg-navy-900/60">
            <div className="flex items-center justify-between pb-4 border-b border-navy-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/30 flex items-center justify-center text-violet-400">
                  <Mail className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">Email (SMTP) Integration</h3>
                  <p className="text-xs text-slate-400">Automated notification summaries</p>
                </div>
              </div>
              <Badge variant={integrations?.email_integration.configured ? 'emerald' : 'slate'} size="sm">
                {integrations?.email_integration.configured ? 'Configured' : 'Disabled / Standby'}
              </Badge>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">SMTP Host Status</span>
                <span className={integrations?.email_integration.smtp_host_configured ? 'text-emerald-400' : 'text-slate-400 font-mono'}>
                  {integrations?.email_integration.smtp_host_configured ? 'Configured' : 'Unset (Zero Credential Leak)'}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">Sender Address</span>
                <span className="text-slate-200 font-mono">
                  {integrations?.email_integration.sender_address || 'argustrace@security.internal'}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400">TLS Encryption</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  STARTTLS Enforced
                </span>
              </div>
            </div>

            <p className="text-[11px] text-slate-400 mt-4 leading-relaxed">
              ArgusTrace strictly handles SMTP credentials via environment variables (`SMTP_HOST`, `SMTP_PASSWORD`). When unconfigured, email alerts remain safely disabled without throwing runtime exceptions.
            </p>
          </Card>
        </div>
      )}

      {/* TAB 5: AUDIT TRAIL */}
      {activeTab === 'audit' && (
        <div className="space-y-4">
          {/* Summary metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Card className="p-4 border-navy-750 bg-navy-900/60">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-mono">Total Events</span>
              <p className="text-xl font-extrabold text-slate-100 mt-1">{auditSummary?.total_events || auditLogs.length}</p>
            </Card>

            <Card className="p-4 border-navy-750 bg-navy-900/60">
              <span className="text-[10px] uppercase tracking-wider text-cyan-400 font-mono">Exports Generated</span>
              <p className="text-xl font-extrabold text-cyan-400 mt-1">{auditSummary?.by_action['EXPORT_GENERATED'] || 0}</p>
            </Card>

            <Card className="p-4 border-navy-750 bg-navy-900/60">
              <span className="text-[10px] uppercase tracking-wider text-violet-400 font-mono">Status Updates</span>
              <p className="text-xl font-extrabold text-violet-400 mt-1">{auditSummary?.by_action['FINDING_STATUS_UPDATED'] || 0}</p>
            </Card>

            <Card className="p-4 border-navy-750 bg-navy-900/60">
              <span className="text-[10px] uppercase tracking-wider text-emerald-400 font-mono">Rules Created</span>
              <p className="text-xl font-extrabold text-emerald-400 mt-1">{auditSummary?.by_action['NOTIFICATION_RULE_CREATED'] || 0}</p>
            </Card>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search audit trail by actor, action, or entity..."
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <select
              value={auditActionFilter}
              onChange={(e) => setAuditActionFilter(e.target.value)}
              className="px-3 py-2 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="all">All Action Types</option>
              <option value="EXPORT_GENERATED">EXPORT_GENERATED</option>
              <option value="NOTIFICATION_RULE_CREATED">NOTIFICATION_RULE_CREATED</option>
              <option value="NOTIFICATION_RULE_UPDATED">NOTIFICATION_RULE_UPDATED</option>
              <option value="NOTIFICATION_RULE_DELETED">NOTIFICATION_RULE_DELETED</option>
              <option value="FINDING_STATUS_UPDATED">FINDING_STATUS_UPDATED</option>
              <option value="SCAN_COMPLETED">SCAN_COMPLETED</option>
            </select>
          </div>

          {filteredAuditLogs.length === 0 ? (
            <Card className="p-12 text-center border-navy-750 bg-navy-950">
              <Activity className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-bold text-slate-200">No Audit Logs Found</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                No audit events matched the selected filters.
              </p>
            </Card>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-navy-750 bg-navy-900/60">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-950 text-slate-400 border-b border-navy-750 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3">Actor</th>
                    <th className="px-4 py-3">Entity Type</th>
                    <th className="px-4 py-3">Entity ID</th>
                    <th className="px-4 py-3">Timestamp (UTC)</th>
                    <th className="px-4 py-3 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-800">
                  {filteredAuditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-navy-850/50 transition-colors">
                      <td className="px-4 py-3 font-semibold text-slate-200 font-mono text-[11px]">
                        {log.action}
                      </td>
                      <td className="px-4 py-3 text-slate-300">
                        {log.actor}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400">
                        {log.entity_type}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                        {log.entity_id || '—'}
                      </td>
                      <td className="px-4 py-3 text-[11px] text-slate-400 font-mono">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedAuditLog(log)}
                        >
                          View
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* CREATE ALERT RULE MODAL */}
      <Modal
        isOpen={isNewRuleModalOpen}
        onClose={() => setIsNewRuleModalOpen(false)}
        title="Create Configurable Alert Rule"
      >
        <form onSubmit={handleCreateRule} className="space-y-4">
          {ruleModalError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300">
              {ruleModalError}
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Rule Name</label>
            <input
              type="text"
              placeholder="e.g. Critical Findings Webhook Dispatch"
              value={newRuleName}
              onChange={(e) => setNewRuleName(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Description (Optional)</label>
            <input
              type="text"
              placeholder="e.g. Forwards CRITICAL/HIGH security observations to SecOps webhook"
              value={newRuleDescription}
              onChange={(e) => setNewRuleDescription(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Event Type</label>
              <select
                value={newRuleEventType}
                onChange={(e) => setNewRuleEventType(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="FINDING_DETECTED">FINDING_DETECTED</option>
                <option value="ASSET_DISCOVERED">ASSET_DISCOVERED</option>
                <option value="ASSET_CHANGED">ASSET_CHANGED</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Authorized Scope</label>
              <select
                value={newRuleScopeId}
                onChange={(e) => setNewRuleScopeId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="all">All Scopes (Global)</option>
                {scopes.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          </div>

          {newRuleEventType === 'FINDING_DETECTED' && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Severity Match Levels</label>
              <div className="flex items-center gap-3 pt-1">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                  <label key={sev} className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={newRuleSeverities.includes(sev)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setNewRuleSeverities((prev) => [...prev, sev]);
                        } else {
                          setNewRuleSeverities((prev) => prev.filter((s) => s !== sev));
                        }
                      }}
                      className="rounded bg-navy-950 border-navy-700 text-cyan-500 focus:ring-0"
                    />
                    <span>{sev}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Delivery Channels</label>
            <div className="flex items-center gap-4 pt-1">
              <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newRuleChannels.includes('webhook')}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setNewRuleChannels((prev) => [...prev, 'webhook']);
                    } else {
                      setNewRuleChannels((prev) => prev.filter((c) => c !== 'webhook'));
                    }
                  }}
                  className="rounded bg-navy-950 border-navy-700 text-cyan-500 focus:ring-0"
                />
                <span>Webhook (HTTP/HTTPS)</span>
              </label>

              <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newRuleChannels.includes('email')}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setNewRuleChannels((prev) => [...prev, 'email']);
                    } else {
                      setNewRuleChannels((prev) => prev.filter((c) => c !== 'email'));
                    }
                  }}
                  className="rounded bg-navy-950 border-navy-700 text-cyan-500 focus:ring-0"
                />
                <span>Email (SMTP)</span>
              </label>
            </div>
          </div>

          {newRuleChannels.includes('webhook') && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Webhook URL
                <span className="text-[11px] text-cyan-400 ml-2 font-normal">(SSRF protected)</span>
              </label>
              <input
                type="url"
                placeholder="https://webhook.site/your-unique-hook"
                value={newRuleWebhookUrl}
                onChange={(e) => setNewRuleWebhookUrl(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                required={newRuleChannels.includes('webhook')}
              />
            </div>
          )}

          {newRuleChannels.includes('email') && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Recipient Email</label>
              <input
                type="email"
                placeholder="security-alerts@yourdomain.com"
                value={newRuleEmail}
                onChange={(e) => setNewRuleEmail(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-navy-950 border border-navy-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                required={newRuleChannels.includes('email')}
              />
            </div>
          )}

          <div className="pt-3 border-t border-navy-800 flex items-center justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              type="button"
              onClick={() => setIsNewRuleModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              type="submit"
              disabled={isSubmittingRule}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              {isSubmittingRule ? 'Saving Rule...' : 'Save Alert Rule'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* VIEW AUDIT DETAILS MODAL */}
      <Modal
        isOpen={Boolean(selectedAuditLog)}
        onClose={() => setSelectedAuditLog(null)}
        title="Audit Event Details"
      >
        {selectedAuditLog && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400 block text-[10px] uppercase">Action</span>
                <span className="font-bold text-slate-100 font-mono">{selectedAuditLog.action}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400 block text-[10px] uppercase">Actor</span>
                <span className="font-bold text-slate-100">{selectedAuditLog.actor}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400 block text-[10px] uppercase">Entity Type</span>
                <span className="font-mono text-cyan-400">{selectedAuditLog.entity_type}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-navy-950 border border-navy-800">
                <span className="text-slate-400 block text-[10px] uppercase">Entity ID</span>
                <span className="font-mono text-slate-300 truncate block">{selectedAuditLog.entity_id || 'N/A'}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1">Sanitized Event Details</span>
              <pre className="p-3 rounded-lg bg-navy-950 border border-navy-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-60">
                {JSON.stringify(selectedAuditLog.details, null, 2)}
              </pre>
            </div>

            <div className="text-right pt-2 border-t border-navy-800">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedAuditLog(null)}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
