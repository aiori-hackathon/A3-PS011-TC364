import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ReportsAlertsView } from '../components/reports/ReportsAlertsView';
import { api } from '../api/client';
import type {
  Scope,
  NotificationRule,
  NotificationEvent,
  IntegrationStatus,
  AuditLog,
  AuditSummary
} from '../api/types';

const mockScopes: Scope[] = [
  {
    id: 'scope-test-1',
    name: 'Production Core Scope',
    targets: ['prod.example.com'],
    allow_local_lab: false,
    authorised_confirmation: true,
    authorised_by: 'CISO Office',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    asset_count: 5,
  },
];

const mockRules: NotificationRule[] = [
  {
    id: 'rule-1',
    name: 'Critical Findings Dispatch',
    description: 'Alert SecOps channel on critical security findings',
    is_enabled: true,
    event_type: 'FINDING_DETECTED',
    scope_id: 'scope-test-1',
    scope_name: 'Production Core Scope',
    conditions: { severities: ['CRITICAL', 'HIGH'] },
    channels: ['webhook'],
    webhook_url: 'https://webhook.site/test-hook',
    email_recipient: null,
    created_at: '2026-10-29T10:00:00Z',
    updated_at: '2026-10-29T10:00:00Z',
  },
];

const mockEvents: NotificationEvent[] = [
  {
    id: 'event-1',
    rule_id: 'rule-1',
    scope_id: 'scope-test-1',
    scope_name: 'Production Core Scope',
    event_type: 'FINDING_DETECTED',
    channel: 'webhook',
    recipient: 'https://webhook.site/test-hook',
    subject: '[ArgusTrace Alert] High Risk Detected',
    message: 'Port 3306 exposed',
    payload: { port: 3306 },
    status: 'SENT',
    error_message: null,
    retry_count: 0,
    max_retries: 3,
    created_at: '2026-10-29T10:05:00Z',
    delivered_at: '2026-10-29T10:05:01Z',
  },
];

const mockIntegrations: IntegrationStatus = {
  live_notifications_enabled: false,
  email_integration: {
    configured: false,
    smtp_host_configured: false,
    smtp_port: null,
    sender_address: 'argustrace@security.internal',
    tls_enabled: true,
  },
  webhook_integration: {
    configured: true,
    timeout_seconds: 5.0,
    ssrf_protection_active: true,
    live_dispatch_enabled: false,
  },
};

const mockAuditLogs: AuditLog[] = [
  {
    id: 'audit-1',
    action: 'EXPORT_GENERATED',
    actor: 'SecOps User',
    entity_type: 'export',
    entity_id: 'inventory_csv',
    details: { format: 'csv', resource: 'inventory', record_count: 5 },
    created_at: '2026-10-29T10:10:00Z',
  },
  {
    id: 'audit-2',
    action: 'NOTIFICATION_RULE_CREATED',
    actor: 'SecOps User',
    entity_type: 'notification_rule',
    entity_id: 'rule-1',
    details: { rule_name: 'Critical Findings Dispatch' },
    created_at: '2026-10-29T10:00:00Z',
  },
];

const mockAuditSummary: AuditSummary = {
  total_events: 2,
  by_action: {
    EXPORT_GENERATED: 1,
    NOTIFICATION_RULE_CREATED: 1,
  },
  by_entity: {
    export: 1,
    notification_rule: 1,
  },
  recent_events: mockAuditLogs,
};

describe('ReportsAlertsView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'getNotificationRules').mockResolvedValue(mockRules);
    vi.spyOn(api, 'getNotificationHistory').mockResolvedValue(mockEvents);
    vi.spyOn(api, 'getIntegrationStatus').mockResolvedValue(mockIntegrations);
    vi.spyOn(api, 'getAuditLogs').mockResolvedValue(mockAuditLogs);
    vi.spyOn(api, 'getAuditSummary').mockResolvedValue(mockAuditSummary);
  });

  it('renders reports export cards with sanitized CSV notices', async () => {
    render(<ReportsAlertsView scopes={mockScopes} />);

    expect(screen.getByText('Reports & Notifications')).toBeDefined();
    expect(screen.getByText('Asset Inventory Dataset')).toBeDefined();
    expect(screen.getByText('Change History Telemetry')).toBeDefined();
    expect(screen.getByText('Findings & Risk Report')).toBeDefined();

    const windowOpenSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const exportCsvBtns = screen.getAllByRole('button', { name: /Export CSV/i });
    expect(exportCsvBtns.length).toBe(3);

    fireEvent.click(exportCsvBtns[0]);
    expect(windowOpenSpy).toHaveBeenCalledWith(expect.stringContaining('/exports/inventory/csv'), '_blank');
  });

  it('switches to Alert Rules tab and displays configured rules', async () => {
    render(<ReportsAlertsView scopes={mockScopes} />);

    const rulesTabBtn = screen.getByRole('button', { name: /Alert Rules/i });
    fireEvent.click(rulesTabBtn);

    await waitFor(() => {
      expect(screen.getByText('Critical Findings Dispatch')).toBeDefined();
      expect(screen.getByText('Webhook: https://webhook.site/test-hook')).toBeDefined();
    });
  });

  it('renders Integration Status with active SSRF protection badge', async () => {
    render(<ReportsAlertsView scopes={mockScopes} />);

    const integrationsTabBtn = screen.getByRole('button', { name: /Integrations & Security/i });
    fireEvent.click(integrationsTabBtn);

    await waitFor(() => {
      expect(screen.getByText('Webhook Integration')).toBeDefined();
      expect(screen.getByText('Active (Cloud Metadata Blocked)')).toBeDefined();
      expect(screen.getByText('Email (SMTP) Integration')).toBeDefined();
    });
  });

  it('renders Audit Trail table and summary metrics', async () => {
    render(<ReportsAlertsView scopes={mockScopes} />);

    const auditTabBtn = screen.getByRole('button', { name: /Audit Trail/i });
    fireEvent.click(auditTabBtn);

    await waitFor(() => {
      expect(screen.getByText('Total Events')).toBeDefined();
      expect(screen.getByText('EXPORT_GENERATED')).toBeDefined();
      expect(screen.getByText('NOTIFICATION_RULE_CREATED')).toBeDefined();
    });
  });
});
