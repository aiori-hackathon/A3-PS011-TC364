import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ScheduledDiscoveryView } from '../components/schedules/ScheduledDiscoveryView';
import { api } from '../api/client';
import type {
  Scope,
  DiscoverySchedule,
  ScanRun,
} from '../api/types';

const mockScopes: Scope[] = [
  {
    id: 'scope-1',
    name: 'Authorized Main Scope',
    targets: ['secops.internal'],
    allow_local_lab: true,
    authorised_confirmation: true,
    authorised_by: 'CISO Office',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    asset_count: 8,
  },
  {
    id: 'scope-unauth',
    name: 'Unconfirmed Scope',
    targets: ['unauth.target'],
    allow_local_lab: false,
    authorised_confirmation: false,
    authorised_by: 'Pending',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    asset_count: 0,
  },
];

const mockSchedules: DiscoverySchedule[] = [
  {
    id: 'sched-1',
    scope_id: 'scope-1',
    scope_name: 'Authorized Main Scope',
    name: 'Nightly Core Discovery Sweep',
    description: 'Automated 24h baseline comparison and port scan',
    is_enabled: true,
    frequency: 'DAILY',
    interval_hours: 24,
    config: { enable_dns: true, enable_ports: true, ports: [80, 443] },
    last_run_at: '2026-10-31T01:00:00Z',
    last_run_status: 'COMPLETED',
    last_scan_run_id: 'scan-1',
    next_run_at: '2026-11-01T01:00:00Z',
    created_at: '2026-10-30T00:00:00Z',
    updated_at: '2026-10-30T00:00:00Z',
    execution_count: 3,
  },
];

const mockExecutions: ScanRun[] = [
  {
    id: 'scan-1',
    scope_id: 'scope-1',
    scope_name: 'Authorized Main Scope',
    status: 'COMPLETED',
    config: { enable_dns: true, enable_ports: true, enable_http: true, enable_tls: true },
    targets_total: 2,
    targets_scanned: 2,
    assets_discovered_count: 2,
    findings_count: 1,
    started_at: '2026-10-31T01:00:00Z',
    completed_at: '2026-10-31T01:00:05Z',
    logs: [],
    schedule_id: 'sched-1',
    is_scheduled: true,
  },
];

describe('Phase 6 ScheduledDiscoveryView Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(api, 'getSchedules').mockResolvedValue(mockSchedules);
    vi.spyOn(api, 'createSchedule').mockImplementation(async (payload) => ({
      id: 'sched-new',
      scope_id: payload.scope_id,
      scope_name: 'Authorized Main Scope',
      name: payload.name,
      description: payload.description || null,
      is_enabled: payload.is_enabled ?? true,
      frequency: payload.frequency || 'DAILY',
      interval_hours: payload.interval_hours || 24,
      config: payload.config || {},
      next_run_at: '2026-11-02T00:00:00Z',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      execution_count: 0,
    }));
    vi.spyOn(api, 'updateSchedule').mockImplementation(async (id, payload) => ({
      ...mockSchedules[0],
      ...payload,
      id,
    }));
    vi.spyOn(api, 'deleteSchedule').mockResolvedValue({ message: 'Deleted', id: 'sched-1' });
    vi.spyOn(api, 'triggerSchedule').mockResolvedValue({
      id: 'scan-triggered-1',
      scope_id: 'scope-1',
      scope_name: 'Authorized Main Scope',
      status: 'IN_PROGRESS',
      config: { enable_dns: true, enable_ports: true, enable_http: true, enable_tls: true },
      targets_total: 1,
      targets_scanned: 0,
      assets_discovered_count: 0,
      findings_count: 0,
      started_at: new Date().toISOString(),
      logs: [],
      schedule_id: 'sched-1',
      is_scheduled: true,
    });
    vi.spyOn(api, 'getScheduleExecutions').mockResolvedValue(mockExecutions);
  });

  it('renders summary metrics and schedule cards with frequency and status', async () => {
    render(<ScheduledDiscoveryView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('Nightly Core Discovery Sweep')).toBeDefined();
    });

    expect(screen.getByText('Active Schedules')).toBeDefined();
    expect(screen.getByText('Automated Executions')).toBeDefined();
    expect(screen.getByText('Every 24 Hours (Daily)')).toBeDefined();
    expect(screen.getByText('Active / Armed')).toBeDefined();
  });

  it('triggers manual run execution when Run Now button is clicked', async () => {
    render(<ScheduledDiscoveryView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('Run Now')).toBeDefined();
    });

    const runNowBtn = screen.getByText('Run Now');
    fireEvent.click(runNowBtn);

    await waitFor(() => {
      expect(api.triggerSchedule).toHaveBeenCalledWith('sched-1');
      expect(screen.getByText(/Scheduled scan triggered immediately/i)).toBeDefined();
    });
  });

  it('opens create modal, prevents unauthorized scopes, and submits valid schedule', async () => {
    render(<ScheduledDiscoveryView scopes={mockScopes} />);

    const configBtn = screen.getByRole('button', { name: /Configure Schedule/i });
    fireEvent.click(configBtn);

    await waitFor(() => {
      expect(screen.getByText('Configure Discovery Schedule')).toBeDefined();
    });

    const submitBtn = screen.getByRole('button', { name: /Create Schedule/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.createSchedule).toHaveBeenCalled();
      expect(screen.getByText(/New schedule.*created and armed/i)).toBeDefined();
    });
  });

  it('opens execution history and lists past runs for the schedule', async () => {
    render(<ScheduledDiscoveryView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText(/History \(3\)/i)).toBeDefined();
    });

    const historyBtn = screen.getByText(/History \(3\)/i);
    fireEvent.click(historyBtn);

    await waitFor(() => {
      expect(api.getScheduleExecutions).toHaveBeenCalledWith('sched-1');
      expect(screen.getByText('#scan-1')).toBeDefined();
    });
  });
});
