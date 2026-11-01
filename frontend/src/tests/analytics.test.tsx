import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { SecurityAnalytics } from '../components/analytics/SecurityAnalytics';
import { AssetDetailDrawer } from '../components/inventory/AssetDetailDrawer';
import type { StatsOverview, DiscoveredAsset, ScanFinding } from '../api/types';

const mockStats: StatsOverview = {
  total_scopes: 2,
  total_assets: 12,
  active_assets: 10,
  unresponsive_assets: 2,
  total_scans: 4,
  asset_types_distribution: {
    domain: 6,
    ipv4: 4,
    ipv6: 2,
  },
  top_open_ports: [],
  findings_by_type: {},
  findings_by_severity: {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 1,
    LOW: 1,
  },
  total_changes: 8,
  changes_by_type: {
    ASSET_ADDED: 5,
    ASSET_REMOVED: 1,
  },
  discovery_timeline: [
    {
      id: 'scan-1',
      scope_name: 'Corp Internal',
      status: 'COMPLETED',
      targets_scanned: 3,
      assets_discovered: 8,
      findings_count: 3,
      started_at: '2026-10-28T09:00:00Z',
    },
    {
      id: 'scan-2',
      scope_name: 'Corp DMZ',
      status: 'COMPLETED',
      targets_scanned: 2,
      assets_discovered: 4,
      findings_count: 2,
      started_at: '2026-10-28T14:00:00Z',
    },
  ],
  changes_timeline: [
    {
      date: '2026-10-27',
      total: 3,
      added: 2,
      removed: 0,
      modified: 1,
    },
    {
      date: '2026-10-28',
      total: 5,
      added: 3,
      removed: 1,
      modified: 1,
    },
  ],
};

const mockAsset: DiscoveredAsset = {
  id: 'asset-42',
  scope_id: 'scope-1',
  host_or_ip: 'api.corp.internal',
  asset_type: 'domain',
  ip_address: '10.0.1.50',
  first_seen: '2026-10-28T08:00:00Z',
  last_seen: '2026-10-28T12:00:00Z',
  status: 'active',
  dns_records: {
    A: ['10.0.1.50'],
    CNAME: ['edge.corp.internal'],
  },
  open_ports: [
    { port: 443, state: 'open', service: 'https', banner: 'nginx/1.24' },
    { port: 80, state: 'open', service: 'http' },
  ],
  http_metadata: {
    status_code: 200,
    server: 'nginx/1.24',
    title: 'Internal API Gateway',
    content_type: 'application/json',
    content_length: 512,
  },
  tls_metadata: {
    subject: 'CN=api.corp.internal',
    issuer: 'Corp Intermediate CA',
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2027-01-01T00:00:00Z',
    days_remaining: 65,
    is_expired: false,
  },
};

const mockFindings: ScanFinding[] = [
  {
    id: 'f-1',
    scope_id: 'scope-1',
    scan_run_id: 'scan-1',
    asset_id: 'asset-42',
    asset_host: 'api.corp.internal',
    finding_type: 'TLS',
    title: 'TLS Certificate Approaching Expiration',
    description: 'X.509 certificate expires in 65 days.',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    review_status: 'OPEN',
    remediation: 'Schedule standard certificate rotation before 30-day grace period.',
    evidence: { days_remaining: 65 },
    status_history: [],
    dedup_key: 'scope-1:asset-42:TLS:expiry',
    first_detected: '2026-10-28T08:00:00Z',
    last_observed: '2026-10-28T12:00:00Z',
    created_at: '2026-10-28T08:00:00Z',
  },
];

describe('SecurityAnalytics Component', () => {
  it('renders interactive security analytics charts with correct metric counts', () => {
    const handleNavigate = vi.fn();
    render(<SecurityAnalytics stats={mockStats} onNavigateTab={handleNavigate} />);

    // Check headings
    expect(screen.getByText(/Security Analytics & Attack Surface Telemetry/i)).toBeDefined();
    expect(screen.getByText('Finding Severity Distribution')).toBeDefined();
    expect(screen.getByText('Asset Categories Breakdown')).toBeDefined();
    expect(screen.getByText('Asset Changes & Diff Velocity')).toBeDefined();

    // Check data points from discovery timeline
    expect(screen.getByText('#1')).toBeDefined();
    expect(screen.getByText('#2')).toBeDefined();
    fireEvent.mouseEnter(screen.getByText('#1').parentElement!);
    expect(screen.getByText('Corp Internal')).toBeDefined();

    // Check severity counts
    expect(screen.getByText('CRITICAL')).toBeDefined();
    expect(screen.getByText('HIGH')).toBeDefined();

    // Check navigation callback when clicking severity segment
    const critBadge = screen.getByText('CRITICAL');
    fireEvent.click(critBadge);
    expect(handleNavigate).toHaveBeenCalledWith('findings');
  });

  it('handles empty stats and zero timelines without errors', () => {
    const emptyStats: StatsOverview = {
      total_scopes: 0,
      total_assets: 0,
      active_assets: 0,
      unresponsive_assets: 0,
      total_scans: 0,
      asset_types_distribution: {},
      top_open_ports: [],
      findings_by_type: {},
      findings_by_severity: {},
      total_changes: 0,
      changes_by_type: {},
      discovery_timeline: [],
      changes_timeline: [],
    };

    render(<SecurityAnalytics stats={emptyStats} />);

    expect(screen.getByText('No discovery runs recorded yet.')).toBeDefined();
    expect(screen.getByText('Zero baseline modifications detected.')).toBeDefined();
    expect(screen.getByText('Zero security findings observed across current scopes.')).toBeDefined();
    expect(screen.getByText('No assets inventory recorded.')).toBeDefined();
  });
});

describe('AssetDetailDrawer Component', () => {
  it('renders asset details, open ports, DNS, HTTP, and linked findings', () => {
    const handleClose = vi.fn();
    render(
      <AssetDetailDrawer
        asset={mockAsset}
        findings={mockFindings}
        isOpen={true}
        onClose={handleClose}
      />
    );

    // Host identity
    expect(screen.getByText('api.corp.internal')).toBeDefined();
    expect(screen.getByText('10.0.1.50')).toBeDefined();

    // Risk posture summary
    expect(screen.getByText('Asset Security Risk Posture')).toBeDefined();

    // Open ports
    expect(screen.getByText('Port 443')).toBeDefined();
    expect(screen.getByText('Port 80')).toBeDefined();

    // Switch to Findings tab
    const findingsTab = screen.getByText(/Findings \(1\)/i);
    fireEvent.click(findingsTab);

    // Finding title and remediation
    expect(screen.getByText('TLS Certificate Approaching Expiration')).toBeDefined();
    expect(screen.getByText(/Schedule standard certificate rotation/i)).toBeDefined();
  });
});
