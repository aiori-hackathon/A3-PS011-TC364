import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { FindingsView } from '../components/findings/FindingsView';
import { api } from '../api/client';
import type { ScanFinding, Scope } from '../api/types';

const mockScopes: Scope[] = [
  {
    id: 'scope-test-1',
    name: 'Authorized Prod Scope',
    targets: ['secops.corp.internal'],
    allow_local_lab: true,
    authorised_confirmation: true,
    authorised_by: 'SecOps Team',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    asset_count: 2,
  },
];

const mockFindings: ScanFinding[] = [
  {
    id: 'finding-1',
    scope_id: 'scope-test-1',
    scan_run_id: 'scan-101',
    asset_id: 'asset-1',
    asset_host: 'db.corp.internal',
    finding_type: 'PORT',
    title: 'Exposed Database Service: MySQL (3306)',
    description: 'Sensitive database service TCP port 3306 (MySQL) was observed listening on network boundary.',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    review_status: 'OPEN',
    remediation: 'Restrict port 3306 via firewall or bind to loopback/private VPC subnet.',
    evidence: { port: 3306, service: 'MySQL', status: 'OPEN' },
    status_history: [],
    dedup_key: 'scope-test-1:asset-1:PORT:3306',
    first_detected: '2026-10-28T10:00:00.000Z',
    last_observed: '2026-10-28T12:00:00.000Z',
    created_at: '2026-10-28T10:00:00.000Z',
  },
  {
    id: 'finding-2',
    scope_id: 'scope-test-1',
    scan_run_id: 'scan-101',
    asset_id: 'asset-2',
    asset_host: 'legacy.corp.internal',
    finding_type: 'TLS',
    title: 'TLS Certificate Expired',
    description: 'The TLS X.509 certificate expired 15 days ago.',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    review_status: 'OPEN',
    remediation: 'Renew or replace the expired certificate through ACME or organizational PKI.',
    evidence: { days_remaining: -15, is_expired: true },
    status_history: [],
    dedup_key: 'scope-test-1:asset-2:TLS:expiry',
    first_detected: '2026-10-28T10:00:00.000Z',
    last_observed: '2026-10-28T12:00:00.000Z',
    created_at: '2026-10-28T10:00:00.000Z',
  },
];

describe('FindingsView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, 'getFindings').mockResolvedValue(mockFindings);
  });

  it('renders findings overview metrics and finding table items', async () => {
    render(<FindingsView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('Exposed Database Service: MySQL (3306)')).toBeDefined();
      expect(screen.getByText('TLS Certificate Expired')).toBeDefined();
    });

    expect(screen.getByText('db.corp.internal')).toBeDefined();
    expect(screen.getByText('legacy.corp.internal')).toBeDefined();
  });

  it('filters findings by search term', async () => {
    render(<FindingsView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('TLS Certificate Expired')).toBeDefined();
    });

    const searchInput = screen.getByPlaceholderText(/search findings/i);
    fireEvent.change(searchInput, { target: { value: 'MySQL' } });

    await waitFor(() => {
      expect(api.getFindings).toHaveBeenCalledWith(
        expect.objectContaining({ search: 'MySQL' })
      );
    });
  });

  it('opens finding detail modal with explainable rationale and submits a status update', async () => {
    const updateSpy = vi.spyOn(api, 'updateFindingStatus').mockResolvedValue({
      ...mockFindings[0],
      review_status: 'IN_REVIEW',
      status_history: [
        {
          status: 'IN_REVIEW',
          previous_status: 'OPEN',
          timestamp: new Date().toISOString(),
          note: 'Ops team assessing internal exposure',
        },
      ],
    });

    render(<FindingsView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('Exposed Database Service: MySQL (3306)')).toBeDefined();
    });

    // Click the Review button for MySQL finding
    const reviewButtons = screen.getAllByRole('button', { name: /review/i });
    fireEvent.click(reviewButtons[0]);

    // Check modal displays explainable rationale
    await waitFor(() => {
      expect(screen.getByText(/Explainable Risk Rationale/i)).toBeDefined();
      expect(
        screen.getAllByText(/Sensitive database service TCP port 3306/i).length
      ).toBeGreaterThanOrEqual(1);
      expect(
        screen.getByText(/Recommended Remediation/i)
      ).toBeDefined();
    });

    // Select new status IN_REVIEW and enter a review note
    const statusSelect = screen.getByLabelText(/new review status/i);
    fireEvent.change(statusSelect, { target: { value: 'IN_REVIEW' } });

    const noteInput = screen.getByPlaceholderText(/e\.g\. Authorized internal database listener/i);
    fireEvent.change(noteInput, { target: { value: 'Ops team assessing internal exposure' } });

    // Submit update
    const submitBtn = screen.getByRole('button', { name: /apply status update/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith(
        'finding-1',
        'IN_REVIEW',
        'Ops team assessing internal exposure'
      );
    });
  });
});
