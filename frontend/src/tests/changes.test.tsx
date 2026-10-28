import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ChangesView } from '../components/changes/ChangesView';
import { api } from '../api/client';
import type { AssetChangeRecord, AssetSnapshot, Scope } from '../api/types';

const mockScopes: Scope[] = [
  {
    id: 'scope-1',
    name: 'Production Core',
    targets: ['app.example.com'],
    allow_local_lab: false,
    authorised_confirmation: true,
    authorised_by: 'CISO',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    asset_count: 1
  }
];

const mockChanges: AssetChangeRecord[] = [
  {
    id: 'change-1',
    scope_id: 'scope-1',
    from_snapshot_id: null,
    to_snapshot_id: 'snap-1',
    scan_run_id: 'scan-1',
    asset_identifier: 'app.example.com',
    change_type: 'ASSET_ADDED',
    attribute_name: 'asset',
    previous_value: null,
    new_value: { host_or_ip: 'app.example.com', ip_address: '1.2.3.4' },
    evidence: { context: 'Initial baseline' },
    is_inconclusive: false,
    created_at: new Date().toISOString()
  },
  {
    id: 'change-2',
    scope_id: 'scope-1',
    from_snapshot_id: 'snap-1',
    to_snapshot_id: 'snap-2',
    scan_run_id: 'scan-2',
    asset_identifier: 'unreachable.example.com',
    change_type: 'ASSET_REMOVED',
    attribute_name: 'asset',
    previous_value: { host_or_ip: 'unreachable.example.com' },
    new_value: null,
    evidence: { context: 'Timeout during probe' },
    is_inconclusive: true,
    created_at: new Date().toISOString()
  }
];

const mockSnapshots: AssetSnapshot[] = [
  {
    id: 'snap-1',
    scope_id: 'scope-1',
    scan_run_id: 'scan-1',
    asset_count: 1,
    snapshot_data: [],
    created_at: new Date().toISOString()
  }
];

describe('Phase 2 ChangesView Component', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getChanges').mockResolvedValue(mockChanges);
    vi.spyOn(api, 'getSnapshots').mockResolvedValue(mockSnapshots);
  });

  it('renders metrics cards correctly', async () => {
    render(<ChangesView scopes={mockScopes} />);
    
    await waitFor(() => {
      expect(screen.getByText('Total Changes')).toBeDefined();
      expect(screen.getByText('Added Assets')).toBeDefined();
      expect(screen.getByText('Removed Assets')).toBeDefined();
    });
  });

  it('renders change records with appropriate badges and inconclusive flags', async () => {
    render(<ChangesView scopes={mockScopes} />);

    await waitFor(() => {
      expect(screen.getByText('app.example.com')).toBeDefined();
      expect(screen.getByText('ASSET ADDED')).toBeDefined();
      expect(screen.getByText('INCONCLUSIVE')).toBeDefined();
    });
  });

  it('switches to baseline snapshots tab', async () => {
    render(<ChangesView scopes={mockScopes} />);

    await waitFor(() => {
      const snapTabBtn = screen.getByRole('button', { name: /Baseline Snapshots Archive/i });
      fireEvent.click(snapTabBtn);
    });

    await waitFor(() => {
      expect(screen.getByText(/IMMUTABLE BASELINE/i)).toBeDefined();
    });
  });
});
