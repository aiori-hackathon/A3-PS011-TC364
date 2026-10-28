import type {
  Scope,
  ScopeCreatePayload,
  TargetValidationResponse,
  ScanRun,
  ScanConfig,
  DiscoveredAsset,
  ScanFinding,
  StatsOverview,
  AssetSnapshot,
  AssetChangeRecord,
  FindingsCountSummary,
} from './types';

const API_BASE = '/api';

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: () => request<{ status: string; service: string; phase: string }>('/health'),

  // Scopes
  getScopes: () => request<Scope[]>('/scopes'),
  getScope: (id: string) => request<Scope>(`/scopes/${id}`),
  createScope: (data: ScopeCreatePayload) =>
    request<Scope>('/scopes', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteScope: (id: string) =>
    request<void>(`/scopes/${id}`, {
      method: 'DELETE',
    }),
  validateTargets: (targets: string[], allowLocalLab: boolean) =>
    request<TargetValidationResponse>('/scopes/validate-targets', {
      method: 'POST',
      body: JSON.stringify({ targets, allow_local_lab: allowLocalLab }),
    }),

  // Scans
  getScans: (scopeId?: string) =>
    request<ScanRun[]>(scopeId ? `/scans?scope_id=${encodeURIComponent(scopeId)}` : '/scans'),
  getScan: (id: string) => request<ScanRun>(`/scans/${id}`),
  launchScan: (scopeId: string, config?: ScanConfig) =>
    request<ScanRun>('/scans', {
      method: 'POST',
      body: JSON.stringify({ scope_id: scopeId, config }),
    }),
  cancelScan: (id: string) =>
    request<{ message: string; scan_id: string }>(`/scans/${id}/cancel`, {
      method: 'POST',
    }),
  getScanFindings: (id: string) => request<ScanFinding[]>(`/scans/${id}/findings`),

  // Assets
  getAssets: (params?: {
    scope_id?: string;
    status?: string;
    asset_type?: string;
    search?: string;
    port?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.scope_id) searchParams.append('scope_id', params.scope_id);
    if (params?.status) searchParams.append('status', params.status);
    if (params?.asset_type) searchParams.append('asset_type', params.asset_type);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.port) searchParams.append('port', params.port.toString());
    const query = searchParams.toString();
    return request<DiscoveredAsset[]>(query ? `/assets?${query}` : '/assets');
  },
  getAsset: (id: string) => request<DiscoveredAsset>(`/assets/${id}`),
  getAssetFindings: (id: string) => request<ScanFinding[]>(`/assets/${id}/findings`),
  getAssetChanges: (id: string) => request<AssetChangeRecord[]>(`/assets/${id}/changes`),
  deleteAsset: (id: string) =>
    request<void>(`/assets/${id}`, {
      method: 'DELETE',
    }),

  // Phase 2: Changes & Snapshots
  getChanges: (params?: {
    scope_id?: string;
    change_type?: string;
    asset?: string;
    is_inconclusive?: boolean;
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.scope_id) searchParams.append('scope_id', params.scope_id);
    if (params?.change_type) searchParams.append('change_type', params.change_type);
    if (params?.asset) searchParams.append('asset', params.asset);
    if (params?.is_inconclusive !== undefined) searchParams.append('is_inconclusive', params.is_inconclusive.toString());
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    const query = searchParams.toString();
    return request<AssetChangeRecord[]>(query ? `/changes?${query}` : '/changes');
  },
  getChange: (id: string) => request<AssetChangeRecord>(`/changes/${id}`),
  getSnapshots: (scopeId?: string) =>
    request<AssetSnapshot[]>(scopeId ? `/snapshots?scope_id=${encodeURIComponent(scopeId)}` : '/snapshots'),
  getSnapshot: (id: string) => request<AssetSnapshot>(`/snapshots/${id}`),

  // Phase 3: Findings & Risk Classification
  getFindings: (params?: {
    scope_id?: string;
    asset_id?: string;
    severity?: string;
    review_status?: string;
    finding_type?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.scope_id) searchParams.append('scope_id', params.scope_id);
    if (params?.asset_id) searchParams.append('asset_id', params.asset_id);
    if (params?.severity) searchParams.append('severity', params.severity);
    if (params?.review_status) searchParams.append('review_status', params.review_status);
    if (params?.finding_type) searchParams.append('finding_type', params.finding_type);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    const query = searchParams.toString();
    return request<ScanFinding[]>(query ? `/findings?${query}` : '/findings');
  },
  getFinding: (id: string) => request<ScanFinding>(`/findings/${id}`),
  updateFindingStatus: (id: string, review_status: string, note?: string) =>
    request<ScanFinding>(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ review_status, note }),
    }),
  getFindingsCounts: (scopeId?: string) =>
    request<FindingsCountSummary>(
      scopeId ? `/findings/summary/counts?scope_id=${encodeURIComponent(scopeId)}` : '/findings/summary/counts'
    ),

  // Stats & Demo
  getStatsOverview: () => request<StatsOverview>('/stats/overview'),
  seedDemoMode: () =>
    request<{ message: string; scope_id: string; assets_count: number }>('/demo/seed', {
      method: 'POST',
    }),
  clearDemoMode: () =>
    request<{ message: string }>('/demo/clear', {
      method: 'POST',
    }),
};
