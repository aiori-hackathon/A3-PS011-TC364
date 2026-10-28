import type {
  Scope,
  ScopeCreatePayload,
  TargetValidationResponse,
  ScanRun,
  ScanConfig,
  DiscoveredAsset,
  ScanFinding,
  StatsOverview
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
  deleteAsset: (id: string) =>
    request<void>(`/assets/${id}`, {
      method: 'DELETE',
    }),

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
