export interface Scope {
  id: string;
  name: string;
  description?: string;
  targets: string[];
  allow_local_lab: boolean;
  authorised_confirmation: boolean;
  authorised_by: string;
  created_at: string;
  updated_at: string;
  asset_count: number;
  last_scan_status?: string | null;
  last_scan_time?: string | null;
}

export interface ScopeCreatePayload {
  name: string;
  description?: string;
  targets: string[];
  allow_local_lab: boolean;
  authorised_confirmation: boolean;
  authorised_by: string;
}

export interface TargetValidationItem {
  raw: string;
  sanitized: string;
  is_valid: boolean;
  error?: string | null;
}

export interface TargetValidationResponse {
  items: TargetValidationItem[];
  all_valid: boolean;
}

export interface ScanConfig {
  ports?: number[];
  enable_dns: boolean;
  enable_ports: boolean;
  enable_http: boolean;
  enable_tls: boolean;
}

export interface ScanRun {
  id: string;
  scope_id: string;
  scope_name?: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'FAILED';
  config: ScanConfig;
  targets_total: number;
  targets_scanned: number;
  assets_discovered_count: number;
  findings_count: number;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  logs: Array<{
    timestamp: string;
    level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS';
    message: string;
  }>;
}

export interface OpenPort {
  port: number;
  status: string;
  service: string;
  latency_ms: number;
  banner?: string | null;
}

export interface DnsRecords {
  A?: string[];
  AAAA?: string[];
  CNAME?: string[];
  MX?: string[];
  NS?: string[];
  TXT?: string[];
  PTR?: string[];
  error?: string | null;
}

export interface HttpSummary {
  reachable?: boolean;
  status_code?: number;
  scheme?: string;
  port?: number;
  url?: string;
  final_url?: string | null;
  redirect_count?: number;
  redirect_blocked_reason?: string | null;
  server?: string | null;
  content_type?: string | null;
  title?: string | null;
  latency_ms?: number;
  headers?: Record<string, string>;
}

export interface TlsSummary {
  has_tls?: boolean;
  port?: number;
  subject_cn?: string;
  subject_org?: string;
  issuer_cn?: string;
  issuer_org?: string;
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number | null;
  is_expired?: boolean;
  sans?: string[];
  cipher?: string | null;
  tls_version?: string | null;
  serial_number?: string | null;
}

export interface DiscoveredAsset {
  id: string;
  scope_id: string;
  scan_run_id?: string | null;
  host_or_ip: string;
  asset_type: 'domain' | 'subdomain' | 'ipv4' | 'ipv6';
  ip_address?: string | null;
  status: 'ACTIVE' | 'UNRESPONSIVE' | 'UNRESOLVED';
  open_ports: OpenPort[];
  dns_records: DnsRecords;
  http_summary: HttpSummary;
  tls_summary: TlsSummary;
  first_seen: string;
  last_seen: string;
}

export interface ScanFinding {
  id: string;
  scan_run_id: string;
  asset_id?: string | null;
  finding_type: 'DNS' | 'PORT' | 'HTTP' | 'TLS';
  title: string;
  severity: 'INFO' | 'NOTICE' | 'WARNING';
  evidence: Record<string, any>;
  created_at: string;
}

export interface StatsOverview {
  total_scopes: number;
  total_assets: number;
  active_assets: number;
  unresponsive_assets: number;
  total_scans: number;
  last_scan?: ScanRun | null;
  asset_types_distribution: Record<string, number>;
  top_open_ports: Array<{ port: number; service: string; count: number }>;
  findings_by_type: Record<string, number>;
}
