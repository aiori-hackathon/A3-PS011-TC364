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

export type FindingSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL'
  | 'INFO'
  | 'NOTICE'
  | 'WARNING';

export type FindingConfidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ReviewStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'IN_REVIEW'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export interface FindingStatusHistoryItem {
  status: ReviewStatus;
  previous_status?: ReviewStatus;
  timestamp: string;
  note?: string | null;
}

export interface ScanFinding {
  id: string;
  scope_id?: string | null;
  scan_run_id: string;
  asset_id?: string | null;
  asset_host?: string | null;
  finding_type: 'DNS' | 'PORT' | 'HTTP' | 'TLS';
  title: string;
  description?: string | null;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  review_status: ReviewStatus;
  remediation?: string | null;
  evidence: Record<string, any>;
  status_history: FindingStatusHistoryItem[];
  dedup_key?: string | null;
  first_detected: string;
  last_observed: string;
  created_at: string;
}

export interface FindingsCountSummary {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
}

export interface DiscoveryTimelineItem {
  id: string;
  scope_name: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'FAILED';
  targets_scanned: number;
  assets_discovered: number;
  findings_count: number;
  started_at: string | null;
}

export interface ChangesTimelineItem {
  date: string;
  total: number;
  added: number;
  removed: number;
  modified: number;
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
  findings_by_severity?: Record<string, number>;
  findings_by_status?: Record<string, number>;
  total_changes?: number;
  changes_by_type?: Record<string, number>;
  discovery_timeline?: DiscoveryTimelineItem[];
  changes_timeline?: ChangesTimelineItem[];
}

export type ChangeType =
  | 'ASSET_ADDED'
  | 'ASSET_REMOVED'
  | 'IP_CHANGED'
  | 'DNS_CHANGED'
  | 'PORT_OPENED'
  | 'PORT_CLOSED'
  | 'HTTP_STATUS_CHANGED'
  | 'TLS_CHANGED';

export interface AssetSnapshot {
  id: string;
  scope_id: string;
  scan_run_id: string;
  asset_count: number;
  snapshot_data: Array<{
    asset_id?: string;
    host_or_ip: string;
    asset_type: string;
    ip_address?: string | null;
    status: string;
    open_ports: OpenPort[];
    dns_records: DnsRecords;
    http_summary: HttpSummary;
    tls_summary: TlsSummary;
    observed_at: string;
  }>;
  created_at: string;
}

export interface AssetChangeRecord {
  id: string;
  scope_id: string;
  from_snapshot_id?: string | null;
  to_snapshot_id: string;
  scan_run_id: string;
  asset_identifier: string;
  change_type: ChangeType;
  attribute_name: string;
  previous_value?: any;
  new_value?: any;
  evidence: Record<string, any>;
  is_inconclusive: boolean;
  created_at: string;
}
