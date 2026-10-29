from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# Target Validation Schemas
class TargetValidationRequest(BaseModel):
    targets: List[str]
    allow_local_lab: bool = False

class TargetValidationItem(BaseModel):
    raw: str
    sanitized: str
    is_valid: bool
    error: Optional[str] = None

class TargetValidationResponse(BaseModel):
    items: List[TargetValidationItem]
    all_valid: bool

# Scope Schemas
class ScopeBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    targets: List[str] = Field(..., min_length=1)
    allow_local_lab: bool = False
    authorised_confirmation: bool = False
    authorised_by: str = Field(..., min_length=2, max_length=120)

class ScopeCreate(ScopeBase):
    pass

class ScopeUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    targets: Optional[List[str]] = None
    allow_local_lab: Optional[bool] = None
    authorised_confirmation: Optional[bool] = None
    authorised_by: Optional[str] = None

class ScopeOut(ScopeBase):
    id: str
    created_at: datetime
    updated_at: datetime
    asset_count: int = 0
    last_scan_status: Optional[str] = None
    last_scan_time: Optional[datetime] = None

    model_config = {"from_attributes": True}

# Scan Schemas
class ScanConfig(BaseModel):
    ports: Optional[List[int]] = None
    enable_dns: bool = True
    enable_ports: bool = True
    enable_http: bool = True
    enable_tls: bool = True

class ScanCreate(BaseModel):
    scope_id: str
    config: Optional[ScanConfig] = None

class ScanOut(BaseModel):
    id: str
    scope_id: str
    scope_name: Optional[str] = None
    status: str
    config: Dict[str, Any]
    targets_total: int
    targets_scanned: int
    assets_discovered_count: int
    findings_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    logs: List[Dict[str, Any]] = []

    model_config = {"from_attributes": True}

# Asset Schemas
class AssetOut(BaseModel):
    id: str
    scope_id: str
    scan_run_id: Optional[str] = None
    host_or_ip: str
    asset_type: str
    ip_address: Optional[str] = None
    status: str
    open_ports: List[Dict[str, Any]] = []
    dns_records: Dict[str, Any] = {}
    http_summary: Dict[str, Any] = {}
    tls_summary: Dict[str, Any] = {}
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}

# Finding Schemas
class FindingOut(BaseModel):
    id: str
    scope_id: Optional[str] = None
    scan_run_id: str
    asset_id: Optional[str] = None
    asset_host: Optional[str] = None
    finding_type: str
    title: str
    description: Optional[str] = None
    severity: str
    confidence: str = "CONFIRMED"
    review_status: str = "OPEN"
    remediation: Optional[str] = None
    evidence: Dict[str, Any] = {}
    status_history: List[Dict[str, Any]] = []
    dedup_key: Optional[str] = None
    first_detected: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}

class FindingStatusUpdate(BaseModel):
    review_status: str
    note: Optional[str] = None

# Stats / Overview Schemas
class StatsOverview(BaseModel):
    total_scopes: int
    total_assets: int
    active_assets: int
    unresponsive_assets: int
    total_scans: int
    last_scan: Optional[ScanOut] = None
    asset_types_distribution: Dict[str, int]
    top_open_ports: List[Dict[str, Any]]
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int] = {}
    findings_by_status: Dict[str, int] = {}
    total_changes: int = 0
    changes_by_type: Dict[str, int] = {}
    discovery_timeline: List[Dict[str, Any]] = []
    changes_timeline: List[Dict[str, Any]] = []

# Phase 2 Snapshot & Change Schemas
class SnapshotOut(BaseModel):
    id: str
    scope_id: str
    scan_run_id: str
    asset_count: int
    snapshot_data: List[Dict[str, Any]] = []
    created_at: datetime

    model_config = {"from_attributes": True}

class ChangeRecordOut(BaseModel):
    id: str
    scope_id: str
    from_snapshot_id: Optional[str] = None
    to_snapshot_id: str
    scan_run_id: str
    asset_identifier: str
    change_type: str
    attribute_name: str
    previous_value: Optional[Any] = None
    new_value: Optional[Any] = None
    evidence: Dict[str, Any] = {}
    is_inconclusive: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}

# Phase 5: Notifications, Reports & Audit Trail Schemas

class NotificationRuleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    description: Optional[str] = None
    is_enabled: bool = True
    event_type: str = Field(..., description="ASSET_DISCOVERED, ASSET_CHANGED, or FINDING_DETECTED")
    scope_id: Optional[str] = None
    conditions: Dict[str, Any] = Field(default_factory=dict)
    channels: List[str] = Field(default_factory=lambda: ["webhook"])
    webhook_url: Optional[str] = None
    email_recipient: Optional[str] = None

class NotificationRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None
    channels: Optional[List[str]] = None
    webhook_url: Optional[str] = None
    email_recipient: Optional[str] = None

class NotificationRuleOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    is_enabled: bool
    event_type: str
    scope_id: Optional[str] = None
    scope_name: Optional[str] = None
    conditions: Dict[str, Any] = {}
    channels: List[str] = []
    webhook_url: Optional[str] = None
    email_recipient: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

class NotificationEventOut(BaseModel):
    id: str
    rule_id: Optional[str] = None
    scope_id: Optional[str] = None
    scope_name: Optional[str] = None
    event_type: str
    channel: str
    recipient: str
    subject: str
    message: str
    payload: Dict[str, Any] = {}
    status: str
    error_message: Optional[str] = None
    retry_count: int
    max_retries: int
    created_at: datetime
    delivered_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class AuditLogOut(BaseModel):
    id: str
    action: str
    actor: str
    entity_type: str
    entity_id: Optional[str] = None
    details: Dict[str, Any] = {}
    created_at: datetime

    model_config = {"from_attributes": True}

class AuditSummaryOut(BaseModel):
    total_events: int
    by_action: Dict[str, int] = {}
    by_entity: Dict[str, int] = {}
    recent_events: List[AuditLogOut] = []

class IntegrationStatusOut(BaseModel):
    live_notifications_enabled: bool
    email_integration: Dict[str, Any]
    webhook_integration: Dict[str, Any]

