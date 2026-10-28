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
    scan_run_id: str
    asset_id: Optional[str] = None
    finding_type: str
    title: str
    severity: str
    evidence: Dict[str, Any] = {}
    created_at: datetime

    model_config = {"from_attributes": True}

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
    total_changes: int = 0
    changes_by_type: Dict[str, int] = {}

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
