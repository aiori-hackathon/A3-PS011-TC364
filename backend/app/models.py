import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, DateTime, Text, ForeignKey, JSON, Index
)
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Scope(Base):
    __tablename__ = "scopes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    targets = Column(JSON, nullable=False, default=list) # List of valid domains/IPs
    allow_local_lab = Column(Boolean, default=False, nullable=False)
    authorised_confirmation = Column(Boolean, default=False, nullable=False)
    authorised_by = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    scans = relationship("ScanRun", back_populates="scope", cascade="all, delete-orphan")
    assets = relationship("DiscoveredAsset", back_populates="scope", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scopes_name", "name"),
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scope_id = Column(String(36), ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(30), default="PENDING", nullable=False) # PENDING, IN_PROGRESS, COMPLETED, CANCELLED, FAILED
    config = Column(JSON, nullable=False, default=dict) # ports, timeouts, flags
    targets_total = Column(Integer, default=0, nullable=False)
    targets_scanned = Column(Integer, default=0, nullable=False)
    assets_discovered_count = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    logs = Column(JSON, default=list, nullable=False) # list of log entries

    # Relationships
    scope = relationship("Scope", back_populates="scans")
    assets = relationship("DiscoveredAsset", back_populates="scan_run")
    findings = relationship("ScanFinding", back_populates="scan_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_status", "status"),
        Index("idx_scans_scope_status", "scope_id", "status"),
    )


class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scope_id = Column(String(36), ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_run_id = Column(String(36), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    
    host_or_ip = Column(String(255), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False) # domain, subdomain, ipv4, ipv6
    ip_address = Column(String(64), nullable=True)
    status = Column(String(50), default="ACTIVE", nullable=False) # ACTIVE, UNRESPONSIVE, UNRESOLVED
    
    open_ports = Column(JSON, default=list, nullable=False)
    dns_records = Column(JSON, default=dict, nullable=False)
    http_summary = Column(JSON, default=dict, nullable=False)
    tls_summary = Column(JSON, default=dict, nullable=False)
    
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scope = relationship("Scope", back_populates="assets")
    scan_run = relationship("ScanRun", back_populates="assets")
    findings = relationship("ScanFinding", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_assets_scope_host", "scope_id", "host_or_ip", unique=True),
        Index("idx_assets_status", "status"),
    )


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_run_id = Column(String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=True, index=True)
    
    finding_type = Column(String(50), nullable=False) # DNS, PORT, HTTP, TLS
    title = Column(String(255), nullable=False)
    severity = Column(String(20), default="INFO", nullable=False) # INFO, NOTICE, WARNING
    evidence = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="findings")
    asset = relationship("DiscoveredAsset", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_type", "scan_run_id", "finding_type"),
    )
