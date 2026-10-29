import csv
import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..models import DiscoveredAsset, AssetChangeRecord, ScanFinding, Scope
from ..security import sanitize_csv_cell
from .audit_service import log_audit_event

def export_assets_csv(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    asset_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> str:
    query = db.query(DiscoveredAsset)
    if scope_id:
        query = query.filter(DiscoveredAsset.scope_id == scope_id)
    if asset_type and asset_type.lower() != "all":
        query = query.filter(DiscoveredAsset.asset_type == asset_type.lower())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (DiscoveredAsset.host_or_ip.ilike(s)) |
            (DiscoveredAsset.ip_address.ilike(s))
        )

    assets = query.order_by(desc(DiscoveredAsset.last_seen)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Headers
    writer.writerow([
        "Asset ID",
        "Scope Name",
        "Host / FQDN / IP",
        "Asset Type",
        "Primary IP Address",
        "Status",
        "Open Ports Count",
        "Open Ports List",
        "DNS Records Summary",
        "HTTP Status",
        "HTTP Server",
        "TLS Certificate Subject",
        "TLS Days Remaining",
        "First Seen",
        "Last Seen"
    ])

    for a in assets:
        scope_name = scopes_map.get(a.scope_id, "Unknown Scope")
        ports_list = ", ".join(f"{p.get('port')}/{p.get('service', 'unknown')}" for p in (a.open_ports or []))
        dns_summary = "; ".join(f"{k}: {', '.join(v)}" for k, v in (a.dns_records or {}).items() if isinstance(v, list) and v)
        http_code = a.http_summary.get("status_code", "") if a.http_summary else ""
        http_server = a.http_summary.get("server", "") if a.http_summary else ""
        tls_subj = a.tls_summary.get("subject_cn") or a.tls_summary.get("subject", "") if a.tls_summary else ""
        tls_days = a.tls_summary.get("days_remaining", "") if a.tls_summary else ""

        writer.writerow([
            sanitize_csv_cell(a.id),
            sanitize_csv_cell(scope_name),
            sanitize_csv_cell(a.host_or_ip),
            sanitize_csv_cell(a.asset_type),
            sanitize_csv_cell(a.ip_address or ""),
            sanitize_csv_cell(a.status),
            sanitize_csv_cell(len(a.open_ports or [])),
            sanitize_csv_cell(ports_list),
            sanitize_csv_cell(dns_summary),
            sanitize_csv_cell(http_code),
            sanitize_csv_cell(http_server),
            sanitize_csv_cell(tls_subj),
            sanitize_csv_cell(tls_days),
            sanitize_csv_cell(a.first_seen.isoformat() if a.first_seen else ""),
            sanitize_csv_cell(a.last_seen.isoformat() if a.last_seen else ""),
        ])

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="inventory_csv",
        actor=actor,
        details={"format": "csv", "resource": "inventory", "record_count": len(assets), "scope_id": scope_id}
    )

    return output.getvalue()

def export_assets_json(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    asset_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> List[Dict[str, Any]]:
    query = db.query(DiscoveredAsset)
    if scope_id:
        query = query.filter(DiscoveredAsset.scope_id == scope_id)
    if asset_type and asset_type.lower() != "all":
        query = query.filter(DiscoveredAsset.asset_type == asset_type.lower())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (DiscoveredAsset.host_or_ip.ilike(s)) |
            (DiscoveredAsset.ip_address.ilike(s))
        )

    assets = query.order_by(desc(DiscoveredAsset.last_seen)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    results = []
    for a in assets:
        results.append({
            "id": a.id,
            "scope_id": a.scope_id,
            "scope_name": scopes_map.get(a.scope_id, "Unknown Scope"),
            "host_or_ip": a.host_or_ip,
            "asset_type": a.asset_type,
            "ip_address": a.ip_address,
            "status": a.status,
            "open_ports": a.open_ports or [],
            "dns_records": a.dns_records or {},
            "http_summary": a.http_summary or {},
            "tls_summary": a.tls_summary or {},
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        })

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="inventory_json",
        actor=actor,
        details={"format": "json", "resource": "inventory", "record_count": len(results), "scope_id": scope_id}
    )

    return results

def export_changes_csv(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    change_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> str:
    query = db.query(AssetChangeRecord)
    if scope_id:
        query = query.filter(AssetChangeRecord.scope_id == scope_id)
    if change_type and change_type.upper() != "ALL":
        query = query.filter(AssetChangeRecord.change_type == change_type.upper())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (AssetChangeRecord.asset_identifier.ilike(s)) |
            (AssetChangeRecord.attribute_name.ilike(s))
        )

    changes = query.order_by(desc(AssetChangeRecord.created_at)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Change ID",
        "Scope Name",
        "Asset Identifier",
        "Change Type",
        "Attribute Name",
        "Previous Value",
        "New Value",
        "Is Inconclusive",
        "Evidence Details",
        "Detected At"
    ])

    for c in changes:
        scope_name = scopes_map.get(c.scope_id, "Unknown Scope")
        prev_val = json.dumps(c.previous_value) if c.previous_value is not None else ""
        new_val = json.dumps(c.new_value) if c.new_value is not None else ""
        evidence_str = json.dumps(c.evidence) if c.evidence else ""

        writer.writerow([
            sanitize_csv_cell(c.id),
            sanitize_csv_cell(scope_name),
            sanitize_csv_cell(c.asset_identifier),
            sanitize_csv_cell(c.change_type),
            sanitize_csv_cell(c.attribute_name or ""),
            sanitize_csv_cell(prev_val),
            sanitize_csv_cell(new_val),
            sanitize_csv_cell("YES" if c.is_inconclusive else "NO"),
            sanitize_csv_cell(evidence_str),
            sanitize_csv_cell(c.created_at.isoformat() if c.created_at else ""),
        ])

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="changes_csv",
        actor=actor,
        details={"format": "csv", "resource": "changes", "record_count": len(changes), "scope_id": scope_id}
    )

    return output.getvalue()

def export_changes_json(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    change_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> List[Dict[str, Any]]:
    query = db.query(AssetChangeRecord)
    if scope_id:
        query = query.filter(AssetChangeRecord.scope_id == scope_id)
    if change_type and change_type.upper() != "ALL":
        query = query.filter(AssetChangeRecord.change_type == change_type.upper())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (AssetChangeRecord.asset_identifier.ilike(s)) |
            (AssetChangeRecord.attribute_name.ilike(s))
        )

    changes = query.order_by(desc(AssetChangeRecord.created_at)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    results = []
    for c in changes:
        results.append({
            "id": c.id,
            "scope_id": c.scope_id,
            "scope_name": scopes_map.get(c.scope_id, "Unknown Scope"),
            "scan_run_id": c.scan_run_id,
            "asset_identifier": c.asset_identifier,
            "change_type": c.change_type,
            "attribute_name": c.attribute_name,
            "previous_value": c.previous_value,
            "new_value": c.new_value,
            "is_inconclusive": c.is_inconclusive,
            "evidence": c.evidence or {},
            "created_at": c.created_at.isoformat() if c.created_at else None,
        })

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="changes_json",
        actor=actor,
        details={"format": "json", "resource": "changes", "record_count": len(results), "scope_id": scope_id}
    )

    return results

def export_findings_csv(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    review_status: Optional[str] = None,
    finding_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> str:
    query = db.query(ScanFinding)
    if scope_id:
        query = query.filter(ScanFinding.scope_id == scope_id)
    if severity and severity.upper() != "ALL":
        query = query.filter(ScanFinding.severity == severity.upper())
    if review_status and review_status.upper() != "ALL":
        query = query.filter(ScanFinding.review_status == review_status.upper())
    if finding_type and finding_type.upper() != "ALL":
        query = query.filter(ScanFinding.finding_type == finding_type.upper())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (ScanFinding.title.ilike(s)) |
            (ScanFinding.description.ilike(s)) |
            (ScanFinding.remediation.ilike(s))
        )

    findings = query.order_by(desc(ScanFinding.last_observed)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}
    assets_map = {a.id: a.host_or_ip for a in db.query(DiscoveredAsset).all()}

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow([
        "Finding ID",
        "Scope Name",
        "Asset Host",
        "Finding Title",
        "Severity",
        "Confidence",
        "Review Status",
        "Finding Type",
        "Explainable Description",
        "Recommended Remediation",
        "Evidence Details",
        "First Detected",
        "Last Observed"
    ])

    for f in findings:
        scope_name = scopes_map.get(f.scope_id, "Unknown Scope")
        asset_host = assets_map.get(f.asset_id, "")
        evidence_str = json.dumps(f.evidence) if f.evidence else ""

        writer.writerow([
            sanitize_csv_cell(f.id),
            sanitize_csv_cell(scope_name),
            sanitize_csv_cell(asset_host),
            sanitize_csv_cell(f.title),
            sanitize_csv_cell(f.severity),
            sanitize_csv_cell(f.confidence),
            sanitize_csv_cell(f.review_status),
            sanitize_csv_cell(f.finding_type),
            sanitize_csv_cell(f.description or ""),
            sanitize_csv_cell(f.remediation or ""),
            sanitize_csv_cell(evidence_str),
            sanitize_csv_cell(f.first_detected.isoformat() if f.first_detected else ""),
            sanitize_csv_cell(f.last_observed.isoformat() if f.last_observed else ""),
        ])

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="findings_csv",
        actor=actor,
        details={"format": "csv", "resource": "findings", "record_count": len(findings), "scope_id": scope_id}
    )

    return output.getvalue()

def export_findings_json(
    db: Session,
    scope_id: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    review_status: Optional[str] = None,
    finding_type: Optional[str] = None,
    actor: str = "SecOps User"
) -> List[Dict[str, Any]]:
    query = db.query(ScanFinding)
    if scope_id:
        query = query.filter(ScanFinding.scope_id == scope_id)
    if severity and severity.upper() != "ALL":
        query = query.filter(ScanFinding.severity == severity.upper())
    if review_status and review_status.upper() != "ALL":
        query = query.filter(ScanFinding.review_status == review_status.upper())
    if finding_type and finding_type.upper() != "ALL":
        query = query.filter(ScanFinding.finding_type == finding_type.upper())
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(
            (ScanFinding.title.ilike(s)) |
            (ScanFinding.description.ilike(s)) |
            (ScanFinding.remediation.ilike(s))
        )

    findings = query.order_by(desc(ScanFinding.last_observed)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}
    assets_map = {a.id: a.host_or_ip for a in db.query(DiscoveredAsset).all()}

    results = []
    for f in findings:
        results.append({
            "id": f.id,
            "scope_id": f.scope_id,
            "scope_name": scopes_map.get(f.scope_id, "Unknown Scope"),
            "asset_id": f.asset_id,
            "asset_host": assets_map.get(f.asset_id),
            "scan_run_id": f.scan_run_id,
            "finding_type": f.finding_type,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "confidence": f.confidence,
            "review_status": f.review_status,
            "remediation": f.remediation,
            "evidence": f.evidence or {},
            "status_history": f.status_history or [],
            "first_detected": f.first_detected.isoformat() if f.first_detected else None,
            "last_observed": f.last_observed.isoformat() if f.last_observed else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })

    log_audit_event(
        db=db,
        action="EXPORT_GENERATED",
        entity_type="export",
        entity_id="findings_json",
        actor=actor,
        details={"format": "json", "resource": "findings", "record_count": len(results), "scope_id": scope_id}
    )

    return results
