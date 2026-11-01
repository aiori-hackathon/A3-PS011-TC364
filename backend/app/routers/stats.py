from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import Scope, ScanRun, DiscoveredAsset, ScanFinding, AssetChangeRecord
from ..discovery.change_detector import create_snapshot_for_scan, detect_and_record_changes
from ..discovery.risk_classifier import evaluate_and_persist_findings
from ..schemas import StatsOverview, ScanOut

router = APIRouter(prefix="", tags=["Stats & Demo"])

@router.get("/stats/overview", response_model=StatsOverview)
def get_stats_overview(db: Session = Depends(get_db)):
    total_scopes = db.query(Scope).count()
    total_assets = db.query(DiscoveredAsset).count()
    active_assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.status == "ACTIVE").count()
    unresolved_assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.status == "UNRESOLVED").count()
    unresponsive_assets = total_assets - (active_assets + unresolved_assets)
    total_scans = db.query(ScanRun).count()

    last_scan_record = db.query(ScanRun).order_by(desc(ScanRun.started_at)).first()
    last_scan_out = None
    if last_scan_record:
        scope = db.query(Scope).filter(Scope.id == last_scan_record.scope_id).first()
        last_scan_out = ScanOut(
            id=last_scan_record.id,
            scope_id=last_scan_record.scope_id,
            scope_name=scope.name if scope else "Unknown Scope",
            status=last_scan_record.status,
            config=last_scan_record.config or {},
            targets_total=last_scan_record.targets_total,
            targets_scanned=last_scan_record.targets_scanned,
            assets_discovered_count=last_scan_record.assets_discovered_count,
            new_assets_count=last_scan_record.new_assets_count if last_scan_record.new_assets_count is not None else last_scan_record.assets_discovered_count,
            updated_assets_count=last_scan_record.updated_assets_count or 0,
            failed_targets_count=last_scan_record.failed_targets_count or 0,
            total_assets_count=last_scan_record.total_assets_count or (last_scan_record.assets_discovered_count or 0),
            findings_count=last_scan_record.findings_count,
            started_at=last_scan_record.started_at,
            completed_at=last_scan_record.completed_at,
            error_message=last_scan_record.error_message,
            logs=last_scan_record.logs or [],
            schedule_id=last_scan_record.schedule_id,
            is_scheduled=last_scan_record.is_scheduled or False
        )

    # Asset types distribution
    all_assets = db.query(DiscoveredAsset).all()
    type_counter = Counter([a.asset_type for a in all_assets])
    
    # Port frequency
    port_counter = Counter()
    for a in all_assets:
        for p in (a.open_ports or []):
            port_num = p.get("port")
            service = p.get("service", "Unknown")
            if port_num:
                port_counter[(port_num, service)] += 1

    top_ports: List[Dict[str, Any]] = [
        {"port": p[0], "service": p[1], "count": count}
        for p, count in port_counter.most_common(8)
    ]

    # Findings by type
    findings = db.query(ScanFinding.finding_type).all()
    finding_counter = Counter([f[0] for f in findings])

    # Findings by severity and status
    all_findings = db.query(ScanFinding.severity, ScanFinding.review_status).all()
    sev_counter = Counter()
    status_counter = Counter()
    for s, st in all_findings:
        sev = (s or "INFORMATIONAL").upper()
        if sev in ("INFO", "NOTICE"):
            sev = "INFORMATIONAL"
        elif sev == "WARNING":
            sev = "MEDIUM"
        sev_counter[sev] += 1
        status_counter[(st or "OPEN").upper()] += 1

    # Changes summary
    total_changes = db.query(AssetChangeRecord).count()
    change_types = db.query(AssetChangeRecord.change_type).all()
    change_counter = Counter([c[0] for c in change_types])

    # Discovery activity timeline (recent 15 scans)
    recent_scans = db.query(ScanRun).order_by(desc(ScanRun.started_at)).limit(15).all()
    all_scopes = {s.id: s.name for s in db.query(Scope).all()}
    discovery_timeline = [
        {
            "id": s.id,
            "scope_name": all_scopes.get(s.scope_id, "Unknown Scope"),
            "status": s.status,
            "targets_scanned": s.targets_scanned,
            "assets_discovered": s.assets_discovered_count,
            "findings_count": s.findings_count,
            "started_at": s.started_at.isoformat() if s.started_at else None
        }
        for s in reversed(recent_scans)
    ]

    # Asset changes over time (grouped chronologically by date)
    recent_changes = db.query(AssetChangeRecord).order_by(AssetChangeRecord.created_at.asc()).all()
    date_grouped_changes: Dict[str, Dict[str, int]] = {}
    for c in recent_changes:
        d_str = c.created_at.strftime("%Y-%m-%d") if c.created_at else "Unknown"
        if d_str not in date_grouped_changes:
            date_grouped_changes[d_str] = {"total": 0, "added": 0, "removed": 0, "modified": 0}
        date_grouped_changes[d_str]["total"] += 1
        if c.change_type == "ASSET_ADDED":
            date_grouped_changes[d_str]["added"] += 1
        elif c.change_type == "ASSET_REMOVED":
            date_grouped_changes[d_str]["removed"] += 1
        else:
            date_grouped_changes[d_str]["modified"] += 1

    changes_timeline = [
        {"date": d_str, **counts}
        for d_str, counts in sorted(date_grouped_changes.items())
    ]

    return StatsOverview(
        total_scopes=total_scopes,
        total_assets=total_assets,
        active_assets=active_assets,
        unresponsive_assets=unresponsive_assets,
        unresolved_assets=unresolved_assets,
        total_scans=total_scans,
        last_scan=last_scan_out,
        asset_types_distribution=dict(type_counter),
        top_open_ports=top_ports,
        findings_by_type=dict(finding_counter),
        findings_by_severity=dict(sev_counter),
        findings_by_status=dict(status_counter),
        total_changes=total_changes,
        changes_by_type=dict(change_counter),
        discovery_timeline=discovery_timeline,
        changes_timeline=changes_timeline
    )

@router.post("/demo/seed")
def seed_demo_mode(db: Session = Depends(get_db)):
    """
    Creates an explicitly labelled synthetic demo dataset so evaluators can inspect
    dashboard components without running live target probes.
    """
    # Clean previous demo scope if any
    existing_demo = db.query(Scope).filter(Scope.name == "[DEMO / SYNTHETIC] Local Lab & Authorised Sample").first()
    if existing_demo:
        db.delete(existing_demo)
        db.commit()

    now = datetime.utcnow()
    demo_scope = Scope(
        name="[DEMO / SYNTHETIC] Local Lab & Authorised Sample",
        description="Explicitly labelled synthetic demonstration data representing an authorized corporate attack surface.",
        targets=[
            "portal.demo-corp.internal",
            "api.demo-corp.internal",
            "vpn.demo-corp.internal",
            "mail.demo-corp.internal",
            "192.168.10.45"
        ],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Security Architect (Simulated Demo)"
    )
    db.add(demo_scope)
    db.commit()
    db.refresh(demo_scope)

    # Demo Scan Run
    demo_scan = ScanRun(
        scope_id=demo_scope.id,
        status="COMPLETED",
        config={
            "ports": [22, 25, 80, 443, 3000, 8080, 8443],
            "enable_dns": True,
            "enable_ports": True,
            "enable_http": True,
            "enable_tls": True
        },
        targets_total=5,
        targets_scanned=5,
        assets_discovered_count=5,
        new_assets_count=5,
        updated_assets_count=0,
        failed_targets_count=0,
        total_assets_count=5,
        findings_count=16,
        started_at=now - timedelta(minutes=12),
        completed_at=now - timedelta(minutes=10),
        logs=[
            {"timestamp": (now - timedelta(minutes=12)).strftime("%H:%M:%S"), "level": "INFO", "message": "Initiating ArgusTrace Discovery Run for Scope: '[DEMO / SYNTHETIC]'"},
            {"timestamp": (now - timedelta(minutes=12)).strftime("%H:%M:%S"), "level": "INFO", "message": "Authorised by: Security Architect | Local Lab Mode: True"},
            {"timestamp": (now - timedelta(minutes=11)).strftime("%H:%M:%S"), "level": "INFO", "message": "Processing target: portal.demo-corp.internal"},
            {"timestamp": (now - timedelta(minutes=11)).strftime("%H:%M:%S"), "level": "SUCCESS", "message": "DNS Resolved A -> 192.168.10.10, AAAA -> 2001:db8::10"},
            {"timestamp": (now - timedelta(minutes=11)).strftime("%H:%M:%S"), "level": "SUCCESS", "message": "Open ports: [80, 443]"},
            {"timestamp": (now - timedelta(minutes=11)).strftime("%H:%M:%S"), "level": "INFO", "message": "HTTP Responsive: 200 OK | Title: 'Demo Corporate SSO Portal'"},
            {"timestamp": (now - timedelta(minutes=11)).strftime("%H:%M:%S"), "level": "INFO", "message": "TLS Certificate Valid: Subject='*.demo-corp.internal' (Expires in 84 days)"},
            {"timestamp": (now - timedelta(minutes=10)).strftime("%H:%M:%S"), "level": "SUCCESS", "message": "Discovery run finished. Targets scanned: 5, Assets: 5, Findings: 16"}
        ]
    )
    db.add(demo_scan)
    db.commit()
    db.refresh(demo_scan)

    # Synthetic Assets
    assets_data = [
        {
            "host": "portal.demo-corp.internal",
            "type": "subdomain",
            "ip": "192.168.10.10",
            "status": "ACTIVE",
            "ports": [
                {"port": 80, "service": "HTTP", "latency_ms": 14.2, "status": "OPEN"},
                {"port": 443, "service": "HTTPS", "latency_ms": 18.5, "status": "OPEN"}
            ],
            "dns": {"A": ["192.168.10.10"], "AAAA": ["2001:db8::10"], "CNAME": [], "MX": [], "NS": [], "TXT": ["v=spf1 include:_spf.demo-corp.internal ~all"], "is_synthetic_demo": True},
            "http": {
                "reachable": True,
                "status_code": 200,
                "scheme": "https",
                "port": 443,
                "server": "nginx/1.24.0",
                "title": "Demo Corporate SSO Portal",
                "latency_ms": 18.5,
                "content_type": "text/html; charset=UTF-8",
                "redirect_count": 1,
                "headers": {"Server": "nginx/1.24.0", "Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
            },
            "tls": {
                "has_tls": True,
                "port": 443,
                "subject_cn": "*.demo-corp.internal",
                "issuer_cn": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                "valid_from": (now - timedelta(days=281)).isoformat(),
                "valid_to": (now + timedelta(days=84)).isoformat(),
                "days_remaining": 84,
                "is_expired": False,
                "sans": ["*.demo-corp.internal", "demo-corp.internal"],
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384"
            }
        },
        {
            "host": "api.demo-corp.internal",
            "type": "subdomain",
            "ip": "192.168.10.20",
            "status": "ACTIVE",
            "ports": [
                {"port": 443, "service": "HTTPS", "latency_ms": 12.1, "status": "OPEN"},
                {"port": 8443, "service": "HTTPS-Alt", "latency_ms": 15.3, "status": "OPEN"}
            ],
            "dns": {"A": ["192.168.10.20"], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "is_synthetic_demo": True},
            "http": {
                "reachable": True,
                "status_code": 200,
                "scheme": "https",
                "port": 443,
                "server": "envoy/1.28.0",
                "title": "API Gateway Health Check",
                "latency_ms": 12.1,
                "content_type": "application/json",
                "redirect_count": 0,
                "headers": {"Server": "envoy/1.28.0", "Content-Type": "application/json"}
            },
            "tls": {
                "has_tls": True,
                "port": 443,
                "subject_cn": "api.demo-corp.internal",
                "issuer_cn": "Let's Encrypt Authority X3",
                "valid_from": (now - timedelta(days=70)).isoformat(),
                "valid_to": (now + timedelta(days=20)).isoformat(),
                "days_remaining": 20,
                "is_expired": False,
                "sans": ["api.demo-corp.internal"],
                "tls_version": "TLSv1.3",
                "cipher": "TLS_CHACHA20_POLY1305_SHA256"
            }
        },
        {
            "host": "vpn.demo-corp.internal",
            "type": "subdomain",
            "ip": "192.168.10.30",
            "status": "ACTIVE",
            "ports": [
                {"port": 443, "service": "HTTPS", "latency_ms": 22.4, "status": "OPEN"},
                {"port": 22, "service": "SSH", "latency_ms": 19.8, "status": "OPEN", "banner": "SSH-2.0-OpenSSH_9.3p1"}
            ],
            "dns": {"A": ["192.168.10.30"], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "is_synthetic_demo": True},
            "http": {
                "reachable": True,
                "status_code": 403,
                "scheme": "https",
                "port": 443,
                "server": "Apache/2.4.58",
                "title": "403 Forbidden - VPN Gateway",
                "latency_ms": 22.4,
                "content_type": "text/html",
                "redirect_count": 0,
                "headers": {"Server": "Apache/2.4.58"}
            },
            "tls": {
                "has_tls": True,
                "port": 443,
                "subject_cn": "vpn.demo-corp.internal",
                "issuer_cn": "DigiCert Global Root CA",
                "valid_from": (now - timedelta(days=350)).isoformat(),
                "valid_to": (now + timedelta(days=15)).isoformat(),
                "days_remaining": 15,
                "is_expired": False,
                "sans": ["vpn.demo-corp.internal"],
                "tls_version": "TLSv1.2",
                "cipher": "ECDHE-RSA-AES256-GCM-SHA384"
            }
        },
        {
            "host": "mail.demo-corp.internal",
            "type": "subdomain",
            "ip": "192.168.10.40",
            "status": "ACTIVE",
            "ports": [
                {"port": 25, "service": "SMTP", "latency_ms": 31.0, "status": "OPEN", "banner": "220 mail.demo-corp.internal ESMTP Postfix"},
                {"port": 587, "service": "Submission", "latency_ms": 29.5, "status": "OPEN"}
            ],
            "dns": {"A": ["192.168.10.40"], "AAAA": [], "CNAME": [], "MX": ["10 mail.demo-corp.internal"], "NS": [], "TXT": [], "is_synthetic_demo": True},
            "http": {},
            "tls": {}
        },
        {
            "host": "192.168.10.45",
            "type": "ipv4",
            "ip": "192.168.10.45",
            "status": "ACTIVE",
            "ports": [
                {"port": 22, "service": "SSH", "latency_ms": 11.2, "status": "OPEN", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}
            ],
            "dns": {"PTR": ["jumpbox.demo-corp.internal"], "is_synthetic_demo": True},
            "http": {},
            "tls": {}
        }
    ]

    for item in assets_data:
        asset = DiscoveredAsset(
            scope_id=demo_scope.id,
            scan_run_id=demo_scan.id,
            host_or_ip=item["host"],
            asset_type=item["type"],
            ip_address=item["ip"],
            status=item["status"],
            open_ports=item["ports"],
            dns_records=item["dns"],
            http_summary=item["http"],
            tls_summary=item["tls"],
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(minutes=10)
        )
        db.add(asset)
        db.flush()

        # Evaluate explainable risk classification and persist deduplicated findings
        evaluate_and_persist_findings(db, demo_scan.id, demo_scope.id, asset)

    db.commit()
    
    # Create baseline snapshot and initial change records for demo
    snap = create_snapshot_for_scan(db, demo_scan.id, demo_scope.id)
    if snap:
        detect_and_record_changes(db, snap)

    return {
        "message": "Demo mode synthetic data loaded successfully. All data is visibly labeled as demo/synthetic.",
        "scope_id": demo_scope.id,
        "assets_count": len(assets_data)
    }

@router.post("/demo/clear")
def clear_demo_mode(db: Session = Depends(get_db)):
    demo_scopes = db.query(Scope).filter(Scope.name.like("%[DEMO / SYNTHETIC]%")).all()
    count = len(demo_scopes)
    for s in demo_scopes:
        db.delete(s)
    db.commit()
    return {"message": f"Cleared {count} demo scope(s) and associated assets."}
