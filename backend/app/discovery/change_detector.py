from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..models import Scope, ScanRun, DiscoveredAsset, AssetSnapshot, AssetChangeRecord

def _normalize_dns_dict(dns_records: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    if not dns_records or not isinstance(dns_records, dict):
        return {}
    normalized = {}
    for k in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR"]:
        val = dns_records.get(k)
        if isinstance(val, list):
            normalized[k] = sorted(list(set(str(x) for x in val)))
        elif val:
            normalized[k] = [str(val)]
        else:
            normalized[k] = []
    return normalized

def _normalize_ports_list(open_ports: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if not open_ports or not isinstance(open_ports, list):
        return []
    # Deduplicate and sort by port number
    seen_ports = {}
    for p in open_ports:
        port_num = p.get("port")
        if isinstance(port_num, int):
            seen_ports[port_num] = {
                "port": port_num,
                "service": p.get("service", "Unknown"),
                "status": p.get("status", "OPEN"),
                "latency_ms": p.get("latency_ms", 0.0),
                "banner": p.get("banner")
            }
    return [seen_ports[k] for k in sorted(seen_ports.keys())]

def _normalize_tls_dict(tls: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not tls or not isinstance(tls, dict) or not tls.get("has_tls"):
        return {"has_tls": False}
    return {
        "has_tls": True,
        "port": tls.get("port", 443),
        "subject_cn": tls.get("subject_cn", ""),
        "issuer_cn": tls.get("issuer_cn", ""),
        "valid_to": tls.get("valid_to", ""),
        "days_remaining": tls.get("days_remaining"),
        "is_expired": bool(tls.get("is_expired")),
        "sans": sorted(list(set(tls.get("sans", []))))
    }

def _normalize_http_dict(http: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not http or not isinstance(http, dict) or not http.get("reachable"):
        return {"reachable": False}
    return {
        "reachable": True,
        "status_code": http.get("status_code"),
        "server": http.get("server") or "",
        "title": http.get("title") or "",
        "scheme": http.get("scheme", "http")
    }

def create_snapshot_for_scan(db: Session, scan_run_id: str, scope_id: str) -> Optional[AssetSnapshot]:
    """
    Creates an immutable baseline snapshot for a completed discovery run.
    Does not replace or create baseline for failed or cancelled scans.
    """
    scan: ScanRun | None = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan or scan.status != "COMPLETED":
        return None

    # Check if a snapshot already exists for this scan run (idempotent)
    existing_snap = db.query(AssetSnapshot).filter(AssetSnapshot.scan_run_id == scan_run_id).first()
    if existing_snap:
        return existing_snap

    # Retrieve all current assets for this scope
    assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.scope_id == scope_id).all()

    snapshot_records = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for a in assets:
        # Normalize fields
        normalized_asset = {
            "asset_id": a.id,
            "host_or_ip": a.host_or_ip.strip().lower(),
            "asset_type": a.asset_type,
            "ip_address": a.ip_address.strip() if a.ip_address else None,
            "status": a.status,
            "open_ports": _normalize_ports_list(a.open_ports),
            "dns_records": _normalize_dns_dict(a.dns_records),
            "http_summary": _normalize_http_dict(a.http_summary),
            "tls_summary": _normalize_tls_dict(a.tls_summary),
            "observed_at": (a.last_seen or now).isoformat()
        }
        snapshot_records.append(normalized_asset)

    # Sort assets by host_or_ip for consistent deterministic storage
    snapshot_records.sort(key=lambda x: x["host_or_ip"])

    snapshot = AssetSnapshot(
        scope_id=scope_id,
        scan_run_id=scan_run_id,
        created_at=now,
        asset_count=len(snapshot_records),
        snapshot_data=snapshot_records
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot

def detect_and_record_changes(db: Session, current_snapshot: AssetSnapshot) -> List[AssetChangeRecord]:
    """
    Compares the current snapshot with the previous valid snapshot for the same scope.
    Identifies additions, removals, and attribute modifications (DNS, IP, ports, HTTP, TLS).
    Ensures idempotency.
    """
    scope_id = current_snapshot.scope_id

    # Retrieve the immediately preceding valid snapshot for this scope
    previous_snapshot: AssetSnapshot | None = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.scope_id == scope_id, AssetSnapshot.id != current_snapshot.id)
        .order_by(desc(AssetSnapshot.created_at))
        .first()
    )

    # Clear any existing change records for this target snapshot (idempotency)
    db.query(AssetChangeRecord).filter(AssetChangeRecord.to_snapshot_id == current_snapshot.id).delete()
    db.commit()

    created_changes: List[AssetChangeRecord] = []
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    curr_assets = {a["host_or_ip"]: a for a in current_snapshot.snapshot_data}

    # Case A: Initial Baseline Snapshot
    if not previous_snapshot:
        for host, asset_data in curr_assets.items():
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=None,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="ASSET_ADDED",
                attribute_name="asset",
                previous_value=None,
                new_value={
                    "host_or_ip": host,
                    "ip_address": asset_data.get("ip_address"),
                    "status": asset_data.get("status"),
                    "ports": [p["port"] for p in asset_data.get("open_ports", [])]
                },
                evidence={"context": "Initial baseline inventory establishment", "asset_data": asset_data},
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)
        db.commit()
        return created_changes

    # Case B: Comparison between previous_snapshot and current_snapshot
    prev_assets = {a["host_or_ip"]: a for a in previous_snapshot.snapshot_data}

    # 1. Newly Added Assets
    added_hosts = set(curr_assets.keys()) - set(prev_assets.keys())
    for host in added_hosts:
        curr_a = curr_assets[host]
        change = AssetChangeRecord(
            scope_id=scope_id,
            from_snapshot_id=previous_snapshot.id,
            to_snapshot_id=current_snapshot.id,
            scan_run_id=current_snapshot.scan_run_id,
            asset_identifier=host,
            change_type="ASSET_ADDED",
            attribute_name="asset",
            previous_value=None,
            new_value={
                "host_or_ip": host,
                "ip_address": curr_a.get("ip_address"),
                "status": curr_a.get("status"),
                "ports": [p["port"] for p in curr_a.get("open_ports", [])]
            },
            evidence={"context": "Newly discovered asset in scope", "asset": curr_a},
            is_inconclusive=False,
            created_at=now
        )
        db.add(change)
        created_changes.append(change)

    # 2. Removed Assets vs Inconclusive/Timeout
    removed_hosts = set(prev_assets.keys()) - set(curr_assets.keys())
    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    scope_target_set = set(t.strip().lower() for t in (scope.targets if scope else []))

    for host in removed_hosts:
        prev_a = prev_assets[host]
        # Distinguish observed removal from target removal or unreachable timeout
        is_target_in_scope = host in scope_target_set
        is_inconclusive = False
        evidence_msg = "Asset no longer present in completed discovery run"

        if not is_target_in_scope:
            evidence_msg = "Target was explicitly removed from authorized scope definition"
        elif prev_a.get("status") == "UNRESPONSIVE":
            is_inconclusive = True
            evidence_msg = "Asset was previously unresponsive and was omitted from active inventory; flagged as inconclusive"

        change = AssetChangeRecord(
            scope_id=scope_id,
            from_snapshot_id=previous_snapshot.id,
            to_snapshot_id=current_snapshot.id,
            scan_run_id=current_snapshot.scan_run_id,
            asset_identifier=host,
            change_type="ASSET_REMOVED",
            attribute_name="asset",
            previous_value={
                "host_or_ip": host,
                "ip_address": prev_a.get("ip_address"),
                "status": prev_a.get("status")
            },
            new_value=None,
            evidence={"context": evidence_msg, "is_target_in_scope": is_target_in_scope},
            is_inconclusive=is_inconclusive,
            created_at=now
        )
        db.add(change)
        created_changes.append(change)

    # 3. Modified Assets (present in both snapshots)
    common_hosts = set(curr_assets.keys()) & set(prev_assets.keys())
    for host in common_hosts:
        p = prev_assets[host]
        c = curr_assets[host]

        # A. IP Address Change
        prev_ip = p.get("ip_address")
        curr_ip = c.get("ip_address")
        if prev_ip != curr_ip and (prev_ip or curr_ip):
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=previous_snapshot.id,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="IP_CHANGED",
                attribute_name="ip_address",
                previous_value=prev_ip,
                new_value=curr_ip,
                evidence={"context": f"IP mapping shifted from {prev_ip} to {curr_ip}"},
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)

        # B. DNS Records Changes
        p_dns = p.get("dns_records", {})
        c_dns = c.get("dns_records", {})
        for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR"]:
            p_recs = p_dns.get(rtype, [])
            c_recs = c_dns.get(rtype, [])
            if p_recs != c_recs:
                change = AssetChangeRecord(
                    scope_id=scope_id,
                    from_snapshot_id=previous_snapshot.id,
                    to_snapshot_id=current_snapshot.id,
                    scan_run_id=current_snapshot.scan_run_id,
                    asset_identifier=host,
                    change_type="DNS_CHANGED",
                    attribute_name=f"dns.{rtype}",
                    previous_value=p_recs,
                    new_value=c_recs,
                    evidence={
                        "context": f"DNS {rtype} records updated",
                        "added": list(set(c_recs) - set(p_recs)),
                        "removed": list(set(p_recs) - set(c_recs))
                    },
                    is_inconclusive=False,
                    created_at=now
                )
                db.add(change)
                created_changes.append(change)

        # C. Open Ports (Port Opened / Port Closed)
        p_ports = {p_item["port"]: p_item for p_item in p.get("open_ports", [])}
        c_ports = {c_item["port"]: c_item for c_item in c.get("open_ports", [])}

        p_nums = set(p_ports.keys())
        c_nums = set(c_ports.keys())

        # Opened ports
        for port_num in (c_nums - p_nums):
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=previous_snapshot.id,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="PORT_OPENED",
                attribute_name="open_ports",
                previous_value=None,
                new_value=port_num,
                evidence={
                    "context": f"TCP port {port_num} became responsive",
                    "port_info": c_ports[port_num]
                },
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)

        # Closed ports
        for port_num in (p_nums - c_nums):
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=previous_snapshot.id,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="PORT_CLOSED",
                attribute_name="open_ports",
                previous_value=port_num,
                new_value=None,
                evidence={
                    "context": f"TCP port {port_num} no longer responsive in allowlist scan",
                    "previous_info": p_ports[port_num]
                },
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)

        # D. HTTP Summary Changes (Status Code or Reachability)
        p_http = p.get("http_summary", {})
        c_http = c.get("http_summary", {})
        if bool(p_http.get("reachable")) != bool(c_http.get("reachable")):
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=previous_snapshot.id,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="HTTP_STATUS_CHANGED",
                attribute_name="http.reachability",
                previous_value=p_http.get("status_code") if p_http.get("reachable") else "UNREACHABLE",
                new_value=c_http.get("status_code") if c_http.get("reachable") else "UNREACHABLE",
                evidence={"previous_http": p_http, "new_http": c_http},
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)
        elif p_http.get("reachable") and c_http.get("reachable"):
            if p_http.get("status_code") != c_http.get("status_code"):
                change = AssetChangeRecord(
                    scope_id=scope_id,
                    from_snapshot_id=previous_snapshot.id,
                    to_snapshot_id=current_snapshot.id,
                    scan_run_id=current_snapshot.scan_run_id,
                    asset_identifier=host,
                    change_type="HTTP_STATUS_CHANGED",
                    attribute_name="http.status_code",
                    previous_value=p_http.get("status_code"),
                    new_value=c_http.get("status_code"),
                    evidence={"previous_http": p_http, "new_http": c_http},
                    is_inconclusive=False,
                    created_at=now
                )
                db.add(change)
                created_changes.append(change)

        # E. TLS Certificate Changes
        p_tls = p.get("tls_summary", {})
        c_tls = c.get("tls_summary", {})
        if bool(p_tls.get("has_tls")) != bool(c_tls.get("has_tls")):
            change = AssetChangeRecord(
                scope_id=scope_id,
                from_snapshot_id=previous_snapshot.id,
                to_snapshot_id=current_snapshot.id,
                scan_run_id=current_snapshot.scan_run_id,
                asset_identifier=host,
                change_type="TLS_CHANGED",
                attribute_name="tls_certificate",
                previous_value={"has_tls": False} if not p_tls.get("has_tls") else {"has_tls": True, "subject": p_tls.get("subject_cn")},
                new_value={"has_tls": False} if not c_tls.get("has_tls") else {"has_tls": True, "subject": c_tls.get("subject_cn")},
                evidence={"previous_tls": p_tls, "new_tls": c_tls},
                is_inconclusive=False,
                created_at=now
            )
            db.add(change)
            created_changes.append(change)
        elif p_tls.get("has_tls") and c_tls.get("has_tls"):
            # Expiry, subject, or issuer changed
            if (p_tls.get("valid_to") != c_tls.get("valid_to") or 
                p_tls.get("issuer_cn") != c_tls.get("issuer_cn") or 
                p_tls.get("subject_cn") != c_tls.get("subject_cn")):
                change = AssetChangeRecord(
                    scope_id=scope_id,
                    from_snapshot_id=previous_snapshot.id,
                    to_snapshot_id=current_snapshot.id,
                    scan_run_id=current_snapshot.scan_run_id,
                    asset_identifier=host,
                    change_type="TLS_CHANGED",
                    attribute_name="tls_certificate",
                    previous_value={"valid_to": p_tls.get("valid_to"), "issuer": p_tls.get("issuer_cn"), "subject": p_tls.get("subject_cn")},
                    new_value={"valid_to": c_tls.get("valid_to"), "issuer": c_tls.get("issuer_cn"), "subject": c_tls.get("subject_cn")},
                    evidence={"previous_tls": p_tls, "new_tls": c_tls},
                    is_inconclusive=False,
                    created_at=now
                )
                db.add(change)
                created_changes.append(change)

    db.commit()
    return created_changes
