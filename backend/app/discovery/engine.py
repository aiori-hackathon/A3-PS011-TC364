import asyncio
import datetime
from typing import Set, Dict, Any, List
import ipaddress
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import Scope, ScanRun, DiscoveredAsset, ScanFinding
from ..security import validate_target, resolve_and_verify_target, is_ip_address
from ..config import settings
from .dns_resolver import resolve_dns_records
from .port_scanner import scan_allowed_ports
from .http_probe import probe_http_service
from .tls_inspector import inspect_tls_certificate
from .change_detector import create_snapshot_for_scan, detect_and_record_changes
from .risk_classifier import evaluate_and_persist_findings

# Thread-safe cancellation set
CANCELLED_SCANS: Set[str] = set()

def cancel_scan(scan_id: str) -> bool:
    CANCELLED_SCANS.add(scan_id)
    return True

def is_scan_cancelled(scan_id: str) -> bool:
    return scan_id in CANCELLED_SCANS

def add_log_entry(logs: List[Dict[str, str]], message: str, level: str = "INFO"):
    timestamp = datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    logs.append({"timestamp": timestamp, "level": level, "message": message})

async def execute_discovery_run(scan_id: str):
    """
    Background executor for an authorized attack surface discovery run (Phase 1).
    """
    db: Session = SessionLocal()
    try:
        scan: ScanRun | None = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if not scan:
            return

        scope: Scope | None = db.query(Scope).filter(Scope.id == scan.scope_id).first()
        if not scope:
            scan.status = "FAILED"
            scan.error_message = "Associated scope not found."
            scan.completed_at = datetime.datetime.utcnow()
            db.commit()
            return

        # Verification of explicit authorization confirmation
        if not scope.authorised_confirmation:
            scan.status = "FAILED"
            scan.error_message = "Scan aborted: Scope lacks verified authorization confirmation flag."
            scan.completed_at = datetime.datetime.utcnow()
            db.commit()
            return

        scan.status = "IN_PROGRESS"
        scan.started_at = datetime.datetime.utcnow()
        logs: List[Dict[str, str]] = list(scan.logs or [])
        add_log_entry(logs, f"Initiating ArgusTrace Phase 1 Discovery Run for Scope: '{scope.name}'")
        add_log_entry(logs, f"Authorised by: {scope.authorised_by} | Local Lab Mode: {scope.allow_local_lab}")
        
        scan.logs = logs
        db.commit()

        # Parse scan configuration
        config = scan.config or {}
        selected_ports = config.get("ports", settings.DEFAULT_ALLOWED_PORTS)
        enable_dns = config.get("enable_dns", True)
        enable_ports = config.get("enable_ports", True)
        enable_http = config.get("enable_http", True)
        enable_tls = config.get("enable_tls", True)

        raw_targets = scope.targets or []
        scan.targets_total = len(raw_targets)
        db.commit()

        targets_scanned = 0
        assets_discovered = 0
        findings_count = 0

        add_log_entry(logs, f"Loaded {len(raw_targets)} targets for validation & discovery")

        for target_str in raw_targets:
            # Check cancellation
            if is_scan_cancelled(scan_id):
                add_log_entry(logs, "Scan cancellation requested by user. Terminating discovery run gracefully.", "WARN")
                scan.status = "CANCELLED"
                scan.completed_at = datetime.datetime.utcnow()
                scan.logs = logs
                db.commit()
                return

            # Target validation & SSRF check
            is_valid, sanitized_target, error_msg = validate_target(target_str, allow_local_lab=scope.allow_local_lab)
            if not is_valid:
                add_log_entry(logs, f"Target '{target_str}' skipped: {error_msg}", "WARN")
                targets_scanned += 1
                scan.targets_scanned = targets_scanned
                scan.logs = logs
                db.commit()
                continue

            add_log_entry(logs, f"Processing target: {sanitized_target}")

            # 1. DNS Resolution Probe
            dns_results = {}
            primary_ip = None
            if enable_dns:
                add_log_entry(logs, f"[{sanitized_target}] Querying DNS records (A, AAAA, CNAME, MX, NS, TXT, PTR)...")
                dns_results = await resolve_dns_records(sanitized_target)
                
                # Determine primary IP
                if dns_results.get("A"):
                    primary_ip = dns_results["A"][0]
                elif dns_results.get("AAAA"):
                    primary_ip = dns_results["AAAA"][0]
                elif is_ip_address(sanitized_target):
                    primary_ip = sanitized_target

            # Verify IP safety before active TCP/HTTP probing
            target_to_probe = primary_ip or sanitized_target
            is_safe, resolved_ip, safety_reason = resolve_and_verify_target(target_to_probe, allow_local_lab=scope.allow_local_lab)
            if not is_safe:
                add_log_entry(logs, f"[{sanitized_target}] SSRF Guardrail: Probe halted. {safety_reason}", "WARN")
                targets_scanned += 1
                scan.targets_scanned = targets_scanned
                scan.logs = logs
                db.commit()
                continue

            if not primary_ip and resolved_ip:
                primary_ip = resolved_ip

            # 2. Bounded Port Scanning
            open_ports = []
            if enable_ports and target_to_probe:
                add_log_entry(logs, f"[{sanitized_target}] Probing {len(selected_ports)} bounded TCP ports...")
                open_ports = await scan_allowed_ports(
                    host=target_to_probe,
                    ports=selected_ports,
                    concurrency=min(settings.MAX_CONCURRENT_PROBES, len(selected_ports)),
                    timeout=settings.TCP_TIMEOUT_SECONDS
                )
                if open_ports:
                    open_port_nums = [p["port"] for p in open_ports]
                    add_log_entry(logs, f"[{sanitized_target}] Open ports detected: {open_port_nums}", "SUCCESS")
                else:
                    add_log_entry(logs, f"[{sanitized_target}] No responsive ports found in allowlist.")

            # 3. HTTP / HTTPS Reachability & Metadata
            http_summary = {}
            if enable_http:
                open_port_nums = [p["port"] for p in open_ports]
                
                # Determine which web ports to probe
                web_ports_to_check = []
                for p in [443, 8443]:
                    if p in open_port_nums or not enable_ports:
                        web_ports_to_check.append((p, True))
                for p in [80, 8080, 8000, 8888, 3000]:
                    if p in open_port_nums or not enable_ports:
                        web_ports_to_check.append((p, False))

                # If no specific open port was detected but ports scan was disabled, test default 80/443
                if not web_ports_to_check and not enable_ports:
                    web_ports_to_check = [(443, True), (80, False)]

                for port, use_https in web_ports_to_check[:3]: # limit to top 3 web candidates
                    if is_scan_cancelled(scan_id):
                        break
                    res = await probe_http_service(
                        host=sanitized_target,
                        port=port,
                        use_https=use_https,
                        allow_local_lab=scope.allow_local_lab,
                        timeout=settings.HTTP_TIMEOUT_SECONDS
                    )
                    if res and res.get("reachable"):
                        http_summary = res
                        add_log_entry(
                            logs,
                            f"[{sanitized_target}] HTTP service responsive on port {port} ({res.get('scheme', 'http').upper()}) "
                            f"- Status: {res.get('status_code')} | Server: {res.get('server') or 'Unknown'} | Title: '{res.get('title') or 'None'}'"
                        )
                        break

            # 4. TLS Certificate Metadata
            tls_summary = {}
            if enable_tls:
                # Check port 443 or 8443 if open or by default for domains
                tls_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443)]
                if not tls_ports and not is_ip_address(sanitized_target):
                    tls_ports = [443]

                for tport in tls_ports[:1]:
                    add_log_entry(logs, f"[{sanitized_target}] Inspecting TLS certificate on port {tport}...")
                    tls_info = await inspect_tls_certificate(sanitized_target, port=tport, timeout=settings.TCP_TIMEOUT_SECONDS)
                    if tls_info and tls_info.get("has_tls"):
                        tls_summary = tls_info
                        exp_str = f"Expires in {tls_info['days_remaining']} days" if tls_info.get('days_remaining') is not None else "Unknown expiry"
                        add_log_entry(
                            logs,
                            f"[{sanitized_target}] TLS Valid: Subject='{tls_info.get('subject_cn')}' Issuer='{tls_info.get('issuer_cn')}' ({exp_str})"
                        )
                        break

            # 5. Asset Classification & Ingestion
            asset_type = "domain"
            if is_ip_address(sanitized_target):
                asset_type = "ipv4" if "." in sanitized_target else "ipv6"
            elif sanitized_target.count(".") > 1:
                asset_type = "subdomain"

            # Determine asset status: ACTIVE if open ports, DNS A/AAAA, or HTTP reachable
            is_active = bool(open_ports or (dns_results.get("A") or dns_results.get("AAAA")) or http_summary.get("reachable"))
            asset_status = "ACTIVE" if is_active else "UNRESPONSIVE"

            # Upsert into DiscoveredAsset
            existing_asset = db.query(DiscoveredAsset).filter(
                DiscoveredAsset.scope_id == scope.id,
                DiscoveredAsset.host_or_ip == sanitized_target
            ).first()

            now = datetime.datetime.utcnow()
            if existing_asset:
                existing_asset.scan_run_id = scan_id
                existing_asset.asset_type = asset_type
                existing_asset.ip_address = primary_ip or existing_asset.ip_address
                existing_asset.status = asset_status
                existing_asset.open_ports = open_ports
                existing_asset.dns_records = dns_results
                existing_asset.http_summary = http_summary
                existing_asset.tls_summary = tls_summary
                existing_asset.last_seen = now
                asset_obj = existing_asset
            else:
                asset_obj = DiscoveredAsset(
                    scope_id=scope.id,
                    scan_run_id=scan_id,
                    host_or_ip=sanitized_target,
                    asset_type=asset_type,
                    ip_address=primary_ip,
                    status=asset_status,
                    open_ports=open_ports,
                    dns_records=dns_results,
                    http_summary=http_summary,
                    tls_summary=tls_summary,
                    first_seen=now,
                    last_seen=now
                )
                db.add(asset_obj)
                assets_discovered += 1

            db.flush() # ensure asset_obj has an id

            # 6. Phase 3: Evaluate explainable risk classification and persist deduplicated findings
            asset_findings = evaluate_and_persist_findings(
                db=db,
                scan_run_id=scan_id,
                scope_id=scope.id,
                asset=asset_obj
            )
            findings_count += len(asset_findings)

            targets_scanned += 1
            scan.targets_scanned = targets_scanned
            scan.assets_discovered_count = assets_discovered
            scan.findings_count = findings_count
            scan.logs = logs
            db.commit()

            # Mild rate limiting delay between targets
            await asyncio.sleep(settings.RATE_LIMIT_DELAY_SECONDS)

        # Mark completed
        scan.status = "COMPLETED"
        scan.completed_at = datetime.datetime.utcnow()
        add_log_entry(logs, f"Discovery run finished. Targets scanned: {targets_scanned}, Assets: {assets_discovered}, Findings: {findings_count}", "SUCCESS")
        scan.logs = logs
        db.commit()

        # Phase 2: Create immutable baseline snapshot and detect changes against previous snapshot
        try:
            snapshot = create_snapshot_for_scan(db, scan_id, scope.id)
            if snapshot:
                changes = detect_and_record_changes(db, snapshot)
                add_log_entry(logs, f"[Phase 2] Baseline snapshot created ({snapshot.asset_count} assets). Detected {len(changes)} change(s).", "SUCCESS")
                scan.logs = logs
                db.commit()
        except Exception as snap_err:
            add_log_entry(logs, f"[Phase 2] Change detection warning: {str(snap_err)}", "WARN")
            scan.logs = logs
            db.commit()

    except Exception as e:
        scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
        if scan:
            scan.status = "FAILED"
            scan.error_message = str(e)
            scan.completed_at = datetime.datetime.utcnow()
            logs = list(scan.logs or [])
            add_log_entry(logs, f"Fatal error during discovery run: {str(e)}", "ERROR")
            scan.logs = logs
            db.commit()
    finally:
        CANCELLED_SCANS.discard(scan_id)
        db.close()
