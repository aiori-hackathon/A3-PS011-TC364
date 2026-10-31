from datetime import datetime, timezone
from app.models import Scope, ScanRun, DiscoveredAsset, AssetSnapshot, AssetChangeRecord
from app.discovery.change_detector import create_snapshot_for_scan, detect_and_record_changes

def test_snapshot_creation_and_rejection_for_incomplete(db):
    scope = Scope(
        name="Production Assets",
        targets=["app.example.com"],
        authorised_confirmation=True,
        authorised_by="Security Lead"
    )
    db.add(scope)
    db.commit()

    failed_scan = ScanRun(
        scope_id=scope.id,
        status="FAILED",
        config={},
        targets_total=1,
        targets_scanned=1
    )
    db.add(failed_scan)
    db.commit()

    # Incomplete or failed scan must not create a baseline snapshot
    snap_failed = create_snapshot_for_scan(db, failed_scan.id, scope.id)
    assert snap_failed is None

    # Completed scan creates a valid snapshot
    completed_scan = ScanRun(
        scope_id=scope.id,
        status="COMPLETED",
        config={},
        targets_total=1,
        targets_scanned=1
    )
    db.add(completed_scan)
    db.commit()

    asset1 = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=completed_scan.id,
        host_or_ip="app.example.com",
        asset_type="subdomain",
        ip_address="93.184.216.34",
        status="ACTIVE",
        open_ports=[{"port": 443, "service": "HTTPS", "status": "OPEN"}],
        dns_records={"A": ["93.184.216.34"]},
        http_summary={"reachable": True, "status_code": 200, "server": "nginx"},
        tls_summary={"has_tls": True, "subject_cn": "app.example.com", "days_remaining": 60}
    )
    db.add(asset1)
    db.commit()

    snap_ok = create_snapshot_for_scan(db, completed_scan.id, scope.id)
    assert snap_ok is not None
    assert snap_ok.asset_count == 1
    assert snap_ok.snapshot_data[0]["host_or_ip"] == "app.example.com"

def test_initial_baseline_change_detection(db):
    scope = Scope(
        name="Scope 1",
        targets=["api.example.com"],
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    scan1 = ScanRun(
        scope_id=scope.id,
        status="COMPLETED",
        config={},
        targets_total=1,
        targets_scanned=1
    )
    db.add(scan1)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan1.id,
        host_or_ip="api.example.com",
        asset_type="subdomain",
        ip_address="10.0.0.1",
        status="ACTIVE",
        open_ports=[{"port": 443, "service": "HTTPS"}]
    )
    db.add(asset)
    db.commit()

    snap1 = create_snapshot_for_scan(db, scan1.id, scope.id)
    changes = detect_and_record_changes(db, snap1)

    assert len(changes) == 1
    assert changes[0].change_type == "ASSET_ADDED"
    assert changes[0].asset_identifier == "api.example.com"
    assert changes[0].from_snapshot_id is None
    assert changes[0].to_snapshot_id == snap1.id

def test_subsequent_scan_modifications_and_add_remove(db):
    scope = Scope(
        name="Scope 2",
        targets=["web.example.com", "db.example.com"],
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    # Scan 1: initial baseline
    scan1 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan1)
    db.commit()

    asset_web = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan1.id,
        host_or_ip="web.example.com",
        asset_type="subdomain",
        ip_address="10.0.0.10",
        status="ACTIVE",
        open_ports=[{"port": 80, "service": "HTTP"}],
        dns_records={"A": ["10.0.0.10"]},
        http_summary={"reachable": True, "status_code": 200, "server": "apache"},
        tls_summary={"has_tls": False}
    )
    asset_db = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan1.id,
        host_or_ip="db.example.com",
        asset_type="subdomain",
        ip_address="10.0.0.20",
        status="ACTIVE",
        open_ports=[{"port": 3306, "service": "MySQL"}]
    )
    db.add_all([asset_web, asset_db])
    db.commit()

    snap1 = create_snapshot_for_scan(db, scan1.id, scope.id)
    detect_and_record_changes(db, snap1)

    # Scan 2:
    # 1. web.example.com: IP changed from 10.0.0.10 to 10.0.0.15, port 80 closed, port 443 opened, TLS enabled, HTTP 301
    # 2. db.example.com: removed (not in scan)
    # 3. new.example.com: added
    scan2 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan2)
    db.commit()

    # Update web.example.com
    asset_web.scan_run_id = scan2.id
    asset_web.ip_address = "10.0.0.15"
    asset_web.open_ports = [{"port": 443, "service": "HTTPS"}]
    asset_web.dns_records = {"A": ["10.0.0.15"]}
    asset_web.http_summary = {"reachable": True, "status_code": 301, "server": "nginx"}
    asset_web.tls_summary = {"has_tls": True, "subject_cn": "web.example.com", "valid_to": "2027-01-01"}

    # Delete db.example.com from current active scope inventory to simulate removal
    db.delete(asset_db)

    # Add new.example.com
    asset_new = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan2.id,
        host_or_ip="new.example.com",
        asset_type="subdomain",
        ip_address="10.0.0.99",
        status="ACTIVE",
        open_ports=[{"port": 8080, "service": "HTTP-Alt"}]
    )
    db.add(asset_new)
    db.commit()

    snap2 = create_snapshot_for_scan(db, scan2.id, scope.id)
    changes = detect_and_record_changes(db, snap2)

    change_types = [c.change_type for c in changes]
    assert "ASSET_ADDED" in change_types
    assert "ASSET_REMOVED" in change_types
    assert "IP_CHANGED" in change_types
    assert "DNS_CHANGED" in change_types
    assert "PORT_OPENED" in change_types
    assert "PORT_CLOSED" in change_types
    assert "HTTP_STATUS_CHANGED" in change_types
    assert "TLS_CHANGED" in change_types

    # Test idempotency: calling detect_and_record_changes again replaces cleanly without duplicate rows
    changes_again = detect_and_record_changes(db, snap2)
    assert len(changes_again) == len(changes)

    total_records = db.query(AssetChangeRecord).filter(AssetChangeRecord.to_snapshot_id == snap2.id).count()
    assert total_records == len(changes)

def test_inconclusive_flag_on_unresponsive_removal(db):
    scope = Scope(
        name="Scope Inconclusive",
        targets=["lab.example.com"],
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    # Snapshot 1 with UNRESPONSIVE asset
    scan1 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan1)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan1.id,
        host_or_ip="lab.example.com",
        asset_type="subdomain",
        ip_address=None,
        status="UNRESPONSIVE",
        open_ports=[]
    )
    db.add(asset)
    db.commit()

    snap1 = create_snapshot_for_scan(db, scan1.id, scope.id)
    detect_and_record_changes(db, snap1)

    # In scan 2, asset is removed from inventory
    scan2 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan2)
    db.delete(asset)
    db.commit()

    snap2 = create_snapshot_for_scan(db, scan2.id, scope.id)
    changes = detect_and_record_changes(db, snap2)

    assert len(changes) == 1
    assert changes[0].change_type == "ASSET_REMOVED"
    assert changes[0].is_inconclusive is True

def test_api_endpoints_for_changes_and_snapshots(client, db):
    scope = Scope(
        name="API Test Scope",
        targets=["api1.test.com"],
        authorised_confirmation=True,
        authorised_by="Auditor"
    )
    db.add(scope)
    db.commit()

    scan = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan.id,
        host_or_ip="api1.test.com",
        asset_type="subdomain",
        status="ACTIVE"
    )
    db.add(asset)
    db.commit()

    snap = create_snapshot_for_scan(db, scan.id, scope.id)
    detect_and_record_changes(db, snap)

    # 1. GET /api/snapshots
    r_snaps = client.get(f"/api/snapshots?scope_id={scope.id}")
    assert r_snaps.status_code == 200
    snaps_data = r_snaps.json()
    assert len(snaps_data) == 1
    assert snaps_data[0]["id"] == snap.id

    # 2. GET /api/snapshots/{id}
    r_snap_single = client.get(f"/api/snapshots/{snap.id}")
    assert r_snap_single.status_code == 200
    assert r_snap_single.json()["asset_count"] == 1

    # 3. GET /api/changes
    r_changes = client.get(f"/api/changes?scope_id={scope.id}&change_type=ASSET_ADDED")
    assert r_changes.status_code == 200
    changes_data = r_changes.json()
    assert len(changes_data) == 1
    change_id = changes_data[0]["id"]
    assert changes_data[0]["asset_identifier"] == "api1.test.com"

    # 4. GET /api/changes/{id}
    r_change_single = client.get(f"/api/changes/{change_id}")
    assert r_change_single.status_code == 200
    assert r_change_single.json()["id"] == change_id

    # 5. GET /api/assets/{id}/changes
    r_asset_changes = client.get(f"/api/assets/{asset.id}/changes")
    assert r_asset_changes.status_code == 200
    assert len(r_asset_changes.json()) == 1

    # 6. GET /api/stats/overview includes total_changes
    r_stats = client.get("/api/stats/overview")
    assert r_stats.status_code == 200
    stats_data = r_stats.json()
    assert stats_data["total_changes"] >= 1
    assert "ASSET_ADDED" in stats_data["changes_by_type"]
