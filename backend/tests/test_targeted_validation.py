import asyncio
import datetime
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Scope, ScanRun, DiscoveredAsset, ScanFinding
from app.discovery.engine import execute_discovery_run, cancel_scan, is_scan_cancelled
from app.security import validate_target, check_ip_safety, resolve_and_verify_target
import ipaddress

# 1. Scope creation and retrieval
def test_scope_creation_and_retrieval(client: TestClient):
    payload = {
        "name": "Audit Target Scope Alpha",
        "description": "Scope for targeted security testing",
        "targets": ["app.example.com", "api.example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": True,
        "authorised_by": "SecOps Tester"
    }
    create_res = client.post("/api/scopes", json=payload)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["id"] is not None
    assert created["name"] == "Audit Target Scope Alpha"
    assert len(created["targets"]) == 2

    # Retrieval
    get_res = client.get(f"/api/scopes/{created['id']}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["id"] == created["id"]
    assert retrieved["authorised_by"] == "SecOps Tester"

# 2. Stale scope ID handling
def test_stale_scope_id_handling(client: TestClient):
    stale_id = "00000000-0000-0000-0000-000000000000"
    get_res = client.get(f"/api/scopes/{stale_id}")
    assert get_res.status_code == 404
    assert "does not exist" in get_res.json()["detail"].lower()

    # Stale scope ID cannot launch a scan
    scan_res = client.post("/api/scans", json={"scope_id": stale_id})
    assert scan_res.status_code == 404
    assert "does not exist" in scan_res.json()["detail"].lower()

# 3. Scan launch with a valid scope
def test_scan_launch_with_valid_scope(client: TestClient):
    scope_payload = {
        "name": "Valid Scan Scope",
        "targets": ["target.example.org"],
        "allow_local_lab": False,
        "authorised_confirmation": True,
        "authorised_by": "Audit Lead"
    }
    scope_res = client.post("/api/scopes", json=scope_payload)
    assert scope_res.status_code == 201
    scope_id = scope_res.json()["id"]

    scan_res = client.post("/api/scans", json={"scope_id": scope_id, "config": {"ports": [80, 443]}})
    assert scan_res.status_code == 201
    scan = scan_res.json()
    assert scan["scope_id"] == scope_id
    assert scan["status"] in ("PENDING", "IN_PROGRESS", "COMPLETED")
    assert scan["targets_total"] == 1
    assert scan["targets_scanned"] == 0
    assert scan["assets_discovered_count"] == 0
    assert scan["new_assets_count"] == 0
    assert scan["updated_assets_count"] == 0

# 4. Scan launch with an invalid scope
def test_scan_launch_with_invalid_scope(client: TestClient):
    # Non-existent scope ID
    bad_res = client.post("/api/scans", json={"scope_id": "non-existent-scope-id"})
    assert bad_res.status_code == 404
    assert "does not exist" in bad_res.json()["detail"].lower()

    # Scope with empty targets is rejected at scope creation
    empty_targets_res = client.post("/api/scopes", json={
        "name": "Empty Targets",
        "targets": [],
        "authorised_confirmation": True,
        "authorised_by": "Tester"
    })
    assert empty_targets_res.status_code in (400, 422)

    # Scope without confirmation
    unconfirmed_res = client.post("/api/scopes", json={
        "name": "Unconfirmed",
        "targets": ["test.com"],
        "authorised_confirmation": False,
        "authorised_by": "Tester"
    })
    assert unconfirmed_res.status_code == 400

# 5. DNS failure handling
@pytest.mark.asyncio
async def test_dns_failure_handling(db: Session):
    scope = Scope(
        name="DNS Failure Scope",
        targets=["offline.unresolvable.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Tester"
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    scan = ScanRun(
        scope_id=scope.id,
        status="PENDING",
        config={"enable_dns": True, "enable_ports": False, "enable_http": False, "enable_tls": False},
        targets_total=1,
        targets_scanned=0,
        assets_discovered_count=0,
        new_assets_count=0,
        updated_assets_count=0,
        failed_targets_count=0,
        total_assets_count=0,
        findings_count=0,
        logs=[]
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Mock DNS resolution returning empty A/AAAA records
    with patch("app.discovery.engine.resolve_dns_records", new_callable=AsyncMock) as mock_dns:
        mock_dns.return_value = {
            "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [],
            "error": "NXDOMAIN", "is_synthetic_demo": True
        }
        await execute_discovery_run(scan.id)

    db.refresh(scan)
    assert scan.status == "COMPLETED"
    assert scan.targets_scanned == 1
    assert scan.failed_targets_count == 1
    # Asset was ingested as UNRESOLVED
    asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.scope_id == scope.id).first()
    assert asset is not None
    assert asset.status == "UNRESOLVED"
    assert asset.host_or_ip == "offline.unresolvable.internal"

# 6. Asset insertion & 7. Existing asset updates & 8. Correct asset counters
@pytest.mark.asyncio
async def test_asset_insertion_and_updates_and_counters(db: Session):
    scope = Scope(
        name="Asset Lifecycle Scope",
        targets=["test-target.example.org"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Tester"
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    # --- Run 1: First scan should insert new asset ---
    scan1 = ScanRun(
        scope_id=scope.id,
        status="PENDING",
        config={"enable_dns": True, "enable_ports": True, "enable_http": False, "enable_tls": False},
        targets_total=1,
        targets_scanned=0,
        assets_discovered_count=0,
        new_assets_count=0,
        updated_assets_count=0,
        failed_targets_count=0,
        total_assets_count=0,
        findings_count=0,
        logs=[]
    )
    db.add(scan1)
    db.commit()
    db.refresh(scan1)

    with patch("app.discovery.engine.resolve_dns_records", new_callable=AsyncMock) as mock_dns, \
         patch("app.discovery.engine.scan_allowed_ports", new_callable=AsyncMock) as mock_ports, \
         patch("app.discovery.engine.resolve_and_verify_target") as mock_verify:
        mock_dns.return_value = {"A": ["10.0.0.15"], "AAAA": [], "error": None}
        mock_verify.return_value = (True, "10.0.0.15", None)
        mock_ports.return_value = [{"port": 80, "status": "OPEN", "service": "HTTP", "latency_ms": 10.0}]

        await execute_discovery_run(scan1.id)

    db.refresh(scan1)
    assert scan1.status == "COMPLETED"
    assert scan1.targets_scanned == 1
    assert scan1.new_assets_count == 1
    assert scan1.assets_discovered_count == 1
    assert scan1.updated_assets_count == 0
    assert scan1.total_assets_count == 1
    assert scan1.failed_targets_count == 0

    first_asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.scope_id == scope.id).first()
    assert first_asset is not None
    assert first_asset.status == "ACTIVE"
    first_seen_time = first_asset.first_seen

    # --- Run 2: Second scan on the same target should update existing asset, NOT insert duplicate ---
    scan2 = ScanRun(
        scope_id=scope.id,
        status="PENDING",
        config={"enable_dns": True, "enable_ports": True, "enable_http": False, "enable_tls": False},
        targets_total=1,
        targets_scanned=0,
        assets_discovered_count=0,
        new_assets_count=0,
        updated_assets_count=0,
        failed_targets_count=0,
        total_assets_count=0,
        findings_count=0,
        logs=[]
    )
    db.add(scan2)
    db.commit()
    db.refresh(scan2)

    with patch("app.discovery.engine.resolve_dns_records", new_callable=AsyncMock) as mock_dns, \
         patch("app.discovery.engine.scan_allowed_ports", new_callable=AsyncMock) as mock_ports, \
         patch("app.discovery.engine.resolve_and_verify_target") as mock_verify:
        mock_dns.return_value = {"A": ["10.0.0.15"], "AAAA": [], "error": None}
        mock_verify.return_value = (True, "10.0.0.15", None)
        mock_ports.return_value = [{"port": 80, "status": "OPEN", "service": "HTTP", "latency_ms": 12.0}]

        await execute_discovery_run(scan2.id)

    db.refresh(scan2)
    assert scan2.status == "COMPLETED"
    assert scan2.targets_scanned == 1
    assert scan2.new_assets_count == 0
    assert scan2.assets_discovered_count == 0
    assert scan2.updated_assets_count == 1
    assert scan2.total_assets_count == 1
    assert scan2.failed_targets_count == 0

    # 9. Duplicate prevention check:
    total_assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.scope_id == scope.id).count()
    assert total_assets == 1, "Duplicate asset was created instead of updating existing record!"

# 10. SSRF protection
def test_ssrf_guardrails_enforcement():
    # Cloud metadata is always blocked, even in local lab mode
    meta_ip = ipaddress.ip_address("169.254.169.254")
    is_safe, reason = check_ip_safety(meta_ip, allow_local_lab=True)
    assert not is_safe
    assert "cloud metadata" in reason.lower()

    # Loopback blocked without local lab mode
    loopback_ip = ipaddress.ip_address("127.0.0.1")
    is_safe_lb, reason_lb = check_ip_safety(loopback_ip, allow_local_lab=False)
    assert not is_safe_lb
    assert "loopback" in reason_lb.lower()

    # Private RFC 1918 blocked without local lab mode
    priv_ip = ipaddress.ip_address("10.50.0.1")
    is_safe_priv, reason_priv = check_ip_safety(priv_ip, allow_local_lab=False)
    assert not is_safe_priv
    assert "private/internal" in reason_priv.lower()

    # Target validation also blocks dangerous syntax
    is_val, _, err = validate_target("target.com;cat /etc/passwd")
    assert not is_val

# 11. Scan cancellation
def test_scan_cancellation_mechanism():
    test_scan_id = "test-cancellation-id-12345"
    assert not is_scan_cancelled(test_scan_id)
    cancel_scan(test_scan_id)
    assert is_scan_cancelled(test_scan_id)

# 12. Demo seed consistency
def test_demo_seed_consistency(client: TestClient):
    # Seed demo mode
    seed_res = client.post("/api/demo/seed")
    assert seed_res.status_code == 200
    data = seed_res.json()
    assert "scope_id" in data
    assert data["assets_count"] == 5

    # Check overview
    ov_res = client.get("/api/stats/overview")
    assert ov_res.status_code == 200
    overview = ov_res.json()
    assert overview["total_scopes"] >= 1
    assert overview["total_assets"] >= 5
    assert overview["active_assets"] >= 5
    assert overview["last_scan"] is not None
    assert overview["last_scan"]["new_assets_count"] == 5
    assert overview["last_scan"]["total_assets_count"] == 5

    # Check assets contain synthetic demo flag
    assets_res = client.get("/api/assets")
    assert assets_res.status_code == 200
    assets = assets_res.json()
    demo_assets = [a for a in assets if "demo-corp" in a["host_or_ip"] or a["host_or_ip"] == "192.168.10.45"]
    assert len(demo_assets) == 5
    for a in demo_assets:
        dns_rec = a.get("dns_records") or {}
        assert dns_rec.get("is_synthetic_demo") is True or a["host_or_ip"].endswith(".internal")

    # Clear demo
    clear_res = client.post("/api/demo/clear")
    assert clear_res.status_code == 200

# 13. Historical DNS record preservation on subsequent resolution failure
@pytest.mark.asyncio
async def test_historical_dns_evidence_preservation_on_subsequent_failure(db: Session):
    scope = Scope(
        name="Historical DNS Scope",
        targets=["vpn.demo-corp.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Tester"
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    # Initial asset with historical IP and DNS records
    initial_asset = DiscoveredAsset(
        scope_id=scope.id,
        host_or_ip="vpn.demo-corp.internal",
        asset_type="subdomain",
        ip_address="192.168.10.30",
        status="ACTIVE",
        open_ports=[{"port": 443, "service": "HTTPS", "status": "OPEN"}],
        dns_records={"A": ["192.168.10.30"], "AAAA": [], "is_synthetic_demo": True},
        http_summary={},
        tls_summary={},
        first_seen=datetime.datetime.utcnow() - datetime.timedelta(days=2),
        last_seen=datetime.datetime.utcnow() - datetime.timedelta(days=1)
    )
    db.add(initial_asset)
    db.commit()
    db.refresh(initial_asset)

    # Now launch a new discovery run where DNS lookup fails (NXDOMAIN)
    scan = ScanRun(
        scope_id=scope.id,
        status="PENDING",
        config={"enable_dns": True, "enable_ports": False, "enable_http": False, "enable_tls": False},
        targets_total=1,
        targets_scanned=0,
        assets_discovered_count=0,
        new_assets_count=0,
        updated_assets_count=0,
        failed_targets_count=0,
        total_assets_count=1,
        findings_count=0,
        logs=[]
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with patch("app.discovery.engine.resolve_dns_records", new_callable=AsyncMock) as mock_dns:
        mock_dns.return_value = {
            "A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [],
            "error": "NXDOMAIN", "is_synthetic_demo": True
        }
        await execute_discovery_run(scan.id)

    db.refresh(scan)
    assert scan.status == "COMPLETED"
    assert scan.failed_targets_count == 1
    assert scan.updated_assets_count == 1

    db.refresh(initial_asset)
    # Asset must be marked UNRESPONSIVE (not UNRESOLVED, because verified historical resolution existed)
    assert initial_asset.status == "UNRESPONSIVE"
    # Historical IP must be preserved
    assert initial_asset.ip_address == "192.168.10.30"
    # Historical A records must be preserved and not wiped!
    assert initial_asset.dns_records.get("A") == ["192.168.10.30"]
    assert initial_asset.dns_records.get("current_resolution_failed") is True
    assert initial_asset.dns_records.get("historical_preserved") is True


