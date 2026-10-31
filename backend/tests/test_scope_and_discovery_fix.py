import pytest
from app.config import CANONICAL_DEMO_SCOPE_ID, CANONICAL_DEMO_SCOPE_NAME
from app.routers.stats import get_or_create_demo_scope
from app.models import Scope, DiscoveredAsset, ScanRun

def test_demo_scope_deterministic_id_and_idempotence(client, db):
    # Call get_or_create_demo_scope repeatedly
    scope1 = get_or_create_demo_scope(db)
    assert scope1.id == CANONICAL_DEMO_SCOPE_ID
    assert scope1.name == CANONICAL_DEMO_SCOPE_NAME

    scope2 = get_or_create_demo_scope(db)
    assert scope2.id == scope1.id

    # Verify no duplicate demo scopes exist
    demo_scopes = db.query(Scope).filter(Scope.name == CANONICAL_DEMO_SCOPE_NAME).all()
    assert len(demo_scopes) == 1

    # Verify assets count
    assets = db.query(DiscoveredAsset).filter(DiscoveredAsset.scope_id == scope1.id).all()
    assert len(assets) == 5
    assert all(a.status == "ACTIVE" for a in assets)

def test_launch_scan_on_demo_scope_completes_with_assets(client, db):
    demo_scope = get_or_create_demo_scope(db)
    
    # Launch discovery scan for this demo scope
    res = client.post("/api/scans", json={
        "scope_id": demo_scope.id,
        "config": {
            "ports": [80, 443],
            "enable_dns": True,
            "enable_ports": True,
            "enable_http": True,
            "enable_tls": True
        }
    })
    assert res.status_code == 201
    data = res.json()
    assert data["scope_id"] == demo_scope.id
    assert data["targets_total"] == 5

    # Check scan execution details
    scans_res = client.get("/api/scans")
    assert scans_res.status_code == 200
    all_scans = scans_res.json()
    latest_scan = next(s for s in all_scans if s["id"] == data["id"])
    assert latest_scan["targets_total"] == 5
    assert latest_scan["assets_discovered_count"] > 0

def test_stale_scope_id_recovery_on_scan_launch(client, db):
    demo_scope = get_or_create_demo_scope(db)
    
    # Send a request with a stale demo ID or canonical demo ID
    res = client.post("/api/scans", json={
        "scope_id": CANONICAL_DEMO_SCOPE_ID,
        "config": {"ports": [80, 443]}
    })
    assert res.status_code == 201
    assert res.json()["scope_id"] == demo_scope.id

def test_clear_demo_mode_cleans_duplicate_and_orphaned_scopes(client, db):
    demo_scope = get_or_create_demo_scope(db)
    demo_id = demo_scope.id
    
    # Create an orphaned scope with 0 assets and 0 scans
    orphan = Scope(
        name="Empty Orphan Scope",
        description="Empty",
        targets=["10.0.0.1"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Test"
    )
    db.add(orphan)
    db.commit()
    orphan_id = orphan.id

    # Clear demo mode
    clear_res = client.post("/api/demo/clear")
    assert clear_res.status_code == 200

    # Verify demo scope is cleared
    remaining_demos = db.query(Scope).filter(Scope.id == demo_id).all()
    assert len(remaining_demos) == 0

    # Verify empty orphan is cleared
    remaining_orphans = db.query(Scope).filter(Scope.id == orphan_id).all()
    assert len(remaining_orphans) == 0

def test_list_scopes_autoseeds_when_db_empty(client, db):
    # Ensure database is empty of scopes
    db.query(DiscoveredAsset).delete()
    db.query(ScanRun).delete()
    db.query(Scope).delete()
    db.commit()

    res = client.get("/api/scopes")
    assert res.status_code == 200
    scopes = res.json()
    assert len(scopes) == 1
    assert scopes[0]["id"] == CANONICAL_DEMO_SCOPE_ID
    assert scopes[0]["name"] == CANONICAL_DEMO_SCOPE_NAME
    assert len(scopes[0]["targets"]) == 5
    assert scopes[0]["asset_count"] == 5

def test_scan_launch_never_fails_with_scope_does_not_exist(client, db):
    # Wipe scopes to simulate fresh serverless container
    db.query(DiscoveredAsset).delete()
    db.query(ScanRun).delete()
    db.query(Scope).delete()
    db.commit()

    # Pass an arbitrary nonexistent UUID
    res = client.post("/api/scans", json={
        "scope_id": "nonexistent-uuid-12345",
        "config": {"ports": [80, 443]}
    })
    assert res.status_code == 201
    data = res.json()
    assert data["scope_id"] == CANONICAL_DEMO_SCOPE_ID
    assert data["targets_total"] == 5

def test_custom_user_scope_scan_execution(client, db):
    # Create custom user scope
    create_res = client.post("/api/scopes", json={
        "name": "Custom Security Scope",
        "description": "User created scope",
        "targets": ["api.demo-corp.internal"],
        "allow_local_lab": True,
        "authorised_confirmation": True,
        "authorised_by": "Lead SecOps"
    })
    assert create_res.status_code == 201
    custom_scope = create_res.json()
    assert custom_scope["name"] == "Custom Security Scope"

    # Launch scan on custom scope
    scan_res = client.post("/api/scans", json={
        "scope_id": custom_scope["id"],
        "config": {"ports": [443, 8443]}
    })
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["scope_id"] == custom_scope["id"]
    assert scan_data["targets_total"] == 1

