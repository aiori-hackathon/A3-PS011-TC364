import pytest
from datetime import datetime, timedelta
from app.models import Scope, ScanRun, DiscoverySchedule, AuditLog
from app.services.schedule_service import compute_next_run, trigger_schedule_execution

def test_schedule_frequency_calculation():
    base = datetime(2026, 1, 1, 12, 0, 0)
    
    # Daily
    next_daily = compute_next_run("DAILY", from_time=base)
    assert next_daily == base + timedelta(hours=24)
    
    # Weekly
    next_weekly = compute_next_run("WEEKLY", from_time=base)
    assert next_weekly == base + timedelta(hours=168)
    
    # 6 hours
    next_6h = compute_next_run("HOURLY_6", from_time=base)
    assert next_6h == base + timedelta(hours=6)
    
    # Custom 48 hours
    next_custom = compute_next_run("CUSTOM", interval_hours=48, from_time=base)
    assert next_custom == base + timedelta(hours=48)

def test_create_schedule_unauthorised_scope_fails(client, db):
    scope = Scope(
        name="Unauthorised Scope",
        targets=["example.com"],
        allow_local_lab=False,
        authorised_confirmation=False, # NOT confirmed
        authorised_by="Tester"
    )
    db.add(scope)
    db.commit()

    res = client.post("/api/schedules", json={
        "scope_id": scope.id,
        "name": "Daily Recon",
        "frequency": "DAILY",
        "interval_hours": 24
    })
    assert res.status_code == 400
    assert "authorised" in res.json()["detail"].lower()

def test_create_and_get_schedule_success(client, db):
    scope = Scope(
        name="Authorised Scope",
        targets=["secops.test"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps Director"
    )
    db.add(scope)
    db.commit()

    res = client.post("/api/schedules", json={
        "scope_id": scope.id,
        "name": "Nightly Asset Sweep",
        "description": "Scans every 24 hours for new assets and ports",
        "frequency": "DAILY",
        "interval_hours": 24,
        "is_enabled": True,
        "config": {"ports": [80, 443, 8080], "enable_dns": True}
    })
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Nightly Asset Sweep"
    assert data["scope_id"] == scope.id
    assert data["scope_name"] == "Authorised Scope"
    assert data["frequency"] == "DAILY"
    assert data["interval_hours"] == 24
    assert data["is_enabled"] is True
    assert data["next_run_at"] is not None

    # Verify audit log was created
    audit = db.query(AuditLog).filter(
        AuditLog.action == "SCHEDULE_CREATED",
        AuditLog.entity_id == data["id"]
    ).first()
    assert audit is not None
    assert audit.details["name"] == "Nightly Asset Sweep"

    # Get single schedule
    get_res = client.get(f"/api/schedules/{data['id']}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == data["id"]

    # List schedules
    list_res = client.get("/api/schedules")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

def test_update_and_toggle_schedule(client, db):
    scope = Scope(
        name="Scoped Target",
        targets=["target.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="Lead SecOps"
    )
    db.add(scope)
    db.commit()

    create_res = client.post("/api/schedules", json={
        "scope_id": scope.id,
        "name": "Hourly Check",
        "frequency": "HOURLY_6",
        "interval_hours": 6,
        "is_enabled": True
    })
    schedule_id = create_res.json()["id"]

    # Toggle disable
    patch_res = client.patch(f"/api/schedules/{schedule_id}", json={
        "is_enabled": False,
        "name": "Paused Check"
    })
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["is_enabled"] is False
    assert updated["name"] == "Paused Check"

    # Verify audit log
    audit = db.query(AuditLog).filter(
        AuditLog.action == "SCHEDULE_UPDATED",
        AuditLog.entity_id == schedule_id
    ).first()
    assert audit is not None

def test_manual_trigger_and_concurrency_protection(client, db):
    scope = Scope(
        name="Production Surface",
        targets=["prod.secops.test"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="CISO"
    )
    db.add(scope)
    db.commit()

    create_res = client.post("/api/schedules", json={
        "scope_id": scope.id,
        "name": "Production Schedule",
        "frequency": "DAILY",
        "interval_hours": 24,
        "is_enabled": True
    })
    schedule_id = create_res.json()["id"]

    # 1. Trigger manually
    trigger_res = client.post(f"/api/schedules/{schedule_id}/trigger")
    assert trigger_res.status_code == 200
    scan_data = trigger_res.json()
    assert scan_data["is_scheduled"] is True
    assert scan_data["schedule_id"] == schedule_id
    assert scan_data["status"] in ("PENDING", "IN_PROGRESS", "COMPLETED")

    # 2. Attempt duplicate trigger while scan is active (scope has active scan)
    # Ensure active scan is IN_PROGRESS
    active_scan = db.query(ScanRun).filter(ScanRun.id == scan_data["id"]).first()
    active_scan.status = "IN_PROGRESS"
    db.commit()

    duplicate_res = client.post(f"/api/schedules/{schedule_id}/trigger")
    assert duplicate_res.status_code == 409
    assert "already" in duplicate_res.json()["detail"].lower()

    # 3. Check executions history
    exec_res = client.get(f"/api/schedules/{schedule_id}/executions")
    assert exec_res.status_code == 200
    executions = exec_res.json()
    assert len(executions) >= 1
    assert executions[0]["id"] == scan_data["id"]

def test_delete_schedule_preserves_historical_scans(client, db):
    scope = Scope(
        name="Audit Scope 2",
        targets=["scope2.test"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    create_res = client.post("/api/schedules", json={
        "scope_id": scope.id,
        "name": "Deletable Schedule",
        "frequency": "DAILY",
        "interval_hours": 24,
        "is_enabled": True
    })
    schedule_id = create_res.json()["id"]

    # Create a historical scan linked to this schedule
    historical_scan = ScanRun(
        scope_id=scope.id,
        schedule_id=schedule_id,
        is_scheduled=True,
        status="COMPLETED"
    )
    db.add(historical_scan)
    db.commit()
    scan_id = historical_scan.id

    # Delete schedule
    del_res = client.delete(f"/api/schedules/{schedule_id}")
    assert del_res.status_code == 200

    # Verify schedule is deleted
    assert db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first() is None

    # Verify scan is preserved!
    preserved_scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    assert preserved_scan is not None
    assert preserved_scan.id == scan_id
