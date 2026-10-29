import pytest
from app.models import Scope, NotificationRule, NotificationEvent, DiscoveredAsset, ScanFinding, AssetChangeRecord
from app.services.notification_service import (
    set_mock_delivery_override,
    evaluate_new_asset_rules,
    evaluate_change_rules,
    evaluate_finding_rules,
    compute_dedup_hash,
    is_duplicate_event
)

@pytest.fixture(autouse=True)
def mock_notifications_mode():
    set_mock_delivery_override(True)
    yield
    set_mock_delivery_override(False)

def test_integration_status_endpoint_never_exposes_secrets(client):
    res = client.get("/api/notifications/integrations/status")
    assert res.status_code == 200
    data = res.json()
    assert "live_notifications_enabled" in data
    assert "email_integration" in data
    assert "webhook_integration" in data
    # Ensure zero passwords or tokens
    assert "password" not in str(data).lower()
    assert "secret" not in str(data).lower()
    assert "token" not in str(data).lower()

def test_webhook_url_ssrf_protection_on_rule_creation(client, db):
    # 1. Cloud metadata IP must be blocked
    res = client.post("/api/notifications/rules", json={
        "name": "Cloud Metadata Exploit",
        "event_type": "ASSET_DISCOVERED",
        "channels": ["webhook"],
        "webhook_url": "http://169.254.169.254/latest/meta-data/"
    })
    assert res.status_code == 400
    assert "prohibited cloud metadata endpoint" in res.json()["detail"].lower()

    # 2. Loopback without lab mode must be blocked
    res = client.post("/api/notifications/rules", json={
        "name": "Localhost SSRF",
        "event_type": "ASSET_DISCOVERED",
        "channels": ["webhook"],
        "webhook_url": "http://127.0.0.1:8080/hook"
    })
    assert res.status_code == 400
    assert "loopback" in res.json()["detail"].lower() or "blocked" in res.json()["detail"].lower()

    # 3. Invalid schemes must be blocked
    res = client.post("/api/notifications/rules", json={
        "name": "FTP Scheme",
        "event_type": "ASSET_DISCOVERED",
        "channels": ["webhook"],
        "webhook_url": "ftp://example.com/hook"
    })
    assert res.status_code == 400
    assert "scheme" in res.json()["detail"].lower()

    # 4. Embedded credentials must be blocked
    res = client.post("/api/notifications/rules", json={
        "name": "Credential Leak",
        "event_type": "ASSET_DISCOVERED",
        "channels": ["webhook"],
        "webhook_url": "https://admin:secretpass@example.com/hook"
    })
    assert res.status_code == 400
    assert "credentials" in res.json()["detail"].lower()

def test_notification_rule_crud_and_audit(client, db):
    scope = Scope(
        name="Notification Test Scope",
        targets=["example.com"],
        allow_local_lab=False,
        authorised_confirmation=True,
        authorised_by="SecOps Lead"
    )
    db.add(scope)
    db.commit()

    # Create rule
    create_res = client.post("/api/notifications/rules", json={
        "name": "Critical Risks Webhook",
        "description": "Alert on Critical findings",
        "event_type": "FINDING_DETECTED",
        "scope_id": scope.id,
        "conditions": {"severities": ["CRITICAL", "HIGH"]},
        "channels": ["webhook"],
        "webhook_url": "https://hooks.security.example.com/alerts"
    })
    assert create_res.status_code == 201
    rule_id = create_res.json()["id"]

    # Read rule
    get_res = client.get(f"/api/notifications/rules/{rule_id}")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Critical Risks Webhook"

    # Update rule
    put_res = client.put(f"/api/notifications/rules/{rule_id}", json={
        "name": "Critical & High Risks Webhook",
        "is_enabled": False
    })
    assert put_res.status_code == 200
    assert put_res.json()["name"] == "Critical & High Risks Webhook"
    assert put_res.json()["is_enabled"] is False

    # Delete rule
    del_res = client.delete(f"/api/notifications/rules/{rule_id}")
    assert del_res.status_code == 204

    # Verify deleted
    assert client.get(f"/api/notifications/rules/{rule_id}").status_code == 404

def test_notification_matching_and_deduplication(client, db):
    scope = Scope(
        name="Audit Scope",
        targets=["sec.corp.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps Audit"
    )
    db.add(scope)
    db.commit()

    # Create rule for ASSET_DISCOVERED
    rule = NotificationRule(
        name="Asset Alert",
        event_type="ASSET_DISCOVERED",
        scope_id=scope.id,
        channels=["webhook"],
        webhook_url="https://secops.example.com/webhook",
        is_enabled=True
    )
    db.add(rule)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        host_or_ip="api.sec.corp.internal",
        asset_type="subdomain",
        status="ACTIVE",
        open_ports=[{"port": 443, "service": "https"}]
    )
    db.add(asset)
    db.commit()

    # 1. Trigger evaluation
    evaluate_new_asset_rules(db, scope.id, asset)

    events = db.query(NotificationEvent).filter(NotificationEvent.rule_id == rule.id).all()
    assert len(events) == 1
    assert events[0].status == "SENT"
    assert "api.sec.corp.internal" in events[0].subject

    # 2. Trigger again - must deduplicate and NOT generate duplicate event
    evaluate_new_asset_rules(db, scope.id, asset)
    events_after = db.query(NotificationEvent).filter(NotificationEvent.rule_id == rule.id).all()
    assert len(events_after) == 1  # No duplicate created

def test_notification_delivery_failure_and_retry(client, db):
    scope = Scope(
        name="Fail Scope",
        targets=["bad.example.com"],
        allow_local_lab=False,
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    # Create an event directly in FAILED status
    event = NotificationEvent(
        scope_id=scope.id,
        event_type="FINDING_DETECTED",
        channel="webhook",
        recipient="https://unreachable.invalid.corp/hook",
        subject="[Test] Failed event",
        message="Failure payload",
        status="FAILED",
        error_message="Connection timed out",
        retry_count=3,
        max_retries=3
    )
    db.add(event)
    db.commit()

    # Trigger retry endpoint
    res = client.post(f"/api/notifications/history/{event.id}/retry")
    assert res.status_code == 200
    data = res.json()
    # With mock override active in fixture, retry succeeds and marks SENT
    assert data["status"] == "SENT"
    assert data["error_message"] is None
