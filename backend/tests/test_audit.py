import pytest
from app.models import Scope, ScanFinding, ScanRun, AuditLog
from app.services.audit_service import log_audit_event, sanitize_audit_details

def test_audit_sensitive_redaction():
    raw_details = {
        "username": "secops_admin",
        "password": "SuperSecretPassword123!",
        "api_token": "bearer_abc123456",
        "smtp_credentials": {"auth_key": "xyz987", "host": "smtp.internal"},
        "clean_field": "public_domain.com"
    }
    sanitized = sanitize_audit_details(raw_details)
    assert sanitized["username"] == "secops_admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_token"] == "[REDACTED]"
    assert sanitized["smtp_credentials"]["auth_key"] == "[REDACTED]"
    assert sanitized["smtp_credentials"]["host"] == "smtp.internal"
    assert sanitized["clean_field"] == "public_domain.com"

def test_audit_log_endpoint_and_summary(client, db):
    scope = Scope(
        name="Audit Scope",
        targets=["audit.test"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    scan = ScanRun(scope_id=scope.id, status="COMPLETED")
    db.add(scan)
    db.commit()

    finding = ScanFinding(
        scope_id=scope.id,
        scan_run_id=scan.id,
        finding_type="PORT",
        title="Open Port 22 SSH",
        severity="MEDIUM",
        review_status="OPEN"
    )
    db.add(finding)
    db.commit()

    # 1. Update finding status to trigger audit log
    patch_res = client.patch(f"/api/findings/{finding.id}/status", json={
        "review_status": "IN_REVIEW",
        "note": "Assigned to network team"
    })
    assert patch_res.status_code == 200

    # 2. Query audit logs
    audit_res = client.get("/api/audit")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    assert len(logs) >= 1

    finding_audit = next((l for l in logs if l["action"] == "FINDING_STATUS_UPDATED"), None)
    assert finding_audit is not None
    assert finding_audit["entity_type"] == "finding"
    assert finding_audit["entity_id"] == finding.id
    assert finding_audit["details"]["new_status"] == "IN_REVIEW"

    # 3. Query audit summary
    summary_res = client.get("/api/audit/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_events"] >= 1
    assert "FINDING_STATUS_UPDATED" in summary["by_action"]
