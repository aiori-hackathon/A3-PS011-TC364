import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app.models import Scope, ScanRun, DiscoveredAsset, ScanFinding
from app.discovery.risk_classifier import evaluate_and_persist_findings

def test_explainable_risk_classification_rules(db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    scope = Scope(
        name="Security Evaluation Scope",
        targets=["db.example.com"],
        authorised_confirmation=True,
        authorised_by="Lead Assessor"
    )
    db.add(scope)
    db.commit()

    scan = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan)
    db.commit()

    # Asset with multiple risk vectors:
    # 1. MySQL port 3306 open (sensitive database exposure -> MEDIUM)
    # 2. Redis port 6379 open (unauthenticated key-value store -> HIGH)
    # 3. Port 443 standard HTTPS (standard web service -> INFORMATIONAL, NOT vulnerable just because open)
    # 4. Expired TLS certificate (valid_to in past -> HIGH)
    # 5. Permissive SPF (+all -> HIGH)
    # 6. HTTP 500 error (server error -> MEDIUM)
    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan.id,
        host_or_ip="db.example.com",
        asset_type="subdomain",
        ip_address="10.10.10.50",
        status="ACTIVE",
        open_ports=[
            {"port": 3306, "service": "MySQL", "status": "OPEN", "latency_ms": 12.0},
            {"port": 6379, "service": "Redis", "status": "OPEN", "latency_ms": 8.5},
            {"port": 443, "service": "HTTPS", "status": "OPEN", "latency_ms": 15.0}
        ],
        dns_records={
            "A": ["10.10.10.50"],
            "TXT": ["v=spf1 +all"]
        },
        http_summary={
            "reachable": True,
            "status_code": 500,
            "server": "nginx/1.24.0",
            "title": "Internal Server Error"
        },
        tls_summary={
            "has_tls": True,
            "is_expired": True,
            "days_remaining": -5,
            "valid_to": (now - timedelta(days=5)).isoformat(),
            "subject_cn": "db.example.com",
            "issuer_cn": "Example CA"
        }
    )
    db.add(asset)
    db.commit()

    findings = evaluate_and_persist_findings(db, scan.id, scope.id, asset)
    assert len(findings) >= 5

    by_title = {f.title: f for f in findings}
    
    # 1. Verify standard port 443 is INFORMATIONAL, NOT vulnerable
    port_443 = next((f for f in findings if "Port 443" in f.title or "Standard Encrypted" in f.title), None)
    assert port_443 is not None
    assert port_443.severity == "INFORMATIONAL"
    assert port_443.confidence == "CONFIRMED"

    # 2. Verify sensitive Redis port 6379 is HIGH
    redis_finding = next((f for f in findings if "Redis" in f.title), None)
    assert redis_finding is not None
    assert redis_finding.severity == "HIGH"
    assert "requirepass" in redis_finding.remediation

    # 3. Verify MySQL is MEDIUM
    mysql_finding = next((f for f in findings if "MySQL" in f.title), None)
    assert mysql_finding is not None
    assert mysql_finding.severity == "MEDIUM"

    # 4. Verify Expired TLS is HIGH
    tls_finding = next((f for f in findings if "Expired TLS" in f.title), None)
    assert tls_finding is not None
    assert tls_finding.severity == "HIGH"
    assert "Renew" in tls_finding.remediation

    # 5. Verify Permissive SPF (+all) is HIGH
    spf_finding = next((f for f in findings if "Permissive SPF" in f.title), None)
    assert spf_finding is not None
    assert spf_finding.severity == "HIGH"

    # 6. Verify HTTP 500 error is MEDIUM
    http_finding = next((f for f in findings if "HTTP 500" in f.title), None)
    assert http_finding is not None
    assert http_finding.severity == "MEDIUM"

def test_findings_deduplication_across_scans(db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    scope = Scope(
        name="Dedup Test Scope",
        targets=["app.test.internal"],
        authorised_confirmation=True,
        authorised_by="Auditor"
    )
    db.add(scope)
    db.commit()

    scan1 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan1)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan1.id,
        host_or_ip="app.test.internal",
        asset_type="subdomain",
        open_ports=[{"port": 443, "service": "HTTPS", "status": "OPEN"}]
    )
    db.add(asset)
    db.commit()

    # First run
    findings1 = evaluate_and_persist_findings(db, scan1.id, scope.id, asset)
    count1 = db.query(ScanFinding).filter(ScanFinding.asset_id == asset.id).count()
    first_detected = findings1[0].first_detected

    # Second run on same asset
    scan2 = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan2)
    db.commit()

    findings2 = evaluate_and_persist_findings(db, scan2.id, scope.id, asset)
    count2 = db.query(ScanFinding).filter(ScanFinding.asset_id == asset.id).count()

    # Must NOT create duplicate rows!
    assert count1 == count2
    # Last observed timestamp must be updated or equal, first_detected unchanged
    assert findings2[0].first_detected == first_detected
    assert findings2[0].scan_run_id == scan2.id

def test_findings_api_endpoints_and_status_updates(client, db):
    scope = Scope(
        name="API Findings Scope",
        targets=["secure.test.internal"],
        authorised_confirmation=True,
        authorised_by="Compliance Lead"
    )
    db.add(scope)
    db.commit()

    scan = ScanRun(scope_id=scope.id, status="COMPLETED", config={})
    db.add(scan)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        scan_run_id=scan.id,
        host_or_ip="secure.test.internal",
        asset_type="subdomain",
        open_ports=[{"port": 22, "service": "SSH", "status": "OPEN"}]
    )
    db.add(asset)
    db.commit()

    evaluate_and_persist_findings(db, scan.id, scope.id, asset)
    finding = db.query(ScanFinding).filter(ScanFinding.asset_id == asset.id).first()
    assert finding is not None

    # 1. GET /api/findings
    resp = client.get(f"/api/findings?scope_id={scope.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["id"] == finding.id
    assert data[0]["asset_host"] == "secure.test.internal"

    # 2. GET /api/findings/{id}
    resp_single = client.get(f"/api/findings/{finding.id}")
    assert resp_single.status_code == 200
    assert resp_single.json()["review_status"] == "OPEN"

    # 3. PATCH /api/findings/{id}/status - transition to IN_REVIEW
    patch_payload = {
        "review_status": "IN_REVIEW",
        "note": "Assigned to infrastructure security team for key hardening"
    }
    patch_resp = client.patch(f"/api/findings/{finding.id}/status", json=patch_payload)
    assert patch_resp.status_code == 200
    updated_data = patch_resp.json()
    assert updated_data["review_status"] == "IN_REVIEW"
    assert len(updated_data["status_history"]) >= 2
    assert updated_data["status_history"][-1]["note"] == "Assigned to infrastructure security team for key hardening"

    # 4. PATCH with invalid status should return 422
    bad_patch = client.patch(f"/api/findings/{finding.id}/status", json={"review_status": "INVALID_STATE"})
    assert bad_patch.status_code == 422

    # 5. GET /api/findings/summary/counts
    counts_resp = client.get(f"/api/findings/summary/counts?scope_id={scope.id}")
    assert counts_resp.status_code == 200
    counts = counts_resp.json()
    assert counts["total"] >= 1
    assert "IN_REVIEW" in counts["by_status"]

    # 6. Non-existent finding returns 404
    resp_404 = client.get("/api/findings/non-existent-id")
    assert resp_404.status_code == 404
