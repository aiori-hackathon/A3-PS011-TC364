import io
import csv
import json
import pytest
from app.models import Scope, DiscoveredAsset, AssetChangeRecord, ScanFinding, AuditLog, ScanRun

def test_csv_formula_injection_defense(client, db):
    scope = Scope(
        name="Injection Test Scope",
        targets=["example.com"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    # Create assets with formula injection payloads
    malicious_hosts = [
        "=cmd|' /C calc'!A0",
        "+123456",
        "-DDE('cmd';'/c calc';'__test__')",
        "@SUM(1,2)",
        "\tmalicious_tab",
        "\rmalicious_cr"
    ]

    for host in malicious_hosts:
        asset = DiscoveredAsset(
            scope_id=scope.id,
            host_or_ip=host,
            asset_type="domain",
            status="ACTIVE"
        )
        db.add(asset)
    db.commit()

    # Request CSV export
    res = client.get(f"/api/exports/inventory/csv?scope_id={scope.id}")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    csv_text = res.text

    # Parse CSV output and check that every dangerous formula is sanitized with a leading single quote
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    header = rows[0]
    host_idx = header.index("Host / FQDN / IP")

    exported_hosts = [row[host_idx] for row in rows[1:]]
    assert len(exported_hosts) == len(malicious_hosts)

    for host_val in exported_hosts:
        # Every formula cell MUST start with a neutralizing quote (')
        assert host_val.startswith("'"), f"Cell '{host_val}' failed formula injection sanitization!"

def test_inventory_exports_csv_and_json(client, db):
    scope = Scope(
        name="Export Scope",
        targets=["app.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps Lead"
    )
    db.add(scope)
    db.commit()

    asset = DiscoveredAsset(
        scope_id=scope.id,
        host_or_ip="app.internal",
        asset_type="domain",
        ip_address="192.168.1.10",
        status="ACTIVE",
        open_ports=[{"port": 80, "service": "http"}]
    )
    db.add(asset)
    db.commit()

    # CSV Export
    csv_res = client.get(f"/api/exports/inventory/csv?scope_id={scope.id}")
    assert csv_res.status_code == 200
    assert "app.internal" in csv_res.text
    assert "192.168.1.10" in csv_res.text

    # JSON Export
    json_res = client.get(f"/api/exports/inventory/json?scope_id={scope.id}")
    assert json_res.status_code == 200
    data = json_res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["host_or_ip"] == "app.internal"

    # Verify audit trail recorded export action
    audit = db.query(AuditLog).filter(
        AuditLog.action == "EXPORT_GENERATED",
        AuditLog.entity_id == "inventory_csv"
    ).first()
    assert audit is not None
    assert audit.details.get("resource") == "inventory"

def test_findings_exports_csv_and_json(client, db):
    scope = Scope(
        name="Findings Export Scope",
        targets=["db.internal"],
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
        title="=HYPERLINK(\"http://evil.com\",\"Dangerous finding\")",
        severity="HIGH",
        confidence="CONFIRMED",
        review_status="OPEN"
    )
    db.add(finding)
    db.commit()

    # CSV Export
    csv_res = client.get(f"/api/exports/findings/csv?scope_id={scope.id}")
    assert csv_res.status_code == 200
    # Must be sanitized
    assert "'=HYPERLINK" in csv_res.text

    # JSON Export
    json_res = client.get(f"/api/exports/findings/json?scope_id={scope.id}")
    assert json_res.status_code == 200
    findings_data = json_res.json()
    assert len(findings_data) == 1
    assert findings_data[0]["severity"] == "HIGH"

def test_changes_exports_csv_and_json(client, db):
    scope = Scope(
        name="Changes Scope",
        targets=["web.internal"],
        allow_local_lab=True,
        authorised_confirmation=True,
        authorised_by="SecOps"
    )
    db.add(scope)
    db.commit()

    scan = ScanRun(scope_id=scope.id, status="COMPLETED")
    db.add(scan)
    db.commit()

    change = AssetChangeRecord(
        scope_id=scope.id,
        to_snapshot_id="snap-1",
        scan_run_id=scan.id,
        asset_identifier="web.internal",
        change_type="ASSET_ADDED",
        attribute_name="asset",
        is_inconclusive=False
    )
    db.add(change)
    db.commit()

    # CSV Export
    csv_res = client.get(f"/api/exports/changes/csv?scope_id={scope.id}")
    assert csv_res.status_code == 200
    assert "web.internal" in csv_res.text
    assert "ASSET_ADDED" in csv_res.text

    # JSON Export
    json_res = client.get(f"/api/exports/changes/json?scope_id={scope.id}")
    assert json_res.status_code == 200
    assert len(json_res.json()) == 1
