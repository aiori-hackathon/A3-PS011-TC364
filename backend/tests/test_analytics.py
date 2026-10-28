import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_analytics_metrics_and_timelines(client: TestClient):
    # Test overview returns all Phase 4 analytics fields
    resp = client.get("/api/stats/overview")
    assert resp.status_code == 200
    data = resp.json()

    assert "asset_types_distribution" in data
    assert "findings_by_severity" in data
    assert "findings_by_status" in data
    assert "discovery_timeline" in data
    assert "changes_timeline" in data
    assert isinstance(data["discovery_timeline"], list)
    assert isinstance(data["changes_timeline"], list)

def test_analytics_data_integrity_with_scans_and_changes(client: TestClient):
    # Seed demo to create real records
    seed_res = client.post("/api/demo/seed")
    assert seed_res.status_code == 200

    overview_res = client.get("/api/stats/overview")
    assert overview_res.status_code == 200
    data = overview_res.json()

    # Asset categories match total assets
    categories_sum = sum(data["asset_types_distribution"].values())
    assert categories_sum == data["total_assets"]

    # Finding severities sum matches findings count
    findings_sum = sum(data["findings_by_severity"].values())
    assert findings_sum > 0

    # Discovery timeline includes the scan
    assert len(data["discovery_timeline"]) > 0
    recent_scan = data["discovery_timeline"][-1]
    assert "assets_discovered" in recent_scan
    assert "findings_count" in recent_scan
    assert "status" in recent_scan
    assert recent_scan["status"] == "COMPLETED"

    # Clean up demo
    clear_res = client.post("/api/demo/clear")
    assert clear_res.status_code == 200
