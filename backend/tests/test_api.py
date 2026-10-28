import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models import Scope, DiscoveredAsset

# Use an isolated in-memory SQLite database for testing with StaticPool
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    return TestClient(app)

def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "Phase 1" in data["phase"]

def test_target_validation_endpoint(client):
    payload = {
        "targets": [
            "valid.example.com",
            "*.wildcard.com",
            "169.254.169.254",
            "192.168.1.1"
        ],
        "allow_local_lab": False
    }
    response = client.post("/api/scopes/validate-targets", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert not data["all_valid"]
    items = data["items"]
    assert items[0]["is_valid"] is True
    assert items[1]["is_valid"] is False # wildcard
    assert items[2]["is_valid"] is False # cloud metadata
    assert items[3]["is_valid"] is False # private IP without lab mode

def test_scope_creation_authorization_required(client):
    # Attempting creation without confirmation checkbox must fail
    payload = {
        "name": "Unauthorized Test Scope",
        "description": "Testing missing authorization",
        "targets": ["example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": False,
        "authorised_by": "Security Officer"
    }
    response = client.post("/api/scopes", json=payload)
    assert response.status_code == 400
    assert "authorisation confirmation is required" in response.json()["detail"].lower()

def test_scope_creation_and_listing(client):
    payload = {
        "name": "Production Core Scope",
        "description": "Public attack surface for core web assets",
        "targets": ["example.com", "api.example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": True,
        "authorised_by": "SecOps Lead (Ticket #SEC-891)"
    }
    response = client.post("/api/scopes", json=payload)
    assert response.status_code == 201
    scope_data = response.json()
    assert scope_data["name"] == "Production Core Scope"
    assert len(scope_data["targets"]) == 2
    scope_id = scope_data["id"]

    # List scopes
    list_resp = client.get("/api/scopes")
    assert list_resp.status_code == 200
    scopes = list_resp.json()
    assert len(scopes) == 1
    assert scopes[0]["id"] == scope_id

def test_scan_launch_requires_authorised_scope(client):
    # Create valid scope
    scope_payload = {
        "name": "Scan Target Scope",
        "targets": ["example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": True,
        "authorised_by": "Audit Lead"
    }
    scope_resp = client.post("/api/scopes", json=scope_payload)
    scope_id = scope_resp.json()["id"]

    # Launch scan
    scan_payload = {
        "scope_id": scope_id,
        "config": {
            "ports": [80, 443],
            "enable_dns": True,
            "enable_ports": True,
            "enable_http": True,
            "enable_tls": True
        }
    }
    scan_resp = client.post("/api/scans", json=scan_payload)
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    assert scan_data["status"] in ("PENDING", "IN_PROGRESS", "COMPLETED")
    assert scan_data["targets_total"] == 1

def test_demo_seed_and_overview(client):
    # Seed demo mode
    demo_resp = client.post("/api/demo/seed")
    assert demo_resp.status_code == 200
    assert "Demo mode synthetic data loaded" in demo_resp.json()["message"]

    # Check overview stats
    stats_resp = client.get("/api/stats/overview")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_scopes"] >= 1
    assert stats["total_assets"] >= 5
    assert stats["active_assets"] >= 5
    assert len(stats["top_open_ports"]) > 0

    # Check asset listing
    assets_resp = client.get("/api/assets")
    assert assets_resp.status_code == 200
    assets = assets_resp.json()
    assert len(assets) >= 5

    # Filter asset by port 443
    port_resp = client.get("/api/assets?port=443")
    assert port_resp.status_code == 200
    filtered_assets = port_resp.json()
    assert len(filtered_assets) > 0
    for a in filtered_assets:
        assert any(p["port"] == 443 for p in a["open_ports"])
