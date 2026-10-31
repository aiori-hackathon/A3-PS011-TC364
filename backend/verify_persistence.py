import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def verify_persistence():
    print("--- Verifying Persistence After Backend Restart ---")
    
    # 1. Scopes survived restart
    scopes_res = client.get("/scopes")
    assert scopes_res.status_code == 200
    scopes = scopes_res.json()
    assert len(scopes) > 0, "Scopes should persist in SQLite after restart"
    found_scope = any(s["name"] == "Live Test Scope (Authorized Local Lab)" for s in scopes)
    assert found_scope, "Live Test Scope not found in persisted scopes"
    print(f"PASS: Verified {len(scopes)} scopes persisted in SQLite.")

    # 2. Scans survived restart
    scans_res = client.get("/scans")
    assert scans_res.status_code == 200
    scans = scans_res.json()
    assert len(scans) > 0, "Scan runs should persist in SQLite after restart"
    completed_scan = next((s for s in scans if s["status"] == "COMPLETED"), None)
    assert completed_scan is not None, "Completed scan run not found after restart"
    assert len(completed_scan["logs"]) > 0, "Scan logs must persist in SQLite"
    print(f"PASS: Verified {len(scans)} scan runs with full execution logs persisted in SQLite.")

    # 3. Assets survived restart
    assets_res = client.get("/assets")
    assert assets_res.status_code == 200
    assets = assets_res.json()
    assert len(assets) > 0, "Discovered assets should persist in SQLite after restart"
    local_asset = next((a for a in assets if a["host_or_ip"] == "127.0.0.1"), None)
    assert local_asset is not None, "127.0.0.1 asset not found after restart"
    assert len(local_asset["open_ports"]) >= 2, "Open ports list must persist"
    print(f"PASS: Verified discovered asset persisted: {local_asset['host_or_ip']} with open ports: {[p['port'] for p in local_asset['open_ports']]}")

    # 4. Findings survived restart
    findings_res = client.get(f"/scans/{completed_scan['id']}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) >= 2, "Scan findings must persist in SQLite"
    print(f"PASS: Verified {len(findings)} findings persisted in SQLite.")

if __name__ == "__main__":
    verify_persistence()
