import time
import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def audit_criterion_1():
    print("=== AUDIT CRITERION 1: Terminal Status & Refresh Consistency ===")
    
    # 1. Inspect existing latest scan run
    scans_res = client.get("/scans")
    assert scans_res.status_code == 200, f"Failed to list scans: {scans_res.status_code}"
    scans = scans_res.json()
    assert len(scans) > 0, "No existing scan runs found"
    
    latest_scan = scans[0]
    print(f"Latest existing scan ID: {latest_scan['id']}")
    print(f"  Status: {latest_scan['status']}")
    print(f"  Targets: {latest_scan['targets_scanned']} / {latest_scan['targets_total']}")
    print(f"  Completed At: {latest_scan.get('completed_at')}")
    assert latest_scan["status"] in ("COMPLETED", "FAILED", "CANCELLED"), f"Expected terminal status, got {latest_scan['status']}"
    assert latest_scan["completed_at"] is not None, "completed_at timestamp must be set"
    
    # 2. Simulate repeated refreshes on this scan
    print("  Testing 5 consecutive refreshes for state consistency...")
    for i in range(1, 6):
        res = client.get(f"/scans/{latest_scan['id']}")
        assert res.status_code == 200
        scan_state = res.json()
        assert scan_state["status"] == latest_scan["status"], f"Status flipped on refresh {i}!"
        assert scan_state["targets_scanned"] == latest_scan["targets_scanned"]
        time.sleep(0.2)
    print("  PASS: Existing scan status remained identical across all refreshes.")

    # 3. Launch a fresh new discovery run on the authorized local lab scope
    scopes = client.get("/scopes").json()
    local_scope = next((s for s in scopes if s.get("allow_local_lab")), None)
    assert local_scope is not None, "Local lab scope not found"
    
    print(f"  Launching fresh scan on scope '{local_scope['name']}' (ID: {local_scope['id']})...")
    launch_res = client.post("/scans", json={
        "scope_id": local_scope["id"],
        "config": {
            "ports": [8000],
            "enable_dns": False,
            "enable_ports": True,
            "enable_http": True,
            "enable_tls": False
        }
    })
    assert launch_res.status_code == 201
    new_scan = launch_res.json()
    new_scan_id = new_scan["id"]
    print(f"  Fresh scan created ID: {new_scan_id}, Initial status: {new_scan['status']}")

    # Wait for terminal status
    terminal_scan = None
    start = time.time()
    while time.time() - start < 20:
        s_res = client.get(f"/scans/{new_scan_id}")
        s_data = s_res.json()
        if s_data["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            terminal_scan = s_data
            break
        time.sleep(0.5)

    assert terminal_scan is not None, "New scan did not reach terminal status within 20s"
    assert terminal_scan["status"] == "COMPLETED", f"Expected COMPLETED, got {terminal_scan['status']}"
    assert terminal_scan["completed_at"] is not None
    print(f"  Fresh scan reached terminal status: {terminal_scan['status']} at {terminal_scan['completed_at']}")

    # 4. Verify post-run refresh consistency
    print("  Verifying refresh consistency after completion (5 iterations)...")
    for i in range(1, 6):
        r = client.get(f"/scans/{new_scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "COMPLETED", f"Status flipped on iteration {i}"
        assert data["targets_scanned"] == terminal_scan["targets_scanned"]
        assert len(data["logs"]) == len(terminal_scan["logs"])
        time.sleep(0.2)
    print("  PASS: New discovery run reached terminal status and maintained complete consistency across all refreshes.")

if __name__ == "__main__":
    audit_criterion_1()
