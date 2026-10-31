import time
import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def test_full_discovery_job():
    print("--- Running Full End-to-End Discovery Job ---")
    
    # 1. Create explicitly authorized local test scope
    scope_data = {
        "name": "Live Test Scope (Authorized Local Lab)",
        "description": "Controlled verification target for Phase 1 asset discovery",
        "targets": ["127.0.0.1"],
        "allow_local_lab": True,
        "authorised_confirmation": True,
        "authorised_by": "SecOps Audit Lead"
    }
    scope_res = client.post("/scopes", json=scope_data)
    assert scope_res.status_code == 201, f"Failed to create scope: {scope_res.text}"
    scope = scope_res.json()
    scope_id = scope["id"]
    print(f"Created authorized scope: {scope['name']} (ID: {scope_id})")

    # 2. Launch Discovery Run with bounded port list [8000, 5173]
    scan_payload = {
        "scope_id": scope_id,
        "config": {
            "ports": [5173, 8000],
            "enable_dns": True,
            "enable_ports": True,
            "enable_http": True,
            "enable_tls": False
        }
    }
    launch_res = client.post("/scans", json=scan_payload)
    assert launch_res.status_code == 201, f"Failed to launch scan: {launch_res.text}"
    scan = launch_res.json()
    scan_id = scan["id"]
    print(f"Launched discovery run ID: {scan_id}, Initial status: {scan['status']}")

    # 3. Poll for progress and completion
    start_time = time.time()
    final_scan = None
    while time.time() - start_time < 30: # 30s timeout
        poll_res = client.get(f"/scans/{scan_id}")
        assert poll_res.status_code == 200
        scan_state = poll_res.json()
        print(f"  [Progress] Status={scan_state['status']}, Targets: {scan_state['targets_scanned']}/{scan_state['targets_total']}, Assets: {scan_state['assets_discovered_count']}, Findings: {scan_state['findings_count']}")
        
        if scan_state["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            final_scan = scan_state
            break
        time.sleep(1.0)

    assert final_scan is not None, "Scan did not reach terminal state within timeout"
    assert final_scan["status"] == "COMPLETED", f"Expected COMPLETED, got {final_scan['status']}: {final_scan.get('error_message')}"
    assert final_scan["targets_scanned"] == 1, "Expected 1 target scanned"
    assert final_scan["assets_discovered_count"] >= 1, "Expected at least 1 discovered asset"
    assert final_scan["findings_count"] >= 2, "Expected findings (open ports 5173, 8000)"
    assert len(final_scan["logs"]) > 0, "Expected non-empty discovery log stream"
    
    print("PASS: Discovery run completed successfully. Sample logs:")
    for log in final_scan["logs"][:4]:
        print(f"    [{log['timestamp']}] {log['level']}: {log['message']}")

    # 4. Check findings for this scan run
    findings_res = client.get(f"/scans/{scan_id}/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    print(f"PASS: Verified {len(findings)} findings recorded for this scan run:")
    for f in findings:
        print(f"    Finding [{f['finding_type']}]: {f['title']}")

    # 5. Check discovered asset in inventory
    asset_res = client.get(f"/assets?scope_id={scope_id}")
    assert asset_res.status_code == 200
    assets = asset_res.json()
    assert len(assets) >= 1, "Expected asset in inventory for this scope"
    asset = assets[0]
    print(f"PASS: Discovered asset verified in inventory:")
    print(f"    Host: {asset['host_or_ip']}, Status: {asset['status']}, Ports: {[p['port'] for p in asset['open_ports']]}")

if __name__ == "__main__":
    test_full_discovery_job()
