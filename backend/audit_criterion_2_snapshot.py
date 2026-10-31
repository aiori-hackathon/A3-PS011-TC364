import json
import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def make_snapshot():
    scopes = client.get("/scopes").json()
    scans = client.get("/scans").json()
    assets = client.get("/assets").json()
    
    total_findings = sum(len(client.get(f"/scans/{s['id']}/findings").json()) for s in scans)
    
    snapshot = {
        "scopes": scopes,
        "scans": scans,
        "assets": assets,
        "total_findings": total_findings
    }
    
    with open("pre_restart_snapshot.json", "w") as f:
        json.dump(snapshot, f, indent=2)
        
    print(f"Snapshot recorded: {len(scopes)} scopes, {len(scans)} scans, {len(assets)} assets, {total_findings} findings.")

def verify_snapshot():
    with open("pre_restart_snapshot.json", "r") as f:
        pre = json.load(f)
        
    scopes = client.get("/scopes").json()
    scans = client.get("/scans").json()
    assets = client.get("/assets").json()
    total_findings = sum(len(client.get(f"/scans/{s['id']}/findings").json()) for s in scans)
    
    print("=== AUDIT CRITERION 2: Comparing State Post-Restart ===")
    assert len(scopes) == len(pre["scopes"]), f"Scope count mismatch: {len(scopes)} vs {len(pre['scopes'])}"
    assert len(scans) == len(pre["scans"]), f"Scan count mismatch: {len(scans)} vs {len(pre['scans'])}"
    assert len(assets) == len(pre["assets"]), f"Asset count mismatch: {len(assets)} vs {len(pre['assets'])}"
    assert total_findings == pre["total_findings"], f"Findings count mismatch: {total_findings} vs {pre['total_findings']}"
    
    # Check specific IDs
    pre_scope_ids = {s["id"] for s in pre["scopes"]}
    cur_scope_ids = {s["id"] for s in scopes}
    assert pre_scope_ids == cur_scope_ids, "Scope IDs altered after restart!"
    
    pre_scan_ids = {s["id"] for s in pre["scans"]}
    cur_scan_ids = {s["id"] for s in scans}
    assert pre_scan_ids == cur_scan_ids, "Scan IDs altered after restart!"

    pre_asset_ids = {a["id"] for a in pre["assets"]}
    cur_asset_ids = {a["id"] for a in assets}
    assert pre_asset_ids == cur_asset_ids, "Asset IDs altered after restart!"
    
    print(f"PASS: Verified all {len(scopes)} scopes, {len(scans)} scan runs, {len(assets)} assets, and {total_findings} findings fully persisted in SQLite across restart.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        verify_snapshot()
    else:
        make_snapshot()
