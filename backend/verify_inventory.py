import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def verify_inventory():
    print("--- Verifying Inventory Search, Filtering, and Error Handling ---")
    
    # 1. Search by IP
    res_search = client.get("/assets?search=127.0.0.1")
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 1
    print("PASS: Search by IP returned matching asset.")

    # 2. Search by non-existent query
    res_empty_search = client.get("/assets?search=nonexistent-host-999")
    assert res_empty_search.status_code == 200
    assert len(res_empty_search.json()) == 0
    print("PASS: Search with non-existent keyword returned empty list.")

    # 3. Filter by port 8000
    res_port = client.get("/assets?port=8000")
    assert res_port.status_code == 200
    port_assets = res_port.json()
    assert len(port_assets) >= 1
    assert any(p["port"] == 8000 for p in port_assets[0]["open_ports"])
    print("PASS: Filter by port 8000 returned matching asset.")

    # 4. Filter by non-open port
    res_no_port = client.get("/assets?port=65432")
    assert res_no_port.status_code == 200
    assert len(res_no_port.json()) == 0
    print("PASS: Filter by non-open port returned empty list.")

    # 5. Filter by status ACTIVE
    res_status = client.get("/assets?status=ACTIVE")
    assert res_status.status_code == 200
    assert len(res_status.json()) >= 1
    print("PASS: Filter by status ACTIVE returned matching active assets.")

    # 6. Filter by asset type ipv4
    res_type = client.get("/assets?asset_type=ipv4")
    assert res_type.status_code == 200
    assert len(res_type.json()) >= 1
    print("PASS: Filter by asset_type ipv4 returned matching IPv4 assets.")

    # 7. Asset details lookup
    asset_id = port_assets[0]["id"]
    res_detail = client.get(f"/assets/{asset_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == asset_id
    
    res_findings = client.get(f"/assets/{asset_id}/findings")
    assert res_findings.status_code == 200
    assert len(res_findings.json()) >= 2
    print(f"PASS: Asset detail and {len(res_findings.json())} findings retrieved for asset ID: {asset_id}")

    # 8. Error handling: non-existent asset ID
    res_404 = client.get("/assets/00000000-0000-0000-0000-000000000000")
    assert res_404.status_code == 404
    assert "detail" in res_404.json()
    print("PASS: Non-existent asset ID returns 404 with structured JSON detail.")

if __name__ == "__main__":
    verify_inventory()
