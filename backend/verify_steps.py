import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def test_scope_validation():
    print("--- Testing Scope Validation & Rejection ---")
    payload = {
        "targets": ["*.evil.com", "169.254.169.254", "192.168.1.5", "example.com"],
        "allow_local_lab": False
    }
    val_res = client.post("/scopes/validate-targets", json=payload)
    assert val_res.status_code == 200, f"Expected 200, got {val_res.status_code}"
    val_data = val_res.json()
    assert val_data["all_valid"] is False, "all_valid should be False"
    
    items = {item["raw"]: item for item in val_data["items"]}
    assert items["*.evil.com"]["is_valid"] is False, "Wildcard should be invalid"
    assert items["169.254.169.254"]["is_valid"] is False, "Metadata IP should be invalid"
    assert items["192.168.1.5"]["is_valid"] is False, "Private IP without lab flag should be invalid"
    assert items["example.com"]["is_valid"] is True, "example.com should be valid"
    print("PASS: Target validation endpoint correctly flags wildcards, metadata, and private IPs.")

    # Scope creation without authorisation confirmation
    res_no_auth = client.post("/scopes", json={
        "name": "Unauthorized Scope",
        "targets": ["example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": False,
        "authorised_by": "Tester"
    })
    assert res_no_auth.status_code == 400, f"Expected 400, got {res_no_auth.status_code}"
    assert "authorisation confirmation is required" in res_no_auth.json()["detail"].lower()
    print("PASS: Scope creation rejected when explicit authorisation is missing.")

    # Scope creation with blocked metadata target
    res_bad_target = client.post("/scopes", json={
        "name": "Metadata Scope",
        "targets": ["169.254.169.254"],
        "allow_local_lab": False,
        "authorised_confirmation": True,
        "authorised_by": "Tester"
    })
    assert res_bad_target.status_code == 400, f"Expected 400, got {res_bad_target.status_code}"
    print("PASS: Scope creation rejected when target violates SSRF policy.")

    # Scope creation with valid targets and authorization
    res_valid = client.post("/scopes", json={
        "name": "Verification Lab Scope",
        "description": "Authorized local testing lab",
        "targets": ["localhost", "127.0.0.1"],
        "allow_local_lab": True,
        "authorised_confirmation": True,
        "authorised_by": "Verification Officer"
    })
    assert res_valid.status_code == 201, f"Expected 201, got {res_valid.status_code}"
    scope_id = res_valid.json()["id"]
    print(f"PASS: Authorized scope successfully created with ID: {scope_id}")
    return scope_id

if __name__ == "__main__":
    test_scope_validation()
