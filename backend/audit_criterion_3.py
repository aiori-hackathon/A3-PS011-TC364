import httpx
from app.security import validate_target, check_ip_safety, is_ip_address
import ipaddress

client = httpx.Client(base_url="http://127.0.0.1:8000/api")

def audit_criterion_3():
    print("=== AUDIT CRITERION 3: Server-Side Scope Enforcement & Rejection ===")

    # 1. Cloud metadata rejection (always rejected, even if allow_local_lab=True)
    val_meta, _, err_meta = validate_target("169.254.169.254", allow_local_lab=True)
    assert not val_meta, "Cloud metadata 169.254.169.254 must be blocked even in local lab mode"
    print(f"  PASS: Cloud metadata blocked: '{err_meta}'")

    val_meta6, _, err_meta6 = validate_target("fd00:ec2::254", allow_local_lab=True)
    assert not val_meta6, "AWS IPv6 metadata must be blocked"
    print(f"  PASS: IPv6 metadata blocked: '{err_meta6}'")

    # 2. Private & loopback rejection without local lab mode
    val_priv, _, err_priv = validate_target("10.0.0.1", allow_local_lab=False)
    assert not val_priv, "Private IP must be blocked when allow_local_lab=False"
    print(f"  PASS: Private 10.0.0.1 blocked: '{err_priv}'")

    val_loop, _, err_loop = validate_target("127.0.0.1", allow_local_lab=False)
    assert not val_loop, "Loopback must be blocked when allow_local_lab=False"
    print(f"  PASS: Loopback 127.0.0.1 blocked: '{err_loop}'")

    # 3. Wildcards and injection patterns
    val_wild, _, err_wild = validate_target("*.target.com")
    assert not val_wild, "Wildcard targets must be rejected"
    print(f"  PASS: Wildcard rejected: '{err_wild}'")

    val_inj, _, err_inj = validate_target("example.com;cat /etc/passwd")
    assert not val_inj, "Command injection characters must be rejected"
    print(f"  PASS: Injection target rejected: '{err_inj}'")

    # 4. API rejection when creating scope without explicit authorization confirmation
    res_no_auth = client.post("/scopes", json={
        "name": "Audit Non-Auth Scope",
        "targets": ["example.com"],
        "allow_local_lab": False,
        "authorised_confirmation": False,
        "authorised_by": "Audit Lead"
    })
    assert res_no_auth.status_code == 400
    assert "authorisation confirmation is required" in res_no_auth.json()["detail"].lower()
    print("  PASS: API rejected scope creation without explicit authorization confirmation.")

    # 5. API rejection when creating scope with prohibited metadata
    res_meta_scope = client.post("/scopes", json={
        "name": "Audit Metadata Scope",
        "targets": ["169.254.169.254"],
        "allow_local_lab": True,
        "authorised_confirmation": True,
        "authorised_by": "Audit Lead"
    })
    assert res_meta_scope.status_code == 400
    print("  PASS: API rejected scope containing prohibited metadata target.")

    # 6. Scope validation endpoint
    val_resp = client.post("/scopes/validate-targets", json={
        "targets": ["*.sub.com", "169.254.169.254", "192.168.1.1", "example.com"],
        "allow_local_lab": False
    })
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["all_valid"] is False
    assert val_data["items"][0]["is_valid"] is False
    assert val_data["items"][1]["is_valid"] is False
    assert val_data["items"][2]["is_valid"] is False
    assert val_data["items"][3]["is_valid"] is True
    print("  PASS: Live /validate-targets endpoint rejected out-of-scope & prohibited targets.")

if __name__ == "__main__":
    audit_criterion_3()
