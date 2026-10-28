import ipaddress
import pytest
from app.security import (
    sanitize_target_input,
    validate_target,
    check_ip_safety,
    validate_port_list
)

def test_sanitize_target_input():
    assert sanitize_target_input("https://example.com/some/path") == "example.com"
    assert sanitize_target_input("http://sub.example.com:8080/test?q=1") == "sub.example.com"
    assert sanitize_target_input("  api.target.org/  ") == "api.target.org"
    assert sanitize_target_input("192.168.1.50:443") == "192.168.1.50"

def test_target_wildcards_blocked():
    is_val, _, err = validate_target("*.example.com")
    assert not is_val
    assert "invalid or wildcard" in err.lower()

    is_val2, _, err2 = validate_target("test;ls")
    assert not is_val2

def test_cloud_metadata_blocked():
    meta_ip = ipaddress.ip_address("169.254.169.254")
    # Even with allow_local_lab=True, cloud metadata must be blocked
    is_safe, reason = check_ip_safety(meta_ip, allow_local_lab=True)
    assert not is_safe
    assert "cloud metadata" in reason.lower()

def test_private_ip_guardrails():
    priv_ip = ipaddress.ip_address("192.168.1.100")
    # Blocked by default
    is_safe, reason = check_ip_safety(priv_ip, allow_local_lab=False)
    assert not is_safe
    assert "private/internal" in reason.lower()

    # Allowed when explicitly authorized local lab
    is_safe_lab, _ = check_ip_safety(priv_ip, allow_local_lab=True)
    assert is_safe_lab

def test_loopback_guardrails():
    loopback_ip = ipaddress.ip_address("127.0.0.1")
    is_safe, reason = check_ip_safety(loopback_ip, allow_local_lab=False)
    assert not is_safe
    assert "loopback" in reason.lower()

    is_safe_lab, _ = check_ip_safety(loopback_ip, allow_local_lab=True)
    assert is_safe_lab

def test_valid_domain_validation():
    is_val, sanitized, err = validate_target("example.com")
    assert is_val
    assert sanitized == "example.com"
    assert err is None

    is_val2, sanitized2, _ = validate_target("sub-1.service.example.co.uk")
    assert is_val2
    assert sanitized2 == "sub-1.service.example.co.uk"

def test_port_list_bounding():
    # Valid bounded list
    is_val, bounded, err = validate_port_list([80, 443, 8080], max_ports=50)
    assert is_val
    assert bounded == [80, 443, 8080]

    # Exceeding max allowable ports
    too_many = list(range(1, 60))
    is_val2, _, err2 = validate_port_list(too_many, max_ports=50)
    assert not is_val2
    assert "exceeded maximum" in err2.lower()

    # Invalid port values
    is_val3, _, err3 = validate_port_list([80, 70000, -1])
    assert not is_val3
    assert "invalid port" in err3.lower()
