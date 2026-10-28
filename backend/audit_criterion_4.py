import asyncio
from app.discovery.dns_resolver import resolve_dns_records
from app.discovery.port_scanner import scan_allowed_ports
from app.discovery.http_probe import probe_http_service
from app.discovery.tls_inspector import inspect_tls_certificate
from app.security import validate_port_list

async def audit_criterion_4():
    print("=== AUDIT CRITERION 4: Real Discovery Probes on Controlled Targets ===")

    # 1. Real DNS Enumeration
    dns_res = await resolve_dns_records("example.com")
    assert len(dns_res["A"]) > 0 or len(dns_res["AAAA"]) > 0, "Real DNS A/AAAA records must be found"
    assert len(dns_res["NS"]) > 0, "Real NS records must be found"
    print(f"  [DNS] example.com: A={dns_res['A']}, AAAA={dns_res['AAAA']}, NS={dns_res['NS']}")

    dns_ptr = await resolve_dns_records("8.8.8.8")
    assert len(dns_ptr["PTR"]) > 0 and "dns.google" in dns_ptr["PTR"][0].lower()
    print(f"  [DNS] 8.8.8.8 PTR: {dns_ptr['PTR']}")

    dns_nx = await resolve_dns_records("nonexistent-test-domain-argustrace-audit-4.com")
    assert len(dns_nx["A"]) == 0
    print(f"  [DNS] Non-existent domain handled safely (0 records returned)")
    print("  PASS: DNS lookups perform real lookups with proper error handling.")

    # 2. Bounded TCP Port Probe
    is_bounded, bounded_list, _ = validate_port_list([5173, 8000, 19876], max_ports=50)
    assert is_bounded and len(bounded_list) == 3
    is_over, _, err_over = validate_port_list(list(range(1, 60)), max_ports=50)
    assert not is_over and "exceeded maximum" in err_over.lower()
    print(f"  [Ports] Port bounding verified: allowlist bounded to max 50 ports")

    tcp_res = await scan_allowed_ports("127.0.0.1", [5173, 8000, 19876], timeout=2.0)
    detected_ports = [p["port"] for p in tcp_res]
    assert 5173 in detected_ports, "Port 5173 (Vite) must be detected as OPEN"
    assert 8000 in detected_ports, "Port 8000 (FastAPI) must be detected as OPEN"
    assert 19876 not in detected_ports, "Closed port 19876 must NOT be open"
    print(f"  [Ports] 127.0.0.1 open ports detected: {detected_ports}")
    print("  PASS: Bounded TCP checks detected actual open services and ignored closed ports.")

    # 3. HTTP / HTTPS Reachability & Metadata
    http_vite = await probe_http_service("127.0.0.1", port=5173, use_https=False, allow_local_lab=True)
    assert http_vite is not None and http_vite["reachable"] is True
    assert http_vite["status_code"] == 200
    assert "ArgusTrace" in (http_vite.get("title") or "")
    print(f"  [HTTP] 127.0.0.1:5173 status={http_vite['status_code']}, title='{http_vite['title']}', latency={http_vite['latency_ms']}ms")

    http_api = await probe_http_service("127.0.0.1", port=8000, use_https=False, allow_local_lab=True)
    assert http_api is not None and http_api["reachable"] is True
    assert http_api["status_code"] == 200
    print(f"  [HTTP] 127.0.0.1:8000 status={http_api['status_code']}, server={http_api.get('server')}")
    print("  PASS: HTTP reachability gathered real status, titles, server headers, and latencies.")

    # 4. TLS Certificate Extraction
    tls_cert = await inspect_tls_certificate("example.com", port=443, timeout=5.0)
    assert tls_cert is not None and tls_cert["has_tls"] is True
    assert tls_cert["subject_cn"] == "example.com"
    assert tls_cert["days_remaining"] is not None and tls_cert["days_remaining"] > 0
    assert tls_cert["is_expired"] is False
    assert "example.com" in tls_cert["sans"]
    print(f"  [TLS] example.com: Subject='{tls_cert['subject_cn']}', Issuer='{tls_cert['issuer_cn']}', Days Left={tls_cert['days_remaining']}, Cipher={tls_cert['cipher']}, SANs={tls_cert['sans']}")
    print("  PASS: TLS certificate extraction retrieved authentic certificate metadata.")

if __name__ == "__main__":
    asyncio.run(audit_criterion_4())
