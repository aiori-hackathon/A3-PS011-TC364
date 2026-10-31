import asyncio
from app.discovery.http_probe import probe_http_service
from app.discovery.tls_inspector import inspect_tls_certificate

async def verify_http_and_tls():
    print("--- Verifying HTTP/HTTPS Reachability & TLS Certificate Inspector ---")

    # 1. HTTP Probe on local Vite server (port 5173)
    http_res = await probe_http_service(
        host="127.0.0.1",
        port=5173,
        use_https=False,
        allow_local_lab=True,
        timeout=3.0
    )
    assert http_res is not None, "HTTP probe on 127.0.0.1:5173 should return result"
    assert http_res["reachable"] is True, "Service should be reachable"
    assert http_res["status_code"] == 200, f"Expected status 200, got {http_res['status_code']}"
    assert "ArgusTrace" in (http_res.get("title") or ""), f"Title should contain ArgusTrace, got {http_res.get('title')}"
    print(f"PASS: HTTP Reachability on 127.0.0.1:5173 succeeded:")
    print(f"  Status: {http_res['status_code']}, Title: '{http_res['title']}', Latency: {http_res['latency_ms']}ms")

    # 2. HTTP Probe on local FastAPI backend (port 8000)
    api_res = await probe_http_service(
        host="127.0.0.1",
        port=8000,
        use_https=False,
        allow_local_lab=True,
        timeout=3.0
    )
    assert api_res is not None and api_res["reachable"] is True
    print(f"PASS: HTTP Reachability on 127.0.0.1:8000 succeeded: Status: {api_res['status_code']}, Server: {api_res.get('server')}")

    # 3. TLS Certificate Inspection on authorized standard test target (example.com)
    tls_res = await inspect_tls_certificate(host="example.com", port=443, timeout=5.0)
    assert tls_res is not None, "TLS certificate inspection should succeed for example.com"
    assert tls_res["has_tls"] is True, "has_tls should be True"
    assert "example" in tls_res["subject_cn"].lower() or len(tls_res.get("sans", [])) > 0, "Subject CN or SAN should match example"
    assert tls_res["days_remaining"] is not None and tls_res["days_remaining"] > 0, "Days remaining should be positive for active cert"
    assert tls_res["is_expired"] is False, "Active cert should not be marked expired"
    print("PASS: TLS Certificate Inspector extracted valid metadata:")
    print(f"  Subject CN: {tls_res.get('subject_cn')}")
    print(f"  Issuer: {tls_res.get('issuer_cn')}")
    print(f"  Days Remaining: {tls_res.get('days_remaining')} days")
    print(f"  TLS Version: {tls_res.get('tls_version')}, Cipher: {tls_res.get('cipher')}")
    print(f"  SANs: {tls_res.get('sans')[:3]}")

if __name__ == "__main__":
    asyncio.run(verify_http_and_tls())
