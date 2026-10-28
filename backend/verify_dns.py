import asyncio
from app.discovery.dns_resolver import resolve_dns_records

async def verify_dns():
    print("--- Verifying DNS Discovery Lookups ---")
    
    # 1. Real lookup for standard RFC 2606 / 6761 reserved domain example.com
    res_example = await resolve_dns_records("example.com")
    print(f"example.com DNS results: A={res_example['A']}, AAAA={res_example['AAAA']}, NS={res_example['NS']}, TXT={len(res_example['TXT'])} records")
    assert len(res_example["A"]) > 0 or len(res_example["AAAA"]) > 0, "Expected at least one A or AAAA record for example.com"
    print("PASS: Real DNS lookup successfully resolved A/AAAA records.")

    # 2. Non-existent domain lookup (NXDOMAIN handling)
    res_nx = await resolve_dns_records("nxdomain-argustrace-verify-test-12345.com")
    print(f"NXDOMAIN DNS results: A={res_nx['A']}, error={res_nx['error']}")
    assert len(res_nx["A"]) == 0, "NXDOMAIN should return empty A records"
    assert len(res_nx["AAAA"]) == 0, "NXDOMAIN should return empty AAAA records"
    print("PASS: NXDOMAIN non-existent domain handled cleanly without crashing.")

    # 3. IP address reverse PTR lookup
    res_ip = await resolve_dns_records("8.8.8.8")
    print(f"8.8.8.8 reverse PTR results: PTR={res_ip['PTR']}")
    assert len(res_ip["PTR"]) > 0, "Expected PTR reverse lookup response for 8.8.8.8"
    assert "dns.google" in res_ip["PTR"][0].lower(), f"Expected dns.google in PTR, got {res_ip['PTR']}"
    print("PASS: Reverse DNS PTR lookup succeeded.")

if __name__ == "__main__":
    asyncio.run(verify_dns())
