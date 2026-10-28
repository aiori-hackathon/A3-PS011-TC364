import asyncio
from app.discovery.port_scanner import scan_allowed_ports
from app.security import validate_port_list

async def verify_ports():
    print("--- Verifying Bounded TCP Checks on Authorised Target ---")
    
    # 1. Port allowlist validation & bounding
    valid, ports, err = validate_port_list([8000, 5173, 19876], max_ports=50)
    assert valid is True and len(ports) == 3, "Valid ports should pass validation"
    
    over_limit, _, err_over = validate_port_list(list(range(1, 60)), max_ports=50)
    assert over_limit is False, "Over 50 ports should be rejected"
    assert "exceeded maximum" in err_over.lower()
    print("PASS: Port bounding logic correctly limits to maximum 50 ports.")

    # 2. Live non-destructive TCP check on local listening targets
    # Port 8000 is open (FastAPI), Port 5173 is open (Vite), Port 19876 is closed
    open_ports = await scan_allowed_ports("127.0.0.1", [8000, 5173, 19876], timeout=2.0)
    print(f"Detected open ports on 127.0.0.1: {[p['port'] for p in open_ports]}")
    
    port_nums = [p["port"] for p in open_ports]
    assert 8000 in port_nums, "Port 8000 (FastAPI) should be detected as OPEN"
    assert 5173 in port_nums, "Port 5173 (Vite) should be detected as OPEN"
    assert 19876 not in port_nums, "Closed port 19876 must NOT be detected as OPEN"
    
    for p in open_ports:
        print(f"  Port {p['port']}: status={p['status']}, service={p['service']}, latency={p['latency_ms']}ms")
    print("PASS: Non-destructive TCP probe correctly detected open ports and ignored closed ports.")

if __name__ == "__main__":
    asyncio.run(verify_ports())
