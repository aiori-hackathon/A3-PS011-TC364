import asyncio
import time
from typing import List, Dict, Any
from ..config import settings

# Common service names for display
KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3000: "Node / Web App",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy / Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Sonar / Web",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

async def check_single_port(host: str, port: int, timeout: float = settings.TCP_TIMEOUT_SECONDS) -> Dict[str, Any] | None:
    """
    Attempts non-destructive, opt-in TCP connection to host:port within bounded timeout.
    Returns open port info or None if closed/filtered.
    """
    start_time = time.perf_counter()
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        
        banner = ""
        # Bounded attempt to read initial banner if server sends one (e.g. SSH, FTP, SMTP)
        try:
            banner_data = await asyncio.wait_for(reader.read(128), timeout=0.5)
            if banner_data:
                banner = banner_data.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return {
            "port": port,
            "status": "OPEN",
            "service": KNOWN_SERVICES.get(port, "Unknown"),
            "latency_ms": duration_ms,
            "banner": banner[:100] if banner else None
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

async def scan_allowed_ports(
    host: str, 
    ports: List[int], 
    concurrency: int = 10,
    timeout: float = settings.TCP_TIMEOUT_SECONDS
) -> List[Dict[str, Any]]:
    """
    Scans a bounded allowlist of ports for the specified host.
    """
    semaphore = asyncio.Semaphore(concurrency)
    open_ports: List[Dict[str, Any]] = []

    async def sem_check(p: int):
        async with semaphore:
            res = await check_single_port(host, p, timeout=timeout)
            if res:
                open_ports.append(res)

    tasks = [sem_check(p) for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Sort open ports numerically
    open_ports.sort(key=lambda x: x["port"])
    return open_ports
