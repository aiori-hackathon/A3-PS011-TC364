import asyncio
import socket
from typing import Dict, Any, List
import dns.resolver
import dns.reversename
from ..config import settings
from ..security import is_ip_address

async def resolve_dns_records(target: str) -> Dict[str, Any]:
    """
    Performs DNS record enumeration for A, AAAA, CNAME, MX, NS, TXT records.
    For IP addresses, performs reverse DNS (PTR) lookup.
    """
    results: Dict[str, Any] = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "PTR": [],
        "error": None
    }
    
    ip_obj = is_ip_address(target)
    if ip_obj:
        # Reverse DNS lookup for IP
        try:
            rev_name = dns.reversename.from_address(str(ip_obj))
            resolver = dns.resolver.Resolver()
            resolver.lifetime = settings.DNS_TIMEOUT_SECONDS
            answers = await asyncio.to_thread(resolver.resolve, rev_name, "PTR")
            for rdata in answers:
                results["PTR"].append(str(rdata).rstrip("."))
        except Exception:
            # Fallback reverse lookup
            try:
                hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, str(ip_obj))
                if hostname:
                    results["PTR"].append(hostname)
            except Exception:
                pass
        return results

    # Domain record enumeration
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.DNS_TIMEOUT_SECONDS
    resolver.timeout = settings.DNS_TIMEOUT_SECONDS

    def query_type(qtype: str) -> List[str]:
        try:
            answers = resolver.resolve(target, qtype)
            items = []
            for rdata in answers:
                if qtype == "MX":
                    items.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif qtype in ("CNAME", "NS"):
                    items.append(str(rdata.target).rstrip("."))
                elif qtype == "TXT":
                    # TXT rdata strings might be bytes/joined
                    txt_vals = [t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t) for t in rdata.strings]
                    items.append("".join(txt_vals))
                else:
                    items.append(str(rdata))
            return items
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    # Run queries concurrently in thread pool
    tasks = [asyncio.to_thread(query_type, qtype) for qtype in record_types]
    query_results = await asyncio.gather(*tasks, return_exceptions=True)

    for qtype, res in zip(record_types, query_results):
        if isinstance(res, list):
            results[qtype] = res

    # Fallback for A records using getaddrinfo if dnspython gave empty A records
    if not results["A"] and not results["AAAA"]:
        try:
            addr_info = await asyncio.to_thread(socket.getaddrinfo, target, None)
            for item in addr_info:
                family = item[0]
                ip_addr = item[4][0]
                if family == socket.AF_INET and ip_addr not in results["A"]:
                    results["A"].append(ip_addr)
                elif family == socket.AF_INET6 and ip_addr not in results["AAAA"]:
                    results["AAAA"].append(ip_addr)
        except Exception as e:
            results["error"] = str(e)

    return results
