import re
import time
from typing import Dict, Any, Optional
import httpx
from ..config import settings
from ..security import resolve_and_verify_target

TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

async def probe_http_service(
    host: str,
    port: int = 80,
    use_https: bool = False,
    allow_local_lab: bool = False,
    timeout: float = settings.HTTP_TIMEOUT_SECONDS
) -> Optional[Dict[str, Any]]:
    """
    Probes an HTTP/HTTPS service for reachability and metadata with strict SSRF protection.
    Blocks redirects to forbidden internal or cloud metadata endpoints.
    """
    scheme = "https" if use_https else "http"
    if (use_https and port == 443) or (not use_https and port == 80):
        url = f"{scheme}://{host}"
    else:
        url = f"{scheme}://{host}:{port}"

    headers = {
        "User-Agent": "ArgusTrace-AssetDiscovery-Scanner/1.0 (+https://argustrace.local/bot; Security Discovery Phase 1)",
        "Accept": "*/*"
    }

    start_time = time.perf_counter()
    redirect_count = 0
    current_url = url
    visited_urls = []

    try:
        # Use an httpx client that does NOT automatically follow redirects blindly
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
            while redirect_count < 5:
                visited_urls.append(current_url)
                resp = await client.get(current_url, headers=headers)
                
                # Check for redirect
                if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                    redirect_location = resp.headers["location"]
                    next_url = str(resp.url.join(redirect_location))
                    redirect_count += 1
                    
                    # Verify next URL host safety before following
                    parsed_next = httpx.URL(next_url)
                    next_host = parsed_next.host
                    
                    if next_host:
                        is_safe, _, reason = resolve_and_verify_target(next_host, allow_local_lab=allow_local_lab)
                        if not is_safe:
                            # Block redirect to prohibited IP
                            return {
                                "reachable": True,
                                "status_code": resp.status_code,
                                "scheme": scheme,
                                "port": port,
                                "url": url,
                                "final_url": current_url,
                                "redirect_count": redirect_count,
                                "redirect_blocked_reason": f"Redirect to unsafe destination blocked: {reason}",
                                "server": resp.headers.get("server"),
                                "content_type": resp.headers.get("content-type"),
                                "title": None,
                                "latency_ms": round((time.perf_counter() - start_time) * 1000, 2)
                            }
                    current_url = next_url
                else:
                    # Final response reached
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    title_match = TITLE_REGEX.search(resp.text[:8192]) # check first 8KB for title
                    title = title_match.group(1).strip() if title_match else None
                    if title:
                        title = re.sub(r"\s+", " ", title)[:120]

                    return {
                        "reachable": True,
                        "status_code": resp.status_code,
                        "scheme": scheme,
                        "port": port,
                        "url": url,
                        "final_url": current_url if redirect_count > 0 else None,
                        "redirect_count": redirect_count,
                        "server": resp.headers.get("server"),
                        "content_type": resp.headers.get("content-type"),
                        "title": title,
                        "latency_ms": duration_ms,
                        "headers": dict(list(resp.headers.items())[:15]) # bounded headers
                    }

            return None
    except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError):
        return None
    except Exception:
        return None
