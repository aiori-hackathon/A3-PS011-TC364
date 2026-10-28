import ipaddress
import re
import socket
from typing import Tuple, Optional, List
from urllib.parse import urlparse

# RFC 1123 Hostname regex (strict, no wildcards, no protocols)
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# Cloud metadata addresses and dangerous ranges
CLOUD_METADATA_IPS = {
    ipaddress.ip_network("169.254.169.254/32"), # AWS, GCP, Azure, OpenStack, DigitalOcean
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

def sanitize_target_input(raw: str) -> str:
    """
    Cleans up user input by stripping protocols (http://, https://), paths, query strings, and whitespace.
    """
    clean = raw.strip()
    if clean.startswith("http://") or clean.startswith("https://"):
        try:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        except Exception:
            pass
    elif "/" in clean:
        clean = clean.split("/")[0]
        
    # Strip port if present in hostname:port (we handle ports separately)
    if ":" in clean and not (clean.startswith("[") or clean.count(":") > 1):
        clean = clean.split(":")[0]
        
    return clean.strip().lower()

def is_ip_address(val: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(val)
    except ValueError:
        return None

def is_valid_domain(val: str) -> bool:
    if len(val) > 253:
        return False
    # Localhost check
    if val == "localhost":
        return True
    return bool(DOMAIN_REGEX.match(val))

def check_ip_safety(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_local_lab: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates whether an IP address is safe to probe.
    Enforces strict SSRF protections:
    - Blocks cloud metadata (169.254.169.254) always.
    - Blocks loopback, link-local, and private ranges unless explicitly authorized as a local lab.
    """
    # Cloud metadata check - always blocked
    for meta_net in CLOUD_METADATA_IPS:
        if ip in meta_net:
            return False, f"Target {ip} matches prohibited cloud metadata endpoint (169.254.169.254)."

    # Prohibited networks
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return False, f"Target {ip} belongs to reserved or special-use network {net}."

    # Loopback
    if ip.is_loopback:
        if not allow_local_lab:
            return False, f"Loopback address {ip} is blocked unless scope has 'Local Lab Mode' explicitly enabled."

    # Link-local
    if ip.is_link_local:
        if not allow_local_lab:
            return False, f"Link-local address {ip} is blocked unless scope has 'Local Lab Mode' explicitly enabled."

    # Private RFC 1918 / ULA
    if ip.is_private:
        if not allow_local_lab:
            return False, f"Private/internal IP address {ip} is blocked. If this is an authorized internal lab, enable 'Local Lab Mode' in scope settings."

    return True, None

def validate_target(target: str, allow_local_lab: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Validates target syntax and initial safety.
    Returns: (is_valid, sanitized_target, error_message)
    """
    sanitized = sanitize_target_input(target)
    if not sanitized:
        return False, "", "Target cannot be empty."

    if any(char in sanitized for char in ["*", "?", ";", "&", "|", "`", "$", " ", "\t", "<", ">", "\"", "'"]):
        return False, sanitized, f"Target contains invalid or wildcard characters: {sanitized}"

    # Check if IP
    ip_obj = is_ip_address(sanitized)
    if ip_obj:
        is_safe, reason = check_ip_safety(ip_obj, allow_local_lab=allow_local_lab)
        if not is_safe:
            return False, sanitized, reason
        return True, sanitized, None

    # Check if domain
    if sanitized == "localhost":
        if not allow_local_lab:
            return False, sanitized, "Localhost target is blocked unless 'Local Lab Mode' is explicitly enabled."
        return True, sanitized, None

    if not is_valid_domain(sanitized):
        return False, sanitized, f"Invalid domain format: {sanitized}. Must be a valid FQDN (e.g., example.com)."

    return True, sanitized, None

def resolve_and_verify_target(host: str, allow_local_lab: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Resolves a hostname and verifies that its underlying IP is safe to probe.
    Prevents DNS rebinding and indirect SSRF.
    Returns: (is_safe, resolved_ip, error_message)
    """
    ip_obj = is_ip_address(host)
    if ip_obj:
        is_safe, reason = check_ip_safety(ip_obj, allow_local_lab=allow_local_lab)
        return is_safe, str(ip_obj), reason

    try:
        resolved_ips = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not resolved_ips:
            return False, None, f"Could not resolve host '{host}'."

        first_ip_str = resolved_ips[0][4][0]
        resolved_ip_obj = ipaddress.ip_address(first_ip_str)

        is_safe, reason = check_ip_safety(resolved_ip_obj, allow_local_lab=allow_local_lab)
        if not is_safe:
            return False, first_ip_str, f"Host '{host}' resolves to prohibited IP ({first_ip_str}): {reason}"

        return True, first_ip_str, None
    except socket.gaierror as e:
        return False, None, f"DNS resolution failed for '{host}': {str(e)}"
    except Exception as e:
        return False, None, f"Error validating target '{host}': {str(e)}"

def validate_port_list(ports: List[int], max_ports: int = 50) -> Tuple[bool, List[int], Optional[str]]:
    """
    Ensures port list is bounded, within 1-65535, and does not exceed maximum limit.
    """
    if not ports:
        return False, [], "At least one port must be specified."
        
    unique_ports = sorted(list(set(ports)))
    
    if len(unique_ports) > max_ports:
        return False, [], f"Exceeded maximum allowable ports ({max_ports}). Selected {len(unique_ports)} ports."

    for p in unique_ports:
        if not isinstance(p, int) or p < 1 or p > 65535:
            return False, [], f"Invalid port number: {p}. Ports must be integers between 1 and 65535."

    return True, unique_ports, None
