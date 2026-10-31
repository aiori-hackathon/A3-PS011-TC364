import asyncio
import datetime
import os
import socket
import ssl
import tempfile
from typing import Dict, Any, Optional
import certifi
from ..config import settings

def _parse_ssl_date(date_str: str) -> Optional[datetime.datetime]:
    try:
        # Format e.g.: "May 15 12:00:00 2025 GMT" or "Dec 25 22:56:35 2026 GMT"
        return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None

def _extract_name_dict(name_tuples) -> Dict[str, str]:
    result = {}
    for item in name_tuples:
        for k, v in item:
            result[k] = v
    return result

def _decode_pem_cert_fallback(pem_str: str) -> Optional[Dict[str, Any]]:
    """
    Decodes PEM certificate into dictionary using Python's internal SSL decoder.
    Works for self-signed, expired, or untrusted lab certificates without requiring verification.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as tmp:
            tmp.write(pem_str)
            tmp_path = tmp.name
        if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
            return ssl._ssl._test_decode_cert(tmp_path)
        return None
    except Exception:
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def inspect_tls_certificate_sync(host: str, port: int = 443, timeout: float = settings.TCP_TIMEOUT_SECONDS) -> Optional[Dict[str, Any]]:
    """
    Connects via TLS and extracts certificate metadata synchronously.
    Handles public verified certificates (via certifi) as well as self-signed / lab certificates.
    """
    cert = None
    cipher = None
    protocol_version = None

    # Step 1: Attempt verified TLS handshake with certifi CA bundle
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        context.check_hostname = False
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()
    except Exception:
        pass

    # Step 2: Fallback for self-signed, lab, or untrusted CA certificates
    if not cert:
        try:
            unverified_context = ssl.create_default_context()
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_bytes = ssock.getpeercert(binary_form=True)
                    if der_bytes:
                        pem_str = ssl.DER_cert_to_PEM_cert(der_bytes)
                        cert = _decode_pem_cert_fallback(pem_str)
                    cipher = ssock.cipher()
                    protocol_version = ssock.version()
        except Exception:
            return None

    if not cert:
        return None

    try:
        subject_dict = _extract_name_dict(cert.get("subject", ()))
        issuer_dict = _extract_name_dict(cert.get("issuer", ()))
        
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        
        valid_from_dt = _parse_ssl_date(not_before_str)
        valid_to_dt = _parse_ssl_date(not_after_str)
        
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_remaining = None
        is_expired = False
        if valid_to_dt:
            diff = valid_to_dt - now
            days_remaining = diff.days
            if days_remaining < 0:
                is_expired = True

        # SANs (Subject Alternative Names)
        sans = []
        for ext in cert.get("subjectAltName", ()):
            if len(ext) == 2 and ext[0].lower() in ("dns", "ip address"):
                sans.append(ext[1])

        return {
            "has_tls": True,
            "port": port,
            "subject_cn": subject_dict.get("commonName", ""),
            "subject_org": subject_dict.get("organizationName", ""),
            "issuer_cn": issuer_dict.get("commonName", ""),
            "issuer_org": issuer_dict.get("organizationName", ""),
            "valid_from": valid_from_dt.isoformat() if valid_from_dt else not_before_str,
            "valid_to": valid_to_dt.isoformat() if valid_to_dt else not_after_str,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "sans": sans[:20],
            "cipher": cipher[0] if cipher else None,
            "tls_version": protocol_version,
            "serial_number": cert.get("serialNumber")
        }
    except Exception:
        return None

async def inspect_tls_certificate(host: str, port: int = 443, timeout: float = settings.TCP_TIMEOUT_SECONDS) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(inspect_tls_certificate_sync, host, port, timeout)
