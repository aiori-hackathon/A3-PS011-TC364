from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from ..models import DiscoveredAsset, ScanFinding

# Documented Sensitive Services Knowledge Base (Port -> Risk Metadata)
SENSITIVE_PORT_RULES = {
    # High Risk Unauthenticated / Raw Exposure
    23: {
        "service": "Telnet",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "Unencrypted Telnet Management Protocol Exposed",
        "description": "Legacy Telnet service observed listening on port 23. Telnet transmits authentication credentials and commands in cleartext, exposing the host to network eavesdropping and credential theft.",
        "remediation": "Disable the Telnet service immediately. Migrate all remote administrative access to SSH (port 22) with cryptographic public-key authentication."
    },
    6379: {
        "service": "Redis",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "Redis In-Memory Key-Value Store Publicly Exposed",
        "description": "Redis database port 6379 is listening on network interfaces. Redis instances are frequently unauthenticated or minimally protected by design, enabling remote unauthenticated command execution and data dumping.",
        "remediation": "Bind Redis strictly to loopback (127.0.0.1) or an internal VPC network; require strong authentication with 'requirepass'; restrict port 6379 access via perimeter firewalls."
    },
    27017: {
        "service": "MongoDB",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "MongoDB Database Port Directly Exposed",
        "description": "MongoDB listener observed open on default port 27017. Direct exposure of database listeners to external networks increases attack surface for brute force and unauthenticated query attacks.",
        "remediation": "Enforce network firewall rules restricting port 27017 strictly to authorized application tiers; enable authentication and TLS wire encryption."
    },
    9200: {
        "service": "Elasticsearch",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "Elasticsearch REST API Endpoint Exposed",
        "description": "Elasticsearch HTTP REST API port 9200 is open. Unprotected Elasticsearch clusters may expose sensitive index documents and cluster management endpoints to unauthorized queries.",
        "remediation": "Restrict port 9200 to internal subnets; enable Elastic Security (X-Pack) authentication and HTTPS."
    },
    # Medium Risk Database & Management Exposure
    3306: {
        "service": "MySQL",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "MySQL Database Listener Exposed",
        "description": "MySQL database server listening on port 3306. Database listeners should only be accessible to dedicated application servers within private network boundaries.",
        "remediation": "Bind MySQL to private VPC interface; block inbound access on port 3306 from external subnets; enforce TLS."
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "PostgreSQL Database Listener Exposed",
        "description": "PostgreSQL database port 5432 observed responsive. Public network exposure increases risk of denial-of-service and credential brute force attempts.",
        "remediation": "Restrict PostgreSQL listen_addresses and pg_hba.conf to authorized client hosts; enforce firewall boundaries."
    },
    1433: {
        "service": "Microsoft SQL Server",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Microsoft SQL Server Database Port Exposed",
        "description": "MSSQL port 1433 observed accessible over the network.",
        "remediation": "Place database server behind perimeter firewalls and restrict access to authorized application servers."
    },
    3389: {
        "service": "Remote Desktop Protocol (RDP)",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Microsoft Remote Desktop (RDP) Exposed",
        "description": "RDP service detected on port 3389. RDP endpoints exposed to untrusted networks are primary targets for automated credential stuffing and ransomware attacks.",
        "remediation": "Require an enterprise VPN or Azure Bastion/Guacamole with MFA for remote administration; never expose RDP directly to untrusted networks."
    },
    5900: {
        "service": "VNC",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Virtual Network Computing (VNC) Desktop Exposed",
        "description": "VNC graphical remote control listening on port 5900. Standard VNC implementations have weak authentication mechanisms.",
        "remediation": "Tunnel VNC sessions over SSH or VPN; avoid public exposure."
    },
    # Low / Informational Services
    22: {
        "service": "SSH",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "SSH Remote Administration Service Exposed",
        "description": "Secure Shell (SSH) listener active on standard port 22.",
        "remediation": "Disable password authentication; enforce public key auth; use rate limiting (fail2ban); restrict access by IP whitelist or VPN where possible."
    },
    21: {
        "service": "FTP",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Cleartext File Transfer Protocol (FTP) Exposed",
        "description": "Legacy FTP service listening on port 21 transmits credentials and files in cleartext.",
        "remediation": "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS with mandatory TLS."
    },
    25: {
        "service": "SMTP",
        "severity": "INFORMATIONAL",
        "confidence": "CONFIRMED",
        "title": "SMTP Mail Transfer Agent Active",
        "description": "Mail transfer agent listening on standard port 25.",
        "remediation": "Ensure STARTTLS is enforced and relay permissions are restricted to authenticated senders."
    },
    587: {
        "service": "SMTP-Submission",
        "severity": "INFORMATIONAL",
        "confidence": "CONFIRMED",
        "title": "Mail Submission Port Active",
        "description": "Message submission port 587 observed active for client outbound email.",
        "remediation": "Require TLS and SASL authentication on submission port."
    },
    80: {
        "service": "HTTP",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Unencrypted HTTP Web Service Active",
        "description": "Cleartext HTTP service detected on port 80.",
        "remediation": "Configure automatic HTTP 301 redirect to HTTPS (port 443) and enable Strict-Transport-Security (HSTS)."
    },
    443: {
        "service": "HTTPS",
        "severity": "INFORMATIONAL",
        "confidence": "CONFIRMED",
        "title": "Standard Encrypted HTTPS Web Service",
        "description": "Standard TLS-encrypted HTTPS web service detected on port 443.",
        "remediation": "Maintain current TLS configuration and verify certificate validity."
    },
    8443: {
        "service": "HTTPS-Alt",
        "severity": "INFORMATIONAL",
        "confidence": "CONFIRMED",
        "title": "Alternative HTTPS Web Service",
        "description": "Encrypted HTTPS service observed on secondary port 8443.",
        "remediation": "Verify that secondary HTTPS port is intentional and matches security policy."
    },
    8080: {
        "service": "HTTP-Proxy/Alt",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Alternative HTTP Service Exposed",
        "description": "Web service listening on alternative port 8080. Often used for administrative consoles, proxies, or internal APIs.",
        "remediation": "Verify whether port 8080 is an administrative interface; enforce TLS and access controls."
    },
    8000: {
        "service": "HTTP-Dev/Alt",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Development / Alternative HTTP Service Active",
        "description": "Alternative HTTP server listening on port 8000.",
        "remediation": "Confirm service is intended for production; terminate unauthorized testing servers."
    },
    3000: {
        "service": "Node/React-Dev",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Web Application Dev Port Active",
        "description": "Port 3000 responsive, commonly associated with Node.js/React development servers or monitoring dashboards (Grafana).",
        "remediation": "Do not expose development servers to untrusted networks; enforce authentication."
    }
}

def evaluate_and_persist_findings(
    db: Session,
    scan_run_id: str,
    scope_id: str,
    asset: DiscoveredAsset
) -> List[ScanFinding]:
    """
    Evaluates deterministic, explainable risk classification rules against an asset's
    observed metadata (open ports, TLS, HTTP, DNS). Persists structured findings and
    handles deduplication across consecutive discovery runs.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    evaluated_findings: List[ScanFinding] = []

    host = asset.host_or_ip
    open_ports = asset.open_ports or []
    dns = asset.dns_records or {}
    http = asset.http_summary or {}
    tls = asset.tls_summary or {}

    candidates: List[Dict[str, Any]] = []

    # 1. EVALUATE OPEN PORTS & EXPOSED SERVICES
    for p in open_ports:
        port_num = p.get("port")
        if not isinstance(port_num, int):
            continue

        rule = SENSITIVE_PORT_RULES.get(port_num)
        if rule:
            severity = rule["severity"]
            title = f"{rule['title']} ({host}:{port_num})"
            desc = rule["description"].format(host=host, port=port_num, service=p.get("service") or rule["service"], banner=p.get("banner") or "")
            remediation = rule["remediation"]
            finding_type = "EXPOSURE" if severity in ("HIGH", "CRITICAL") else "PORT"
            confidence = rule["confidence"]
        else:
            # Generic bounded port check - NOT classified as vulnerable solely because open!
            severity = "INFORMATIONAL"
            finding_type = "PORT"
            confidence = "CONFIRMED"
            title = f"TCP Port {port_num} ({p.get('service', 'Unknown')}) Responsive"
            desc = f"TCP port {port_num} ({p.get('service', 'Unknown')}) responded with SYN-ACK within allowable latency ({p.get('latency_ms', 0)}ms). Port is documented as part of authorized surface."
            remediation = "Confirm that this service port is required by business applications. Close unused ports via firewall or local service configuration."

        candidates.append({
            "dedup_key": f"{scope_id}:{asset.id}:PORT:{port_num}",
            "finding_type": finding_type,
            "title": title,
            "description": desc,
            "severity": severity,
            "confidence": confidence,
            "remediation": remediation,
            "evidence": {
                "port": port_num,
                "service": p.get("service"),
                "status": p.get("status"),
                "latency_ms": p.get("latency_ms"),
                "banner": p.get("banner")
            }
        })

    # 2. EVALUATE TLS CERTIFICATES
    if tls.get("has_tls"):
        valid_to = tls.get("valid_to")
        days_rem = tls.get("days_remaining")
        is_expired = bool(tls.get("is_expired"))
        issuer = tls.get("issuer_cn") or "Unknown Issuer"

        if is_expired or (days_rem is not None and days_rem < 0):
            days_overdue = abs(days_rem) if days_rem is not None else 0
            sev = "CRITICAL" if days_overdue > 30 else "HIGH"
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:TLS:expired",
                "finding_type": "TLS",
                "title": f"Expired TLS Certificate on {host} ({days_overdue} days overdue)",
                "description": f"The TLS certificate for '{host}' expired on {valid_to}. Web browsers and TLS clients will reject connections with fatal certificate authority or validity errors.",
                "severity": sev,
                "confidence": "CONFIRMED",
                "remediation": "Renew and deploy an active X.509 certificate immediately using your certificate authority or automated ACME workflow (Certbot/Let's Encrypt).",
                "evidence": tls
            })
        elif days_rem is not None and days_rem <= 14:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:TLS:imminent_expiry",
                "finding_type": "TLS",
                "title": f"Imminent TLS Certificate Expiry on {host} ({days_rem} days remaining)",
                "description": f"The TLS certificate for '{host}' issued by '{issuer}' expires in {days_rem} days (on {valid_to}).",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "remediation": "Initiate certificate renewal and installation before expiration to avoid service interruption and customer security warnings.",
                "evidence": tls
            })
        elif days_rem is not None and days_rem <= 30:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:TLS:approaching_expiry",
                "finding_type": "TLS",
                "title": f"Approaching TLS Certificate Expiry on {host} ({days_rem} days remaining)",
                "description": f"The TLS certificate for '{host}' issued by '{issuer}' will expire within 30 days ({days_rem} days remaining).",
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "remediation": "Schedule certificate renewal within the next operational maintenance window.",
                "evidence": tls
            })
        else:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:TLS:valid",
                "finding_type": "TLS",
                "title": f"Valid TLS Certificate ({tls.get('subject_cn', host)})",
                "description": f"Valid TLS certificate detected, issued by '{issuer}' with {days_rem or 'unspecified'} days of validity remaining.",
                "severity": "INFORMATIONAL",
                "confidence": "CONFIRMED",
                "remediation": "Continue regular certificate lifecycle tracking.",
                "evidence": tls
            })

    # 3. EVALUATE HTTP WEB OBSERVATIONS
    if http.get("reachable"):
        code = http.get("status_code")
        server = http.get("server") or ""
        title_str = http.get("title") or ""

        # Server error status
        if isinstance(code, int) and code >= 500:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:HTTP:status_{code}",
                "finding_type": "HTTP",
                "title": f"HTTP {code} Internal Server Error on {host}",
                "description": f"HTTP probe returned server error status code {code} ({title_str}). This may indicate an unhandled exception or upstream service disruption.",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "remediation": "Inspect application error logs, reverse proxy gateways, and downstream database dependencies.",
                "evidence": http
            })
        elif isinstance(code, int) and code == 403:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:HTTP:status_403",
                "finding_type": "HTTP",
                "title": f"HTTP 403 Forbidden Access Control Active on {host}",
                "description": f"Web server responded with HTTP 403 Forbidden, indicating access restriction or WAF enforcement is active.",
                "severity": "INFORMATIONAL",
                "confidence": "CONFIRMED",
                "remediation": "Verify authorization rules and ensure administrative paths are not leaking sensitive metadata.",
                "evidence": http
            })

        # Server version banner disclosure
        if server and any(c.isdigit() for c in server):
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:HTTP:version_disclosure",
                "finding_type": "CONFIGURATION",
                "title": f"Web Server Advertises Software Version ({server})",
                "description": f"The HTTP Server response header reveals precise software and version metadata: '{server}'. Attackers use version banners to identify potential known CVEs.",
                "remediation": "Disable detailed version banners in your web server configuration (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off' in Nginx).",
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "evidence": {"server_header": server, "http_summary": http}
            })

    # 4. EVALUATE DNS CONFIGURATIONS
    txt_records = dns.get("TXT", [])
    mx_records = dns.get("MX", [])

    # Check for overly permissive SPF
    for txt in txt_records:
        if "v=spf1" in txt and "+all" in txt:
            candidates.append({
                "dedup_key": f"{scope_id}:{asset.id}:DNS:permissive_spf",
                "finding_type": "CONFIGURATION",
                "title": f"Permissive SPF Record (+all) on {host}",
                "description": f"The SPF record contains '+all': '{txt}'. This explicitly authorizes ANY IP address on the internet to send email on behalf of your domain.",
                "severity": "HIGH",
                "confidence": "HIGH",
                "remediation": "Change '+all' to '-all' (hardfail) or '~all' (softfail), specifying only authorized mail servers.",
                "evidence": {"spf_record": txt}
            })
            break

    # Check for missing SPF on domains that accept mail
    if mx_records and not any("v=spf1" in txt for txt in txt_records):
        candidates.append({
            "dedup_key": f"{scope_id}:{asset.id}:DNS:missing_spf",
            "finding_type": "CONFIGURATION",
            "title": f"Missing SPF Authentication on Mail Domain {host}",
            "description": f"Domain publishes MX mail exchange records ({mx_records}) but has no SPF (v=spf1) record configured in TXT. Mail sent from this domain may fail DMARC or be spoofed.",
            "severity": "LOW",
            "confidence": "HIGH",
            "remediation": "Publish an authorized SPF TXT record for this domain.",
            "evidence": {"mx_records": mx_records, "txt_records": txt_records}
        })

    # DNS Resolution Finding
    if dns.get("A") or dns.get("AAAA"):
        ip_list = dns.get("A", []) + dns.get("AAAA", [])
        candidates.append({
            "dedup_key": f"{scope_id}:{asset.id}:DNS:resolution",
            "finding_type": "DNS",
            "title": f"DNS Resolution Active for {host}",
            "description": f"Host successfully resolves to IP mappings: {ip_list}.",
            "severity": "INFORMATIONAL",
            "confidence": "CONFIRMED",
            "remediation": "Maintain regular DNS zone record auditing.",
            "evidence": dns
        })

    # DEDUPLICATION & PERSISTENCE
    for cand in candidates:
        dedup_key = cand["dedup_key"]
        existing: Optional[ScanFinding] = (
            db.query(ScanFinding)
            .filter(ScanFinding.dedup_key == dedup_key)
            .first()
        )

        if existing:
            # Update existing finding with new observation timestamp and scan link
            existing.last_observed = now
            existing.scan_run_id = scan_run_id
            existing.evidence = cand["evidence"]
            existing.description = cand["description"]
            existing.remediation = cand["remediation"]
            existing.severity = cand["severity"]
            existing.confidence = cand["confidence"]
            evaluated_findings.append(existing)
        else:
            # Create new finding
            status_history = [
                {
                    "status": "OPEN",
                    "timestamp": now.isoformat(),
                    "note": "Initial observation by discovery engine"
                }
            ]
            finding = ScanFinding(
                scope_id=scope_id,
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                finding_type=cand["finding_type"],
                title=cand["title"],
                description=cand["description"],
                severity=cand["severity"],
                confidence=cand["confidence"],
                review_status="OPEN",
                remediation=cand["remediation"],
                evidence=cand["evidence"],
                status_history=status_history,
                dedup_key=dedup_key,
                first_detected=now,
                last_observed=now,
                created_at=now
            )
            db.add(finding)
            evaluated_findings.append(finding)

    db.commit()
    return evaluated_findings
