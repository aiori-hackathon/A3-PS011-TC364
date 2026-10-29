import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import urllib.request
import urllib.error

from sqlalchemy.orm import Session
from ..models import NotificationRule, NotificationEvent, Scope, DiscoveredAsset, AssetChangeRecord, ScanFinding
from ..config import settings
from ..security import validate_webhook_url
from .audit_service import log_audit_event

logger = logging.getLogger("argustrace")

# Global mock flag for test suites and offline simulations
MOCK_DELIVERY_OVERRIDE = False

def set_mock_delivery_override(enabled: bool):
    global MOCK_DELIVERY_OVERRIDE
    MOCK_DELIVERY_OVERRIDE = enabled

def compute_dedup_hash(rule_id: str, event_type: str, entity_id: str, extra: str = "") -> str:
    raw = f"{rule_id}:{event_type}:{entity_id}:{extra}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def is_duplicate_event(db: Session, dedup_hash: str, window_hours: int = 24) -> bool:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=window_hours)
    existing = db.query(NotificationEvent).filter(
        NotificationEvent.dedup_hash == dedup_hash,
        NotificationEvent.created_at >= cutoff,
        NotificationEvent.status.in_(["SENT", "PENDING"])
    ).first()
    return existing is not None

def get_integration_status() -> Dict[str, Any]:
    """
    Returns high-level readiness status of external notification integrations
    without exposing any passwords, secrets, or internal server tokens.
    """
    has_smtp = bool(settings.SMTP_HOST and settings.SMTP_HOST.strip())
    return {
        "live_notifications_enabled": settings.ENABLE_LIVE_NOTIFICATIONS,
        "email_integration": {
            "configured": has_smtp,
            "smtp_host_configured": has_smtp,
            "smtp_port": settings.SMTP_PORT if has_smtp else None,
            "sender_address": settings.SMTP_FROM,
            "tls_enabled": settings.SMTP_TLS
        },
        "webhook_integration": {
            "configured": True,
            "timeout_seconds": settings.WEBHOOK_TIMEOUT_SECONDS,
            "ssrf_protection_active": True,
            "live_dispatch_enabled": settings.ENABLE_LIVE_NOTIFICATIONS
        }
    }

def deliver_webhook_notification(event: NotificationEvent, allow_local_lab: bool = False) -> tuple[bool, Optional[str]]:
    """
    Dispatches notification payload to configured webhook destination.
    Validates URL safety, enforces SSRF defenses, and handles mock mode safely.
    """
    url = event.recipient
    is_safe, error_msg = validate_webhook_url(url, allow_local_lab=allow_local_lab)
    if not is_safe:
        return False, f"SSRF Protection blocked webhook delivery: {error_msg}"

    # If live dispatch disabled or mock mode active, succeed safely without network calls
    if not settings.ENABLE_LIVE_NOTIFICATIONS or MOCK_DELIVERY_OVERRIDE:
        return True, "Delivered via simulated secure channel (Live dispatch disabled or test mode)"

    # Live delivery mode
    try:
        payload_bytes = json.dumps(event.payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ArgusTrace-AlertEngine/1.0",
                "X-ArgusTrace-Event": event.event_type
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=settings.WEBHOOK_TIMEOUT_SECONDS) as response:
            if 200 <= response.status < 300:
                return True, f"HTTP {response.status} OK"
            return False, f"Remote endpoint responded with HTTP {response.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Network delivery failed: {str(e.reason)}"
    except Exception as e:
        return False, f"Webhook delivery error: {str(e)}"

def deliver_email_notification(event: NotificationEvent) -> tuple[bool, Optional[str]]:
    """
    Dispatches notification email to configured recipient.
    Validates SMTP presence and handles mock mode safely.
    """
    recipient = event.recipient
    if not recipient or "@" not in recipient:
        return False, "Invalid email recipient address."

    # If SMTP is not configured or live notifications disabled, handle gracefully
    if not settings.ENABLE_LIVE_NOTIFICATIONS or MOCK_DELIVERY_OVERRIDE:
        return True, "Delivered via simulated SMTP channel (Live dispatch disabled or test mode)"

    if not settings.SMTP_HOST:
        return False, "SMTP server not configured in environment (SMTP_HOST is empty)."

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart()
        msg["From"] = settings.SMTP_FROM
        msg["To"] = recipient
        msg["Subject"] = event.subject
        msg.attach(MIMEText(event.message, "plain"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.WEBHOOK_TIMEOUT_SECONDS) as server:
            if settings.SMTP_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

        return True, "SMTP message accepted for delivery."
    except Exception as e:
        return False, f"SMTP delivery error: {str(e)}"

def process_and_dispatch_event(db: Session, event: NotificationEvent, allow_local_lab: bool = False) -> bool:
    """
    Processes delivery for a NotificationEvent and updates its terminal status.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    if event.channel == "webhook":
        success, message = deliver_webhook_notification(event, allow_local_lab=allow_local_lab)
    elif event.channel == "email":
        success, message = deliver_email_notification(event)
    else:
        success, message = False, f"Unsupported notification channel: {event.channel}"

    if success:
        event.status = "SENT"
        event.delivered_at = now
        event.error_message = None
        db.commit()
        log_audit_event(
            db=db,
            action="NOTIFICATION_SENT",
            entity_type="notification_event",
            entity_id=event.id,
            details={
                "channel": event.channel,
                "event_type": event.event_type,
                "recipient": event.recipient,
                "subject": event.subject,
                "confirmation": message
            }
        )
        return True
    else:
        event.retry_count += 1
        event.error_message = message
        if event.retry_count >= event.max_retries:
            event.status = "FAILED"
        else:
            event.status = "PENDING"
        db.commit()
        log_audit_event(
            db=db,
            action="NOTIFICATION_FAILED",
            entity_type="notification_event",
            entity_id=event.id,
            details={
                "channel": event.channel,
                "event_type": event.event_type,
                "recipient": event.recipient,
                "error": message,
                "retry_count": event.retry_count,
                "max_retries": event.max_retries
            }
        )
        return False

def retry_notification_event(db: Session, event_id: str) -> NotificationEvent:
    """
    Manually retries a failed or pending notification event.
    """
    event = db.query(NotificationEvent).filter(NotificationEvent.id == event_id).first()
    if not event:
        raise ValueError(f"Notification event {event_id} not found.")

    scope = db.query(Scope).filter(Scope.id == event.scope_id).first() if event.scope_id else None
    allow_local_lab = scope.allow_local_lab if scope else False

    event.status = "PENDING"
    db.commit()

    log_audit_event(
        db=db,
        action="NOTIFICATION_RETRY",
        entity_type="notification_event",
        entity_id=event.id,
        details={"channel": event.channel, "previous_retries": event.retry_count}
    )

    process_and_dispatch_event(db, event, allow_local_lab=allow_local_lab)
    db.refresh(event)
    return event

# --- Rule Evaluation Handlers ---

def evaluate_new_asset_rules(db: Session, scope_id: str, asset: DiscoveredAsset):
    """
    Evaluates enabled notification rules for newly discovered assets.
    """
    rules = db.query(NotificationRule).filter(
        NotificationRule.is_enabled == True,
        NotificationRule.event_type == "ASSET_DISCOVERED",
        (NotificationRule.scope_id == None) | (NotificationRule.scope_id == scope_id)
    ).all()

    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    scope_name = scope.name if scope else "Unknown Scope"
    allow_local_lab = scope.allow_local_lab if scope else False

    for rule in rules:
        conds = rule.conditions or {}
        req_types = conds.get("asset_types")
        if req_types and asset.asset_type not in req_types:
            continue

        dedup = compute_dedup_hash(rule.id, "ASSET_DISCOVERED", asset.id, asset.host_or_ip)
        if is_duplicate_event(db, dedup):
            continue

        subject = f"[ArgusTrace Alert] New Asset Discovered: {asset.host_or_ip}"
        message = (
            f"A new authorized attack surface asset was discovered.\n\n"
            f"Host / Identifier: {asset.host_or_ip}\n"
            f"Asset Type: {asset.asset_type}\n"
            f"IP Address: {asset.ip_address or 'Unresolved'}\n"
            f"Scope: {scope_name}\n"
            f"First Observed: {asset.first_seen.isoformat() if asset.first_seen else 'N/A'}\n"
        )
        payload = {
            "event": "ASSET_DISCOVERED",
            "rule_id": rule.id,
            "rule_name": rule.name,
            "scope_id": scope_id,
            "scope_name": scope_name,
            "asset_id": asset.id,
            "host": asset.host_or_ip,
            "asset_type": asset.asset_type,
            "ip_address": asset.ip_address
        }

        # Dispatch for each configured channel
        for ch in (rule.channels or []):
            recip = rule.webhook_url if ch == "webhook" else rule.email_recipient
            if not recip:
                continue

            event = NotificationEvent(
                rule_id=rule.id,
                scope_id=scope_id,
                event_type="ASSET_DISCOVERED",
                channel=ch,
                recipient=recip,
                subject=subject,
                message=message,
                payload=payload,
                status="PENDING",
                dedup_hash=dedup,
                max_retries=settings.MAX_NOTIFICATION_RETRIES
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            process_and_dispatch_event(db, event, allow_local_lab=allow_local_lab)

def evaluate_change_rules(db: Session, scope_id: str, change: AssetChangeRecord):
    """
    Evaluates enabled notification rules for detected baseline asset changes.
    """
    rules = db.query(NotificationRule).filter(
        NotificationRule.is_enabled == True,
        NotificationRule.event_type == "ASSET_CHANGED",
        (NotificationRule.scope_id == None) | (NotificationRule.scope_id == scope_id)
    ).all()

    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    scope_name = scope.name if scope else "Unknown Scope"
    allow_local_lab = scope.allow_local_lab if scope else False

    for rule in rules:
        conds = rule.conditions or {}
        req_changes = conds.get("change_types")
        if req_changes and change.change_type not in req_changes:
            continue

        dedup = compute_dedup_hash(rule.id, "ASSET_CHANGED", change.id, change.change_type)
        if is_duplicate_event(db, dedup):
            continue

        subject = f"[ArgusTrace Alert] Asset Change Detected: {change.change_type} on {change.asset_identifier}"
        message = (
            f"An attack surface state shift was detected against the baseline.\n\n"
            f"Asset: {change.asset_identifier}\n"
            f"Change Type: {change.change_type}\n"
            f"Attribute: {change.attribute_name or 'N/A'}\n"
            f"Previous Value: {json.dumps(change.previous_value)}\n"
            f"New Value: {json.dumps(change.new_value)}\n"
            f"Scope: {scope_name}\n"
            f"Observed Time: {change.created_at.isoformat() if change.created_at else 'N/A'}\n"
        )
        payload = {
            "event": "ASSET_CHANGED",
            "rule_id": rule.id,
            "rule_name": rule.name,
            "scope_id": scope_id,
            "scope_name": scope_name,
            "change_id": change.id,
            "asset": change.asset_identifier,
            "change_type": change.change_type,
            "attribute": change.attribute_name,
            "previous_value": change.previous_value,
            "new_value": change.new_value,
            "is_inconclusive": change.is_inconclusive
        }

        for ch in (rule.channels or []):
            recip = rule.webhook_url if ch == "webhook" else rule.email_recipient
            if not recip:
                continue

            event = NotificationEvent(
                rule_id=rule.id,
                scope_id=scope_id,
                event_type="ASSET_CHANGED",
                channel=ch,
                recipient=recip,
                subject=subject,
                message=message,
                payload=payload,
                status="PENDING",
                dedup_hash=dedup,
                max_retries=settings.MAX_NOTIFICATION_RETRIES
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            process_and_dispatch_event(db, event, allow_local_lab=allow_local_lab)

def evaluate_finding_rules(db: Session, scope_id: str, finding: ScanFinding):
    """
    Evaluates enabled notification rules for new or elevated security findings.
    """
    rules = db.query(NotificationRule).filter(
        NotificationRule.is_enabled == True,
        NotificationRule.event_type == "FINDING_DETECTED",
        (NotificationRule.scope_id == None) | (NotificationRule.scope_id == scope_id)
    ).all()

    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    scope_name = scope.name if scope else "Unknown Scope"
    allow_local_lab = scope.allow_local_lab if scope else False

    for rule in rules:
        conds = rule.conditions or {}
        req_severities = conds.get("severities")
        if req_severities and finding.severity.upper() not in [s.upper() for s in req_severities]:
            continue

        dedup = compute_dedup_hash(rule.id, "FINDING_DETECTED", finding.id, finding.severity)
        if is_duplicate_event(db, dedup):
            continue

        subject = f"[ArgusTrace Alert] {finding.severity} Risk Detected: {finding.title}"
        message = (
            f"A security observation matching your alert policy was detected.\n\n"
            f"Title: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"Confidence: {finding.confidence}\n"
            f"Type: {finding.finding_type}\n"
            f"Scope: {scope_name}\n"
            f"Description: {finding.description}\n"
            f"Recommended Remediation: {finding.remediation}\n"
        )
        payload = {
            "event": "FINDING_DETECTED",
            "rule_id": rule.id,
            "rule_name": rule.name,
            "scope_id": scope_id,
            "scope_name": scope_name,
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "finding_type": finding.finding_type,
            "remediation": finding.remediation,
            "evidence": finding.evidence
        }

        for ch in (rule.channels or []):
            recip = rule.webhook_url if ch == "webhook" else rule.email_recipient
            if not recip:
                continue

            event = NotificationEvent(
                rule_id=rule.id,
                scope_id=scope_id,
                event_type="FINDING_DETECTED",
                channel=ch,
                recipient=recip,
                subject=subject,
                message=message,
                payload=payload,
                status="PENDING",
                dedup_hash=dedup,
                max_retries=settings.MAX_NOTIFICATION_RETRIES
            )
            db.add(event)
            db.commit()
            db.refresh(event)
            process_and_dispatch_event(db, event, allow_local_lab=allow_local_lab)
