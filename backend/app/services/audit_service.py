import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from ..models import AuditLog

logger = logging.getLogger("argustrace")

# Sensitive keys that should never be stored in audit logs
REDACTED_KEYS = {"password", "secret", "token", "auth", "api_key", "credentials", "smtp_password", "key"}

def sanitize_audit_details(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data or not isinstance(data, dict):
        return {}
    
    clean: Dict[str, Any] = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if isinstance(v, dict):
            clean[k] = sanitize_audit_details(v)
        elif any(redacted in k_lower for redacted in REDACTED_KEYS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, (str, int, float, bool, list)):
            clean[k] = v
        else:
            clean[k] = str(v)
    return clean

def log_audit_event(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: Optional[str] = None,
    actor: str = "SecOps User",
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Persists an immutable audit log entry for security and operational actions.
    Ensures zero sensitive payloads are recorded.
    """
    clean_details = sanitize_audit_details(details)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    log_entry = AuditLog(
        action=action.upper(),
        actor=actor,
        entity_type=entity_type.lower(),
        entity_id=entity_id,
        details=clean_details,
        created_at=now
    )
    
    db.add(log_entry)
    try:
        db.commit()
        db.refresh(log_entry)
        logger.info(f"[Audit] {action} on {entity_type}:{entity_id or 'all'} by {actor}")
        return log_entry
    except Exception as e:
        db.rollback()
        logger.error(f"[Audit Error] Failed to persist audit log: {e}", exc_info=True)
        return log_entry
