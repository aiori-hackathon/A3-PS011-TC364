from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import NotificationRule, NotificationEvent, Scope
from ..schemas import (
    NotificationRuleCreate,
    NotificationRuleUpdate,
    NotificationRuleOut,
    NotificationEventOut,
    IntegrationStatusOut
)
from ..security import validate_webhook_url
from ..services.notification_service import (
    get_integration_status,
    retry_notification_event
)
from ..services.audit_service import log_audit_event

router = APIRouter(prefix="/notifications", tags=["Notifications & Alerts"])

VALID_EVENT_TYPES = {"ASSET_DISCOVERED", "ASSET_CHANGED", "FINDING_DETECTED"}
VALID_CHANNELS = {"webhook", "email"}

def _to_rule_out(rule: NotificationRule, scope_name: Optional[str] = None) -> NotificationRuleOut:
    return NotificationRuleOut(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        is_enabled=rule.is_enabled,
        event_type=rule.event_type,
        scope_id=rule.scope_id,
        scope_name=scope_name or (rule.scope.name if rule.scope else "All Scopes"),
        conditions=rule.conditions or {},
        channels=rule.channels or [],
        webhook_url=rule.webhook_url,
        email_recipient=rule.email_recipient,
        created_at=rule.created_at,
        updated_at=rule.updated_at
    )

def _to_event_out(event: NotificationEvent, scope_name: Optional[str] = None) -> NotificationEventOut:
    return NotificationEventOut(
        id=event.id,
        rule_id=event.rule_id,
        scope_id=event.scope_id,
        scope_name=scope_name or (event.scope.name if event.scope else "Global"),
        event_type=event.event_type,
        channel=event.channel,
        recipient=event.recipient,
        subject=event.subject,
        message=event.message,
        payload=event.payload or {},
        status=event.status,
        error_message=event.error_message,
        retry_count=event.retry_count,
        max_retries=event.max_retries,
        created_at=event.created_at,
        delivered_at=event.delivered_at
    )

@router.get("/integrations/status", response_model=IntegrationStatusOut)
def get_integrations_readiness():
    return get_integration_status()

# --- Notification Rules Endpoints ---

@router.get("/rules", response_model=List[NotificationRuleOut])
def list_notification_rules(
    scope_id: Optional[str] = Query(None, description="Filter by authorized scope ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    enabled_only: Optional[bool] = Query(None, description="Filter only enabled rules"),
    db: Session = Depends(get_db)
):
    query = db.query(NotificationRule)
    if scope_id:
        query = query.filter((NotificationRule.scope_id == scope_id) | (NotificationRule.scope_id == None))
    if event_type:
        query = query.filter(NotificationRule.event_type == event_type.upper())
    if enabled_only is not None:
        query = query.filter(NotificationRule.is_enabled == enabled_only)

    rules = query.order_by(desc(NotificationRule.created_at)).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    return [_to_rule_out(r, scopes_map.get(r.scope_id)) for r in rules]

@router.post("/rules", response_model=NotificationRuleOut, status_code=status.HTTP_201_CREATED)
def create_notification_rule(payload: NotificationRuleCreate, db: Session = Depends(get_db)):
    ev_type = payload.event_type.upper().strip()
    if ev_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid event_type '{payload.event_type}'. Allowed: {sorted(list(VALID_EVENT_TYPES))}"
        )

    # Validate channels
    for ch in payload.channels:
        if ch not in VALID_CHANNELS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported channel '{ch}'. Allowed channels: {sorted(list(VALID_CHANNELS))}"
            )

    # Scope validation
    allow_local_lab = False
    if payload.scope_id:
        scope = db.query(Scope).filter(Scope.id == payload.scope_id).first()
        if not scope:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Specified scope does not exist.")
        allow_local_lab = scope.allow_local_lab

    # Webhook SSRF validation
    if "webhook" in payload.channels:
        if not payload.webhook_url:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="webhook_url is required when webhook channel is selected.")
        is_safe, error_msg = validate_webhook_url(payload.webhook_url, allow_local_lab=allow_local_lab)
        if not is_safe:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid or unsafe webhook URL: {error_msg}")

    # Email validation
    if "email" in payload.channels:
        if not payload.email_recipient or "@" not in payload.email_recipient:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Valid email_recipient is required when email channel is selected.")

    new_rule = NotificationRule(
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description else None,
        is_enabled=payload.is_enabled,
        event_type=ev_type,
        scope_id=payload.scope_id,
        conditions=payload.conditions,
        channels=payload.channels,
        webhook_url=payload.webhook_url,
        email_recipient=payload.email_recipient
    )

    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    log_audit_event(
        db=db,
        action="NOTIFICATION_RULE_CREATED",
        entity_type="notification_rule",
        entity_id=new_rule.id,
        details={
            "rule_name": new_rule.name,
            "event_type": new_rule.event_type,
            "channels": new_rule.channels,
            "scope_id": new_rule.scope_id
        }
    )

    return _to_rule_out(new_rule)

@router.get("/rules/{rule_id}", response_model=NotificationRuleOut)
def get_notification_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification rule not found.")
    return _to_rule_out(rule)

@router.put("/rules/{rule_id}", response_model=NotificationRuleOut)
def update_notification_rule(rule_id: str, payload: NotificationRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification rule not found.")

    allow_local_lab = False
    if rule.scope_id:
        scope = db.query(Scope).filter(Scope.id == rule.scope_id).first()
        if scope:
            allow_local_lab = scope.allow_local_lab

    if payload.name is not None:
        rule.name = payload.name.strip()
    if payload.description is not None:
        rule.description = payload.description.strip() if payload.description else None
    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled
    if payload.conditions is not None:
        rule.conditions = payload.conditions
    if payload.channels is not None:
        rule.channels = payload.channels
    if payload.webhook_url is not None:
        if payload.webhook_url:
            is_safe, error_msg = validate_webhook_url(payload.webhook_url, allow_local_lab=allow_local_lab)
            if not is_safe:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsafe webhook URL: {error_msg}")
        rule.webhook_url = payload.webhook_url
    if payload.email_recipient is not None:
        rule.email_recipient = payload.email_recipient

    rule.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(rule)

    log_audit_event(
        db=db,
        action="NOTIFICATION_RULE_UPDATED",
        entity_type="notification_rule",
        entity_id=rule.id,
        details={
            "rule_name": rule.name,
            "is_enabled": rule.is_enabled,
            "channels": rule.channels
        }
    )

    return _to_rule_out(rule)

@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification rule not found.")

    rule_name = rule.name
    db.delete(rule)
    db.commit()

    log_audit_event(
        db=db,
        action="NOTIFICATION_RULE_DELETED",
        entity_type="notification_rule",
        entity_id=rule_id,
        details={"rule_name": rule_name}
    )

# --- Notification History Endpoints ---

@router.get("/history", response_model=List[NotificationEventOut])
def list_notification_history(
    scope_id: Optional[str] = Query(None, description="Filter by scope ID"),
    status: Optional[str] = Query(None, description="Filter by status: PENDING, SENT, FAILED"),
    channel: Optional[str] = Query(None, description="Filter by channel: webhook, email"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(NotificationEvent)
    if scope_id:
        query = query.filter(NotificationEvent.scope_id == scope_id)
    if status:
        query = query.filter(NotificationEvent.status == status.upper())
    if channel:
        query = query.filter(NotificationEvent.channel == channel.lower())

    events = query.order_by(desc(NotificationEvent.created_at)).offset(offset).limit(limit).all()
    scopes_map = {s.id: s.name for s in db.query(Scope).all()}

    return [_to_event_out(e, scopes_map.get(e.scope_id)) for e in events]

@router.post("/history/{event_id}/retry", response_model=NotificationEventOut)
def retry_failed_notification(event_id: str, db: Session = Depends(get_db)):
    try:
        updated = retry_notification_event(db, event_id)
        return _to_event_out(updated)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Retry failed: {str(e)}")
