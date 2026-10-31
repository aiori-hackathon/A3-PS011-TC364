from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from ..database import get_db
from ..models import AuditLog
from ..schemas import AuditLogOut, AuditSummaryOut

router = APIRouter(prefix="/audit", tags=["Audit Trail"])

@router.get("", response_model=List[AuditLogOut])
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    search: Optional[str] = Query(None, description="Search actor or details"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action.upper())
    if entity_type:
        query = query.filter(AuditLog.entity_type == entity_type.lower())
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (AuditLog.actor.ilike(s)) |
            (AuditLog.action.ilike(s)) |
            (AuditLog.entity_id.ilike(s))
        )

    logs = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit).all()
    return logs

@router.get("/summary", response_model=AuditSummaryOut)
def get_audit_summary(db: Session = Depends(get_db)):
    total = db.query(func.count(AuditLog.id)).scalar() or 0

    action_counts = (
        db.query(AuditLog.action, func.count(AuditLog.id))
        .group_by(AuditLog.action)
        .all()
    )
    by_action = {act: cnt for act, cnt in action_counts}

    entity_counts = (
        db.query(AuditLog.entity_type, func.count(AuditLog.id))
        .group_by(AuditLog.entity_type)
        .all()
    )
    by_entity = {ent: cnt for ent, cnt in entity_counts}

    recent = db.query(AuditLog).order_by(desc(AuditLog.created_at)).limit(10).all()

    return AuditSummaryOut(
        total_events=total,
        by_action=by_action,
        by_entity=by_entity,
        recent_events=recent
    )
