from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import DiscoverySchedule, Scope, ScanRun
from ..schemas import ScheduleCreate, ScheduleUpdate, ScheduleOut, ScanOut
from ..services.schedule_service import compute_next_run, trigger_schedule_execution, ScheduleConcurrencyError
from ..services.audit_service import log_audit_event

router = APIRouter(prefix="/schedules", tags=["Discovery Schedules"])

def to_schedule_out(sched: DiscoverySchedule, db: Session) -> ScheduleOut:
    scope = db.query(Scope).filter(Scope.id == sched.scope_id).first()
    exec_count = db.query(ScanRun).filter(ScanRun.schedule_id == sched.id).count()
    return ScheduleOut(
        id=sched.id,
        scope_id=sched.scope_id,
        scope_name=scope.name if scope else "Unknown Scope",
        name=sched.name,
        description=sched.description,
        is_enabled=sched.is_enabled,
        frequency=sched.frequency,
        interval_hours=sched.interval_hours,
        config=sched.config or {},
        last_run_at=sched.last_run_at,
        last_run_status=sched.last_run_status,
        last_scan_run_id=sched.last_scan_run_id,
        next_run_at=sched.next_run_at,
        created_at=sched.created_at,
        updated_at=sched.updated_at,
        execution_count=exec_count
    )

@router.get("", response_model=List[ScheduleOut])
def list_schedules(scope_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(DiscoverySchedule)
    if scope_id:
        query = query.filter(DiscoverySchedule.scope_id == scope_id)
    schedules = query.order_by(desc(DiscoverySchedule.created_at)).all()
    return [to_schedule_out(s, db) for s in schedules]

@router.get("/{schedule_id}", response_model=ScheduleOut)
def get_schedule(schedule_id: str, db: Session = Depends(get_db)):
    sched = db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery schedule not found.")
    return to_schedule_out(sched, db)

@router.post("", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db)):
    scope = db.query(Scope).filter(Scope.id == payload.scope_id).first()
    if not scope:
        from ..config import CANONICAL_DEMO_SCOPE_ID
        if payload.scope_id == CANONICAL_DEMO_SCOPE_ID or payload.scope_id.startswith("00000000-") or "demo" in payload.scope_id.lower() or db.query(Scope).count() == 0:
            from .stats import get_or_create_demo_scope
            scope = get_or_create_demo_scope(db)
        else:
            scope = db.query(Scope).filter(
                (Scope.name.ilike("%[DEMO / SYNTHETIC]%")) |
                (Scope.name.ilike("%Demo Lab%"))
            ).first()
    if not scope:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Specified target scope does not exist.")

    if not scope.authorised_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot configure scheduled scans: Scope has not been confirmed as authorised."
        )

    initial_next_run = compute_next_run(payload.frequency, payload.interval_hours, datetime.utcnow())

    schedule = DiscoverySchedule(
        scope_id=payload.scope_id,
        name=payload.name,
        description=payload.description,
        is_enabled=payload.is_enabled,
        frequency=payload.frequency,
        interval_hours=payload.interval_hours,
        config=payload.config or {},
        next_run_at=initial_next_run
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    log_audit_event(
        db=db,
        action="SCHEDULE_CREATED",
        entity_type="discovery_schedule",
        entity_id=schedule.id,
        actor="SecOps Admin",
        details={
            "name": schedule.name,
            "scope_id": scope.id,
            "scope_name": scope.name,
            "frequency": schedule.frequency,
            "interval_hours": schedule.interval_hours,
            "next_run_at": schedule.next_run_at.isoformat()
        }
    )

    return to_schedule_out(schedule, db)

@router.patch("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: str, payload: ScheduleUpdate, db: Session = Depends(get_db)):
    sched = db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery schedule not found.")

    if payload.name is not None:
        sched.name = payload.name
    if payload.description is not None:
        sched.description = payload.description
    if payload.is_enabled is not None:
        sched.is_enabled = payload.is_enabled
    if payload.frequency is not None:
        sched.frequency = payload.frequency
    if payload.interval_hours is not None:
        sched.interval_hours = payload.interval_hours
    if payload.config is not None:
        sched.config = payload.config

    if (payload.frequency is not None or payload.interval_hours is not None) and sched.is_enabled:
        sched.next_run_at = compute_next_run(sched.frequency, sched.interval_hours, datetime.utcnow())

    sched.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(sched)

    log_audit_event(
        db=db,
        action="SCHEDULE_UPDATED",
        entity_type="discovery_schedule",
        entity_id=sched.id,
        actor="SecOps Admin",
        details={
            "name": sched.name,
            "is_enabled": sched.is_enabled,
            "frequency": sched.frequency,
            "interval_hours": sched.interval_hours,
            "next_run_at": sched.next_run_at.isoformat()
        }
    )

    return to_schedule_out(sched, db)

@router.delete("/{schedule_id}", status_code=status.HTTP_200_OK)
def delete_schedule(schedule_id: str, db: Session = Depends(get_db)):
    sched = db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery schedule not found.")

    schedule_name = sched.name
    scope_id = sched.scope_id

    log_audit_event(
        db=db,
        action="SCHEDULE_DELETED",
        entity_type="discovery_schedule",
        entity_id=schedule_id,
        actor="SecOps Admin",
        details={"name": schedule_name, "scope_id": scope_id}
    )

    db.delete(sched)
    db.commit()

    return {"message": "Schedule deleted successfully.", "id": schedule_id}

@router.post("/{schedule_id}/trigger", response_model=ScanOut)
async def trigger_schedule_now(schedule_id: str, db: Session = Depends(get_db)):
    try:
        scan = trigger_schedule_execution(
            db=db,
            schedule_id=schedule_id,
            actor="SecOps User (Manual Run)",
            is_manual=True
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ScheduleConcurrencyError as ce:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ce))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    scope = db.query(Scope).filter(Scope.id == scan.scope_id).first()
    return ScanOut(
        id=scan.id,
        scope_id=scan.scope_id,
        scope_name=scope.name if scope else "Unknown Scope",
        status=scan.status,
        config=scan.config or {},
        targets_total=scan.targets_total,
        targets_scanned=scan.targets_scanned,
        assets_discovered_count=scan.assets_discovered_count,
        findings_count=scan.findings_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        logs=scan.logs or [],
        schedule_id=scan.schedule_id,
        is_scheduled=scan.is_scheduled or False
    )

@router.get("/{schedule_id}/executions", response_model=List[ScanOut])
def get_schedule_executions(schedule_id: str, db: Session = Depends(get_db)):
    sched = db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery schedule not found.")

    executions = db.query(ScanRun).filter(
        ScanRun.schedule_id == schedule_id
    ).order_by(desc(ScanRun.started_at), desc(ScanRun.id)).all()

    scope = db.query(Scope).filter(Scope.id == sched.scope_id).first()
    scope_name = scope.name if scope else "Unknown Scope"

    results = []
    for s in executions:
        results.append(ScanOut(
            id=s.id,
            scope_id=s.scope_id,
            scope_name=scope_name,
            status=s.status,
            config=s.config or {},
            targets_total=s.targets_total,
            targets_scanned=s.targets_scanned,
            assets_discovered_count=s.assets_discovered_count,
            findings_count=s.findings_count,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error_message=s.error_message,
            logs=s.logs or [],
            schedule_id=s.schedule_id,
            is_scheduled=s.is_scheduled or False
        ))
    return results
