import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..models import DiscoverySchedule, Scope, ScanRun
from ..config import settings
from .audit_service import log_audit_event

logger = logging.getLogger("argustrace")

class ScheduleConcurrencyError(Exception):
    """Raised when an active scan is already running for the target scope."""
    pass

FREQUENCY_HOURS = {
    "DAILY": 24,
    "WEEKLY": 168,
    "HOURLY_6": 6,
    "HOURLY_12": 12,
}

def compute_next_run(frequency: str, interval_hours: int = 24, from_time: Optional[datetime] = None) -> datetime:
    """
    Computes the next execution timestamp based on frequency preset or custom hours interval.
    """
    base_time = from_time or datetime.utcnow()
    freq_upper = (frequency or "DAILY").upper()
    
    if freq_upper in FREQUENCY_HOURS:
        hours = FREQUENCY_HOURS[freq_upper]
    else:
        hours = max(1, min(interval_hours or 24, 8760))
        
    return base_time + timedelta(hours=hours)

def trigger_schedule_execution(
    db: Session,
    schedule_id: str,
    actor: str = "Automated Scheduler",
    is_manual: bool = False
) -> ScanRun:
    """
    Triggers an execution of a discovery schedule:
    1. Verifies scope exists and has explicit authorization confirmation.
    2. Enforces concurrency protection: Prevents duplicate concurrent scans on the same scope.
    3. Creates a new ScanRun linked to the schedule.
    4. Updates schedule run statistics and computes next run time.
    5. Dispatches background discovery engine execution.
    6. Records audit event.
    """
    from ..discovery.engine import execute_discovery_run

    schedule: Optional[DiscoverySchedule] = db.query(DiscoverySchedule).filter(DiscoverySchedule.id == schedule_id).first()
    if not schedule:
        raise ValueError(f"Discovery schedule '{schedule_id}' not found.")

    scope: Optional[Scope] = db.query(Scope).filter(Scope.id == schedule.scope_id).first()
    if not scope:
        schedule.last_run_status = "FAILED"
        db.commit()
        raise ValueError(f"Associated scope for schedule '{schedule.name}' no longer exists.")

    if not scope.authorised_confirmation:
        schedule.last_run_status = "FAILED"
        db.commit()
        raise PermissionError(f"Scan aborted: Scope '{scope.name}' lacks verified authorization confirmation.")

    if not scope.targets:
        schedule.last_run_status = "FAILED"
        db.commit()
        raise ValueError(f"Scope '{scope.name}' has no targets configured.")

    # Concurrency protection: Check if a scan for this scope is already running
    active_scan = db.query(ScanRun).filter(
        ScanRun.scope_id == scope.id,
        ScanRun.status.in_(["PENDING", "IN_PROGRESS"])
    ).first()

    if active_scan:
        logger.warning(f"Skipping scheduled scan for scope {scope.id}: Scan {active_scan.id} is already {active_scan.status}")
        if is_manual:
            raise ScheduleConcurrencyError(f"A discovery scan ({active_scan.id}) is already {active_scan.status.lower()} for this scope. Duplicate concurrent executions are disallowed.")
        
        # Advance next_run_at and record skipped status
        schedule.last_run_at = datetime.utcnow()
        schedule.last_run_status = "SKIPPED_CONCURRENT"
        schedule.next_run_at = compute_next_run(schedule.frequency, schedule.interval_hours, datetime.utcnow())
        db.commit()
        return active_scan

    # Build scan configuration
    cfg = schedule.config or {}
    ports_to_scan = cfg.get("ports", settings.DEFAULT_ALLOWED_PORTS)
    scan_config = {
        "ports": ports_to_scan,
        "enable_dns": cfg.get("enable_dns", True),
        "enable_ports": cfg.get("enable_ports", True),
        "enable_http": cfg.get("enable_http", True),
        "enable_tls": cfg.get("enable_tls", True),
    }

    timestamp_str = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    trigger_type = "Manual 'Run Now' trigger" if is_manual else "Automated recurring schedule"

    new_scan = ScanRun(
        scope_id=scope.id,
        schedule_id=schedule.id,
        is_scheduled=True,
        status="PENDING",
        config=scan_config,
        targets_total=len(scope.targets),
        targets_scanned=0,
        assets_discovered_count=0,
        findings_count=0,
        logs=[{
            "timestamp": timestamp_str,
            "level": "INFO",
            "message": f"{trigger_type} triggered for schedule: '{schedule.name}'"
        }]
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Update schedule execution metadata
    schedule.last_run_at = datetime.utcnow()
    schedule.last_run_status = "IN_PROGRESS"
    schedule.last_scan_run_id = new_scan.id
    schedule.next_run_at = compute_next_run(schedule.frequency, schedule.interval_hours, datetime.utcnow())
    db.commit()

    # Log audit event
    log_audit_event(
        db=db,
        action="SCHEDULE_TRIGGERED" if is_manual else "SCHEDULE_EXECUTED",
        entity_type="discovery_schedule",
        entity_id=schedule.id,
        actor=actor,
        details={
            "schedule_name": schedule.name,
            "scope_id": scope.id,
            "scope_name": scope.name,
            "scan_run_id": new_scan.id,
            "is_manual": is_manual,
            "frequency": schedule.frequency,
            "next_run_at": schedule.next_run_at.isoformat()
        }
    )

    # Dispatch non-blocking background discovery execution
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(execute_discovery_run(new_scan.id))
    except RuntimeError:
        pass

    return new_scan

async def check_and_run_due_schedules(db: Session):
    """
    Checks all enabled discovery schedules where next_run_at <= now,
    and launches background discovery runs safely.
    """
    now = datetime.utcnow()
    due_schedules = db.query(DiscoverySchedule).filter(
        DiscoverySchedule.is_enabled == True,
        DiscoverySchedule.next_run_at <= now
    ).all()

    if not due_schedules:
        return

    logger.info(f"[Scheduler] Found {len(due_schedules)} due discovery schedule(s).")

    for sched in due_schedules:
        try:
            trigger_schedule_execution(
                db=db,
                schedule_id=sched.id,
                actor="System Scheduler",
                is_manual=False
            )
            logger.info(f"[Scheduler] Successfully triggered schedule: {sched.name} ({sched.id})")
        except Exception as e:
            logger.error(f"[Scheduler] Error executing due schedule {sched.id} ('{sched.name}'): {e}", exc_info=True)
