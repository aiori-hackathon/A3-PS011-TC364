import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import ScanRun, Scope, ScanFinding
from ..schemas import ScanCreate, ScanOut, FindingOut
from ..security import validate_port_list
from ..config import settings
from ..discovery.engine import execute_discovery_run, cancel_scan

router = APIRouter(prefix="/scans", tags=["Discovery Runs"])

@router.get("", response_model=List[ScanOut])
def list_scans(scope_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ScanRun)
    if scope_id:
        query = query.filter(ScanRun.scope_id == scope_id)
    scans = query.order_by(desc(ScanRun.started_at), desc(ScanRun.id)).all()
    
    results = []
    for s in scans:
        scope = db.query(Scope).filter(Scope.id == s.scope_id).first()
        results.append(ScanOut(
            id=s.id,
            scope_id=s.scope_id,
            scope_name=scope.name if scope else "Unknown Scope",
            status=s.status,
            config=s.config or {},
            targets_total=s.targets_total,
            targets_scanned=s.targets_scanned,
            assets_discovered_count=s.assets_discovered_count,
            findings_count=s.findings_count,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error_message=s.error_message,
            logs=s.logs or []
        ))
    return results

@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def launch_discovery_run(payload: ScanCreate, db: Session = Depends(get_db)):
    scope = db.query(Scope).filter(Scope.id == payload.scope_id).first()
    if not scope:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Specified scope does not exist.")

    if not scope.authorised_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot launch discovery scan: Scope has not been confirmed as authorised."
        )

    if not scope.targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scope has no targets configured."
        )

    # Configuration defaults and port bounding
    cfg = payload.config
    ports_to_scan = settings.DEFAULT_ALLOWED_PORTS
    if cfg and cfg.ports is not None:
        is_valid_ports, bounded_ports, err = validate_port_list(cfg.ports, max_ports=settings.MAX_PORTS_PER_SCAN)
        if not is_valid_ports:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)
        ports_to_scan = bounded_ports

    scan_config = {
        "ports": ports_to_scan,
        "enable_dns": cfg.enable_dns if cfg else True,
        "enable_ports": cfg.enable_ports if cfg else True,
        "enable_http": cfg.enable_http if cfg else True,
        "enable_tls": cfg.enable_tls if cfg else True,
    }

    new_scan = ScanRun(
        scope_id=scope.id,
        status="PENDING",
        config=scan_config,
        targets_total=len(scope.targets),
        targets_scanned=0,
        assets_discovered_count=0,
        findings_count=0,
        logs=[]
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Launch non-blocking background discovery execution
    asyncio.create_task(execute_discovery_run(new_scan.id))

    return ScanOut(
        id=new_scan.id,
        scope_id=new_scan.scope_id,
        scope_name=scope.name,
        status=new_scan.status,
        config=new_scan.config,
        targets_total=new_scan.targets_total,
        targets_scanned=new_scan.targets_scanned,
        assets_discovered_count=new_scan.assets_discovered_count,
        findings_count=new_scan.findings_count,
        started_at=new_scan.started_at,
        completed_at=new_scan.completed_at,
        error_message=new_scan.error_message,
        logs=new_scan.logs or []
    )

@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

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
        logs=scan.logs or []
    )

@router.post("/{scan_id}/cancel")
def cancel_scan_endpoint(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    if scan.status not in ("PENDING", "IN_PROGRESS"):
        return {"message": f"Scan is already in {scan.status} state."}

    cancel_scan(scan_id)
    return {"message": "Cancellation signal sent to discovery engine.", "scan_id": scan_id}

@router.get("/{scan_id}/findings", response_model=List[FindingOut])
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(ScanFinding).filter(ScanFinding.scan_run_id == scan_id).order_by(desc(ScanFinding.created_at)).all()
    return [FindingOut.model_validate(f) for f in findings]
