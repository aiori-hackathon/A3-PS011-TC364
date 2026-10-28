from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import ScanFinding, DiscoveredAsset, Scope
from ..schemas import FindingOut, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["Findings & Risk Classification"])

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO", "NOTICE", "WARNING"}
VALID_STATUSES = {"OPEN", "ACKNOWLEDGED", "IN_REVIEW", "RESOLVED", "FALSE_POSITIVE"}

def _to_finding_out(finding: ScanFinding, asset_host: Optional[str] = None) -> FindingOut:
    return FindingOut(
        id=finding.id,
        scope_id=finding.scope_id,
        scan_run_id=finding.scan_run_id,
        asset_id=finding.asset_id,
        asset_host=asset_host or (finding.asset.host_or_ip if finding.asset else None),
        finding_type=finding.finding_type,
        title=finding.title,
        description=finding.description or finding.title,
        severity=finding.severity,
        confidence=finding.confidence or "CONFIRMED",
        review_status=finding.review_status or "OPEN",
        remediation=finding.remediation or "Review configuration against enterprise security baselines.",
        evidence=finding.evidence or {},
        status_history=finding.status_history or [],
        dedup_key=finding.dedup_key,
        first_detected=finding.first_detected or finding.created_at,
        last_observed=finding.last_observed or finding.created_at,
        created_at=finding.created_at
    )

@router.get("", response_model=List[FindingOut])
def list_findings(
    scope_id: Optional[str] = Query(None, description="Filter by authorized scope ID"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    review_status: Optional[str] = Query(None, description="Filter by review status"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    search: Optional[str] = Query(None, description="Search finding title, description, or asset host"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(ScanFinding).outerjoin(DiscoveredAsset, ScanFinding.asset_id == DiscoveredAsset.id)

    if scope_id:
        query = query.filter(
            (ScanFinding.scope_id == scope_id) |
            (DiscoveredAsset.scope_id == scope_id)
        )
    if asset_id:
        query = query.filter(ScanFinding.asset_id == asset_id)
    if severity:
        query = query.filter(ScanFinding.severity == severity.upper())
    if review_status:
        query = query.filter(ScanFinding.review_status == review_status.upper())
    if finding_type:
        query = query.filter(ScanFinding.finding_type == finding_type.upper())
    if search:
        s_pat = f"%{search.strip()}%"
        query = query.filter(
            (ScanFinding.title.ilike(s_pat)) |
            (ScanFinding.description.ilike(s_pat)) |
            (DiscoveredAsset.host_or_ip.ilike(s_pat))
        )

    # Order by severity priority then most recently observed
    findings = query.order_by(desc(ScanFinding.last_observed)).offset(offset).limit(limit).all()
    
    return [_to_finding_out(f) for f in findings]

@router.get("/summary/counts")
def get_findings_counts(
    scope_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(ScanFinding)
    if scope_id:
        query = query.filter(ScanFinding.scope_id == scope_id)

    all_findings = query.all()
    by_severity: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
    }
    by_status: Dict[str, int] = {
        "OPEN": 0, "ACKNOWLEDGED": 0, "IN_REVIEW": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0
    }
    by_type: Dict[str, int] = {}

    for f in all_findings:
        sev = f.severity.upper()
        if sev in ("INFO", "NOTICE"):
            sev = "INFORMATIONAL"
        elif sev == "WARNING":
            sev = "MEDIUM"
        by_severity[sev] = by_severity.get(sev, 0) + 1

        st = (f.review_status or "OPEN").upper()
        by_status[st] = by_status.get(st, 0) + 1

        ft = f.finding_type.upper()
        by_type[ft] = by_type.get(ft, 0) + 1

    return {
        "total": len(all_findings),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type
    }

@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(ScanFinding).filter(ScanFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding record not found."
        )
    return _to_finding_out(finding)

@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    finding = db.query(ScanFinding).filter(ScanFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding record not found."
        )

    new_status = payload.review_status.upper().strip()
    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid review status '{new_status}'. Allowed statuses: {sorted(list(VALID_STATUSES))}"
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    prev_status = finding.review_status or "OPEN"

    # Only update if status changed or note provided
    if prev_status != new_status or payload.note:
        finding.review_status = new_status
        history = list(finding.status_history or [])
        history.append({
            "status": new_status,
            "previous_status": prev_status,
            "timestamp": now.isoformat(),
            "note": payload.note or f"Status shifted from {prev_status} to {new_status}"
        })
        finding.status_history = history
        db.commit()
        db.refresh(finding)

    return _to_finding_out(finding)
