from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..services.export_service import (
    export_assets_csv,
    export_assets_json,
    export_changes_csv,
    export_changes_json,
    export_findings_csv,
    export_findings_json
)

router = APIRouter(prefix="/exports", tags=["Reports & Exports"])

def _timestamp_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# --- Inventory Exports ---

@router.get("/inventory/csv")
def download_inventory_csv(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    csv_data = export_assets_csv(db, scope_id=scope_id, search=search, asset_type=asset_type)
    filename = f"argustrace_inventory_{_timestamp_str()}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/inventory/json")
def download_inventory_json(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    json_data = export_assets_json(db, scope_id=scope_id, search=search, asset_type=asset_type)
    filename = f"argustrace_inventory_{_timestamp_str()}.json"
    return JSONResponse(
        content=json_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# --- Changes History Exports ---

@router.get("/changes/csv")
def download_changes_csv(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    csv_data = export_changes_csv(db, scope_id=scope_id, search=search, change_type=change_type)
    filename = f"argustrace_changes_{_timestamp_str()}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/changes/json")
def download_changes_json(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    change_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    json_data = export_changes_json(db, scope_id=scope_id, search=search, change_type=change_type)
    filename = f"argustrace_changes_{_timestamp_str()}.json"
    return JSONResponse(
        content=json_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# --- Findings Exports ---

@router.get("/findings/csv")
def download_findings_csv(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    csv_data = export_findings_csv(
        db,
        scope_id=scope_id,
        search=search,
        severity=severity,
        review_status=review_status,
        finding_type=finding_type
    )
    filename = f"argustrace_findings_{_timestamp_str()}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/findings/json")
def download_findings_json(
    scope_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    review_status: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    json_data = export_findings_json(
        db,
        scope_id=scope_id,
        search=search,
        severity=severity,
        review_status=review_status,
        finding_type=finding_type
    )
    filename = f"argustrace_findings_{_timestamp_str()}.json"
    return JSONResponse(
        content=json_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
