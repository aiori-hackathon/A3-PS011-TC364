from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import AssetSnapshot, AssetChangeRecord, Scope
from ..schemas import SnapshotOut, ChangeRecordOut

router = APIRouter(prefix="", tags=["Changes & Snapshots"])

@router.get("/changes", response_model=List[ChangeRecordOut])
def get_changes(
    scope_id: Optional[str] = Query(None, description="Filter by authorized scope ID"),
    change_type: Optional[str] = Query(None, description="Filter by change type (e.g., ASSET_ADDED, PORT_OPENED)"),
    asset: Optional[str] = Query(None, description="Filter by asset hostname or IP"),
    is_inconclusive: Optional[bool] = Query(None, description="Filter inconclusive status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(AssetChangeRecord)

    if scope_id:
        query = query.filter(AssetChangeRecord.scope_id == scope_id)
    if change_type:
        query = query.filter(AssetChangeRecord.change_type == change_type)
    if asset:
        query = query.filter(AssetChangeRecord.asset_identifier.ilike(f"%{asset.strip()}%"))
    if is_inconclusive is not None:
        query = query.filter(AssetChangeRecord.is_inconclusive == is_inconclusive)

    changes = query.order_by(desc(AssetChangeRecord.created_at)).offset(offset).limit(limit).all()
    return changes

@router.get("/changes/{change_id}", response_model=ChangeRecordOut)
def get_change_record(change_id: str, db: Session = Depends(get_db)):
    record = db.query(AssetChangeRecord).filter(AssetChangeRecord.id == change_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Change record not found.")
    return record

@router.get("/snapshots", response_model=List[SnapshotOut])
def get_snapshots(
    scope_id: Optional[str] = Query(None, description="Filter by authorized scope ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(AssetSnapshot)
    if scope_id:
        query = query.filter(AssetSnapshot.scope_id == scope_id)

    snapshots = query.order_by(desc(AssetSnapshot.created_at)).offset(offset).limit(limit).all()
    return snapshots

@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(snapshot_id: str, db: Session = Depends(get_db)):
    snap = db.query(AssetSnapshot).filter(AssetSnapshot.id == snapshot_id).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found.")
    return snap
