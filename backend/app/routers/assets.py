from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import DiscoveredAsset, ScanFinding
from ..schemas import AssetOut, FindingOut

router = APIRouter(prefix="/assets", tags=["Discovered Assets"])

@router.get("", response_model=List[AssetOut])
def list_assets(
    scope_id: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
    port: Optional[int] = None,
    db: Session = Depends(get_db)
):
    query = db.query(DiscoveredAsset)

    if scope_id:
        query = query.filter(DiscoveredAsset.scope_id == scope_id)
    if status_filter:
        query = query.filter(DiscoveredAsset.status == status_filter.upper())
    if asset_type:
        query = query.filter(DiscoveredAsset.asset_type == asset_type.lower())
    if search:
        s_pattern = f"%{search.strip()}%"
        query = query.filter(
            (DiscoveredAsset.host_or_ip.ilike(s_pattern)) | 
            (DiscoveredAsset.ip_address.ilike(s_pattern))
        )

    assets = query.order_by(desc(DiscoveredAsset.last_seen)).all()

    # In-memory filter for port if specified
    if port is not None:
        filtered = []
        for a in assets:
            open_ports = a.open_ports or []
            if any(p.get("port") == port for p in open_ports):
                filtered.append(a)
        assets = filtered

    return [AssetOut.model_validate(a) for a in assets]

@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return AssetOut.model_validate(asset)

@router.get("/{asset_id}/findings", response_model=List[FindingOut])
def get_asset_findings(asset_id: str, db: Session = Depends(get_db)):
    findings = db.query(ScanFinding).filter(ScanFinding.asset_id == asset_id).order_by(desc(ScanFinding.created_at)).all()
    return [FindingOut.model_validate(f) for f in findings]

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(DiscoveredAsset).filter(DiscoveredAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    db.delete(asset)
    db.commit()
    return None
