
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scope, ScanRun, DiscoveredAsset
from ..schemas import (
    ScopeCreate,
    ScopeUpdate,
    ScopeOut,
    TargetValidationRequest,
    TargetValidationResponse,
    TargetValidationItem,
)
from ..security import validate_target

router = APIRouter(prefix="/scopes", tags=["Scopes"])


@router.post("/validate-targets", response_model=TargetValidationResponse)
def validate_targets_endpoint(payload: TargetValidationRequest):
    """
    Validates a list of target inputs for syntax and SSRF compliance without persisting.
    """
    items = []
    all_valid = True

    for raw in payload.targets:
        is_val, sanitized, err = validate_target(
            raw,
            allow_local_lab=payload.allow_local_lab,
        )

        if not is_val:
            all_valid = False

        items.append(
            TargetValidationItem(
                raw=raw,
                sanitized=sanitized,
                is_valid=is_val,
                error=err,
            )
        )

    return TargetValidationResponse(items=items, all_valid=all_valid)


@router.get("", response_model=List[ScopeOut])
def list_scopes(db: Session = Depends(get_db)):
    scopes = db.query(Scope).order_by(desc(Scope.created_at)).all()

    if not scopes:
        from .stats import get_or_create_demo_scope

        demo_scope = get_or_create_demo_scope(db)
        scopes = [demo_scope]

    results = []

    for s in scopes:
        asset_count = (
            db.query(DiscoveredAsset)
            .filter(DiscoveredAsset.scope_id == s.id)
            .count()
        )

        last_scan = (
            db.query(ScanRun)
            .filter(ScanRun.scope_id == s.id)
            .order_by(desc(ScanRun.started_at))
            .first()
        )

        results.append(
            ScopeOut(
                id=s.id,
                name=s.name,
                description=s.description,
                targets=s.targets or [],
                allow_local_lab=s.allow_local_lab,
                authorised_confirmation=s.authorised_confirmation,
                authorised_by=s.authorised_by,
                created_at=s.created_at,
                updated_at=s.updated_at,
                asset_count=asset_count,
                last_scan_status=last_scan.status if last_scan else None,
                last_scan_time=last_scan.started_at if last_scan else None,
            )
        )

    return results


@router.post("", response_model=ScopeOut, status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeCreate, db: Session = Depends(get_db)):
    # Explicit authorization check
    if not payload.authorised_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit authorisation confirmation is required to create a scanning scope.",
        )

    if not payload.targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scope must contain at least one target.",
        )

    # Validate each target
    sanitized_targets = []

    for raw_target in payload.targets:
        is_valid, sanitized, error_msg = validate_target(
            raw_target,
            allow_local_lab=payload.allow_local_lab,
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target validation failed for '{raw_target}': {error_msg}",
            )

        if sanitized not in sanitized_targets:
            sanitized_targets.append(sanitized)

    # Check if a scope with identical name already exists
    existing = (
        db.query(Scope)
        .filter(Scope.name == payload.name.strip())
        .first()
    )

    if existing:
        existing.description = payload.description or existing.description
        existing.targets = sanitized_targets
        existing.allow_local_lab = payload.allow_local_lab
        existing.authorised_confirmation = payload.authorised_confirmation
        existing.authorised_by = payload.authorised_by

        db.commit()
        db.refresh(existing)
        new_scope = existing

    else:
        new_scope = Scope(
            name=payload.name.strip(),
            description=payload.description,
            targets=sanitized_targets,
            allow_local_lab=payload.allow_local_lab,
            authorised_confirmation=payload.authorised_confirmation,
            authorised_by=payload.authorised_by,
        )

        db.add(new_scope)
        db.commit()
        db.refresh(new_scope)

    return ScopeOut(
        id=new_scope.id,
        name=new_scope.name,
        description=new_scope.description,
        targets=new_scope.targets or [],
        allow_local_lab=new_scope.allow_local_lab,
        authorised_confirmation=new_scope.authorised_confirmation,
        authorised_by=new_scope.authorised_by,
        created_at=new_scope.created_at,
        updated_at=new_scope.updated_at,
        asset_count=0,
        last_scan_status=None,
        last_scan_time=None,
    )


@router.get("/{scope_id}", response_model=ScopeOut)
def get_scope(scope_id: str, db: Session = Depends(get_db)):
    scope = db.query(Scope).filter(Scope.id == scope_id).first()

    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope with ID '{scope_id}' does not exist",
        )

    asset_count = (
        db.query(DiscoveredAsset)
        .filter(DiscoveredAsset.scope_id == scope.id)
        .count()
    )

    last_scan = (
        db.query(ScanRun)
        .filter(ScanRun.scope_id == scope.id)
        .order_by(desc(ScanRun.started_at))
        .first()
    )

    return ScopeOut(
        id=scope.id,
        name=scope.name,
        description=scope.description,
        targets=scope.targets or [],
        allow_local_lab=scope.allow_local_lab,
        authorised_confirmation=scope.authorised_confirmation,
        authorised_by=scope.authorised_by,
        created_at=scope.created_at,
        updated_at=scope.updated_at,
        asset_count=asset_count,
        last_scan_status=last_scan.status if last_scan else None,
        last_scan_time=last_scan.started_at if last_scan else None,
    )


@router.put("/{scope_id}", response_model=ScopeOut)
def update_scope(
    scope_id: str,
    payload: ScopeUpdate,
    db: Session = Depends(get_db),
):
    scope = db.query(Scope).filter(Scope.id == scope_id).first()

    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Specified scope does not exist or has been removed.",
        )

    if payload.name is not None:
        scope.name = payload.name

    if payload.description is not None:
        scope.description = payload.description

    if payload.allow_local_lab is not None:
        scope.allow_local_lab = payload.allow_local_lab

    if payload.authorised_confirmation is not None:
        scope.authorised_confirmation = payload.authorised_confirmation

    if payload.authorised_by is not None:
        scope.authorised_by = payload.authorised_by

    if payload.targets is not None:
        sanitized_targets = []

        for raw_target in payload.targets:
            is_valid, sanitized, error_msg = validate_target(
                raw_target,
                allow_local_lab=scope.allow_local_lab,
            )

            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target validation failed for '{raw_target}': {error_msg}",
                )

            if sanitized not in sanitized_targets:
                sanitized_targets.append(sanitized)

        scope.targets = sanitized_targets

    db.commit()
    db.refresh(scope)

    asset_count = (
        db.query(DiscoveredAsset)
        .filter(DiscoveredAsset.scope_id == scope.id)
        .count()
    )

    last_scan = (
        db.query(ScanRun)
        .filter(ScanRun.scope_id == scope.id)
        .order_by(desc(ScanRun.started_at))
        .first()
    )

    return ScopeOut(
        id=scope.id,
        name=scope.name,
        description=scope.description,
        targets=scope.targets or [],
        allow_local_lab=scope.allow_local_lab,
        authorised_confirmation=scope.authorised_confirmation,
        authorised_by=scope.authorised_by,
        created_at=scope.created_at,
        updated_at=scope.updated_at,
        asset_count=asset_count,
        last_scan_status=last_scan.status if last_scan else None,
        last_scan_time=last_scan.started_at if last_scan else None,
    )


@router.delete("/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(scope_id: str, db: Session = Depends(get_db)):
    scope = db.query(Scope).filter(Scope.id == scope_id).first()

    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Specified scope does not exist or has been removed.",
        )

    db.delete(scope)
    db.commit()

    return None




