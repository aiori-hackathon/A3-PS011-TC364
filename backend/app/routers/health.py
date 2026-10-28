import datetime
from fastapi import APIRouter
from ..config import settings

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "phase": "Phase 1 - Attack Surface Discovery & Initial Inventory",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "database": "sqlite_connected"
    }
