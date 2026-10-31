import asyncio
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import init_db, SessionLocal
from .routers import health, scopes, scans, assets, stats, changes, findings, notifications, exports, audit, schedules
from .services.schedule_service import check_and_run_due_schedules

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("argustrace")

async def schedule_worker():
    """Background worker that periodically checks and executes due discovery schedules."""
    while True:
        try:
            await asyncio.sleep(20)
            db = SessionLocal()
            try:
                await check_and_run_due_schedules(db)
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in discovery schedule background worker: {e}", exc_info=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ArgusTrace database schema...")
    init_db()
    logger.info("Database schema initialized successfully.")
    
    # Start background scheduler task
    scheduler_task = asyncio.create_task(schedule_worker())
    logger.info("Background discovery scheduler worker started.")
    
    yield
    
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass
    logger.info("ArgusTrace shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Authorized Attack-Surface Asset Discovery & Initial Inventory Engine (PS-011 Phase 1)",
    version="1.0.0-phase1",
    lifespan=lifespan
)

# CORS configuration restricted to authorized frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global error handler for uncaught exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error occurred. Check backend logs for diagnostics."}
    )

# Include API Routers under /api
app.include_router(health.router, prefix=settings.API_V1_STR)
app.include_router(scopes.router, prefix=settings.API_V1_STR)
app.include_router(scans.router, prefix=settings.API_V1_STR)
app.include_router(assets.router, prefix=settings.API_V1_STR)
app.include_router(stats.router, prefix=settings.API_V1_STR)
app.include_router(changes.router, prefix=settings.API_V1_STR)
app.include_router(findings.router, prefix=settings.API_V1_STR)
app.include_router(notifications.router, prefix=settings.API_V1_STR)
app.include_router(exports.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)
app.include_router(schedules.router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "app": "ArgusTrace",
        "description": "Authorized Attack Surface Discovery Engine - Phase 1 Prototype",
        "docs_url": "/docs",
        "api_v1": "/api"
    }
