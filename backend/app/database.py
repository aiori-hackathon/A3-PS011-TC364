from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

# For SQLite, check_same_thread=False is needed for multi-threaded access in FastAPI
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)

    # Safe non-destructive column migration for SQLite
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "scan_findings" in inspector.get_table_names():
            existing_cols = {col["name"] for col in inspector.get_columns("scan_findings")}
            cols_to_add = [
                ("scope_id", "VARCHAR(36)"),
                ("description", "TEXT"),
                ("confidence", "VARCHAR(20) DEFAULT 'CONFIRMED'"),
                ("review_status", "VARCHAR(20) DEFAULT 'OPEN'"),
                ("remediation", "TEXT"),
                ("status_history", "JSON DEFAULT '[]'"),
                ("dedup_key", "VARCHAR(255)"),
                ("first_detected", "DATETIME"),
                ("last_observed", "DATETIME"),
            ]
            with engine.begin() as conn:
                for col_name, col_def in cols_to_add:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE scan_findings ADD COLUMN {col_name} {col_def}"))
                # Backfill first_detected and last_observed if null
                conn.execute(text("UPDATE scan_findings SET first_detected = created_at WHERE first_detected IS NULL"))
                conn.execute(text("UPDATE scan_findings SET last_observed = created_at WHERE last_observed IS NULL"))
    except Exception as e:
        import logging
        logging.getLogger("argustrace").warning(f"Database migration note: {e}")
