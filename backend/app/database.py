from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

# For SQLite, check_same_thread=False is needed for multi-threaded access in FastAPI
# pool_pre_ping=True protects against stale connection drops on hosted PostgreSQL / external DBs
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if settings.DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
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

def init_db(target_engine=None):
    use_engine = target_engine or engine
    Base.metadata.create_all(bind=use_engine)

    # Safe non-destructive column migration for SQLite
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(use_engine)
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
            with use_engine.begin() as conn:
                for col_name, col_def in cols_to_add:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE scan_findings ADD COLUMN {col_name} {col_def}"))
                # Backfill first_detected and last_observed if null
                conn.execute(text("UPDATE scan_findings SET first_detected = created_at WHERE first_detected IS NULL"))
                conn.execute(text("UPDATE scan_findings SET last_observed = created_at WHERE last_observed IS NULL"))

        if "scan_runs" in inspector.get_table_names():
            existing_cols = {col["name"] for col in inspector.get_columns("scan_runs")}
            cols_to_add = [
                ("schedule_id", "VARCHAR(36)"),
                ("is_scheduled", "BOOLEAN DEFAULT 0"),
                ("new_assets_count", "INTEGER DEFAULT 0"),
                ("updated_assets_count", "INTEGER DEFAULT 0"),
                ("failed_targets_count", "INTEGER DEFAULT 0"),
                ("total_assets_count", "INTEGER DEFAULT 0"),
            ]
            with use_engine.begin() as conn:
                for col_name, col_def in cols_to_add:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE scan_runs ADD COLUMN {col_name} {col_def}"))

        # Non-destructive recovery of historical DNS A records for assets with known IP addresses
        if "discovered_assets" in inspector.get_table_names():
            from .models import DiscoveredAsset
            from sqlalchemy.orm import Session
            with Session(use_engine) as session:
                assets = session.query(DiscoveredAsset).all()
                for a in assets:
                    if a.ip_address and a.asset_type != "ipv4":
                        dns = dict(a.dns_records or {})
                        if not dns.get("A"):
                            dns["A"] = [a.ip_address]
                            a.dns_records = dns
                session.commit()
    except Exception as e:
        import logging
        logging.getLogger("argustrace").warning(f"Database migration note: {e}")
