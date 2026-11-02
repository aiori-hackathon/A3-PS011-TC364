import sys
import os
import tempfile

# Set up paths so backend package can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, ".."))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Normalize postgres:// to postgresql:// if set in Vercel environment
if os.environ.get("DATABASE_URL") and os.environ["DATABASE_URL"].startswith("postgres://"):
    os.environ["DATABASE_URL"] = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)

# Ensure SQLite database uses writable temp directory on Vercel serverless environment if no DATABASE_URL provided
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    tmp_dir = tempfile.gettempdir().replace("\\", "/")
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{tmp_dir}/argustrace.db")

from app.main import app
from app.database import init_db, SessionLocal

# Guarantee DB tables are initialized in serverless environment
init_db()

# Guarantee canonical demo data is seeded if database has no scopes
db = SessionLocal()
try:
    from app.models import Scope
    if db.query(Scope).count() == 0:
        from app.routers.stats import get_or_create_demo_scope
        get_or_create_demo_scope(db)
except Exception:
    pass
finally:
    db.close()
