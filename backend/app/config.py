import os
import tempfile
from typing import List, Optional
from pydantic_settings import BaseSettings

def get_default_db_url() -> str:
    env_db = os.environ.get("DATABASE_URL")
    if env_db:
        return env_db
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        tmp_dir = tempfile.gettempdir().replace("\\", "/")
        return f"sqlite:///{tmp_dir}/argustrace.db"
    
    # Absolute path to backend/argustrace.db regardless of invocation working directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "argustrace.db").replace("\\", "/")
    return f"sqlite:///{db_path}"

class Settings(BaseSettings):
    PROJECT_NAME: str = "ArgusTrace - Attack Surface Asset Discovery (PS-011)"
    API_V1_STR: str = "/api"
    DATABASE_URL: str = get_default_db_url()
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    
    # Discovery Limits & Safety Guardrails
    MAX_CONCURRENT_PROBES: int = 10
    TCP_TIMEOUT_SECONDS: float = 3.0
    HTTP_TIMEOUT_SECONDS: float = 5.0
    DNS_TIMEOUT_SECONDS: float = 3.0
    RATE_LIMIT_DELAY_SECONDS: float = 0.1
    MAX_PORTS_PER_SCAN: int = 50
    DEFAULT_ALLOWED_PORTS: List[int] = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 5432, 8000, 8080, 8443, 8888]
    
    # SSRF / Local Lab Safety
    ALLOW_LOCAL_LAB_DEFAULT: bool = False

    # Phase 5: Notifications & Integration Configuration (from env only)
    ENABLE_LIVE_NOTIFICATIONS: bool = False
    WEBHOOK_TIMEOUT_SECONDS: float = 5.0
    MAX_NOTIFICATION_RETRIES: int = 3
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "argustrace@security.internal"
    SMTP_TLS: bool = True
    
    model_config = {"env_file": ".env", "extra": "ignore"}

settings = Settings()
