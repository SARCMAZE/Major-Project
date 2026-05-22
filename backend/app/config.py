import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOGS_DIR = os.getenv("LOGS_DIR", str(BASE_DIR / "logs"))

# Create logs directory if it doesn't exist
os.makedirs(LOGS_DIR, exist_ok=True)

# Application Configurations
APP_ENV = os.getenv("APP_ENV", "development")

# Database Configuration (Supports PostgreSQL, falls back to local SQLite if PG is offline)
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "soc_db")

DEFAULT_PG_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_PG_URL)
SQLITE_FALLBACK_URL = f"sqlite:///{BASE_DIR / 'soc_local_fallback.db'}"

# Streaming Configuration (Supports Redis Pub/Sub, falls back to local in-memory broker)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_URL = os.getenv("REDIS_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}/0")
ALERT_CHANNEL = "security_alerts"

# Threat Emulator configurations
EMULATOR_MIN_INTERVAL = float(os.getenv("EMULATOR_MIN_INTERVAL", "0.5"))
EMULATOR_MAX_INTERVAL = float(os.getenv("EMULATOR_MAX_INTERVAL", "2.0"))

# GenAI Security configurations
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# If GEMINI_API_KEY is not in env, try reading from .env.local
if not GEMINI_API_KEY:
    env_local_path = BASE_DIR / ".env.local"
    if env_local_path.exists():
        try:
            with open(env_local_path, "r") as f:
                for line in f:
                    if line.startswith("GEMINI_API_KEY="):
                        GEMINI_API_KEY = line.strip().split("=", 1)[1]
                        break
        except Exception:
            pass
