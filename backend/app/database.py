import sys
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.app import config

# Setup Logging
logger = logging.getLogger("SOC-Database")
logging.basicConfig(level=logging.INFO)

Base = declarative_base()

class RawLog(Base):
    __tablename__ = "raw_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50), nullable=False) # network, web, auth, db, cloud
    payload = Column(JSON, nullable=False)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    
    id = Column(String(100), primary_key=True) # Unique Alert/Flow ID
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    source = Column(String(50), nullable=False)
    source_ip = Column(String(50), nullable=False)
    destination_ip = Column(String(50), nullable=True)
    l1_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    attack_type = Column(String(100), nullable=False)
    explanation = Column(String(1000), nullable=True)
    recommendation = Column(String(1000), nullable=True)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    status = Column(String(50), default="flagged") # flagged, escalated, resolved
    raw_payload = Column(JSON, nullable=False)

class IPState(Base):
    __tablename__ = "ip_states"
    
    ip = Column(String(50), primary_key=True)
    risk_score = Column(Float, default=0.0)
    attack_history = Column(JSON, default=list) # List of dictionaries tracking event triggers
    event_count = Column(Integer, default=0)
    last_seen = Column(DateTime, default=datetime.utcnow)

# Engine connection pool with SQLite fallback
engine = None
SessionLocal = None

def init_db():
    global engine, SessionLocal
    try:
        logger.info(f"Connecting to database at {config.DATABASE_URL}...")
        engine = create_engine(config.DATABASE_URL, pool_pre_ping=True)
        # Try to connect
        with engine.connect() as conn:
            logger.info("Successfully connected to PostgreSQL database!")
    except Exception as e:
        logger.warning(f"Failed to connect to PostgreSQL database: {e}")
        logger.info(f"Falling back to local SQLite database: {config.SQLITE_FALLBACK_URL}")
        engine = create_engine(config.SQLITE_FALLBACK_URL, connect_args={"check_same_thread": False})

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

# Initalize database tables immediately
init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
