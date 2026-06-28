import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os
from .logging_config import logger
from app.config.config import settings

# Load environment variables from .env file
load_dotenv()

# Get the DATABASE_URL from environment variables
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

if not SQLALCHEMY_DATABASE_URL:
    logger.error("DATABASE_URL not found in environment variables")
    raise ValueError("DATABASE_URL not found in environment variables")

logger.info("Connecting to the database...")

# Pool sized for concurrent load. Keep workers × (pool_size + max_overflow)
# under Postgres max_connections (~100). pre_ping drops dead connections so a
# request after an idle period doesn't fail; recycle avoids stale sockets.
engine = create_engine(
    settings.database_url,
    pool_size=8,
    max_overflow=12,
    pool_pre_ping=True,
    pool_recycle=1800,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()