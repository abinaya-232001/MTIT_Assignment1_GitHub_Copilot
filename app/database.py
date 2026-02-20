import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .config import settings


# SQLAlchemy engine; database URL comes from config
# SQLAlchemy expects a string for the URL; pydantic AnyUrl returns object
url = str(settings.DATABASE_URL)
engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# dependency

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
