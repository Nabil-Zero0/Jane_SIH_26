"""
Jane Database Session and Engine Factory
Manages SQLAlchemy engine and session factory for Jane's SQLite database.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session

from jane.db.models import Base

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"

_ENGINE: Optional[Engine] = None
_SESSION_FACTORY: Optional[sessionmaker] = None


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine(url: Optional[str] = None) -> Engine:
    global _ENGINE
    target_url = url or get_database_url()
    if _ENGINE is None or url is not None:
        engine = create_engine(target_url, echo=False)
        Base.metadata.create_all(engine)
        if url is None:
            _ENGINE = engine
        return engine
    return _ENGINE


def get_session_factory(url: Optional[str] = None) -> sessionmaker:
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None or url is not None:
        engine = get_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        if url is None:
            _SESSION_FACTORY = factory
        return factory
    return _SESSION_FACTORY


@contextmanager
def get_session(url: Optional[str] = None) -> Generator[Session, None, None]:
    factory = get_session_factory(url)
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
