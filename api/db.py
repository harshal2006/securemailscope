"""SQLite job store via SQLAlchemy.

Stores job metadata plus the already-rendered JSON/HTML report text,
computed once by a background task (core/report.py, never duplicated
here). Every API read endpoint serves from these cached strings rather
than recomputing, so results are guaranteed consistent within a job's
lifetime.
"""

from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path

from sqlalchemy import DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATA_DIR = Path(__file__).parent.parent / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
# Overridable so tests can run against an isolated DB file without
# touching the one a locally running dev server might be using.
DB_PATH = Path(os.environ.get("SECUREMAILSCOPE_DB_PATH", str(DATA_DIR / "securemailscope.db")))

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String, default="queued")  # queued|running|done|failed
    pcap_filename: Mapped[str] = mapped_column(String)
    pcap_path: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_html: Mapped[str | None] = mapped_column(Text, nullable=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
