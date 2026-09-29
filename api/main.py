"""FastAPI wrapper around core/analyze.py and core/report.py.

Every endpoint here reads results that were computed once, by a real
call into core/report.py (never reimplemented), inside a background
task. Nothing is mocked - upload a real pcap and every endpoint reflects
what core.analyze would print for that same file, because they share
the exact same code.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session as DBSession

from api.db import UPLOADS_DIR, Job, SessionLocal, get_db, init_db
from api.schemas import (
    AnalyzeResponse,
    FindingItem,
    FindingsResponse,
    HealthResponse,
    JobStatusResponse,
    SessionDetailResponse,
    SessionListItem,
    SessionListResponse,
    SummaryResponse,
)
from core.report import build_report, render_html, report_to_json


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SecureMailScope API", version="0.1.0", lifespan=_lifespan)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _run_analysis(job_id: str, pcap_path: Path) -> None:
    """Background task: build the report once via core/report.py and
    cache its JSON/HTML text. Every read endpoint serves from this
    cache, so results never drift from what core.analyze would print.
    """
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        job.status = "running"
        db.commit()

        report = build_report(pcap_path)
        job.report_json = report_to_json(report)
        job.report_html = render_html(report)
        job.status = "done"
        db.commit()
    except Exception as exc:  # noqa: BLE001 - report the real error to the client
        job = db.get(Job, job_id)
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
        db.commit()
    finally:
        db.close()


def _get_job_or_404(job_id: str, db: DBSession) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


def _get_done_report_dict(job_id: str, db: DBSession) -> dict:
    job = _get_job_or_404(job_id, db)
    if job.status == "failed":
        raise HTTPException(status_code=422, detail=f"analysis failed: {job.error}")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"job is {job.status}, not done yet")
    return json.loads(job.report_json)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    tshark_version = None
    try:
        result = subprocess.run(
            ["tshark", "--version"], capture_output=True, text=True, timeout=5
        )
        tshark_version = result.stdout.splitlines()[0] if result.stdout else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return HealthResponse(status="ok", tshark_version=tshark_version)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(file: UploadFile, background_tasks: BackgroundTasks, db: DBSession = Depends(get_db)) -> AnalyzeResponse:
    job_id = str(uuid.uuid4())
    pcap_path = UPLOADS_DIR / f"{job_id}.pcap"
    with pcap_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    job = Job(
        id=job_id,
        status="queued",
        pcap_filename=file.filename or "upload.pcap",
        pcap_path=str(pcap_path),
    )
    db.add(job)
    db.commit()

    background_tasks.add_task(_run_analysis, job_id, pcap_path)
    return AnalyzeResponse(job_id=job_id)


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str, db: DBSession = Depends(get_db)) -> JobStatusResponse:
    job = _get_job_or_404(job_id, db)
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        pcap_filename=job.pcap_filename,
        created_at=job.created_at.isoformat(),
        updated_at=job.updated_at.isoformat(),
        error=job.error,
    )


@app.get("/api/v1/jobs/{job_id}/summary", response_model=SummaryResponse)
def get_summary(job_id: str, db: DBSession = Depends(get_db)) -> SummaryResponse:
    data = _get_done_report_dict(job_id, db)
    return SummaryResponse(**data["summary"])


@app.get("/api/v1/jobs/{job_id}/sessions", response_model=SessionListResponse)
def list_sessions(
    job_id: str,
    protocol: str | None = None,
    tls_mode: str | None = None,
    role: str | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    db: DBSession = Depends(get_db),
) -> SessionListResponse:
    data = _get_done_report_dict(job_id, db)
    sessions = data["sessions"]

    if protocol is not None:
        sessions = [s for s in sessions if s["protocol"] == protocol]
    if tls_mode is not None:
        sessions = [s for s in sessions if s["tls_mode"] == tls_mode]
    if role is not None:
        sessions = [s for s in sessions if s["role"] == role]
    if min_score is not None:
        sessions = [s for s in sessions if s["score"] >= min_score]
    if max_score is not None:
        sessions = [s for s in sessions if s["score"] <= max_score]

    total = len(sessions)
    start = (page - 1) * page_size
    page_items = sessions[start : start + page_size]

    return SessionListResponse(
        page=page,
        page_size=page_size,
        total=total,
        sessions=[
            SessionListItem(
                tcp_stream=s["tcp_stream"],
                protocol=s["protocol"],
                tls_mode=s["tls_mode"],
                role=s["role"],
                client_ip=s["client_ip"],
                server_ip=s["server_ip"],
                server_port=s["server_port"],
                negotiated_tls_version=s["negotiated_tls_version"],
                score=s["score"],
                finding_count=len(s["findings"]),
            )
            for s in page_items
        ],
    )


@app.get("/api/v1/jobs/{job_id}/sessions/{tcp_stream}", response_model=SessionDetailResponse)
def get_session_detail(job_id: str, tcp_stream: int, db: DBSession = Depends(get_db)) -> SessionDetailResponse:
    data = _get_done_report_dict(job_id, db)
    session = next((s for s in data["sessions"] if s["tcp_stream"] == tcp_stream), None)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found in this job")
    return SessionDetailResponse(**session)


@app.get("/api/v1/jobs/{job_id}/findings", response_model=FindingsResponse)
def get_findings(job_id: str, db: DBSession = Depends(get_db)) -> FindingsResponse:
    data = _get_done_report_dict(job_id, db)
    findings: list[FindingItem] = []
    for session in data["sessions"]:
        for f in session["findings"]:
            findings.append(
                FindingItem(
                    rule_id=f["rule_id"],
                    plan_id=f["plan_id"],
                    severity=f["severity"],
                    message=f["message"],
                    score_impact=f["score_impact"],
                    tcp_stream=session["tcp_stream"],
                    protocol=session["protocol"],
                )
            )
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.score_impact))
    return FindingsResponse(total=len(findings), findings=findings)


@app.get("/api/v1/jobs/{job_id}/report")
def get_report(job_id: str, format: str = Query("json", pattern="^(json|html)$"), db: DBSession = Depends(get_db)):
    job = _get_job_or_404(job_id, db)
    if job.status == "failed":
        raise HTTPException(status_code=422, detail=f"analysis failed: {job.error}")
    if job.status != "done":
        raise HTTPException(status_code=409, detail=f"job is {job.status}, not done yet")

    if format == "html":
        return HTMLResponse(content=job.report_html)
    return JSONResponse(content=json.loads(job.report_json))
