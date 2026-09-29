"""Pydantic response models for the API.

Shapes mirror core/report_models.py's dataclasses (the single source of
truth for report content) but are declared separately since Pydantic
models and dataclasses serve different jobs here - these validate/
document the HTTP response contract, not the internal computation.
"""

from __future__ import annotations

from pydantic import BaseModel


class AnalyzeResponse(BaseModel):
    job_id: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str  # queued | running | done | failed
    pcap_filename: str
    created_at: str
    updated_at: str
    error: str | None = None


class SummaryResponse(BaseModel):
    overall_score: int | None
    grade: str
    session_count: int
    findings_by_severity: dict[str, int]
    observable_cert_sessions: int
    tls_session_count: int
    observable_cert_ratio: float | None


class FindingItem(BaseModel):
    rule_id: str
    plan_id: str | None
    severity: str
    message: str
    score_impact: int
    tcp_stream: int
    protocol: str


class SessionListItem(BaseModel):
    tcp_stream: int
    protocol: str
    tls_mode: str
    role: str
    client_ip: str
    server_ip: str
    server_port: int
    negotiated_tls_version: str | None
    score: int
    finding_count: int


class SessionListResponse(BaseModel):
    page: int
    page_size: int
    total: int
    sessions: list[SessionListItem]


class SessionDetailResponse(BaseModel):
    tcp_stream: int
    protocol: str
    tls_mode: str
    role: str
    client_ip: str
    server_ip: str
    server_port: int
    first_frame: int
    last_frame: int
    score: int
    negotiated_tls_version: str | None
    cipher_suite: str | None
    sni_hostname: str | None
    cert_observable: bool | None
    cert_not_observable_reason: str | None
    certificate: dict | None
    timeline: list[dict]
    findings: list[dict]


class FindingsResponse(BaseModel):
    total: int
    findings: list[FindingItem]


class HealthResponse(BaseModel):
    status: str
    tshark_version: str | None
