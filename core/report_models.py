"""Result schema for the report renderer (core/report.py).

Dataclasses, consistent with the rest of this codebase (Session,
TLSInfo, CertInfo, Finding all use dataclasses). JSON output is
validated against core/report_schema.json at render time - see
core/report.py's REPORT_JSON_SCHEMA.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CertificateSummary:
    subject_cn: str | None
    issuer_cn: str | None
    self_signed: bool
    key_algorithm: str
    key_size: int | None
    signature_hash_algorithm: str | None
    san_dns_names: list[str]
    not_before: str  # ISO 8601
    not_after: str  # ISO 8601
    is_expired: bool


@dataclass
class TimelineEventSummary:
    frame_number: int
    direction: str
    kind: str
    text: str  # already redacted by core/starttls.py


@dataclass
class FindingSummary:
    rule_id: str
    plan_id: str | None
    severity: str
    message: str
    score_impact: int


@dataclass
class SessionReport:
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
    negotiated_tls_version: str | None = None
    cipher_suite: str | None = None
    sni_hostname: str | None = None
    cert_observable: bool | None = None
    cert_not_observable_reason: str | None = None
    certificate: CertificateSummary | None = None
    timeline: list[TimelineEventSummary] = field(default_factory=list)
    findings: list[FindingSummary] = field(default_factory=list)


@dataclass
class Summary:
    overall_score: int | None
    grade: str  # "A"-"F", or "N/A" if overall_score is None
    session_count: int
    findings_by_severity: dict[str, int]
    observable_cert_sessions: int
    tls_session_count: int  # sessions with any TLS observed (denominator for the ratio above)
    observable_cert_ratio: float | None  # observable_cert_sessions / tls_session_count


@dataclass
class Recommendation:
    rule_id: str
    plan_id: str | None
    title: str
    fix: str
    verification_command: str | None


@dataclass
class RuleReference:
    rule_id: str
    plan_id: str | None
    name: str
    severity: str | None  # None for role-aware rules (severity varies)


@dataclass
class Report:
    pcap_path: str
    summary: Summary
    sessions: list[SessionReport]
    recommendations: list[Recommendation]
    limitations: list[str]
    rules_reference: list[RuleReference]
