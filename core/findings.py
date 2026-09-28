"""Finding: one rule result attached to a session."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    score_impact: int
    message: str
    tcp_stream: int
    protocol: str
    server_port: int
    plan_id: str | None = None  # the hackathon plan's rule numbering, if any
