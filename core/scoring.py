"""Turns per-session findings into a 0-100 posture score.

A session's score is 100 minus the sum of its findings' score_impact,
floored at 0. The overall posture score for a capture is the minimum of
its session scores: posture is only as strong as the weakest session.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.findings import Finding


@dataclass
class SessionScore:
    tcp_stream: int
    protocol: str
    server_port: int
    score: int
    findings: list[Finding]


@dataclass
class PostureReport:
    overall_score: int | None  # None if no sessions were found at all
    session_scores: list[SessionScore]


def score_session_findings(findings: list[Finding]) -> int:
    impact = sum(f.score_impact for f in findings)
    return max(0, 100 - impact)


def build_posture_report(sessions_and_findings: list[tuple]) -> PostureReport:
    """sessions_and_findings: list of (Session, list[Finding]) pairs."""
    session_scores = [
        SessionScore(
            tcp_stream=session.tcp_stream,
            protocol=session.protocol,
            server_port=session.server_port,
            score=score_session_findings(findings),
            findings=findings,
        )
        for session, findings in sessions_and_findings
    ]

    overall = min((s.score for s in session_scores), default=None)
    return PostureReport(overall_score=overall, session_scores=session_scores)
