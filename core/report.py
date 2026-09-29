"""Renders the analyzer's output into the Report schema (core/report_models.py)
as schema-validated JSON or an HTML page.

Reuses core.analyze's pipeline (read_packets -> build_sessions ->
build_timeline -> evaluate_session -> build_posture_report) rather than
recomputing anything - this module is presentation only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema
import yaml
from jinja2 import Environment, FileSystemLoader

from core.analyze import _analyze
from core.findings import Finding
from core.report_models import (
    CertificateSummary,
    FindingSummary,
    Recommendation,
    Report,
    RuleReference,
    SessionReport,
    Summary,
    TimelineEventSummary,
)

RULES_DIR = Path(__file__).parent.parent / "rules"
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

LIMITATIONS = [
    "Passive analysis only: this tool never connects to, probes, or sends traffic "
    "to any mail server. It only reads pcap files that already exist.",
    "TLS 1.3 certificates are never observable to a passive listener - the "
    "Certificate message is encrypted. Reported as 'not observable', never guessed.",
    "Certificate expiry is judged against the pcap's own capture timestamp, not "
    "the time this report was generated.",
    "C-03 (weak Diffie-Hellman parameters, <=1024 bits) is not implemented - it "
    "would require parsing the ServerKeyExchange handshake message, which this "
    "tool does not currently do.",
    "NULL-cipher and anonymous-DH weak-cipher findings, and the C-05 "
    "(no-forward-secrecy) finding for static-DH (as opposed to static-RSA) key "
    "exchange, are implemented but have no real-capture test coverage - only "
    "RC4, 3DES, and static-RSA key exchange have been verified against real "
    "traffic.",
    "Hostname/SAN matching only covers exact matches and a single leftmost "
    "wildcard label (RFC 6125 style); it is not a full RFC 6125 implementation.",
]

# Rule IDs that are informational (never "wrong", nothing to recommend fixing).
_INFORMATIONAL_RULE_IDS = {
    "CERT_NOT_OBSERVABLE",
    "CERT_HOSTNAME_NOT_EVALUABLE",
    "FORWARD_SECRECY_NOT_EVALUABLE",
    "TLS_VERSION_1_3",
}


def _load_yaml(name: str) -> dict:
    with open(RULES_DIR / name) as f:
        return yaml.safe_load(f)


def _grade(score: int | None) -> str:
    if score is None:
        return "N/A"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _cert_summary(cert) -> CertificateSummary | None:
    if cert is None:
        return None
    return CertificateSummary(
        subject_cn=cert.subject_cn,
        issuer_cn=cert.issuer_cn,
        self_signed=cert.self_signed,
        key_algorithm=cert.key_algorithm,
        key_size=cert.key_size,
        signature_hash_algorithm=cert.signature_hash_algorithm,
        san_dns_names=cert.san_dns_names,
        not_before=cert.not_before.isoformat(),
        not_after=cert.not_after.isoformat(),
        is_expired=cert.is_expired,
    )


def _finding_summary(f: Finding) -> FindingSummary:
    return FindingSummary(
        rule_id=f.rule_id,
        plan_id=f.plan_id,
        severity=f.severity,
        message=f.message,
        score_impact=f.score_impact,
    )


def _build_rules_reference() -> list[RuleReference]:
    refs: list[RuleReference] = []

    tls_version_rules = _load_yaml("tls_version_rules.yaml")
    for name, meta in tls_version_rules.items():
        refs.append(RuleReference(meta["rule_id"], meta.get("id"), f"{name} negotiated", meta["severity"]))

    cert_rules = _load_yaml("cert_rules.yaml")
    for rule_id, meta in cert_rules.items():
        refs.append(RuleReference(rule_id, meta.get("id"), rule_id.replace("_", " ").title(), meta["severity"]))

    mode_rules = _load_yaml("mode_rules.yaml")
    for rule_id, meta in mode_rules.items():
        refs.append(RuleReference(rule_id, meta.get("id"), rule_id.replace("_", " ").title(), meta["severity"]))

    weak_ciphers = _load_yaml("weak_ciphers.yaml")
    refs.append(
        RuleReference(
            weak_ciphers["rule_id"], weak_ciphers.get("id"), "Weak/broken cipher suite", weak_ciphers["severity"]
        )
    )

    forward_secrecy = _load_yaml("forward_secrecy.yaml")
    refs.append(
        RuleReference(
            forward_secrecy["rule_id"],
            forward_secrecy.get("id"),
            "No forward secrecy (static key exchange)",
            forward_secrecy["severity"],
        )
    )
    refs.append(
        RuleReference("FORWARD_SECRECY_NOT_EVALUABLE", None, "Forward secrecy not evaluable", "INFO")
    )

    starttls_rules = _load_yaml("starttls_rules.yaml")
    for rule_id, meta in starttls_rules.items():
        # T-02/T-03 are role-aware (severity varies by mx/submission).
        severity = meta.get("severity")
        refs.append(RuleReference(rule_id, meta.get("id"), meta["message"], severity))

    return refs


def _build_recommendations(all_findings: list[FindingSummary]) -> list[Recommendation]:
    recs_yaml = _load_yaml("recommendations.yaml")
    seen_rule_ids: set[str] = set()
    recommendations: list[Recommendation] = []
    for f in all_findings:
        if f.rule_id in _INFORMATIONAL_RULE_IDS or f.rule_id in seen_rule_ids:
            continue
        meta = recs_yaml.get(f.rule_id)
        if meta is None:
            continue
        seen_rule_ids.add(f.rule_id)
        recommendations.append(
            Recommendation(
                rule_id=f.rule_id,
                plan_id=f.plan_id,
                title=meta["title"],
                fix=meta["fix"],
                verification_command=meta.get("verification_command"),
            )
        )
    return recommendations


def build_report(pcap_path: Path) -> Report:
    pcap_path = Path(pcap_path)
    sessions, starttls_by_stream, posture_report = _analyze(pcap_path)

    session_reports: list[SessionReport] = []
    all_findings: list[FindingSummary] = []
    findings_by_severity: dict[str, int] = {}
    observable_cert_sessions = 0
    tls_session_count = 0

    for session_score in posture_report.session_scores:
        session = next(s for s in sessions if s.tcp_stream == session_score.tcp_stream)
        tls_info = session.tls_info
        starttls_analysis = starttls_by_stream.get(session.tcp_stream)

        finding_summaries = [_finding_summary(f) for f in session_score.findings]
        all_findings.extend(finding_summaries)
        for fs in finding_summaries:
            findings_by_severity[fs.severity] = findings_by_severity.get(fs.severity, 0) + 1

        if tls_info is not None:
            tls_session_count += 1
            if tls_info.cert_observable:
                observable_cert_sessions += 1

        session_reports.append(
            SessionReport(
                tcp_stream=session.tcp_stream,
                protocol=session.protocol,
                tls_mode=session.tls_mode,
                role=session.role,
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                server_port=session.server_port,
                first_frame=session.first_frame,
                last_frame=session.last_frame,
                score=session_score.score,
                negotiated_tls_version=tls_info.negotiated_version if tls_info else None,
                cipher_suite=tls_info.cipher_suite if tls_info else None,
                sni_hostname=tls_info.sni_hostname if tls_info else None,
                cert_observable=tls_info.cert_observable if tls_info else None,
                cert_not_observable_reason=tls_info.cert_not_observable_reason if tls_info else None,
                certificate=_cert_summary(tls_info.leaf_cert) if tls_info else None,
                timeline=[
                    TimelineEventSummary(ev.frame_number, ev.direction, ev.kind, ev.text)
                    for ev in starttls_analysis.timeline
                ]
                if starttls_analysis
                else [],
                findings=finding_summaries,
            )
        )

    summary = Summary(
        overall_score=posture_report.overall_score,
        grade=_grade(posture_report.overall_score),
        session_count=len(session_reports),
        findings_by_severity=findings_by_severity,
        observable_cert_sessions=observable_cert_sessions,
        tls_session_count=tls_session_count,
        observable_cert_ratio=(observable_cert_sessions / tls_session_count) if tls_session_count else None,
    )

    return Report(
        pcap_path=str(pcap_path),
        summary=summary,
        sessions=session_reports,
        recommendations=_build_recommendations(all_findings),
        limitations=LIMITATIONS,
        rules_reference=_build_rules_reference(),
    )


REPORT_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["pcap_path", "summary", "sessions", "recommendations", "limitations", "rules_reference"],
    "properties": {
        "pcap_path": {"type": "string"},
        "summary": {
            "type": "object",
            "required": [
                "overall_score", "grade", "session_count", "findings_by_severity",
                "observable_cert_sessions", "tls_session_count", "observable_cert_ratio",
            ],
            "properties": {
                "overall_score": {"type": ["integer", "null"]},
                "grade": {"type": "string"},
                "session_count": {"type": "integer"},
                "findings_by_severity": {"type": "object"},
                "observable_cert_sessions": {"type": "integer"},
                "tls_session_count": {"type": "integer"},
                "observable_cert_ratio": {"type": ["number", "null"]},
            },
        },
        "sessions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "tcp_stream", "protocol", "tls_mode", "role", "client_ip", "server_ip",
                    "server_port", "first_frame", "last_frame", "score", "findings", "timeline",
                ],
                "properties": {
                    "tcp_stream": {"type": "integer"},
                    "protocol": {"type": "string"},
                    "tls_mode": {"type": "string"},
                    "role": {"type": "string"},
                    "score": {"type": "integer"},
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["rule_id", "severity", "message", "score_impact"],
                            "properties": {
                                "rule_id": {"type": "string"},
                                "severity": {"type": "string"},
                                "message": {"type": "string"},
                                "score_impact": {"type": "integer"},
                            },
                        },
                    },
                },
            },
        },
        "recommendations": {"type": "array"},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "rules_reference": {"type": "array"},
    },
}


def report_to_dict(report: Report) -> dict:
    return dataclasses.asdict(report)


def report_to_json(report: Report, *, validate: bool = True) -> str:
    data = report_to_dict(report)
    if validate:
        jsonschema.validate(instance=data, schema=REPORT_JSON_SCHEMA)
    return json.dumps(data, indent=2)


def render_html(report: Report) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        # Always HTML output regardless of the template filename's own
        # extension (report.html.j2 ends in .j2, so
        # select_autoescape(["html"]) would silently disable escaping -
        # found via screenshot review: <host>:<port> placeholders in
        # recommendation commands were eaten as bogus HTML tags).
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(report=report)


# Common install locations for a Chromium-family browser with headless
# print-to-pdf support. Checked in order; overridable via $CHROME_PATH.
_CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
]


def _find_chrome_binary() -> str:
    import os

    env_path = os.environ.get("CHROME_PATH")
    if env_path and Path(env_path).exists():
        return env_path
    for candidate in _CHROME_CANDIDATES:
        if Path(candidate).is_absolute():
            if Path(candidate).exists():
                return candidate
        else:
            found = shutil.which(candidate)
            if found:
                return found
    raise RuntimeError(
        "No Chromium-family browser found for PDF export. Install Google Chrome or "
        "Chromium, or set $CHROME_PATH to its binary."
    )


def render_pdf_from_html(html: str) -> bytes:
    """PDF export via a headless Chromium's built-in print-to-pdf, given
    already-rendered HTML (e.g. the API's cached job.report_html) - no
    second template, no separate PDF-specific rendering logic, and no
    need to recompute the report just to get a PDF of it. The HTML is
    written to a real temp file first because Chrome's headless
    print-to-pdf needs a file:// (or http://) URL, not stdin.
    """
    chrome = _find_chrome_binary()

    with tempfile.TemporaryDirectory() as tmp_dir:
        html_path = Path(tmp_dir) / "report.html"
        pdf_path = Path(tmp_dir) / "report.pdf"
        html_path.write_text(html)

        result = subprocess.run(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                f"file://{html_path}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if not pdf_path.exists():
            raise RuntimeError(
                f"PDF export failed (chrome exit {result.returncode}): {result.stderr}"
            )
        return pdf_path.read_bytes()


def render_pdf(report: Report) -> bytes:
    """Convenience wrapper: render_pdf_from_html(render_html(report))."""
    return render_pdf_from_html(render_html(report))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.report")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--json", type=Path, help="write schema-validated JSON to this path")
    parser.add_argument("--html", type=Path, help="write an HTML report to this path")
    parser.add_argument("--pdf", type=Path, help="write a PDF report to this path")
    args = parser.parse_args(argv)

    report = build_report(args.pcap)

    if not args.json and not args.html and not args.pdf:
        print(report_to_json(report))
        return 0

    if args.json:
        args.json.write_text(report_to_json(report))
        print(f"Wrote {args.json}")
    if args.html:
        args.html.write_text(render_html(report))
        print(f"Wrote {args.html}")
    if args.pdf:
        args.pdf.write_bytes(render_pdf(report))
        print(f"Wrote {args.pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
