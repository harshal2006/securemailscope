"""CLI: parse a pcap, apply rules, and print sessions/findings/posture score.

Usage:
  python -m core.analyze <path-to-pcap>
  python -m core.analyze <path-to-pcap> --json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from core.pcap_reader import read_packets
from core.rules_engine import evaluate_session, load_rules
from core.scoring import build_posture_report
from core.session_builder import build_sessions, group_packets_by_stream
from core.starttls import build_timeline


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m core.analyze")
    parser.add_argument("pcap", type=Path)
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON instead of text"
    )
    return parser.parse_args(argv)


def _analyze(pcap_path: Path):
    """Returns (sessions, starttls_by_stream, report)."""
    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)
    packets_by_stream = group_packets_by_stream(packets)

    rules = load_rules()
    starttls_by_stream = {}
    sessions_and_findings = []
    for session in sessions:
        starttls_analysis = None
        if session.tls_mode in ("plaintext_only", "starttls"):
            starttls_analysis = build_timeline(
                packets_by_stream[session.tcp_stream], session.server_port, session.protocol
            )
            starttls_by_stream[session.tcp_stream] = starttls_analysis
        findings = evaluate_session(session, rules, starttls_analysis)
        sessions_and_findings.append((session, findings))

    report = build_posture_report(sessions_and_findings)
    return sessions, starttls_by_stream, report


def _cert_to_dict(cert) -> dict | None:
    if cert is None:
        return None
    return {
        "subject_cn": cert.subject_cn,
        "issuer_cn": cert.issuer_cn,
        "self_signed": cert.self_signed,
        "key_algorithm": cert.key_algorithm,
        "key_size": cert.key_size,
        "signature_hash_algorithm": cert.signature_hash_algorithm,
        "san_dns_names": cert.san_dns_names,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "is_expired": cert.is_expired,
    }


def _session_to_dict(session, starttls_analysis, findings, score) -> dict:
    tls_info = session.tls_info
    return {
        "tcp_stream": session.tcp_stream,
        "protocol": session.protocol,
        "tls_mode": session.tls_mode,
        "role": session.role,
        "client_ip": session.client_ip,
        "server_ip": session.server_ip,
        "server_port": session.server_port,
        "frames": [session.first_frame, session.last_frame],
        "tls": None
        if tls_info is None
        else {
            "negotiated_version": tls_info.negotiated_version,
            "cipher_suite": tls_info.cipher_suite,
            "cert_observable": tls_info.cert_observable,
            "cert_not_observable_reason": tls_info.cert_not_observable_reason,
            "leaf_cert": _cert_to_dict(tls_info.leaf_cert),
        },
        "starttls": None
        if starttls_analysis is None
        else {
            "capability_advertised_starttls": starttls_analysis.capability_advertised_starttls,
            "starttls_issued": starttls_analysis.starttls_issued,
            "starttls_success": starttls_analysis.starttls_success,
            "tls_followed": starttls_analysis.tls_followed,
            "auth_before_tls": starttls_analysis.auth_before_tls,
            "auth_after_tls": starttls_analysis.auth_after_tls,
            "timeline": [dataclasses.asdict(ev) for ev in starttls_analysis.timeline],
        },
        "findings": [dataclasses.asdict(f) for f in findings],
        "score": score,
    }


def _print_text(pcap_path: Path, sessions, starttls_by_stream, report) -> None:
    for session_score in report.session_scores:
        session = next(s for s in sessions if s.tcp_stream == session_score.tcp_stream)
        print(f"stream {session.tcp_stream}: {session.protocol} {session.tls_mode} "
              f"({session.role}) {session.client_ip} -> {session.server_ip}:{session.server_port} "
              f"(frames {session.first_frame}-{session.last_frame})")
        if session.tls_info:
            t = session.tls_info
            print(f"  negotiated TLS version: {t.negotiated_version}")
            print(f"  cipher suite: {t.cipher_suite}")
            if t.cert_observable:
                c = t.leaf_cert
                print(f"  certificate: CN={c.subject_cn} issuer={c.issuer_cn} "
                      f"{c.key_algorithm}-{c.key_size} sig={c.signature_hash_algorithm} "
                      f"self_signed={c.self_signed} expired={c.is_expired}")
            else:
                print(f"  certificate: not observable ({t.cert_not_observable_reason})")

        starttls_analysis = starttls_by_stream.get(session.tcp_stream)
        if starttls_analysis is not None:
            print("  STARTTLS timeline:")
            for ev in starttls_analysis.timeline:
                print(f"    [{ev.frame_number}] {ev.direction:8s} {ev.kind:12s} {ev.text!r}")
            print(f"  capability_advertised_starttls={starttls_analysis.capability_advertised_starttls} "
                  f"starttls_issued={starttls_analysis.starttls_issued} "
                  f"starttls_success={starttls_analysis.starttls_success} "
                  f"auth_before_tls={starttls_analysis.auth_before_tls}")

        if session_score.findings:
            print("  findings:")
            for f in session_score.findings:
                plan_suffix = f" ({f.plan_id})" if f.plan_id else ""
                print(f"    [{f.severity}] {f.rule_id}{plan_suffix}: {f.message}")
        print(f"  session score: {session_score.score}/100")
        print()

    print(f"Overall posture score: {report.overall_score}/100")


def main(argv: list[str]) -> int:
    args = _parse_args(argv)

    sessions, starttls_by_stream, report = _analyze(args.pcap)

    if not sessions:
        if args.json:
            print(json.dumps({"pcap": str(args.pcap), "overall_score": None, "sessions": []}))
        else:
            print("No SMTP/IMAP/POP3 sessions recognized in this capture.")
        return 0

    if args.json:
        session_dicts = []
        for session_score in report.session_scores:
            session = next(s for s in sessions if s.tcp_stream == session_score.tcp_stream)
            starttls_analysis = starttls_by_stream.get(session.tcp_stream)
            session_dicts.append(
                _session_to_dict(
                    session, starttls_analysis, session_score.findings, session_score.score
                )
            )
        print(json.dumps(
            {
                "pcap": str(args.pcap),
                "overall_score": report.overall_score,
                "sessions": session_dicts,
            },
            indent=2,
        ))
    else:
        _print_text(args.pcap, sessions, starttls_by_stream, report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
