"""CLI: parse a pcap, apply rules, and print sessions/findings/posture score.

Usage: python -m core.analyze <path-to-pcap>
"""

from __future__ import annotations

import sys
from pathlib import Path

from core.pcap_reader import read_packets
from core.rules_engine import evaluate_session, load_rules
from core.scoring import build_posture_report
from core.session_builder import build_sessions


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m core.analyze <pcap>", file=sys.stderr)
        return 2

    pcap_path = Path(argv[1])
    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)

    if not sessions:
        print("No SMTP/IMAP/POP3 sessions recognized in this capture.")
        return 0

    rules = load_rules()
    sessions_and_findings = [(s, evaluate_session(s, rules)) for s in sessions]
    report = build_posture_report(sessions_and_findings)

    for session_score in report.session_scores:
        session = next(s for s in sessions if s.tcp_stream == session_score.tcp_stream)
        print(f"stream {session.tcp_stream}: {session.protocol} {session.tls_mode} "
              f"{session.client_ip} -> {session.server_ip}:{session.server_port} "
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

        if session_score.findings:
            print("  findings:")
            for f in session_score.findings:
                print(f"    [{f.severity}] {f.rule_id}: {f.message}")
        print(f"  session score: {session_score.score}/100")
        print()

    print(f"Overall posture score: {report.overall_score}/100")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
