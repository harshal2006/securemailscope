"""Runs a pcap through the real rule engine AND the ML classifier, then
fuses them (ml/fusion.py) - demonstrates the fusion in action rather
than reporting the ML model standalone.

Usage: python -m ml.predict <pcap>
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd

from core.pcap_reader import read_packets
from core.rules_engine import evaluate_session, load_rules
from core.session_builder import build_sessions, group_packets_by_stream
from core.starttls import build_timeline
from ml.features import FEATURE_NAMES, extract_features
from ml.fusion import fuse_severity

MODEL_PATH = Path(__file__).parent / "models" / "risk_classifier.joblib"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m ml.predict <pcap>", file=sys.stderr)
        return 2

    if not MODEL_PATH.exists():
        print(f"No trained model at {MODEL_PATH} - run `python -m ml.train` first.", file=sys.stderr)
        return 1

    clf = joblib.load(MODEL_PATH)
    rules = load_rules()

    pcap_path = Path(argv[0])
    packets = read_packets(pcap_path)
    sessions = build_sessions(packets)
    packets_by_stream = group_packets_by_stream(packets)

    if not sessions:
        print("No SMTP/IMAP/POP3 sessions recognized in this capture.")
        return 0

    for session in sessions:
        starttls_analysis = None
        if session.tls_mode in ("plaintext_only", "starttls"):
            starttls_analysis = build_timeline(
                packets_by_stream[session.tcp_stream], session.server_port, session.protocol
            )
        findings = evaluate_session(session, rules, starttls_analysis)
        feature_row = extract_features(session, starttls_analysis, rules)
        X = pd.DataFrame([feature_row], columns=FEATURE_NAMES)
        ml_pred = clf.predict(X)[0]

        verdict = fuse_severity(findings, ml_pred)

        print(f"stream {session.tcp_stream}: {session.protocol} {session.tls_mode} ({session.role})")
        print(f"  rule findings: {[f.rule_id for f in findings] or '(none)'}")
        print(f"  rule severity (worst): {verdict.rule_severity}")
        print(f"  ML predicted risk class: {verdict.ml_risk_class}"
              f" (-> {verdict.ml_severity_raw}"
              f"{', discounted to ' + verdict.ml_severity_adjusted if verdict.rules_silent else ''})")
        print(f"  rules silent (no actionable finding): {verdict.rules_silent}")
        print(f"  FUSED FINAL SEVERITY: {verdict.final_severity}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
